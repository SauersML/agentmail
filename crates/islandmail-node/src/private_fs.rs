//! Owner-only files and directories for keys and mail. On Unix: modes 0600 and 0700, no group or world bits. On
//! Windows: a protected DACL that grants only the current user; a file passes the check when every allow entry names
//! that user, the file's owner, SYSTEM or Administrators (the Windows counterparts of root, which can read any file).

use std::fs::{File, OpenOptions};
use std::path::Path;

use anyhow::{Context, Result};

/// Open options that create files owner-only and do not follow a symlink at the final path component;
/// `check_file` refuses a file other users could read or write; `check_writers` refuses a file that decides what this
/// node trusts or holds (config, trust file) when another user could change it: on Unix, group or other write bits on
/// it, or on its folder without the sticky bit, or an owner other than this user or root (Windows: not checked, access
/// lists there are inherited and checked for key files only); `sync_dir` persists directory entries (Windows has no
/// directory fsync; NTFS journals metadata).
pub use imp::{check_file, check_writers, links, options, sync_dir};

pub fn restrict_file(file: &File, path: &Path) -> Result<()> {
    imp::restrict_file(file, path).with_context(|| format!("restricting {} to its owner", path.display()))
}

/// Create a directory (and missing parents) owner-only; an existing directory is left as it is.
pub fn create_dir(path: &Path) -> Result<()> {
    imp::create_dir(path).with_context(|| format!("creating {}", path.display()))
}

/// Make a directory, and files later created in it, owner-only.
pub fn restrict_dir(path: &Path) -> Result<()> {
    imp::restrict_dir(path).with_context(|| format!("restricting {} to its owner", path.display()))
}

/// Refuse a directory that is a symlink, not a directory, or open to other users.
pub fn check_dir(path: &Path) -> Result<()> {
    anyhow::ensure!(path.symlink_metadata()?.is_dir(), "{} is not a directory", path.display());
    imp::check_file(&imp::open_dir(path)?, path)
}

// The access list check runs on Windows; its parser is tested everywhere.
#[cfg(any(windows, test))]
const PRIVILEGED: [&str; 8] = ["SY", "S-1-5-18", "BA", "S-1-5-32-544", "OW", "S-1-3-4", "CO", "S-1-3-0"];

/// Check an SDDL string (owner and DACL). Err names the first trustee, other than `user` (a SID string), the owner,
/// SYSTEM or Administrators, that an allow entry grants access to. A missing (NULL) DACL grants everyone.
#[cfg(any(windows, test))]
pub fn sddl_private(sddl: &str, user: &str) -> std::result::Result<(), String> {
    let owner = sddl.strip_prefix("O:").map(|rest| match rest.strip_prefix("S-") {
        Some(tail) => format!("S-{}", tail.split(|c: char| !(c.is_ascii_digit() || c == '-')).next().unwrap_or("")),
        None => rest.chars().take(2).collect(),
    });
    let Some(at) = sddl.find("D:") else { return Err("everyone (no access list)".into()) };
    let dacl = &sddl[at + 2..];
    let aces_at = dacl.find('(').unwrap_or(dacl.len());
    if dacl[..aces_at].contains("NO_ACCESS_CONTROL") {
        return Err("everyone (no access list)".into());
    }
    let mut rest = &dacl[aces_at..];
    while let Some(body) = rest.strip_prefix('(') {
        let Some(end) = body.find(')') else { return Err("an unreadable access list".into()) };
        let fields: Vec<&str> = body[..end].split(';').collect();
        rest = &body[end + 1..];
        let (Some(kind), Some(sid)) = (fields.first(), fields.get(5)) else { return Err("an unreadable access list".into()) };
        if !matches!(*kind, "A" | "OA" | "XA" | "ZA") {
            continue;
        }
        let local_admin = *sid == "LA" && user.ends_with("-500");
        if *sid != user && Some(*sid) != owner.as_deref() && !PRIVILEGED.contains(sid) && !local_admin {
            return Err((*sid).to_string());
        }
    }
    Ok(())
}

#[cfg(unix)]
mod imp {
    use super::*;
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};

    pub fn options() -> OpenOptions {
        let mut o = OpenOptions::new();
        o.mode(0o600).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        o
    }

    pub fn check_file(file: &File, path: &Path) -> Result<()> {
        let md = file.metadata()?;
        let mode = md.permissions().mode() & 0o777;
        anyhow::ensure!(mode & 0o077 == 0, "{} must be private but has mode {mode:o}; run chmod go= on it", path.display());
        check_owner(&md, path)
    }

    fn check_owner(md: &std::fs::Metadata, path: &Path) -> Result<()> {
        let me = unsafe { libc::geteuid() };
        anyhow::ensure!(md.uid() == me || md.uid() == 0,
                        "{} is owned by another user (uid {}); it must be this user's (uid {me}) or root's: run chown {me} on it",
                        path.display(), md.uid());
        Ok(())
    }

    pub fn check_writers(path: &Path) -> Result<()> {
        let md = std::fs::metadata(path).with_context(|| format!("reading {}", path.display()))?;
        let mode = md.permissions().mode() & 0o7777;
        anyhow::ensure!(mode & 0o022 == 0,
                        "{} is writable by other users (mode {:o}); run chmod go-w on it", path.display(), mode & 0o777);
        check_owner(&md, path)?;
        // Whoever can write its folder can replace it, unless the folder is sticky (as /tmp is).
        let dir = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
        let dmd = std::fs::metadata(dir).with_context(|| format!("reading {}", dir.display()))?;
        let dmode = dmd.permissions().mode() & 0o7777;
        anyhow::ensure!(dmode & 0o022 == 0 || dmode & 0o1000 != 0,
                        "{} is in {}, which other users can write (mode {:o}): they could replace it; run chmod go-w on \
                         that folder or move the file", path.display(), dir.display(), dmode & 0o777);
        check_owner(&dmd, dir)
    }

    pub fn restrict_file(file: &File, _path: &Path) -> Result<()> {
        Ok(file.set_permissions(std::fs::Permissions::from_mode(0o600))?)
    }

    pub fn create_dir(path: &Path) -> Result<()> {
        Ok(std::fs::DirBuilder::new().mode(0o700).recursive(true).create(path)?)
    }

    pub fn restrict_dir(path: &Path) -> Result<()> {
        Ok(std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?)
    }

    pub fn open_dir(path: &Path) -> Result<File> {
        Ok(OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY).open(path)?)
    }

    pub fn links(file: &File) -> Result<u64> {
        Ok(file.metadata()?.nlink())
    }

    pub fn sync_dir(path: &Path) -> Result<()> {
        Ok(File::open(path)?.sync_all()?)
    }
}

#[cfg(windows)]
mod imp {
    use super::*;
    use std::ffi::OsStr;

    pub fn check_writers(_path: &Path) -> Result<()> {
        Ok(())
    }
    use std::io::Error;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use std::ptr::null_mut;
    use windows_sys::core::PWSTR;
    use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, HANDLE};
    use windows_sys::Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW, ConvertSidToStringSidW,
        ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SetNamedSecurityInfoW, SDDL_REVISION_1,
        SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        GetSecurityDescriptorDacl, GetTokenInformation, TokenUser, ACL, DACL_SECURITY_INFORMATION,
        OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, TOKEN_QUERY, TOKEN_USER,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    fn wide(s: &OsStr) -> Vec<u16> {
        s.encode_wide().chain(Some(0)).collect()
    }

    /// Copy and free a string the system allocated with LocalAlloc.
    unsafe fn take_wide(p: PWSTR) -> String {
        let mut n = 0;
        while *p.add(n) != 0 {
            n += 1;
        }
        let s = String::from_utf16_lossy(std::slice::from_raw_parts(p, n));
        LocalFree(p.cast());
        s
    }

    pub fn user_sid() -> Result<String> {
        unsafe {
            let mut token: HANDLE = null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return Err(Error::last_os_error().into());
            }
            let mut len = 0u32;
            GetTokenInformation(token, TokenUser, null_mut(), 0, &mut len);
            let mut buf = vec![0u64; (len as usize).div_ceil(8)];
            let ok = GetTokenInformation(token, TokenUser, buf.as_mut_ptr().cast(), len, &mut len);
            let err = Error::last_os_error();
            CloseHandle(token);
            anyhow::ensure!(ok != 0, "reading the current user: {err}");
            let user = &*(buf.as_ptr() as *const TOKEN_USER);
            let mut s: PWSTR = null_mut();
            if ConvertSidToStringSidW(user.User.Sid, &mut s) == 0 {
                return Err(Error::last_os_error().into());
            }
            Ok(take_wide(s))
        }
    }

    fn sddl_of(file: &File) -> Result<String> {
        let what = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
        unsafe {
            let mut sd: PSECURITY_DESCRIPTOR = null_mut();
            let err = GetSecurityInfo(file.as_raw_handle() as HANDLE, SE_FILE_OBJECT, what, null_mut(), null_mut(),
                null_mut(), null_mut(), &mut sd);
            if err != 0 {
                return Err(Error::from_raw_os_error(err as i32).into());
            }
            let mut s: PWSTR = null_mut();
            let ok = ConvertSecurityDescriptorToStringSecurityDescriptorW(sd, SDDL_REVISION_1, what, &mut s, null_mut());
            let err = Error::last_os_error();
            LocalFree(sd);
            anyhow::ensure!(ok != 0, "reading an access list: {err}");
            Ok(take_wide(s))
        }
    }

    pub fn check_file(file: &File, path: &Path) -> Result<()> {
        if let Err(who) = sddl_private(&sddl_of(file)?, &user_sid()?) {
            anyhow::bail!("{} must be private but {who} can access it; allow only your user \
                (icacls \"{}\" /inheritance:r /grant:r \"%USERNAME%:F\")", path.display(), path.display());
        }
        Ok(())
    }

    /// Replace the DACL of `path` with the one in `sddl` (protected: nothing inherited from the parent).
    pub fn set_dacl(path: &Path, sddl: &str) -> Result<()> {
        unsafe {
            let mut sd: PSECURITY_DESCRIPTOR = null_mut();
            if ConvertStringSecurityDescriptorToSecurityDescriptorW(wide(OsStr::new(sddl)).as_ptr(), SDDL_REVISION_1,
                &mut sd, null_mut()) == 0
            {
                return Err(Error::last_os_error().into());
            }
            let (mut present, mut defaulted) = (0, 0);
            let mut dacl: *mut ACL = null_mut();
            let err = if GetSecurityDescriptorDacl(sd, &mut present, &mut dacl, &mut defaulted) == 0 {
                Error::last_os_error().raw_os_error().unwrap_or(1) as u32
            } else {
                SetNamedSecurityInfoW(wide(path.as_os_str()).as_ptr(), SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, null_mut(), null_mut(), dacl,
                    null_mut())
            };
            LocalFree(sd);
            if err != 0 {
                return Err(Error::from_raw_os_error(err as i32).into());
            }
        }
        Ok(())
    }

    pub fn options() -> OpenOptions {
        let mut o = OpenOptions::new();
        o.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        o
    }

    pub fn restrict_file(_file: &File, path: &Path) -> Result<()> {
        set_dacl(path, &format!("D:P(A;;FA;;;{})", user_sid()?))
    }

    pub fn create_dir(path: &Path) -> Result<()> {
        if path.is_dir() {
            return Ok(());
        }
        std::fs::create_dir_all(path)?;
        restrict_dir(path)
    }

    pub fn restrict_dir(path: &Path) -> Result<()> {
        // Object and container inherit: files and folders created inside get the same single entry.
        set_dacl(path, &format!("D:P(A;OICI;FA;;;{})", user_sid()?))
    }

    pub fn open_dir(path: &Path) -> Result<File> {
        Ok(OpenOptions::new().read(true).custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?)
    }

    pub fn links(file: &File) -> Result<u64> {
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        if unsafe { GetFileInformationByHandle(file.as_raw_handle() as HANDLE, &mut info) } == 0 {
            return Err(Error::last_os_error().into());
        }
        Ok(u64::from(info.nNumberOfLinks))
    }

    pub fn sync_dir(_path: &Path) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ME: &str = "S-1-5-21-1-2-3-1001";

    #[test]
    fn sddl_allows_only_the_user_owner_system_and_administrators() {
        assert_eq!(sddl_private("O:S-1-5-21-1-2-3-1001G:S-1-5-21-1-2-3-513D:P(A;;FA;;;S-1-5-21-1-2-3-1001)", ME), Ok(()));
        assert_eq!(sddl_private("O:BAD:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;OICIID;FA;;;S-1-5-21-1-2-3-1001)", ME), Ok(()));
        assert_eq!(sddl_private("O:BAD:P(A;OICIIO;GA;;;CO)(D;;FA;;;WD)", ME), Ok(()));
        assert_eq!(sddl_private("O:DDD:P", ME), Ok(()));
        assert_eq!(sddl_private("O:S-1-5-21-1-2-3-1001D:P(A;;FR;;;WD)", ME), Err("WD".into()));
        assert_eq!(sddl_private("O:S-1-5-21-1-2-3-1001D:AI(A;ID;0x1200a9;;;BU)", ME), Err("BU".into()));
        assert_eq!(sddl_private("O:S-1-5-21-1-2-3-1001D:P(A;;FA;;;S-1-5-21-1-2-3-1002)", ME), Err("S-1-5-21-1-2-3-1002".into()));
        assert!(sddl_private("O:S-1-5-21-1-2-3-1001D:NO_ACCESS_CONTROL", ME).is_err());
        assert!(sddl_private("O:S-1-5-21-1-2-3-1001", ME).is_err());
        assert_eq!(sddl_private("O:BAD:P(A;;FA;;;LA)", "S-1-5-21-1-2-3-500"), Ok(()));
        assert_eq!(sddl_private("O:BAD:P(A;;FA;;;LA)", ME), Err("LA".into()));
    }

    #[cfg(unix)]
    #[test]
    fn config_and_trust_files_others_can_write_are_refused() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("islandmail-node-writers-{}", islandmail_core::b64u(&islandmail_core::random_bytes::<9>())));
        create_dir(&dir)?;
        let path = dir.join("members.json");
        std::fs::write(&path, b"{}")?;
        for (mode, ok) in [(0o644, true), (0o600, true), (0o664, false), (0o646, false), (0o666, false)] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))?;
            let r = check_writers(&path);
            assert_eq!(r.is_ok(), ok, "mode {mode:o}");
            if let Err(e) = r {
                assert!(format!("{e:#}").contains("chmod go-w"), "{e:#}");
            }
        }
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))?;
        // A folder others can write (not sticky): the file could be replaced.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777))?;
        assert!(format!("{:#}", check_writers(&path).unwrap_err()).contains("replace"));
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o1777))?;
        check_writers(&path)?;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
        check_writers(&path)?;
        std::fs::remove_dir_all(dir)?;
        Ok(())
    }

    #[test]
    fn created_files_and_dirs_are_private_and_open_ones_are_refused() -> Result<()> {
        let dir = std::env::temp_dir().join(format!("islandmail-node-private-{}", islandmail_core::b64u(&islandmail_core::random_bytes::<9>())));
        create_dir(&dir.join("inner"))?;
        check_dir(&dir.join("inner"))?;
        let path = dir.join("inner").join("f");
        let f = options().write(true).create_new(true).open(&path)?;
        restrict_file(&f, &path)?;
        check_file(&f, &path)?;
        assert_eq!(links(&f)?, 1);
        drop(f);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640))?;
        }
        #[cfg(windows)]
        imp::set_dacl(&path, &format!("D:P(A;;FA;;;{})(A;;FR;;;WD)", imp::user_sid()?))?;
        let f = options().read(true).open(&path)?;
        assert!(check_file(&f, &path).is_err());
        drop(f);
        std::fs::remove_dir_all(dir)?;
        Ok(())
    }
}
