// Regenerates the aid1 test vectors with archipelago-home's own minter and checks them with its own verifier.
//   node --experimental-transform-types mint.mjs ARCHIPELAGO_HOME_CHECKOUT OUT_DIR
// Reads src/token.ts and src/keys.ts from the checkout (copied to a temporary folder; the checkout is not changed).
import { createPrivateKey, createPublicKey } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const [home, out] = process.argv.slice(2);
const tmp = mkdtempSync(join(tmpdir(), 'aid1-'));
for (const f of ['token.ts', 'keys.ts']) {
  const src = readFileSync(join(home, 'src', f), 'utf8').replaceAll("'./keys.js'", "'./keys.ts'");
  writeFileSync(join(tmp, f), src);
}
const { mintToken, verifyToken } = await import(pathToFileURL(join(tmp, 'token.ts')).href);
const { fingerprintOfPrivate } = await import(pathToFileURL(join(tmp, 'keys.ts')).href);

const PKCS8 = Buffer.from('302e020100300506032b657004220420', 'hex');
const priv = (hex) => createPrivateKey({ key: Buffer.concat([PKCS8, Buffer.from(hex, 'hex')]), format: 'der', type: 'pkcs8' });
const issuer = priv('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60');
const holder = fingerprintOfPrivate(priv('4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb'));
const NOW = 1785100600;
// The payload today's mintFor (src/exchange.ts) builds for an agent, in its key order: no kg, no cnf, exp required.
const base = { v: 1, iss: 'id.test', sub: 'agent:fable@guest', kind: 'agent', name: 'Fable', aud: 'islandmail:TESTNET',
               scopes: ['mail:send'], iat: NOW - 300 };
const drop = (o, k) => { const c = { ...o }; delete c[k]; return c; };
const vectors = {
  good: { ...base, exp: NOW + 300 },
  // With FEDERATION.md §9.7's kg and cnf (cnf where mintFor would put it, after exp).
  good_cnf_kg: { ...base, exp: NOW + 300, kg: 1, cnf: holder },
  expired: { ...base, exp: NOW - 10 },
  no_exp: drop({ ...base, exp: NOW + 300 }, 'exp'),
  long_lived: { ...base, exp: NOW + 3300 },
};
const opts = { issuerId: fingerprintOfPrivate(issuer), iss: 'id.test', aud: 'islandmail:TESTNET', nowMs: NOW * 1000 };
for (const [name, payload] of Object.entries(vectors)) {
  const tok = mintToken(issuer, payload);
  writeFileSync(join(out, `${name}.txt`), tok + '\n');
  const v = verifyToken(tok, opts);
  console.log(name, v.ok ? 'reference verifier: ok' : `reference verifier: ${v.reason}`);
}
console.log('issuer', opts.issuerId, 'holder', holder);
