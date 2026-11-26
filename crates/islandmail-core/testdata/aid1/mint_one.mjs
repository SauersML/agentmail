// Mints one aid1 token with archipelago-home's own mintToken, for tests/homes.py --archipelago-home.
//   echo '{"seed": "<issuer seed hex>", "payload": {...}}' | node --experimental-transform-types mint_one.mjs CHECKOUT
// Reads src/token.ts and src/keys.ts from the checkout (copied to a temporary folder; the checkout is not changed).
import { createPrivateKey } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const [home] = process.argv.slice(2);
const tmp = mkdtempSync(join(tmpdir(), 'aid1-'));
for (const f of ['token.ts', 'keys.ts']) {
  writeFileSync(join(tmp, f), readFileSync(join(home, 'src', f), 'utf8').replaceAll("'./keys.js'", "'./keys.ts'"));
}
const { mintToken } = await import(pathToFileURL(join(tmp, 'token.ts')).href);
rmSync(tmp, { recursive: true });
const { seed, payload } = JSON.parse(readFileSync(0, 'utf8'));
const PKCS8 = Buffer.from('302e020100300506032b657004220420', 'hex');
const key = createPrivateKey({ key: Buffer.concat([PKCS8, Buffer.from(seed, 'hex')]), format: 'der', type: 'pkcs8' });
console.log(mintToken(key, payload));
