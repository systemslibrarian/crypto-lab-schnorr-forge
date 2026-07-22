// Compressed-size budget for the shipped bundle. Keeps the lab's performance
// advantage from silently eroding. Run after `npm run build`.
import { readdirSync, readFileSync } from 'node:fs';
import { gzipSync } from 'node:zlib';
import { join } from 'node:path';

const BUDGETS = { js: 35 * 1024, css: 10 * 1024 }; // gzip bytes
const assetsDir = join('dist', 'assets');

let files;
try {
  files = readdirSync(assetsDir);
} catch {
  console.error('No dist/assets — run `npm run build` first.');
  process.exit(1);
}

const totals = { js: 0, css: 0 };
for (const f of files) {
  const ext = f.endsWith('.js') ? 'js' : f.endsWith('.css') ? 'css' : null;
  if (!ext) continue;
  const gz = gzipSync(readFileSync(join(assetsDir, f))).length;
  totals[ext] += gz;
  console.log(`  ${f}: ${(gz / 1024).toFixed(2)} kB gzip`);
}

let failed = false;
for (const [ext, used] of Object.entries(totals)) {
  const budget = BUDGETS[ext];
  const ok = used <= budget;
  failed ||= !ok;
  console.log(
    `${ok ? 'OK  ' : 'FAIL'} ${ext.toUpperCase()}: ${(used / 1024).toFixed(2)} kB / ${(budget / 1024).toFixed(0)} kB gzip budget`,
  );
}
process.exit(failed ? 1 : 0);
