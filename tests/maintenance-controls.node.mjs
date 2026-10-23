import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import test from 'node:test';

const root = new URL('../', import.meta.url);
const workflow = readFileSync(new URL('.github/workflows/deploy.yml', root), 'utf8');
const packageJson = JSON.parse(readFileSync(new URL('package.json', root), 'utf8'));
const gitignore = readFileSync(new URL('.gitignore', root), 'utf8');
const dom = readFileSync(new URL('src/ui/dom.ts', root), 'utf8');
const claims = readFileSync(new URL('e2e/claims.spec.ts', root), 'utf8');

function job(name) {
  const pattern = '\\n  ' + name + ':\\n[\\s\\S]*?(?=\\n  [a-z][a-z0-9-]*:\\n|$)';
  const match = workflow.match(new RegExp(pattern));
  assert.ok(match, `missing ${name} job`);
  return match[0];
}

test('one workflow owns the pull-request gate and Pages deployment', () => {
  assert.equal(existsSync(new URL('.github/workflows/ci.yml', root)), false);
  assert.match(workflow, /push:\n\s+branches: \[main\]/);
  assert.match(workflow, /pull_request:\n\s+branches: \[main\]/);
  assert.match(workflow, /workflow_dispatch:/);
});

test('only the deploy job can mint Pages credentials', () => {
  const header = workflow.slice(0, workflow.indexOf('\njobs:'));
  assert.match(header, /permissions:\n  contents: read\n/);
  assert.doesNotMatch(header, /pages: write|id-token: write/);
  assert.doesNotMatch(job('build'), /pages: write|id-token: write/);
  assert.match(job('deploy'), /permissions:\n      contents: read\n      pages: write\n      id-token: write\n/);
});

test('every third-party action is pinned to an immutable commit', () => {
  const actions = [...workflow.matchAll(/^\s+uses:\s+([^@\s]+)@([^\s]+)/gm)];
  assert.ok(actions.length > 0, 'workflow has no actions');
  for (const [, action, reference] of actions) {
    assert.match(reference, /^[0-9a-f]{40}$/, `${action} is not commit-pinned`);
  }
});

test('pull requests run the complete gate without packaging Pages', () => {
  const build = job('build');
  assert.match(build, /run: npm ci/);
  assert.match(build, /run: npm test/);
  assert.match(build, /run: npm run build/);
  assert.match(build, /run: npm run size-budget/);
  assert.match(build, /run: npm run test:e2e:all/);
  assert.match(build, /run: npx playwright install chromium firefox webkit/);
  assert.doesNotMatch(build, /^\s+run: [^\n]*--with-deps/m);
  assert.match(build, /name: Upload Pages artifact\n\s+if: github\.event_name != 'pull_request'\n\s+uses: actions\/upload-pages-artifact@[0-9a-f]{40}/);
});

test('post-merge behavior is direct and fail-closed', () => {
  const autoMerge = job('dependabot-auto-merge');
  assert.doesNotMatch(autoMerge, /dependabot\/fetch-metadata/);
  assert.match(autoMerge, /set -eu/);
  assert.match(autoMerge, /exit 1/);
  assert.match(autoMerge, /gh workflow run deploy\.yml --repo "\$GITHUB_REPOSITORY" --ref main/);
  assert.doesNotMatch(autoMerge, /gh workflow run[^\n]*(?:\|\||continue-on-error)/);
});

test('a deployment carries and verifies exact source provenance', () => {
  assert.match(job('build'), /public\/deployment\.json/);
  assert.match(gitignore, /^public\/deployment\.json$/m);
  assert.match(job('deploy'), /deployment\.json\?sha=\$\{GITHUB_SHA\}/);
  assert.match(job('deploy'), /p\.source_sha===process\.argv\[2\]/);
  assert.match(job('deploy'), /p\.repository===process\.argv\[3\]/);
  assert.match(job('deploy'), /grep -Fq 'id="app"'/);
});

test('every job has an explicit timeout', () => {
  for (const name of ['build', 'deploy', 'dependabot-auto-merge']) {
    assert.match(job(name), /timeout-minutes: \d+/);
  }
});

test('user-controlled strings have no innerHTML sink', () => {
  assert.doesNotMatch(dom, /innerHTML/);
});

test('browser claims pin evidence retirement and visible key normalization', () => {
  assert.match(claims, /signing canonicalizes the visible key and input edits retire its evidence/);
  assert.match(claims, /Verify Workbench retires a verdict as soon as an artifact changes/);
  assert.match(claims, /nonce-reuse and aggregation evidence retires with its message/);
});

test('the production build enforces maintenance controls', () => {
  assert.equal(packageJson.scripts['test:maintenance'], 'node --test tests/maintenance-controls.node.mjs');
  assert.match(packageJson.scripts.build, /npm run test:maintenance/);
});
