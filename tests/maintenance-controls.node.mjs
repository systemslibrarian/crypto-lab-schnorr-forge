import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import test from 'node:test';

const root = new URL('../', import.meta.url);
const workflow = readFileSync(new URL('.github/workflows/deploy.yml', root), 'utf8');
const packageJson = JSON.parse(readFileSync(new URL('package.json', root), 'utf8'));
const packageLock = JSON.parse(readFileSync(new URL('package-lock.json', root), 'utf8'));
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
  // Both step shapes. This pattern required leading whitespace and NO dash, so it
  // is the mirror of the dash-only hole found in eleven sibling labs: every
  // `uses:` line in this workflow happens to sit under a `- name:` today, so the
  // gap is latent rather than live -- the first step written `- uses: x@v1` would
  // be invisible to it, unpinned and unreported. Measured: rewriting the
  // deploy-pages step to `- uses: actions/deploy-pages@v5` passes the old pattern
  // and fails this one.
  const actions = [...workflow.matchAll(/^[ \t]*(?:-[ \t]+)?uses:[ \t]+([^@\s]+)@([^\s]+)/gm)];

  // A declared denominator. Every `uses:` line present must be a `uses:` line
  // parsed, so a step in a shape neither pattern can read fails here instead of
  // passing unseen.
  const present = workflow.match(/^[ \t]*(?:-[ \t]+)?uses:/gm) ?? [];
  assert.equal(actions.length, present.length,
    `${present.length - actions.length} uses: line(s) this control cannot read`);
  assert.ok(actions.length > 0, 'workflow has no actions');
  for (const [, action, reference] of actions) {
    assert.match(reference, /^[0-9a-f]{40}$/, `${action} is not commit-pinned`);
  }
});

test('pull requests run the complete gate without packaging Pages', () => {
  const build = job('build');
  const browser = job('browser-gate');
  assert.match(build, /run: npm ci/);
  assert.match(build, /run: npm test/);
  assert.match(build, /run: npm run build/);
  assert.match(build, /run: npm run size-budget/);
  assert.match(browser, /run: npm ci/);
  assert.match(browser, /run: npm run test:e2e:all/);
  assert.doesNotMatch(browser, /playwright install|--with-deps/);
  assert.match(build, /name: Upload Pages artifact\n\s+if: github\.event_name != 'pull_request'\n\s+uses: actions\/upload-pages-artifact@[0-9a-f]{40}/);
  assert.match(job('deploy'), /needs: \[build, browser-gate\]/);
  assert.match(job('dependabot-auto-merge'), /needs: \[build, browser-gate\]/);
});

test('browser image matches Playwright and is immutable', () => {
  const version = packageLock.packages['node_modules/@playwright/test'].version;
  assert.equal(version, packageLock.packages['node_modules/playwright-core'].version);
  assert.match(
    job('browser-gate'),
    new RegExp(`image: mcr\\.microsoft\\.com/playwright:v${version}-noble@sha256:[0-9a-f]{64}`),
  );
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
  for (const name of ['build', 'browser-gate', 'deploy', 'dependabot-auto-merge']) {
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

test('the auto-merge path reads the bump type from the pull request and fails closed', async () => {
  // This repository keeps no third-party action in the merge path, so the bump
  // type is derived from the pull request's own text by an in-repo script and
  // the merge step is gated on its answer.
  const autoMerge = job('dependabot-auto-merge');
  assert.match(autoMerge, /\.github\/scripts\/bump-type\.mjs/,
    'the job must read the bump type from the in-repo script');
  assert.match(autoMerge, /if:\s*steps\.bump\.outputs\.bump\s*==\s*'non-major'/,
    'the merge step must run only for a non-major bump');
  const { bumpType } = await import('../.github/scripts/bump-type.mjs');
  // Fails closed, which is the property that matters: anything it cannot read
  // is 'unknown', and 'unknown' does not merge.
  assert.equal(bumpType({ title: 'Bump the npm group across 1 directory', body: 'no versions here' }), 'unknown');
  assert.equal(bumpType({ title: 'a retitled pull request', body: 'prose only' }), 'unknown');
  assert.equal(bumpType({ title: 'Bump x from 1.2.3 to 2.0.0', body: undefined }), 'unknown', 'a missing body must not merge');
  assert.equal(bumpType({ title: 'Bump x from one to two', body: 'b' }), 'unknown');
  // And it still answers the two readable cases.
  assert.equal(bumpType({ title: 'Bump vitest from 5.0.5 to 5.1.0', body: 'b' }), 'non-major');
  assert.equal(bumpType({ title: 'Bump next from 15.5.27 to 16.4.2', body: 'b' }), 'major');
  assert.equal(bumpType({ title: 'Bump zod from 0.4.1 to 0.5.0', body: 'b' }), 'major', '0.x minor is breaking');
});
