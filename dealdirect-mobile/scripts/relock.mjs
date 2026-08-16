/**
 * Regenerate package-lock.json so the EAS builder can actually install it.
 *
 * Run this instead of `npm install` whenever a dependency changes, then commit
 * the lockfile. It exists because a lockfile written by a plain `npm install`
 * on this machine has twice produced a lockfile that fails on EAS, for two
 * unrelated reasons:
 *
 *   1. Platform binaries. `npm install` records only the optional dependencies
 *      it actually installed, so a Windows machine writes a lockfile
 *      containing lightningcss-win32-x64-msvc and nothing else. `npm ci` on the
 *      Linux builder then has no binary to install, and the JS bundle step dies
 *      with "Cannot find module '../lightningcss.linux-x64-gnu.node'" the
 *      moment metro.config.js loads nativewind. Resolving in a directory with
 *      no node_modules forces a pure resolution, which records all of them.
 *
 *   2. npm version. The builder runs npm 10.9.3. Local npm 11 writes lockfiles
 *      npm 10 rejects outright (it dropped yaml@2.9.0 from the tree once).
 *      Pinning the resolver version here keeps the two in agreement.
 *
 * Both failures surface only on EAS, after a queue and a build, so they are
 * worth catching with a 30-second local command.
 */

import { execSync } from 'node:child_process';
import { copyFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

/** The npm shipped by the EAS Android image. Keep in step with the build log. */
const NPM_VERSION = '10.9.3';

const projectDir = dirname(dirname(fileURLToPath(import.meta.url)));
const projectLock = join(projectDir, 'package-lock.json');

// A shell string rather than execFileSync: on Windows npx is a .cmd shim, and
// since Node 24 execFile refuses to run one without a shell. Every part of the
// command below is a literal defined in this file, so there is nothing to
// escape and no injection surface.
const npm = (args, cwd) =>
  execSync(`npx -y npm@${NPM_VERSION} ${args.join(' ')}`, {
    cwd,
    stdio: ['ignore', 'pipe', 'inherit'],
    encoding: 'utf8',
  });

const scratch = mkdtempSync(join(tmpdir(), 'dd-relock-'));

try {
  // package.json alone. No node_modules, so npm resolves the graph from the
  // registry rather than describing what happens to be installed here.
  copyFileSync(join(projectDir, 'package.json'), join(scratch, 'package.json'));

  console.log(`Resolving with npm ${NPM_VERSION} in a clean directory...`);
  npm(['install', '--package-lock-only'], scratch);

  copyFileSync(join(scratch, 'package-lock.json'), projectLock);

  console.log('Verifying `npm ci` accepts it, the way EAS will...');
  npm(['ci', '--include=dev', '--ignore-scripts', '--dry-run'], projectDir);

  console.log('\npackage-lock.json regenerated. Commit it with package.json.');
} finally {
  rmSync(scratch, { recursive: true, force: true });
}
