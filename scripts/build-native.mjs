import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmod, copyFile, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const require = createRequire(import.meta.url);
const { radiochronCoreManifestPath } = require('radiochron');
const radiochronPackage = require('radiochron/package.json');
const crate = radiochronCoreManifestPath();
const executable = process.platform === 'win32' ? 'radiochron-node-bridge.exe' : 'radiochron-node-bridge';
const source = join(dirname(crate), 'target', 'release', executable);
const binDir = join(root, 'native', 'bin');
const destination = join(binDir, executable);

const cargoArgs = [
  ...(process.platform === 'win32' ? ['+stable-x86_64-pc-windows-msvc'] : []),
  'build',
  '--locked',
  '--release',
  '--manifest-path',
  crate
];

execFileSync('cargo', cargoArgs, {
  cwd: root,
  stdio: 'inherit'
});

await rm(binDir, { recursive: true, force: true });
await mkdir(binDir, { recursive: true });
await copyFile(source, destination);
if (process.platform !== 'win32') await chmod(destination, 0o755);

const digest = createHash('sha256').update(await readFile(destination)).digest('hex');
await writeFile(join(binDir, 'build-info.json'), `${JSON.stringify({
  schema: 'radiochron.desktop_native_build.v1',
  core_revision: radiochronPackage.radiochronCore.gitSha,
  platform: process.platform,
  arch: process.arch,
  executable,
  sha256: digest
}, null, 2)}\n`);

console.log(`Prepared ${destination} (${digest})`);
