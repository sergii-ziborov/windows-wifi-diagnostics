import { spawn } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import electron from 'electron';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const captureDir = resolve(root, process.argv[2] ?? 'docs/screenshots');
const child = spawn(electron, [root], {
  cwd: root,
  env: {
    ...process.env,
    RADIOCHRON_DEMO: '1',
    RADIOCHRON_CAPTURE_DIR: captureDir
  },
  stdio: 'inherit',
  windowsHide: true
});

child.on('error', (error) => {
  console.error(error);
  process.exitCode = 1;
});
child.on('exit', (code) => {
  process.exitCode = code ?? 1;
});
