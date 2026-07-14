import { spawn } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const rootDir = dirname(dirname(fileURLToPath(import.meta.url)));
const electronViteCli = join(rootDir, 'node_modules', 'electron-vite', 'bin', 'electron-vite.js');
const env = { ...process.env };

delete env.ELECTRON_RUN_AS_NODE;

const child = spawn(process.execPath, [electronViteCli, ...process.argv.slice(2)], {
  cwd: rootDir,
  env,
  stdio: 'inherit'
});

child.on('exit', (code, signal) => {
  if (signal) {
    process.kill(process.pid, signal);
    return;
  }

  process.exitCode = code ?? 0;
});
