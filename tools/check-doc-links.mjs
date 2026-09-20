import fs from 'node:fs';
import path from 'node:path';

const root = path.resolve(import.meta.dirname, '..');
const entries = ['README.md', 'README.es.md', 'README.ru.md', 'README.zh-CN.md'];
function visit(directory) {
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const target = path.join(directory, entry.name);
    if (entry.isDirectory() && entry.name !== 'superpowers') visit(target);
    else if (entry.name.endsWith('.md')) entries.push(path.relative(root, target));
  }
}
visit(path.join(root, 'docs'));
let checked = 0;
const broken = [];
for (const entry of entries) {
  const file = path.join(root, entry);
  const source = fs.readFileSync(file, 'utf8');
  for (const match of source.matchAll(/!?(?:\[[^\]]*\])\(([^)]+)\)/g)) {
    const raw = match[1].split('#', 1)[0];
    if (!raw || /^[a-z][a-z0-9+.-]*:/i.test(raw)) continue;
    const target = path.resolve(path.dirname(file), decodeURIComponent(raw));
    checked++;
    if (!fs.existsSync(target)) broken.push(`${entry}: ${match[1]}`);
  }
}
for (const item of broken) process.stderr.write(`${item}\n`);
process.stdout.write(`Checked ${checked} local Markdown links in ${entries.length} files; broken=${broken.length}\n`);
if (broken.length) process.exitCode = 1;
