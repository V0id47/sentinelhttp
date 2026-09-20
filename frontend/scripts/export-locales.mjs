import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import vm from 'node:vm';

const project = path.resolve(import.meta.dirname, '../..');
const input = path.join(project, 'frontend/src/i18n.ts');
const source = fs.readFileSync(input, 'utf8');
const declaration = source.indexOf('export const translations:');
const start = source.indexOf('{', declaration);
const end = source.indexOf('\n};', start);
if (declaration < 0 || start < 0 || end < 0) throw new Error('localization literal missing');
const translations = vm.runInNewContext('(' + source.slice(start, end + 2) + ')', Object.create(null), { timeout: 1000 });
const target = path.join(project, 'internal/core/localization/catalog.json');
fs.mkdirSync(path.dirname(target), { recursive: true });
fs.writeFileSync(target, JSON.stringify(translations, null, 2) + '\n');
process.stdout.write(`Exported ${Object.keys(translations).length} localization entries to ${pathToFileURL(target).pathname}\n`);
