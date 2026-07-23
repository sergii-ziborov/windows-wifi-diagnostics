import { mkdir, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const sourceCommit = 'ca479a8f4bc008c1d676f4853e3ae33e207e93a7';
const sourceCommitDate = '2026-06-18T09:41:56Z';
const sourceRepository = 'https://github.com/NordicSemiconductor/bluetooth-numbers-database';
const sourceBase = `https://raw.githubusercontent.com/NordicSemiconductor/bluetooth-numbers-database/${sourceCommit}/v1`;
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const destination = resolve(root, 'src/renderer/src/generated/bleAssignedNumbers.json');
const sourceFiles = {
  companies: `${sourceBase}/company_ids.json`,
  services: `${sourceBase}/service_uuids.json`,
  appearances: `${sourceBase}/gap_appearance.json`
};

const [companyRows, serviceRows, appearanceRows] = await Promise.all([
  downloadJson(sourceFiles.companies),
  downloadJson(sourceFiles.services),
  downloadJson(sourceFiles.appearances)
]);
const companies = Object.fromEntries(companyRows.map((row) => [String(row.code), row.name]));
const services = Object.fromEntries(serviceRows.map((row) => [
  normalizeUuid(row.uuid),
  { name: row.name, source: row.source }
]));
const appearances = {};
for (const category of appearanceRows) {
  appearances[String(category.category << 6)] = category.name;
  for (const subcategory of category.subcategory ?? []) {
    appearances[String((category.category << 6) | subcategory.value)] = subcategory.name;
  }
}

const counts = {
  companies: Object.keys(companies).length,
  services: Object.keys(services).length,
  appearances: Object.keys(appearances).length
};
if (counts.companies < 3_990 || counts.services < 120 || counts.appearances < 100) {
  throw new Error(`Bluetooth database looks incomplete: ${JSON.stringify(counts)}`);
}

await mkdir(dirname(destination), { recursive: true });
await writeFile(destination, `${JSON.stringify({
  schema_version: 1,
  metadata: {
    source_repository: sourceRepository,
    source_commit: sourceCommit,
    source_commit_date: sourceCommitDate,
    license: 'BSD-3-Clause',
    source_files: sourceFiles,
    counts
  },
  companies,
  services,
  appearances
})}\n`, 'utf8');
console.log(`Wrote Bluetooth assigned numbers ${JSON.stringify(counts)} to ${destination}`);

async function downloadJson(url) {
  const response = await fetch(url);
  if (!response.ok) throw new Error(`Bluetooth database download failed (${response.status}): ${url}`);
  return response.json();
}

function normalizeUuid(value) {
  return String(value).toLowerCase().replace(/^0x/, '');
}
