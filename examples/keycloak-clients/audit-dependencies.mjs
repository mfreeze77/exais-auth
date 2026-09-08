// Dependency content/license inventory from exact installed npm artifacts, not a security certification.
import { readFile, writeFile, readdir, stat, mkdir } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
const root = process.env.WORKSPACE || '/workspace';
const here = `${root}/examples/keycloak-clients`;
const output = `${root}/evidence/foundation/keycloak-clients`;
await mkdir(output, { recursive: true });
const lock = JSON.parse(await readFile(`${here}/package-lock.json`));
const sha = value => createHash('sha256').update(value).digest('hex');
const records = [], notices = [], blocked = [];
const allowed = new Set(['MIT', 'ISC', 'Apache-2.0', 'BSD-2-Clause', 'BSD-3-Clause', '0BSD', '(MIT OR CC0-1.0)']);
async function files(directory, relative = '') {
  const values = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    if (entry.name === 'node_modules' || entry.name === '.bin') continue;
    const path = `${directory}/${entry.name}`, key = relative ? `${relative}/${entry.name}` : entry.name;
    if (entry.isSymbolicLink()) { values.push({ path: key, symlink: true }); continue; }
    if (entry.isDirectory()) values.push(...await files(path, key));
    else values.push({ path: key, sha256: sha(await readFile(path)), size_bytes: (await stat(path)).size });
  }
  return values;
}
for (const [path, declaration] of Object.entries(lock.packages)) {
  if (!path) continue;
  let metadata;
  try { metadata = JSON.parse(await readFile(`${here}/${path}/package.json`)); }
  catch (error) {
    if (error.code !== 'ENOENT') throw error;
    records.push({ destination: path, version: declaration.version, license: declaration.license,
      tarball: declaration.resolved, tarball_integrity: declaration.integrity, installed: false,
      reason: 'Lockfile optional platform dependency not installed for this Linux proof' });
    if (!declaration.optional) blocked.push({ path, reason: 'Required package missing' });
    continue;
  }
  const packageFiles = await files(`${here}/${path}`);
  const licenseFiles = packageFiles.filter(row => /(^|\/)(licen[sc]e|copying|notice)(\.|$)/i.test(row.path));
  if (metadata.name === 'cookie-signature' && metadata.version === '1.0.6') {
    const readme = packageFiles.find(row => row.path === 'Readme.md');
    const text = await readFile(`${here}/${path}/Readme.md`, 'utf8');
    if (text.includes('## License') && text.includes('Permission is hereby granted, free of charge')) licenseFiles.push({ ...readme, note: 'Full upstream MIT grant embedded in README' });
  }
  if (metadata.name.startsWith('@esbuild/') && !licenseFiles.length) {
    const owner = JSON.parse(await readFile(`${here}/node_modules/esbuild/package.json`));
    if (owner.version !== metadata.version || owner.license !== metadata.license) throw new Error('ESBUILD_LICENSE_VERSION_MISMATCH');
    const licensePath = '../../esbuild/LICENSE.md';
    licenseFiles.push({ path: licensePath, sha256: sha(await readFile(`${here}/${path}/${licensePath}`)),
      note: 'Unmodified esbuild platform binary distributed by exact matching esbuild package; root upstream MIT license' });
  }
  if (!allowed.has(metadata.license)) blocked.push({ path, reason: `License requires separate review: ${metadata.license}` });
  if (!licenseFiles.length) blocked.push({ path, reason: 'No upstream license text in installed artifact' });
  for (const file of licenseFiles) notices.push(`\n===== ${metadata.name}@${metadata.version} / ${file.path} =====\n${await readFile(`${here}/${path}/${file.path}`, 'utf8')}`);
  records.push({ name: metadata.name, version: metadata.version, upstream_repository: metadata.repository,
    immutable_revision: `${metadata.name}@${metadata.version}; exact content pinned by npm tarball integrity`,
    upstream_source_boundary: 'Published maintained npm package, unmodified supported dependency',
    destination: path, license: metadata.license, tarball: declaration.resolved, tarball_integrity: declaration.integrity,
    installed: true, build_or_test_only: !!declaration.dev, modifications: 'None',
    requirement_mapping: 'M1 candidate developer-contract proof only; no original requirement marked verified by this inventory',
    validation_evidence: ['http-results.json', 'browser-results.json'], license_files: licenseFiles, source_files: packageFiles });
}
await writeFile(`${output}/npm-reuse-files.json`, JSON.stringify({ generated_at: new Date().toISOString(),
  package_lock_sha256: sha(await readFile(`${here}/package-lock.json`)), components: records, blocked,
  scope: 'Candidate dependencies; excludes separately audited Keycloak SPI/engine and test-only PyOTP wheel' }, null, 2) + '\n');
await writeFile(`${here}/THIRD_PARTY_NOTICES.txt`, notices.join('\n'));
for (const [args, name] of [[['sbom', '--sbom-format', 'cyclonedx'], 'npm-sbom.cdx.json'], [['audit', '--json'], 'npm-audit.json']]) {
  const result = spawnSync('npm', args, { cwd: here, encoding: 'utf8' });
  if (result.error) throw result.error;
  const report = JSON.parse(result.stdout);
  await writeFile(`${output}/${name}`, JSON.stringify(report, null, 2) + '\n');
  if (result.status !== 0) blocked.push({ command: `npm ${args.join(' ')}`, exit_code: result.status, report: name });
}
console.log(JSON.stringify({ components: records.length, installed: records.filter(row => row.installed).length, blockers: blocked }));
process.exitCode = blocked.length ? 1 : 0;
