// Synthetic archive boundary tests, not original-package/runtime correspondence.
// Uses actual npm tar Header and Parser (or legacy Parse), without parser doubles.
import * as fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { gzipSync } from 'node:zlib';
import { fileURLToPath } from 'node:url';
import { archiveMembers, tarParserInterface } from '../../tools/verify_node_runtime.mjs';
import { argsOf, regularBytes, sha256, need } from '../../tools/export_node_packages.mjs';

const expectedChecks = 8;
const report = { schema: 'expertauth-node-package-parser-boundaries-v1', ok: false, expected_checks: expectedChecks,
  qualification: 'Synthetic parser unit checks only; no npm cache export or installed runtime/package correspondence proof',
  foundation_passed: false, original_package_correspondence_verified: false, native_platform_tests_passed: false,
  license_approval: false, rows: [], errors: [], skipped: 0,
  cleanup: { temporary_directory_created: false, temporary_directory_removed: false, files_removed: 0 } };
let directory, output, outputOwned = false;
const createdFiles = [];

async function check(id, action) {
  const started = performance.now();
  try {
    const details = await action();
    report.rows.push({ id, status: 'passed', elapsed_ms: Math.round(performance.now() - started), details });
  } catch {
    report.rows.push({ id, status: 'failed', elapsed_ms: Math.round(performance.now() - started), error: 'PARSER_BOUNDARY_ASSERTION_FAILED' });
  }
}

try {
  const options = argsOf(process.argv.slice(2), ['tar-module', 'temp-root', 'output'], {
    'tar-module': '/usr/local/lib/node_modules/npm/node_modules/tar/dist/commonjs/index.min.js', 'temp-root': '/tmp',
  });
  need(path.isAbsolute(options['tar-module']) && path.isAbsolute(options['temp-root']) &&
    (options.output === undefined || path.isAbsolute(options.output)), 'ABSOLUTE_PATHS_REQUIRED');
  if (options.output !== undefined) {
    output = path.resolve(options.output);
    fs.mkdirSync(path.dirname(output), { recursive: true });
    fs.writeFileSync(output, JSON.stringify(report) + '\n', { flag: 'wx' }); outputOwned = true;
  }
  report.sources = Object.fromEntries([
    ['test', new URL(import.meta.url)], ['verifier', new URL('../../tools/verify_node_runtime.mjs', import.meta.url)],
    ['exporter', new URL('../../tools/export_node_packages.mjs', import.meta.url)],
  ].map(([name, location]) => [name, sha256(regularBytes(fileURLToPath(location), 1024 * 1024))]));
  const parserPath = options['tar-module'];
  need(!fs.lstatSync(parserPath).isSymbolicLink(), 'UNSAFE_TAR_MODULE_PATH');
  const tar = createRequire(import.meta.url)(parserPath);
  need(typeof tar.Header === 'function', 'UNSUPPORTED_NPM_TAR_HEADER_INTERFACE');
  const parserInterface = tarParserInterface(tar);
  let packageDirectory = path.dirname(parserPath), metadata;
  for (let index = 0; index < 6; index++, packageDirectory = path.dirname(packageDirectory)) {
    const candidate = path.join(packageDirectory, 'package.json');
    if (fs.existsSync(candidate)) {
      const bytes = regularBytes(candidate, 1024 * 1024), parsed = JSON.parse(bytes);
      if (parsed.name === 'tar') { metadata = { name: parsed.name, version: parsed.version, package_json_sha256: sha256(bytes) }; break; }
    }
  }
  need(metadata && typeof metadata.version === 'string', 'NPM_TAR_METADATA_UNAVAILABLE');
  report.parser = { ...metadata, parser_interface: parserInterface, module_path: parserPath, module_sha256: sha256(regularBytes(parserPath, 32 * 1024 * 1024)) };
  const base = path.resolve(options['temp-root']);
  need(fs.realpathSync(base) === base && fs.lstatSync(base).isDirectory(), 'UNSAFE_TEMPORARY_ROOT');
  directory = fs.mkdtempSync(path.join(base, 'expertauth-node-package-boundaries-'));
  report.cleanup.temporary_directory_created = true;
  report.cleanup.temporary_directory = directory;
  report.cleanup.temporary_root = base;
  const pkg = { path: 'package/package.json', body: JSON.stringify({ name: 'synthetic-parser-unit-only', version: '1.0.0' }) };

  function archive(entries) {
    const chunks = [];
    for (const entry of entries) {
      const bytes = Buffer.from(entry.body || '');
      const header = new tar.Header({ path: entry.path, type: entry.type || 'File', size: entry.size ?? bytes.length,
        mode: 0o644, uid: 0, gid: 0, mtime: new Date(0), linkpath: entry.linkpath });
      header.encode();
      need(Buffer.isBuffer(header.block) && header.block.length === 512, 'UNSUPPORTED_TAR_HEADER_ENCODING');
      chunks.push(header.block, bytes, Buffer.alloc((512 - bytes.length % 512) % 512));
    }
    chunks.push(Buffer.alloc(1024));
    const compressed = gzipSync(Buffer.concat(chunks));
    need(compressed.length <= 65536, 'SYNTHETIC_ARCHIVE_SIZE_LIMIT');
    const file = path.join(directory, `fixture-${createdFiles.length}.tgz`);
    createdFiles.push(file);
    fs.writeFileSync(file, compressed, { flag: 'wx', mode: 0o600 });
    return file;
  }

  await check('NPM-PARSER-001-REGULAR-FILES', async () => {
    const license = 'Synthetic parser fixture text; no licensing conclusion';
    const result = await archiveMembers(tar, archive([pkg, { path: 'package/LICENSE', body: license }]));
    assert.equal(result.package_root, 'package'); assert.equal(result.files.length, 2);
    assert.equal(result.files.find(file => file.path === 'package.json').sha256, sha256(Buffer.from(pkg.body)));
    assert.equal(result.files.find(file => file.path === 'LICENSE').sha256, sha256(Buffer.from(license)));
    assert.equal(result.files.find(file => file.path === 'LICENSE').license_file_candidate, true);
    return { matched_synthetic_file_hashes: 2 };
  });
  await check('NPM-PARSER-002-SAFE-SYMLINK', async () => {
    const result = await archiveMembers(tar, archive([pkg, { path: 'package/current', type: 'SymbolicLink', linkpath: 'package.json' }]));
    assert.equal(result.files.length, 2);
    const link = result.files.find(file => file.path === 'current');
    assert.equal(link.type, 'symlink'); assert.equal(link.target, 'package.json');
    assert.equal(link.target_sha256, sha256(Buffer.from('package.json')));
    return { safe_internal_symlink_target_verified: true };
  });
  const rejected = [
    ['NPM-PARSER-003-DUPLICATE', [pkg, pkg], 'DUPLICATE_TAR_MEMBER'],
    ['NPM-PARSER-004-TRAVERSAL', [pkg, { path: 'package/../escape', body: 'x' }], 'UNSAFE_RELATIVE_PATH'],
    ['NPM-PARSER-005-HARDLINK', [pkg, { path: 'package/hard', type: 'Link', linkpath: 'package/package.json' }], 'UNSUPPORTED_TAR_ENTRY_TYPE'],
    ['NPM-PARSER-006-ESCAPING-SYMLINK', [pkg, { path: 'package/link', type: 'SymbolicLink', linkpath: '../../outside' }], 'UNSAFE_RELATIVE_PATH'],
    ['NPM-PARSER-007-OVERSIZE', [pkg, { path: 'package/huge', size: 33 * 1024 * 1024 }], 'OVERSIZE_TAR_MEMBER'],
    ['NPM-PARSER-008-MULTIPLE-ROOTS', [pkg, { path: 'other/file', body: 'x' }], 'TAR_MULTIPLE_ROOTS'],
  ];
  for (const [id, entries, expectedCode] of rejected) {
    await check(id, async () => {
      await assert.rejects(archiveMembers(tar, archive(entries)), error => error.message === expectedCode);
      return { expected_rejection_code: expectedCode, rejected_for_expected_reason: true };
    });
  }
} catch (error) {
  report.errors.push(/^[A-Z][A-Z0-9_]+$/.test(error.message || '') ? error.message : 'PARSER_TEST_INITIALIZATION_OR_OPERATION_FAILED');
} finally {
  if (directory !== undefined) {
    try {
      const real = fs.realpathSync(directory), base = report.cleanup.temporary_root;
      need(real === directory && path.dirname(real) === base && path.basename(real).startsWith('expertauth-node-package-boundaries-'), 'TEMPORARY_CLEANUP_BOUNDARY_DIFFERED');
      const expectedNames = createdFiles.map(file => path.basename(file)).sort();
      assert.deepEqual(fs.readdirSync(real).sort(), expectedNames);
      for (const file of createdFiles) {
        need(path.dirname(path.resolve(file)) === real && fs.lstatSync(file).isFile() && !fs.lstatSync(file).isSymbolicLink(), 'UNEXPECTED_TEMPORARY_FILE_TYPE');
      }
      for (const file of createdFiles) { fs.unlinkSync(file); report.cleanup.files_removed++; }
      fs.rmdirSync(real); need(!fs.existsSync(real), 'TEMPORARY_DIRECTORY_REMAINED');
      report.cleanup.temporary_directory_removed = true;
    } catch { report.errors.push('EXACT_TEMPORARY_CLEANUP_FAILED'); }
  }
  report.passed = report.rows.filter(row => row.status === 'passed').length;
  report.failed = report.rows.filter(row => row.status === 'failed').length;
  report.unexecuted = expectedChecks - report.rows.length;
  report.ok = report.errors.length === 0 && report.passed === expectedChecks && report.failed === 0 && report.unexecuted === 0 &&
    report.cleanup.temporary_directory_created && report.cleanup.temporary_directory_removed;
  if (outputOwned) {
    try { fs.writeFileSync(output, JSON.stringify(report, null, 2) + '\n'); }
    catch { report.ok = false; report.errors.push('PARSER_TEST_REPORT_WRITE_FAILED'); }
  }
}
console.log(JSON.stringify({ ok: report.ok, passed: report.passed, failed: report.failed, unexecuted: report.unexecuted,
  skipped: 0, temporary_directory_removed: report.cleanup.temporary_directory_removed, errors: report.errors }));
process.exitCode = report.ok ? 0 : 1;
