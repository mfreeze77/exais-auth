// Read-only installed-runtime inventory and exact npm tar-member comparison.
// No extraction, dependency installation, lifecycle scripts, or network requests.
import * as fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { argsOf, need, regularBytes, safeRelative, within, packageName, selectLocked, digestOf, sha256, LIMITS } from './export_node_packages.mjs';

const BOUNDS = Object.freeze({ files: 100000, fileBytes: 32 * 1024 * 1024, installedBytes: 512 * 1024 * 1024,
  archiveMembers: 50000, expandedArchiveBytes: 128 * 1024 * 1024, allExpandedBytes: 512 * 1024 * 1024, reportBytes: 64 * 1024 * 1024 });
const order = (a, b) => a < b ? -1 : a > b ? 1 : 0;
const canonicalHash = value => sha256(Buffer.from(JSON.stringify(value)));
const licenseName = value => /^(licen[cs]e|copying|notice|copyright)(?:[._-].*|$)/i.test(path.posix.basename(value));

export function nativeKind(relative, prefix) {
  if (prefix.subarray(0, 4).equals(Buffer.from([0x7f, 0x45, 0x4c, 0x46]))) return 'ELF';
  if (prefix.subarray(0, 2).toString('ascii') === 'MZ') return 'PE-candidate';
  if (prefix.subarray(0, 8).toString('ascii') === '!<arch>\n') return 'static-archive';
  if (['feedface', 'cefaedfe', 'feedfacf', 'cffaedfe', 'cafebabe', 'bebafeca'].includes(prefix.subarray(0, 4).toString('hex'))) return 'Mach-O-or-fat-candidate';
  if (prefix.subarray(0, 4).equals(Buffer.from([0x00, 0x61, 0x73, 0x6d]))) return 'WebAssembly';
  if (/\.(?:node|so(?:\.[0-9]+)*|dll|dylib|a)$/i.test(relative)) return 'native-extension-candidate';
  return null;
}

export function installedTree(app) {
  const files = [], directories = [];
  let total = 0;
  function walk(directory, prefix = '') {
    const names = fs.readdirSync(directory).sort(order);
    for (const name of names) {
      const relative = safeRelative(prefix + name), full = path.join(directory, name), stat = fs.lstatSync(full);
      need(files.length + directories.length < BOUNDS.files, 'INSTALLED_MEMBER_COUNT_LIMIT');
      if (stat.isSymbolicLink()) {
        const target = fs.readlinkSync(full);
        need(target.length > 0 && target.length <= 4096 && !/[\x00-\x1f\x7f]/.test(target), 'INVALID_INSTALLED_SYMLINK');
        const destination = path.resolve(path.dirname(full), target);
        need(destination.startsWith(app + path.sep) && fs.realpathSync(full).startsWith(app + path.sep), 'INSTALLED_SYMLINK_ESCAPES_APP');
        files.push({ path: relative, type: 'symlink', target, target_sha256: sha256(Buffer.from(target)),
          resolved_target: path.relative(app, fs.realpathSync(full)).split(path.sep).join('/'), mode: stat.mode & 0o777 });
      } else if (stat.isDirectory()) {
        directories.push(relative); walk(full, relative + '/');
      } else {
        need(stat.isFile(), 'UNSUPPORTED_INSTALLED_MEMBER');
        const bytes = regularBytes(full, BOUNDS.fileBytes);
        total += bytes.length; need(total <= BOUNDS.installedBytes, 'INSTALLED_BYTE_LIMIT');
        files.push({ path: relative, type: 'file', bytes: bytes.length, sha256: sha256(bytes), mode: stat.mode & 0o777,
          native_kind: nativeKind(relative, bytes.subarray(0, 64)), license_file_candidate: licenseName(relative) });
      }
    }
  }
  walk(app);
  return { files: files.sort((a, b) => order(a.path, b.path)), directories: directories.sort(order), total_bytes: total };
}

function loadTar(modulePath) {
  if (!fs.existsSync(modulePath)) return { parser: null, metadata: { available: false, reason: 'NPM_BUNDLED_TAR_MODULE_UNAVAILABLE' } };
  need(path.isAbsolute(modulePath) && !fs.lstatSync(modulePath).isSymbolicLink(), 'UNSAFE_TAR_MODULE_PATH');
  const parser = createRequire(import.meta.url)(modulePath);
  need(typeof parser.Parse === 'function', 'UNSUPPORTED_NPM_TAR_INTERFACE');
  let directory = path.dirname(modulePath), packageFile;
  for (let index = 0; index < 6; index++, directory = path.dirname(directory)) {
    const candidate = path.join(directory, 'package.json');
    if (fs.existsSync(candidate) && JSON.parse(regularBytes(candidate, 1024 * 1024)).name === 'tar') { packageFile = candidate; break; }
  }
  need(packageFile, 'NPM_TAR_PACKAGE_METADATA_UNAVAILABLE');
  const bytes = regularBytes(packageFile, 1024 * 1024), meta = JSON.parse(bytes);
  const licenses = fs.readdirSync(path.dirname(packageFile)).filter(licenseName).sort(order).map(name => {
    const value = regularBytes(path.join(path.dirname(packageFile), name), 1024 * 1024);
    return { path: name, sha256: sha256(value), bytes: value.length };
  });
  return { parser, metadata: { available: true, name: meta.name, version: meta.version, module_path: modulePath,
    module_sha256: sha256(regularBytes(modulePath, BOUNDS.fileBytes)), package_json_sha256: sha256(bytes),
    declared_license: meta.license ?? null, license_files: licenses, license_approval: false } };
}

export async function archiveMembers(parserModule, archive, expandedBudget = { bytes: 0 }) {
  const files = new Map(), seen = new Set();
  let rootName, declaredBytes = 0, actualBytes = 0, memberCount = 0;
  await new Promise((resolve, reject) => {
    const input = fs.createReadStream(archive, { highWaterMark: 65536 });
    let rejected = false, parser;
    const fail = code => {
      if (!rejected) {
        rejected = true; input.destroy();
        if (typeof parser?.abort === 'function') parser.abort(new Error(code));
        reject(new Error(code));
      }
    };
    parser = new parserModule.Parse({ strict: true, maxMetaEntrySize: 65536 });
    parser.on('error', () => fail('INVALID_TAR_ARCHIVE'));
    parser.on('ignoredEntry', () => fail('UNSUPPORTED_OR_OVERSIZE_TAR_ENTRY'));
    parser.on('end', () => { if (!rejected) resolve(); });
    parser.on('entry', entry => {
      try {
        need(++memberCount <= BOUNDS.archiveMembers, 'TAR_MEMBER_COUNT_LIMIT');
        need(['File', 'OldFile', 'Directory', 'SymbolicLink'].includes(entry.type), 'UNSUPPORTED_TAR_ENTRY_TYPE');
        need(typeof entry.path === 'string' && !entry.path.includes('\\') && !String(entry.header?.path || '').includes('\\'), 'UNSAFE_TAR_PATH');
        const full = entry.path.replace(/\/$/, ''); safeRelative(full);
        const pieces = full.split('/'), root = pieces.shift();
        need(rootName === undefined || rootName === root, 'TAR_MULTIPLE_ROOTS'); rootName = root;
        const relative = pieces.join('/');
        need(relative || entry.type === 'Directory', 'TAR_FILE_WITHOUT_PACKAGE_ROOT');
        need(!seen.has(full), 'DUPLICATE_TAR_MEMBER'); seen.add(full);
        need(Number.isSafeInteger(entry.size) && entry.size >= 0 && entry.size <= BOUNDS.fileBytes, 'OVERSIZE_TAR_MEMBER');
        declaredBytes += entry.size;
        need(declaredBytes <= BOUNDS.expandedArchiveBytes, 'EXPANDED_ARCHIVE_BYTE_LIMIT');
        if (entry.type === 'Directory') { need(entry.size === 0, 'DIRECTORY_WITH_DATA'); entry.resume(); return; }
        if (entry.type === 'SymbolicLink') {
          need(entry.size === 0 && typeof entry.linkpath === 'string' && entry.linkpath.length <= 4096 &&
            !/[\\\x00-\x1f\x7f]/.test(entry.linkpath) && !path.posix.isAbsolute(entry.linkpath), 'UNSAFE_TAR_SYMLINK');
          const destination = path.posix.normalize(path.posix.join(path.posix.dirname(relative), entry.linkpath));
          safeRelative(destination);
          files.set(relative, { path: relative, type: 'symlink', target: entry.linkpath, target_sha256: sha256(Buffer.from(entry.linkpath)), mode: entry.mode & 0o777 });
          entry.resume(); return;
        }
        const hash = createHash('sha256'); let count = 0, prefix = Buffer.alloc(0);
        entry.on('data', bytes => {
          count += bytes.length; actualBytes += bytes.length; expandedBudget.bytes += bytes.length;
          if (count > entry.size || actualBytes > BOUNDS.expandedArchiveBytes || expandedBudget.bytes > BOUNDS.allExpandedBytes) { fail('TAR_EXPANSION_LIMIT'); return; }
          if (prefix.length < 64) prefix = Buffer.concat([prefix, bytes.subarray(0, 64 - prefix.length)]);
          hash.update(bytes);
        });
        entry.on('end', () => {
          if (rejected) return;
          if (count !== entry.size) { fail('TAR_MEMBER_LENGTH_MISMATCH'); return; }
          files.set(relative, { path: relative, type: 'file', bytes: count, sha256: hash.digest('hex'), mode: entry.mode & 0o777,
            native_kind: nativeKind(relative, prefix), license_file_candidate: licenseName(relative) });
        });
        entry.resume();
      } catch (error) { fail(/^[A-Z][A-Z0-9_]+$/.test(error.message || '') ? error.message : 'INVALID_TAR_ENTRY'); entry.resume(); }
    });
    input.on('error', () => fail('ARCHIVE_READ_FAILED'));
    input.pipe(parser);
  });
  need(files.has('package.json'), 'ARCHIVE_PACKAGE_JSON_MISSING');
  return { files: [...files.values()].sort((a, b) => order(a.path, b.path)), package_root: rootName,
    member_count: memberCount, expanded_file_bytes: actualBytes };
}

export async function verifyRuntime(options) {
  const report = { schema: 'expertauth-node-runtime-file-verification-v1', ok: false, inventory_verified: false,
    platform: { os: 'linux', cpu: 'x64', libc: 'glibc' }, foundation_passed: false, browser_passed: false,
    native_platform_tests_passed: false, native_compiled_source_correspondence_verified: false, license_approval: false,
    limits: BOUNDS, app_files: [], dependency_files: [], packages: [], native_members: [], errors: [],
    tar_correspondence: { verified: false, matched_files: 0, missing_files: 0, different_files: 0, extra_installed_files: 0,
      unsupported_entries: 0, failed_archives: 0, mode_differences: 0, package_count_verified: 0 },
    limitations: ['File and original archive byte correspondence only; native compilation/toolchain/platform and license obligations remain separate',
      'npm-generated .bin links and hidden install metadata are inventoried separately and are not original tarball members'] };
  let reportOwned = false;
  const output = path.resolve(options.output);
  try {
    need(process.platform === 'linux' && process.arch === 'x64', 'VERIFIER_REQUIRES_LINUX_X64');
    need(['app', 'cache', 'cache-report', 'output', 'tar-module'].every(key => path.isAbsolute(options[key])), 'ABSOLUTE_PATHS_REQUIRED');
    const app = path.resolve(options.app), cache = path.resolve(options.cache);
    need(fs.realpathSync(app) === app && fs.realpathSync(cache) === cache && !output.startsWith(app + path.sep) &&
      !output.startsWith(cache + path.sep), 'UNSAFE_RUNTIME_OR_OUTPUT_ROOT');
    fs.mkdirSync(path.dirname(output), { recursive: true });
    fs.writeFileSync(output, JSON.stringify(report) + '\n', { flag: 'wx' }); reportOwned = true;
    const lockBytes = regularBytes(within(app, 'package-lock.json'), 4 * 1024 * 1024), lock = JSON.parse(lockBytes);
    const selected = selectLocked(lock), cacheReportBytes = regularBytes(options['cache-report'], BOUNDS.reportBytes), expected = JSON.parse(cacheReportBytes);
    report.lock_sha256 = sha256(lockBytes); report.cache_report_sha256 = sha256(cacheReportBytes);
    need(expected.schema === 'expertauth-offline-npm-cache-v1' && expected.ok === true && expected.lock_sha256 === report.lock_sha256 &&
      expected.platform?.os === 'linux' && expected.platform?.cpu === 'x64' && expected.platform?.libc === 'glibc', 'CACHE_REPORT_OR_LOCK_MISMATCH');
    need(sha256(regularBytes(within(cache, 'package-lock.json'), 4 * 1024 * 1024)) === report.lock_sha256, 'EXPORTED_LOCK_FILE_MISMATCH');
    need(Array.isArray(expected.packages) && Array.isArray(expected.archives) && expected.packages.length === selected.packages.length &&
      new Set(expected.packages.map(value => value.lock_path)).size === expected.packages.length, 'CACHE_PACKAGE_MEMBERSHIP_MISMATCH');
    const expectedMap = new Map(expected.packages.map(value => [value.lock_path, value]));
    for (const locked of selected.packages) {
      const actual = expectedMap.get(locked.lock_path);
      need(actual?.exported === true && Object.entries(locked).every(([key, value]) => JSON.stringify(actual[key]) === JSON.stringify(value)), 'EXPORTED_PACKAGE_FACTS_MISMATCH');
    }
    need(JSON.stringify(selected.excluded) === JSON.stringify(expected.excluded_packages), 'EXCLUDED_PLATFORM_MEMBERSHIP_MISMATCH');
    report.applicable_package_count = selected.packages.length; report.excluded_package_count = selected.excluded.length;
    const tree = installedTree(app);
    report.app_files = tree.files.filter(file => !file.path.startsWith('node_modules/'));
    report.dependency_files = tree.files.filter(file => file.path.startsWith('node_modules/'));
    report.dependency_directories = tree.directories.filter(value => value.startsWith('node_modules/'));
    report.app_files_sha256 = canonicalHash(report.app_files); report.dependency_files_sha256 = canonicalHash(report.dependency_files);
    report.installed_file_bytes = tree.total_bytes;
    report.native_members = tree.files.filter(file => file.native_kind).map(file => ({ path: file.path, kind: file.native_kind, bytes: file.bytes, sha256: file.sha256 }));
    const installedPaths = new Set();
    for (const file of report.dependency_files.filter(value => value.type === 'file' && value.path.endsWith('/package.json'))) {
      const candidate = path.posix.dirname(file.path);
      try { packageName(candidate); installedPaths.add(candidate); } catch { /* Internal fixture/package.json belongs to its enclosing package. */ }
    }
    need(installedPaths.size === selected.packages.length && selected.packages.every(pkg => installedPaths.has(pkg.lock_path)), 'INSTALLED_PLATFORM_PACKAGE_MEMBERSHIP_MISMATCH');
    const owners = [...installedPaths].sort((a, b) => b.length - a.length || order(a, b));
    const filesByOwner = new Map(owners.map(owner => [owner, []]));
    report.generated_dependency_entries = [];
    for (const file of report.dependency_files) {
      const owner = owners.find(value => file.path.startsWith(value + '/'));
      if (owner) filesByOwner.get(owner).push(file);
      else {
        need(file.path === 'node_modules/.package-lock.json' || (file.path.startsWith('node_modules/.bin/') && file.type === 'symlink'), 'UNOWNED_INSTALLED_DEPENDENCY_FILE');
        report.generated_dependency_entries.push(file);
      }
    }
    const loaded = loadTar(options['tar-module']); report.tar_parser = loaded.metadata;
    const archives = new Map(), budget = { bytes: 0 };
    need(expected.archives.length === new Set(selected.packages.map(value => value.sha512_hex)).size &&
      new Set(expected.archives.map(value => value.sha512_hex)).size === expected.archives.length, 'CACHE_ARCHIVE_MEMBERSHIP_MISMATCH');
    let archiveBytes = 0;
    for (const original of expected.archives) {
      const digest = digestOf(original.sha512_sri);
      need(original.sha512_hex === digest.hex && original.path === `_cacache/content-v2/${digest.contentPath}`, 'INVALID_REPORTED_ARCHIVE_PATH');
      const file = within(cache, original.path), bytes = regularBytes(file, LIMITS.archiveBytes);
      archiveBytes += bytes.length; need(archiveBytes <= LIMITS.cacheBytes, 'CACHE_ARCHIVE_BYTE_LIMIT');
      need(bytes.length === original.bytes && sha256(bytes) === original.sha256 && createHash('sha512').update(bytes).digest('hex') === digest.hex, 'EXPORTED_ARCHIVE_BYTES_MISMATCH');
      try { archives.set(digest.hex, loaded.parser ? await archiveMembers(loaded.parser, file, budget) : null); }
      catch (error) {
        report.tar_correspondence.failed_archives++;
        const code = /^[A-Z][A-Z0-9_]+$/.test(error.message || '') ? error.message : 'TAR_MEMBER_VERIFICATION_FAILED';
        if (code.startsWith('UNSUPPORTED_')) report.tar_correspondence.unsupported_entries++;
        report.errors.push({ archive_sha512_hex: digest.hex, code });
        archives.set(digest.hex, null);
      }
    }
    const declaredBins = new Map();
    for (const locked of selected.packages) {
      const files = filesByOwner.get(locked.lock_path), metaPath = within(app, locked.lock_path + '/package.json');
      const packageBytes = regularBytes(metaPath, 4 * 1024 * 1024), meta = JSON.parse(packageBytes);
      need(meta.name === locked.name && meta.version === locked.version, 'INSTALLED_PACKAGE_VERSION_OR_NAME_MISMATCH');
      const bins = typeof meta.bin === 'string' ? { [meta.name.split('/').at(-1)]: meta.bin } : meta.bin ?? {};
      need(bins && typeof bins === 'object' && !Array.isArray(bins), 'INVALID_INSTALLED_BIN_DECLARATION');
      for (const [name, target] of Object.entries(bins)) {
        need(/^[A-Za-z0-9._-]+$/.test(name) && typeof target === 'string', 'INVALID_INSTALLED_BIN_DECLARATION');
        const relative = safeRelative(target.replace(/^\.\//, ''));
        const allowed = declaredBins.get(name) || new Set();
        allowed.add(locked.lock_path + '/' + relative); declaredBins.set(name, allowed);
      }
      const row = { lock_path: locked.lock_path, name: meta.name, version: meta.version, package_json_sha256: sha256(packageBytes),
        declared_license_from_package: meta.license ?? meta.licenses ?? null, declared_license_from_lock: locked.declared_license_from_lock,
        license_files: files.filter(file => file.license_file_candidate), installed_file_count: files.length,
        original_members_verified: false, matched_files: 0, missing_files: [], different_files: [], extra_installed_files: [], mode_differences: [] };
      const archive = archives.get(locked.sha512_hex);
      if (archive) {
        const installed = new Map(files.map(file => [file.path.slice(locked.lock_path.length + 1), file]));
        const originals = new Set(archive.files.map(file => file.path));
        row.archive_package_root = archive.package_root; row.archive_file_count = archive.files.length;
        row.archive_members_sha256 = canonicalHash(archive.files);
        for (const member of archive.files) {
          const actual = installed.get(member.path);
          if (!actual) row.missing_files.push(member.path);
          else if (actual.type !== member.type || (member.type === 'file' ? actual.sha256 !== member.sha256 || actual.bytes !== member.bytes : actual.target !== member.target)) row.different_files.push(member.path);
          else {
            row.matched_files++;
            if (actual.mode !== member.mode) row.mode_differences.push({ path: member.path, archive_mode: member.mode, installed_mode: actual.mode });
          }
        }
        row.extra_installed_files = [...installed.keys()].filter(value => !originals.has(value)).sort(order);
        row.original_members_verified = row.missing_files.length === 0 && row.different_files.length === 0 && row.extra_installed_files.length === 0;
        for (const key of ['missing_files', 'different_files', 'extra_installed_files', 'mode_differences']) report.tar_correspondence[key] += row[key].length;
        report.tar_correspondence.matched_files += row.matched_files;
        if (row.original_members_verified) report.tar_correspondence.package_count_verified++;
      }
      report.packages.push(row);
    }
    for (const entry of report.generated_dependency_entries.filter(value => value.type === 'symlink')) {
      need(declaredBins.get(path.posix.basename(entry.path))?.has(entry.resolved_target) &&
        report.dependency_files.some(file => file.path === entry.resolved_target && file.type === 'file'), 'NPM_BIN_LINK_HAS_NO_LOCKED_DECLARED_TARGET');
    }
    report.inventory_verified = true;
    report.total_archive_bytes_verified = archiveBytes;
    report.tar_correspondence.verified = loaded.metadata.available && report.tar_correspondence.failed_archives === 0 &&
      report.packages.every(pkg => pkg.original_members_verified);
    report.tar_correspondence.scope = 'Exact original member file bytes and symlink targets; modes reported separately; generated npm entries excluded explicitly';
    report.ok = report.inventory_verified && report.tar_correspondence.verified && report.errors.length === 0;
    if (!report.tar_correspondence.verified) report.errors.push({ code: 'ORIGINAL_TARBALL_CORRESPONDENCE_NOT_ESTABLISHED' });
    need(sha256(regularBytes(within(app, 'package-lock.json'), 4 * 1024 * 1024)) === report.lock_sha256, 'INSTALLED_LOCK_CHANGED_DURING_VERIFICATION');
    report.runtime = { node_version: process.version, platform: process.platform, architecture: process.arch };
  } catch (error) {
    report.ok = false;
    report.errors.push({ code: /^[A-Z][A-Z0-9_]+$/.test(error.message || '') ? error.message : 'RUNTIME_VERIFICATION_PRECONDITION_OR_OPERATION_FAILED' });
  }
  if (reportOwned) {
    const encoded = JSON.stringify(report, null, 2) + '\n';
    need(Buffer.byteLength(encoded) <= BOUNDS.reportBytes, 'VERIFICATION_REPORT_SIZE_LIMIT');
    fs.writeFileSync(output, encoded);
  }
  return report;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const options = argsOf(process.argv.slice(2), ['app', 'cache-report', 'cache', 'output', 'tar-module'], {
      app: '/app', 'cache-report': '/cache/cache-report.json', cache: '/cache', output: '/out/runtime-report.json',
      'tar-module': '/usr/local/lib/node_modules/npm/node_modules/tar/dist/commonjs/index.min.js',
    });
    const result = await verifyRuntime(options);
    console.log(JSON.stringify({ ok: result.ok, inventory_verified: result.inventory_verified, packages: result.packages.length,
      dependency_files: result.dependency_files.length, tar_correspondence: result.tar_correspondence, errors: result.errors }));
    process.exitCode = result.ok ? 0 : 1;
  } catch { console.log(JSON.stringify({ ok: false, code: 'RUNTIME_VERIFIER_INITIALIZATION_OR_REPORT_FAILED' })); process.exitCode = 1; }
}
