// Offline recovery of exact locked npm archives; no registry requests or scripts.
import * as fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';

export const LIMITS = Object.freeze({ packages: 512, archiveBytes: 32 * 1024 * 1024, cacheBytes: 128 * 1024 * 1024 });
export function need(value, code) { if (!value) throw new Error(code); }
export const sha256 = value => createHash('sha256').update(value).digest('hex');
export function argsOf(argv, allowed, defaults = {}) {
  const result = { ...defaults }, seen = new Set();
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index]?.replace(/^--/, '');
    need(argv[index]?.startsWith('--') && allowed.includes(key) && !seen.has(key) &&
      typeof argv[index + 1] === 'string' && !argv[index + 1].startsWith('--'), 'INVALID_ARGUMENTS');
    seen.add(key); result[key] = argv[index + 1];
  }
  return result;
}
export function regularBytes(file, maximum) {
  const fd = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
  try {
    const before = fs.fstatSync(fd);
    need(before.isFile() && before.size <= maximum, 'UNSAFE_OR_OVERSIZE_FILE');
    const value = fs.readFileSync(fd);
    const after = fs.fstatSync(fd);
    need(value.length <= maximum && value.length === before.size && before.size === after.size &&
      before.mtimeMs === after.mtimeMs && before.ino === after.ino, 'FILE_CHANGED_DURING_READ');
    return value;
  } finally { fs.closeSync(fd); }
}
export function safeRelative(value) {
  need(typeof value === 'string' && value.length > 0 && value.length <= 4096 && !/[\\\x00-\x1f\x7f:]/.test(value) &&
    !path.posix.isAbsolute(value) && value.split('/').every(part => part && part !== '.' && part !== '..'), 'UNSAFE_RELATIVE_PATH');
  return value;
}
export function within(root, relative) {
  safeRelative(relative);
  const full = path.resolve(root, ...relative.split('/'));
  need(full.startsWith(path.resolve(root) + path.sep), 'PATH_ESCAPED_ROOT');
  let current = path.resolve(root);
  for (const part of relative.split('/')) {
    current = path.join(current, part);
    if (fs.existsSync(current)) need(!fs.lstatSync(current).isSymbolicLink(), 'UNSAFE_PATH_SYMLINK');
  }
  return full;
}
export function packageName(lockPath) {
  safeRelative(lockPath);
  const parts = lockPath.split('/');
  let name;
  for (let index = 0; index < parts.length;) {
    need(parts[index++] === 'node_modules', 'UNSUPPORTED_LOCK_PACKAGE_PATH');
    let scope = '';
    if (parts[index]?.startsWith('@')) {
      scope = parts[index++]; need(/^@[A-Za-z0-9._-]+$/.test(scope) && scope !== '@.' && scope !== '@..', 'INVALID_PACKAGE_SCOPE');
    }
    const component = parts[index++];
    need(/^[A-Za-z0-9._-]+$/.test(component || '') && !['.', '..'].includes(component), 'INVALID_PACKAGE_NAME');
    name = scope ? `${scope}/${component}` : component;
  }
  return name;
}
export function platformAllows(declaration, target) {
  if (declaration === undefined) return true;
  const values = typeof declaration === 'string' ? [declaration] : declaration;
  need(Array.isArray(values) && values.length > 0 && values.every(value => typeof value === 'string' && /^!?[a-z0-9_-]+$/.test(value)), 'INVALID_PLATFORM_DECLARATION');
  if (values.length === 1 && values[0] === 'any') return true;
  if (values.includes('!' + target)) return false;
  const positives = values.filter(value => !value.startsWith('!'));
  return positives.length === 0 || positives.includes(target);
}
export function digestOf(integrity) {
  need(typeof integrity === 'string', 'MISSING_ARCHIVE_INTEGRITY');
  const tokens = integrity.trim().split(/\s+/).filter(value => value.startsWith('sha512-'));
  need(tokens.length === 1 && /^sha512-[A-Za-z0-9+/]{86}==$/.test(tokens[0]), 'UNSUPPORTED_ARCHIVE_INTEGRITY');
  const encoded = tokens[0].slice(7), bytes = Buffer.from(encoded, 'base64');
  need(bytes.length === 64 && bytes.toString('base64') === encoded, 'NONCANONICAL_ARCHIVE_INTEGRITY');
  const hex = bytes.toString('hex');
  return { sri: tokens[0], hex, contentPath: `sha512/${hex.slice(0, 2)}/${hex.slice(2, 4)}/${hex.slice(4)}` };
}
export function selectLocked(lock) {
  need(lock?.lockfileVersion === 3 && lock.packages && typeof lock.packages === 'object' && !Array.isArray(lock.packages), 'UNSUPPORTED_LOCKFILE');
  const all = Object.entries(lock.packages).filter(([name]) => name).sort(([a], [b]) => a.localeCompare(b, 'en'));
  need(all.length <= LIMITS.packages, 'TOO_MANY_LOCKED_PACKAGES');
  const packages = [], excluded = [];
  for (const [lockPath, meta] of all) {
    const inferredName = packageName(lockPath);
    need(meta && typeof meta === 'object' && !meta.link && !meta.inBundle, 'UNSUPPORTED_LOCKED_PACKAGE');
    const matches = platformAllows(meta.os, 'linux') && platformAllows(meta.cpu, 'x64') && platformAllows(meta.libc, 'glibc');
    if (!matches) {
      need(meta.optional === true, 'REQUIRED_PACKAGE_PLATFORM_MISMATCH');
      excluded.push({ lock_path: lockPath, version: meta.version, reason: 'optional-platform-mismatch', os: meta.os ?? null, cpu: meta.cpu ?? null, libc: meta.libc ?? null });
      continue;
    }
    need(typeof meta.version === 'string' && /^[0-9][A-Za-z0-9.+-]{0,127}$/.test(meta.version), 'INVALID_LOCKED_VERSION');
    const source = new URL(meta.resolved);
    need(source.protocol === 'https:' && source.hostname === 'registry.npmjs.org' && !source.username && !source.password &&
      !source.search && !source.hash && source.pathname.endsWith('.tgz'), 'UNSUPPORTED_LOCKED_ARCHIVE_SOURCE');
    const digest = digestOf(meta.integrity);
    packages.push({ lock_path: lockPath, name: meta.name ?? inferredName, version: meta.version, resolved: meta.resolved,
      integrity: meta.integrity, sha512_sri: digest.sri, sha512_hex: digest.hex,
      archive_path: `_cacache/content-v2/${digest.contentPath}`, dev: meta.dev === true, optional: meta.optional === true,
      declared_license_from_lock: meta.license ?? null });
  }
  return { packages, excluded };
}

export async function exportPackages(options) {
  const output = path.resolve(options.out), cache = path.resolve(options.cache);
  let ownedOutput = false;
  const report = { schema: 'expertauth-offline-npm-cache-v1', ok: false, platform: { os: 'linux', cpu: 'x64', libc: 'glibc' },
    includes_development_dependencies: true, archive_correspondence: 'Exact SHA-512 integrity-bound archive bytes only; installed file correspondence is separate',
    license_approval: false, native_platform_tests_passed: false, limits: LIMITS, packages: [], excluded_packages: [], archives: [], errors: [] };
  try {
    need(process.platform === 'linux' && process.arch === 'x64', 'EXPORT_REQUIRES_LINUX_X64');
    need(path.isAbsolute(options.out) && path.isAbsolute(options.cache) && path.isAbsolute(options.lock), 'ABSOLUTE_PATHS_REQUIRED');
    fs.mkdirSync(output, { recursive: true });
    need(fs.realpathSync(output) === output && fs.readdirSync(output).length === 0 && fs.realpathSync(cache) === cache &&
      output !== cache && !output.startsWith(cache + path.sep) && !cache.startsWith(output + path.sep), 'OUTPUT_MUST_BE_FRESH_AND_PATHS_UNLINKED');
    ownedOutput = true;
    const lockBytes = regularBytes(options.lock, 4 * 1024 * 1024);
    const selected = selectLocked(JSON.parse(lockBytes.toString('utf8')));
    report.lock_sha256 = sha256(lockBytes);
    report.packages = selected.packages; report.excluded_packages = selected.excluded;
    const archives = new Map(), failedDigests = new Set();
    let total = 0;
    for (const entry of report.packages) {
      if (failedDigests.has(entry.sha512_hex)) continue;
      if (archives.has(entry.sha512_hex)) {
        const prior = archives.get(entry.sha512_hex);
        need(prior.name === entry.name && prior.version === entry.version, 'ARCHIVE_SHARED_BY_DIFFERENT_PACKAGE_IDENTITIES');
        continue;
      }
      try {
        const digest = digestOf(entry.integrity), source = within(cache, digest.contentPath);
        const bytes = regularBytes(source, LIMITS.archiveBytes);
        need(bytes.length > 0 && createHash('sha512').update(bytes).digest('hex') === digest.hex, 'CACHED_ARCHIVE_INTEGRITY_MISMATCH');
        need(bytes[0] === 0x1f && bytes[1] === 0x8b, 'CACHED_CONTENT_IS_NOT_GZIP_ARCHIVE');
        total += bytes.length;
        need(total <= LIMITS.cacheBytes, 'CACHE_EXPORT_BYTE_LIMIT_EXCEEDED');
        const archive = { path: entry.archive_path, name: entry.name, version: entry.version, sha512_sri: digest.sri,
          sha512_hex: digest.hex, sha256: sha256(bytes), bytes: bytes.length };
        const destination = within(output, entry.archive_path);
        fs.mkdirSync(path.dirname(destination), { recursive: true });
        fs.writeFileSync(destination, bytes, { flag: 'wx', mode: 0o644 });
        need(sha256(regularBytes(destination, LIMITS.archiveBytes)) === archive.sha256, 'EXPORTED_ARCHIVE_WRITE_MISMATCH');
        archives.set(digest.hex, archive); report.archives.push(archive);
      } catch (error) {
        failedDigests.add(entry.sha512_hex);
        report.errors.push({ lock_path: entry.lock_path, code: /^[A-Z][A-Z0-9_]+$/.test(error.message || '') ? error.message : 'CACHED_ARCHIVE_UNAVAILABLE_OR_INVALID' });
      }
    }
    for (const entry of report.packages) {
      const archive = archives.get(entry.sha512_hex);
      entry.exported = Boolean(archive);
      if (archive) { entry.sha256 = archive.sha256; entry.bytes = archive.bytes; }
    }
    fs.writeFileSync(path.join(output, 'package-lock.json'), lockBytes, { flag: 'wx', mode: 0o644 });
    need(sha256(regularBytes(options.lock, 4 * 1024 * 1024)) === report.lock_sha256, 'SOURCE_LOCK_CHANGED_DURING_EXPORT');
    report.unique_archive_count = archives.size; report.total_archive_bytes = report.archives.reduce((sum, value) => sum + value.bytes, 0);
    report.applicable_package_count = report.packages.length; report.excluded_package_count = report.excluded_packages.length;
    report.ok = report.errors.length === 0 && report.packages.every(entry => entry.exported);
  } catch (error) { report.errors.push({ code: /^[A-Z][A-Z0-9_]+$/.test(error.message || '') ? error.message : 'EXPORT_PRECONDITION_OR_OPERATION_FAILED' }); }
  if (ownedOutput) fs.writeFileSync(path.join(output, 'cache-report.json'), JSON.stringify(report, null, 2) + '\n', { flag: 'wx' });
  return report;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const result = await exportPackages(argsOf(process.argv.slice(2), ['lock', 'cache', 'out'],
      { lock: '/app/package-lock.json', cache: '/root/.npm/_cacache/content-v2', out: '/out' }));
    console.log(JSON.stringify({ ok: result.ok, applicable_packages: result.applicable_package_count, unique_archives: result.unique_archive_count,
      total_archive_bytes: result.total_archive_bytes, errors: result.errors }));
    process.exitCode = result.ok ? 0 : 1;
  } catch { console.log(JSON.stringify({ ok: false, code: 'EXPORT_INITIALIZATION_OR_REPORT_FAILED' })); process.exitCode = 1; }
}
