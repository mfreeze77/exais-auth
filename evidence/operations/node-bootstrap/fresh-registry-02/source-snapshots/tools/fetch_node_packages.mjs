// Acquire exact locked public npm archives, without resolution or installation.
import * as fs from 'node:fs';
import path from 'node:path';
import https from 'node:https';
import { createHash, randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { argsOf, LIMITS, need, regularBytes, selectLocked, sha256, within } from './export_node_packages.mjs';

export const REQUEST_MS = 15000;
export const ACQUISITION_MS = 180000;
const MAX_REPORT = 4 * 1024 * 1024;
const codeOf = error => /^[A-Z][A-Z0-9_]+$/.test(error?.message || '') ? error.message : 'ACQUISITION_OPERATION_FAILED';

function approvedURL(value) {
  const url = new URL(value);
  need(url.protocol === 'https:' && url.host === 'registry.npmjs.org' && !url.username && !url.password &&
    !url.search && !url.hash && url.pathname.endsWith('.tgz'), 'UNAPPROVED_ARCHIVE_ORIGIN');
  return url;
}

function requestArchive(value, agent, remainingBytes, deadline, report) {
  const url = approvedURL(value), maximum = Math.min(LIMITS.archiveBytes, remainingBytes);
  const timeout = Math.min(REQUEST_MS, deadline - performance.now());
  need(timeout > 0 && maximum > 0, 'ACQUISITION_BOUND_EXCEEDED');
  report.network_requests++;
  return new Promise((resolve, reject) => {
    let settled = false, timer, request;
    const finish = (error, bytes) => {
      if (settled) return;
      settled = true; clearTimeout(timer);
      if (error) { request?.destroy(); reject(error); } else resolve(bytes);
    };
    request = https.get(url, { agent, rejectUnauthorized: true, maxHeaderSize: 16384,
      headers: { Accept: 'application/octet-stream', 'User-Agent': 'ExpertAuth-locked-source-bootstrap/1' } }, response => {
      if (response.statusCode !== 200) return finish(new Error('ARCHIVE_HTTP_STATUS_REJECTED'));
      const declared = response.headers['content-length'];
      if (declared !== undefined && (!/^\d+$/.test(declared) || Number(declared) > maximum)) return finish(new Error('ARCHIVE_RESPONSE_TOO_LARGE'));
      const chunks = []; let size = 0;
      response.on('data', chunk => {
        if (settled) return;
        size += chunk.length;
        if (size > maximum) return finish(new Error('ARCHIVE_RESPONSE_TOO_LARGE'));
        chunks.push(chunk);
      });
      response.once('error', () => finish(new Error('ARCHIVE_RESPONSE_INTERRUPTED')));
      response.once('end', () => {
        if (!response.complete || size === 0 || (declared !== undefined && size !== Number(declared))) return finish(new Error('ARCHIVE_RESPONSE_INCOMPLETE'));
        finish(null, Buffer.concat(chunks, size));
      });
      response.once('close', () => { if (!response.complete) finish(new Error('ARCHIVE_RESPONSE_INTERRUPTED')); });
    });
    request.once('error', () => finish(new Error('ARCHIVE_HTTPS_REQUEST_FAILED')));
    timer = setTimeout(() => finish(new Error('ARCHIVE_REQUEST_DEADLINE_EXCEEDED')), timeout);
  });
}

function inventory(cache, allowed) {
  const files = new Map(); let total = 0;
  function visit(directory) {
    for (const item of fs.readdirSync(directory, { withFileTypes: true })) {
      const full = path.join(directory, item.name), relative = path.relative(cache, full).split(path.sep).join('/');
      need(!item.isSymbolicLink(), 'LINK_IN_PACKAGE_CACHE');
      if (item.isDirectory()) {
        need([...allowed].some(name => name.startsWith(relative + '/')), 'UNKNOWN_CACHE_DIRECTORY');
        visit(full);
      } else {
        need(item.isFile() && allowed.has(relative), 'UNKNOWN_CACHE_ENTRY');
        const stat = fs.lstatSync(full);
        need(stat.size <= (relative.endsWith('.json') ? MAX_REPORT : LIMITS.archiveBytes), 'CACHE_FILE_TOO_LARGE');
        total += stat.size; need(total <= LIMITS.cacheBytes, 'CACHE_ALREADY_EXCEEDS_BOUND');
        files.set(relative, stat.size);
      }
    }
  }
  visit(cache); return { files, total };
}

function originalArchive(bytes, entry) {
  need(bytes.length > 0 && bytes.length <= LIMITS.archiveBytes &&
    createHash('sha512').update(bytes).digest('hex') === entry.sha512_hex, 'ARCHIVE_HASH_MISMATCH');
  need(bytes[0] === 0x1f && bytes[1] === 0x8b, 'ARCHIVE_GZIP_HEADER_MISMATCH');
  return { path: entry.archive_path, name: entry.name, version: entry.version,
    sha512_sri: entry.sha512_sri, sha512_hex: entry.sha512_hex, sha256: sha256(bytes), bytes: bytes.length };
}

export async function acquirePackages(options) {
  const report = { schema: 'expertauth-npm-archive-acquisition-v1', passed: false,
    started: new Date().toISOString(), mode: options.mode ?? 'offline', network_requests: 0,
    downloaded_archives: 0, downloaded_bytes: 0, reused_archives: 0, cache_manifest_written: false,
    cache_lock_acquired: false, cache_lock_removed: false, errors: [], archives: [],
    limits: { ...LIMITS, requestMilliseconds: REQUEST_MS, acquisitionMilliseconds: ACQUISITION_MS },
    foundation_passed: false, license_approval: false, native_platform_tests_passed: false };
  let reportOwned = false, output, cache, lockPath, lockBody, agent;
  const deadline = performance.now() + ACQUISITION_MS;
  try {
    need(process.platform === 'linux' && process.arch === 'x64', 'ACQUISITION_REQUIRES_LINUX_X64');
    need(['online', 'offline'].includes(report.mode), 'INVALID_ACQUISITION_MODE');
    need(['cache', 'lock', 'report'].every(key => typeof options[key] === 'string' && path.isAbsolute(options[key])), 'ABSOLUTE_PATHS_REQUIRED');
    output = path.resolve(options.report); cache = path.resolve(options.cache);
    need(output !== cache && !output.startsWith(cache + path.sep), 'REPORT_MUST_BE_OUTSIDE_CACHE');
    fs.mkdirSync(path.dirname(output), { recursive: true });
    need(fs.realpathSync(path.dirname(output)) === path.dirname(output), 'LINKED_REPORT_DIRECTORY');
    fs.writeFileSync(output, JSON.stringify(report) + '\n', { flag: 'wx' }); reportOwned = true;
    const lockBytes = regularBytes(options.lock, MAX_REPORT);
    const selected = selectLocked(JSON.parse(lockBytes.toString('utf8')));
    for (const entry of selected.packages) approvedURL(entry.resolved);
    const unique = new Map();
    for (const entry of selected.packages) {
      const prior = unique.get(entry.sha512_hex);
      need(!prior || (prior.name === entry.name && prior.version === entry.version), 'AMBIGUOUS_ARCHIVE_IDENTITY');
      unique.set(entry.sha512_hex, entry);
    }
    report.lock_sha256 = sha256(lockBytes);
    report.applicable_package_count = selected.packages.length;
    report.excluded_package_count = selected.excluded.length;
    report.unique_archive_count = unique.size;
    fs.mkdirSync(cache, { recursive: true });
    need(fs.realpathSync(cache) === cache && fs.lstatSync(cache).isDirectory(), 'LINKED_CACHE_ROOT');
    const allowed = new Set([...unique.values()].map(row => row.archive_path));
    for (const name of ['package-lock.json', 'cache-report.json', '.acquire.lock']) allowed.add(name);
    const before = inventory(cache, allowed);
    report.cache_bytes_before = before.total;
    lockPath = within(cache, '.acquire.lock'); lockBody = Buffer.from(randomUUID() + '\n');
    try { fs.writeFileSync(lockPath, lockBody, { flag: 'wx', mode: 0o600 }); }
    catch (error) { if (error.code === 'EEXIST') throw new Error('PACKAGE_CACHE_BUSY'); throw error; }
    report.cache_lock_acquired = true;
    const storedLock = within(cache, 'package-lock.json'), storedReport = within(cache, 'cache-report.json');
    if (fs.existsSync(storedLock)) need(sha256(regularBytes(storedLock, MAX_REPORT)) === report.lock_sha256, 'CACHED_LOCKFILE_DIFFERS');
    let priorManifest;
    if (fs.existsSync(storedReport)) {
      priorManifest = JSON.parse(regularBytes(storedReport, MAX_REPORT).toString('utf8'));
      need(priorManifest.schema === 'expertauth-offline-npm-cache-v1' && priorManifest.ok === true &&
        priorManifest.platform?.os === 'linux' && priorManifest.platform?.cpu === 'x64' && priorManifest.platform?.libc === 'glibc' &&
        priorManifest.includes_development_dependencies === true && priorManifest.license_approval === false &&
        priorManifest.native_platform_tests_passed === false &&
        priorManifest.lock_sha256 === report.lock_sha256 && priorManifest.applicable_package_count === selected.packages.length &&
        priorManifest.excluded_package_count === selected.excluded.length && priorManifest.unique_archive_count === unique.size &&
        fs.existsSync(storedLock), 'EXISTING_CACHE_MANIFEST_DIFFERS');
    }
    agent = new https.Agent({ keepAlive: true, maxSockets: 2, maxTotalSockets: 2, maxFreeSockets: 1, proxyEnv: {} });
    let total = before.total + lockBody.length;
    for (const entry of unique.values()) {
      report.active_archive = { lock_path: entry.lock_path, resolved: entry.resolved, integrity: entry.sha512_sri };
      need(performance.now() < deadline, 'ACQUISITION_DEADLINE_EXCEEDED');
      const destination = within(cache, entry.archive_path), reused = fs.existsSync(destination);
      let bytes;
      if (reused) bytes = regularBytes(destination, LIMITS.archiveBytes);
      else {
        need(report.mode === 'online', 'ARCHIVE_MISSING_IN_OFFLINE_CACHE');
        bytes = await requestArchive(entry.resolved, agent, LIMITS.cacheBytes - total - MAX_REPORT, deadline, report);
      }
      const archive = originalArchive(bytes, entry);
      if (!reused) {
        fs.mkdirSync(path.dirname(destination), { recursive: true });
        within(cache, entry.archive_path);
        fs.writeFileSync(destination, bytes, { flag: 'wx', mode: 0o644 });
        need(sha256(regularBytes(destination, LIMITS.archiveBytes)) === archive.sha256, 'ARCHIVE_WRITE_MISMATCH');
        total += bytes.length; report.downloaded_archives++; report.downloaded_bytes += bytes.length;
      } else report.reused_archives++;
      report.archives.push({ ...archive, reused, resolved: entry.resolved });
    }
    const byDigest = new Map(report.archives.map(row => [row.sha512_hex, row]));
    const manifest = { schema: 'expertauth-offline-npm-cache-v1', ok: true,
      platform: { os: 'linux', cpu: 'x64', libc: 'glibc' }, includes_development_dependencies: true,
      archive_correspondence: 'Exact SHA-512 integrity-bound archive bytes only; installed file correspondence is separate',
      license_approval: false, native_platform_tests_passed: false, limits: LIMITS,
      lock_sha256: report.lock_sha256, packages: selected.packages.map(entry => ({ ...entry, exported: true,
        sha256: byDigest.get(entry.sha512_hex).sha256, bytes: byDigest.get(entry.sha512_hex).bytes })),
      excluded_packages: selected.excluded,
      archives: report.archives.map(({ reused, resolved, ...archive }) => archive), errors: [],
      applicable_package_count: selected.packages.length, excluded_package_count: selected.excluded.length,
      unique_archive_count: unique.size, total_archive_bytes: report.archives.reduce((sum, row) => sum + row.bytes, 0) };
    if (priorManifest) {
      for (const key of ['packages', 'excluded_packages', 'archives']) {
        // Coordinates and byte facts must match; preserved exporter ordering is irrelevant.
        const id = key === 'archives' ? 'path' : 'lock_path';
        const normalize = rows => rows.map(row => Object.fromEntries(Object.entries(row).sort(([a], [b]) => a.localeCompare(b))))
          .sort((a, b) => a[id].localeCompare(b[id]));
        need(JSON.stringify(normalize(priorManifest[key])) === JSON.stringify(normalize(manifest[key])), 'EXISTING_CACHE_MEMBERS_DIFFER');
      }
      need(priorManifest.total_archive_bytes === manifest.total_archive_bytes, 'EXISTING_CACHE_BYTE_COUNT_DIFFERS');
    } else {
      const encoded = Buffer.from(JSON.stringify(manifest, null, 2) + '\n');
      need(encoded.length <= MAX_REPORT && total + encoded.length + lockBytes.length <= LIMITS.cacheBytes, 'CACHE_MANIFEST_EXCEEDS_BOUND');
      if (!fs.existsSync(storedLock)) fs.writeFileSync(storedLock, lockBytes, { flag: 'wx', mode: 0o644 });
      fs.writeFileSync(storedReport, encoded, { flag: 'wx', mode: 0o644 }); report.cache_manifest_written = true;
    }
    need(sha256(regularBytes(options.lock, MAX_REPORT)) === report.lock_sha256, 'SOURCE_LOCK_CHANGED_DURING_ACQUISITION');
    report.cache_manifest_sha256 = sha256(regularBytes(storedReport, MAX_REPORT));
    report.cache_bytes_after_with_lock = inventory(cache, allowed).total;
    delete report.active_archive;
    report.passed = true;
  } catch (error) { report.errors.push(codeOf(error)); }
  finally {
    agent?.destroy();
    if (report.cache_lock_acquired) {
      try {
        need(regularBytes(lockPath, 256).equals(lockBody), 'CACHE_LOCK_OWNERSHIP_CHANGED');
        fs.unlinkSync(lockPath); report.cache_lock_removed = true;
      } catch (error) { report.passed = false; report.errors.push(codeOf(error)); }
    }
    report.finished = new Date().toISOString();
    if (reportOwned) fs.writeFileSync(output, JSON.stringify(report, null, 2) + '\n');
  }
  return report;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const result = await acquirePackages(argsOf(process.argv.slice(2), ['lock', 'cache', 'report', 'mode'], { mode: 'offline' }));
    console.log(JSON.stringify({ passed: result.passed, downloaded: result.downloaded_archives, reused: result.reused_archives,
      requests: result.network_requests, errors: result.errors }));
    process.exitCode = result.passed ? 0 : 1;
  } catch { console.log(JSON.stringify({ passed: false, code: 'ACQUISITION_INITIALIZATION_OR_REPORT_FAILED' })); process.exitCode = 1; }
}
