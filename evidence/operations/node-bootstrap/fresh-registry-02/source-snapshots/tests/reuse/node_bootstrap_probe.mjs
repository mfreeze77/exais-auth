// Real registry acquisition and fresh offline npm install; no auth claim.
import * as fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { acquirePackages } from '../../tools/fetch_node_packages.mjs';
import { argsOf, need, selectLocked, sha256, regularBytes } from '../../tools/export_node_packages.mjs';
import { verifyRuntime } from '../../tools/verify_node_runtime.mjs';

const options = argsOf(process.argv.slice(2), ['stage'], {});
const root = '/work', cache = '/cache', output = '/out';
const lock = '/repo/examples/node-react/package-lock.json';
const lockBytes = regularBytes(lock, 4 * 1024 * 1024), data = JSON.parse(lockBytes);
const report = { schema: 'expertauth-node-bootstrap-probe-v1', stage: options.stage,
  passed: false, started: new Date().toISOString(), rows: [], errors: [], skipped: 0,
  foundation_passed: false, fresh_stack_deployment_qualified: false, license_approval: false,
  source_sha256: Object.fromEntries(['tools/fetch_node_packages.mjs', 'tools/export_node_packages.mjs',
    'tools/verify_node_runtime.mjs', 'tests/reuse/node_bootstrap_probe.mjs', 'examples/node-react/package-lock.json']
    .map(name => [name, sha256(regularBytes('/repo/' + name, 4 * 1024 * 1024))])) };

async function check(id, action) {
  const before = performance.now();
  try { const detail = await action(); report.rows.push({ id, status: 'passed', elapsed_ms: Math.round(performance.now() - before), detail }); }
  catch (error) { report.rows.push({ id, status: 'failed', error: /^[A-Z][A-Z0-9_]+$/.test(error.message || '') ? error.message : 'PROBE_ASSERTION_FAILED' }); throw error; }
}
function acquisition(name, mode, chosenCache = cache, chosenLock = lock) {
  return acquirePackages({ lock: chosenLock, cache: chosenCache, mode, report: `${output}/${name}.json` });
}
function snapshot(directory) {
  const files = {};
  function visit(base) {
    for (const entry of fs.readdirSync(base, { withFileTypes: true })) {
      const file = path.join(base, entry.name);
      if (entry.isDirectory()) visit(file);
      else { need(entry.isFile(), 'UNEXPECTED_CACHE_LINK'); files[path.relative(directory, file)] = sha256(regularBytes(file, 32 * 1024 * 1024)); }
    }
  }
  visit(directory); return Object.fromEntries(Object.entries(files).sort(([a], [b]) => a.localeCompare(b)));
}
function negative(result, expected) {
  need(result.passed === false && result.errors.includes(expected) && result.network_requests === 0 &&
    (!result.cache_lock_acquired || result.cache_lock_removed), 'EXPECTED_NEGATIVE_REJECTION_MISSING');
  return { rejection: expected, requests: result.network_requests, cache_lock_removed: result.cache_lock_removed };
}

try {
  need(['online', 'offline'].includes(options.stage), 'INVALID_PROBE_STAGE');
  need([root, cache, output].every(p => fs.realpathSync(p) === p), 'UNSAFE_PROBE_ROOT');
  if (options.stage === 'online') {
    await check('NPM-BOOTSTRAP-FRESH-REGISTRY-AND-EXCLUSIVE-LOCK', async () => {
      need(fs.readdirSync(cache).length === 0, 'FRESH_CACHE_REQUIRED');
      const first = acquisition('fresh-registry', 'online');
      const contender = await acquisition('concurrent-denied', 'online');
      negative(contender, 'PACKAGE_CACHE_BUSY');
      const fetched = await first;
      need(fetched.passed && fetched.network_requests === 141 && fetched.downloaded_archives === 141 &&
        fetched.downloaded_bytes === 14580488 && fetched.reused_archives === 0 && fetched.cache_lock_removed, 'FRESH_REGISTRY_ACQUISITION_FAILED');
      return { actual_requests: fetched.network_requests, downloaded_bytes: fetched.downloaded_bytes,
        packages: fetched.applicable_package_count, concurrent_requests: contender.network_requests, concurrent_rejection: contender.errors[0] };
    });
    await check('NPM-BOOTSTRAP-RESUME-ONE-MISSING-ARCHIVE', async () => {
      const before = snapshot(cache), manifest = JSON.parse(fs.readFileSync(cache + '/cache-report.json'));
      const member = [...manifest.archives].sort((a, b) => a.bytes - b.bytes)[0];
      const target = path.join(cache, member.path);
      need(sha256(regularBytes(target, 32 * 1024 * 1024)) === member.sha256 && target.startsWith(cache + '/_cacache/content-v2/'), 'OWNED_ARCHIVE_DIFFERS');
      fs.unlinkSync(target);
      const resumed = await acquisition('one-missing-resume', 'online');
      need(resumed.passed && resumed.downloaded_archives === 1 && resumed.reused_archives === 140 &&
        resumed.network_requests === 1 && resumed.cache_lock_removed && !resumed.cache_manifest_written &&
        JSON.stringify(snapshot(cache)) === JSON.stringify(before), 'PARTIAL_CACHE_RESUME_DIFFERS');
      return { fetched_archive: member.path, fetched_bytes: member.bytes, actual_requests: 1, all_cache_bytes_restored: true };
    });
    await check('NPM-BOOTSTRAP-ACTUAL-RESPONSE-WRONG-INTEGRITY', async () => {
      const item = selectLocked(data).packages.find(row => row.name === 'is-promise');
      need(item, 'SMALL_LOCKED_PACKAGE_MISSING');
      const altered = structuredClone(data); altered.packages = { '': data.packages[''], [item.lock_path]: structuredClone(data.packages[item.lock_path]) };
      const sri = Buffer.from(item.sha512_hex, 'hex'); sri[0] ^= 1;
      altered.packages[item.lock_path].integrity = 'sha512-' + sri.toString('base64');
      const modified = root + '/wrong-integrity-lock.json'; fs.writeFileSync(modified, JSON.stringify(altered), { flag: 'wx' });
      const badCache = root + '/wrong-integrity';
      const rejected = await acquisition('wrong-integrity', 'online', badCache, modified);
      need(!rejected.passed && rejected.errors.includes('ARCHIVE_HASH_MISMATCH') && rejected.network_requests === 1 &&
        rejected.downloaded_archives === 0 && rejected.cache_lock_removed && fs.readdirSync(badCache).length === 0, 'BAD_REMOTE_BYTES_NOT_REJECTED');
      return { real_requests: 1, persisted_archives: 0, rejection: 'ARCHIVE_HASH_MISMATCH' };
    });
  } else {
    await check('NPM-BOOTSTRAP-OFFLINE-CACHE-REUSE', async () => {
      const before = snapshot(cache), reused = await acquisition('offline-reuse', 'offline');
      need(reused.passed && reused.reused_archives === 141 && reused.network_requests === 0 && !reused.cache_manifest_written &&
        reused.cache_lock_removed && JSON.stringify(snapshot(cache)) === JSON.stringify(before), 'OFFLINE_CACHE_REUSE_FAILED');
      return { archives: 141, network_requests: 0, all_cache_bytes_unchanged: true };
    });
    await check('NPM-BOOTSTRAP-EMPTY-OFFLINE-REJECTION', async () => negative(await acquisition('empty-offline', 'offline', root + '/empty-cache'), 'ARCHIVE_MISSING_IN_OFFLINE_CACHE'));
    await check('NPM-BOOTSTRAP-CORRUPT-CACHE-PRESERVED', async () => {
      const entry = selectLocked(data).packages[0], chosen = root + '/corrupt-cache', file = path.join(chosen, entry.archive_path);
      fs.mkdirSync(path.dirname(file), { recursive: true }); fs.writeFileSync(file, 'intentional-corruption', { flag: 'wx' });
      const before = snapshot(chosen), result = negative(await acquisition('corrupt-cache', 'offline', chosen), 'ARCHIVE_HASH_MISMATCH');
      need(JSON.stringify(before) === JSON.stringify(snapshot(chosen)), 'CORRUPT_INPUT_WAS_OVERWRITTEN'); return result;
    });
    await check('NPM-BOOTSTRAP-LINK-REJECTION', async () => {
      const entry = selectLocked(data).packages[0], chosen = root + '/linked-cache', file = path.join(chosen, entry.archive_path);
      fs.mkdirSync(path.dirname(file), { recursive: true });
      const protectedFile = root + '/protected-input'; fs.writeFileSync(protectedFile, 'preserved', { flag: 'wx' }); fs.symlinkSync(protectedFile, file);
      const result = negative(await acquisition('linked-cache', 'offline', chosen), 'LINK_IN_PACKAGE_CACHE');
      need(fs.readFileSync(protectedFile, 'utf8') === 'preserved' && fs.lstatSync(file).isSymbolicLink(), 'LINK_TARGET_CHANGED'); return result;
    });
    await check('NPM-BOOTSTRAP-OVERSIZE-CACHE-REJECTION', async () => {
      const entry = selectLocked(data).packages[0], chosen = root + '/oversize-cache', file = path.join(chosen, entry.archive_path);
      fs.mkdirSync(path.dirname(file), { recursive: true }); fs.closeSync(fs.openSync(file, 'wx')); fs.truncateSync(file, 32 * 1024 * 1024 + 1);
      return negative(await acquisition('oversize-cache', 'offline', chosen), 'CACHE_FILE_TOO_LARGE');
    });
    await check('NPM-BOOTSTRAP-UNKNOWN-ENTRY-PRESERVED', async () => {
      const chosen = root + '/unknown-cache'; fs.mkdirSync(chosen); fs.writeFileSync(chosen + '/keep.txt', 'preserved', { flag: 'wx' });
      const result = negative(await acquisition('unknown-cache', 'offline', chosen), 'UNKNOWN_CACHE_ENTRY');
      need(fs.readFileSync(chosen + '/keep.txt', 'utf8') === 'preserved', 'UNKNOWN_ENTRY_CHANGED'); return result;
    });
    await check('NPM-BOOTSTRAP-UNAPPROVED-ORIGIN-REJECTION', async () => {
      const altered = structuredClone(data), key = selectLocked(data).packages[0].lock_path;
      altered.packages[key].resolved = altered.packages[key].resolved.replace('registry.npmjs.org', 'registry.npmjs.org:444');
      const file = root + '/wrong-origin-lock.json'; fs.writeFileSync(file, JSON.stringify(altered), { flag: 'wx' });
      return negative(await acquisition('unapproved-origin', 'online', root + '/unapproved-origin', file), 'UNAPPROVED_ARCHIVE_ORIGIN');
    });
    await check('NPM-BOOTSTRAP-FRESH-OFFLINE-INSTALL-AND-COMPILE', async () => {
      const app = root + '/app'; fs.mkdirSync(app);
      const names = ['package.json', 'package-lock.json', 'server.js', 'email-delivery.js', 'client.jsx', 'build.mjs', 'public/index.html'];
      for (const name of names) { const target = path.join(app, name); fs.mkdirSync(path.dirname(target), { recursive: true }); fs.copyFileSync('/repo/examples/node-react/' + name, target, fs.constants.COPYFILE_EXCL); }
      const commands = [ ['node', '/usr/local/lib/node_modules/npm/bin/npm-cli.js', 'ci', '--offline', '--cache=/cache', '--ignore-scripts', '--no-audit', '--no-fund', '--logs-max=0', '--logs-dir=/tmp/npm-logs', '--update-notifier=false'], ['node', 'build.mjs'] ];
      const records = [];
      for (const [index, argv] of commands.entries()) {
        const result = spawnSync(argv[0], argv.slice(1), { cwd: app, timeout: 60000, maxBuffer: 1024 * 1024, encoding: 'utf8' });
        for (const stream of ['stdout', 'stderr']) fs.writeFileSync(`${output}/offline-command-${index}.${stream}`, result[stream] ?? '', { flag: 'wx' });
        records.push({ argv, exit_code: result.status, signal: result.signal,
          stdout_sha256: sha256(Buffer.from(result.stdout ?? '')), stderr_sha256: sha256(Buffer.from(result.stderr ?? '')) });
        need(result.status === 0 && !result.error, 'ACTUAL_OFFLINE_INSTALL_OR_BUILD_FAILED');
      }
      const audit = await verifyRuntime({ app, cache, 'cache-report': cache + '/cache-report.json',
        output: output + '/fresh-runtime-report.json', 'tar-module': '/usr/local/lib/node_modules/npm/node_modules/tar/dist/commonjs/index.min.js' });
      const previous = JSON.parse(fs.readFileSync('/repo/evidence/operations/node-image-build/offline-build-02/candidate-runtime/runtime-report.json'));
      need(audit.ok && audit.dependency_files_sha256 === previous.dependency_files_sha256 &&
        audit.app_files_sha256 === previous.app_files_sha256, 'FRESH_INSTALLED_BYTES_DIFFER');
      return { commands: records, packages: audit.packages.length, original_members: audit.tar_correspondence.matched_files,
        dependency_files_sha256: audit.dependency_files_sha256, app_files_sha256: audit.app_files_sha256 };
    });
  }
  report.passed = report.rows.length === (options.stage === 'online' ? 3 : 8) && report.rows.every(row => row.status === 'passed');
} catch (error) { report.errors.push(/^[A-Z][A-Z0-9_]+$/.test(error.message || '') ? error.message : 'BOOTSTRAP_PROBE_FAILED'); }
report.finished = new Date().toISOString();
fs.writeFileSync(`${output}/${options.stage}-probe.json`, JSON.stringify(report, null, 2) + '\n', { flag: 'wx' });
console.log(JSON.stringify({ stage: options.stage, passed: report.passed, checks: report.rows.length, errors: report.errors }));
process.exitCode = report.passed ? 0 : 1;
