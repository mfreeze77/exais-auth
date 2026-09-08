// Isolated dependency qualification. Never edits the application package graph.
// Synthetic data, a local SMTP sink, and local filesystem/HTTP canaries only.
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import {createRequire} from 'node:module';
import {spawnSync} from 'node:child_process';
import net from 'node:net';
import http from 'node:http';
import assert from 'node:assert/strict';

const work = await fs.mkdtemp(path.join(os.tmpdir(), 'expertauth-nodemailer-'));
const report = {kind: 'Isolated dependency qualification; local test SMTP sink, not live-provider or product acceptance',
  started_at: new Date().toISOString(), node: process.version, tests: [], npm: {}};
const digest = data => crypto.createHash('sha256').update(data).digest('hex');
const lock = await fs.readFile('/source/package-lock.json');
report.original_lock_sha256 = digest(lock);
const packageSpec = {name: 'expertauth-nodemailer-qualification', version: '0.0.0', private: true,
  dependencies: {'supertokens-node': '24.0.3'}, overrides: {'supertokens-node': {nodemailer: '9.1.1'}}};
await fs.writeFile(path.join(work, 'package.json'), JSON.stringify(packageSpec));
report.test_package_spec = packageSpec;
const install = spawnSync('npm', ['install', '--ignore-scripts', '--no-fund'], {cwd: work, encoding: 'utf8', timeout: 180000});
report.npm.install = {exit_code: install.status, stdout: install.stdout, stderr: install.stderr};
if (install.status !== 0) throw new Error('Isolated npm install failed');
const audit = spawnSync('npm', ['audit', '--json'], {cwd: work, encoding: 'utf8', timeout: 60000});
report.npm.audit = {exit_code: audit.status, result: JSON.parse(audit.stdout), stderr: audit.stderr};
const patchedLock = await fs.readFile(path.join(work, 'package-lock.json'));
report.isolated_lock_sha256 = digest(patchedLock);
report.resolved_nodemailer = JSON.parse(patchedLock).packages['node_modules/nodemailer'];
const require = createRequire(path.join(work, 'package.json'));
const nodemailer = require('nodemailer');
assert.equal(require('nodemailer/package.json').version, '9.1.1');
const test = async (id, action) => {
  try { await action(); report.tests.push({id, status: 'passed'}); }
  catch (error) { report.tests.push({id, status: 'failed', error: error.message}); }
};

const fileMarker = 'EXPERTAUTH_SYNTHETIC_FILE_CANARY_' + crypto.randomUUID();
const file = path.join(work, 'canary.txt');
await fs.writeFile(file, fileMarker);
const urlMarker = 'EXPERTAUTH_SYNTHETIC_HTTP_CANARY_' + crypto.randomUUID();
let httpRequests = 0;
const httpServer = http.createServer((req, res) => { httpRequests++; res.end(urlMarker); });
await new Promise(resolve => httpServer.listen(0, '127.0.0.1', resolve));
const url = `http://127.0.0.1:${httpServer.address().port}/canary`;
const transporter = nodemailer.createTransport({streamTransport: true, buffer: true,
  disableFileAccess: true, disableUrlAccess: true});
const baseMail = {from: 'sender@example.test', to: 'recipient@example.test', subject: 'Synthetic dependency proof'};
await test('NM9-positive-text-and-html', async () => {
  const result = await transporter.sendMail({...baseMail, text: 'synthetic text', html: '<b>synthetic html</b>'});
  assert.match(result.message.toString(), /synthetic text/);
  assert.match(result.message.toString(), /synthetic html/);
});
await test('NM9-raw-file-policy-blocks-read', async () => {
  await assert.rejects(transporter.sendMail({...baseMail, raw: {path: file}}), /file access rejected/i);
});
await test('NM9-raw-url-policy-blocks-loopback-fetch', async () => {
  await assert.rejects(transporter.sendMail({...baseMail, raw: {href: url}}), /url access rejected/i);
  assert.equal(httpRequests, 0);
});
await test('NM9-message-cannot-reopen-file-policy', async () => {
  await assert.rejects(transporter.sendMail({...baseMail, disableFileAccess: false, raw: {path: file}}), /file access rejected/i);
});
await test('NM9-attachment-file-policy-blocks-read', async () => {
  await assert.rejects(transporter.sendMail({...baseMail, text: 'safe', attachments: [{path: file}]}), /file access rejected/i);
});
await new Promise(resolve => httpServer.close(resolve));

const messages = [];
const sockets = new Set();
const smtp = net.createServer(socket => {
  sockets.add(socket); socket.on('close', () => sockets.delete(socket));
  socket.setTimeout(15000, () => socket.destroy());
  socket.write('220 expertauth.test ESMTP synthetic sink\r\n');
  let buffer = '', data = false, message = [];
  socket.on('data', chunk => {
    buffer += chunk.toString();
    while (buffer.includes('\r\n')) {
      const index = buffer.indexOf('\r\n');
      const line = buffer.slice(0, index); buffer = buffer.slice(index + 2);
      if (data) {
        if (line === '.') { messages.push(message.join('\r\n')); message = []; data = false; socket.write('250 accepted synthetic message\r\n'); }
        else message.push(line);
      } else if (/^(EHLO|HELO)/i.test(line)) socket.write('250-expertauth.test\r\n250 AUTH PLAIN\r\n');
      else if (/^AUTH PLAIN/i.test(line)) socket.write('235 synthetic authentication accepted\r\n');
      else if (/^DATA$/i.test(line)) { data = true; socket.write('354 end with dot\r\n'); }
      else if (/^QUIT$/i.test(line)) socket.end('221 bye\r\n');
      else socket.write('250 ok\r\n');
    }
  });
});
await new Promise(resolve => smtp.listen(0, '127.0.0.1', resolve));
for (const recipe of ['emailpassword', 'emailverification', 'passwordless', 'webauthn']) {
  await test('ST24-NM9-' + recipe + '-smtp-text-html', async () => {
    const SMTPService = require(path.join(work, 'node_modules/supertokens-node/lib/build/recipe', recipe, 'emaildelivery/services/smtp/index.js')).default;
    const service = new SMTPService({smtpSettings: {host: '127.0.0.1', port: smtp.address().port,
      secure: false, authUsername: 'synthetic-user', password: 'synthetic-password',
      from: {name: 'ExpertAuth Test', email: 'sender@example.test'}}});
    for (const isHtml of [false, true]) {
      const marker = `EXPERTAUTH_${recipe}_${isHtml ? 'HTML' : 'TEXT'}`;
      await service.serviceImpl.sendRawEmail({toEmail: 'recipient@example.test', subject: 'Synthetic dependency proof',
        isHtml, body: isHtml ? `<p>${marker}</p>` : marker, userContext: {}});
      assert.match(messages.at(-1), new RegExp(marker));
      assert.match(messages.at(-1), /recipient@example.test/);
    }
  });
}
for (const socket of sockets) socket.destroy();
await new Promise(resolve => smtp.close(resolve));
report.local_smtp_messages = messages.length;
report.outbound_provider_messages = 0;
report.finished_at = new Date().toISOString();
report.passed = report.tests.filter(test => test.status === 'passed').length;
report.failed = report.tests.filter(test => test.status === 'failed').length;
report.limitations = ['Major dependency override outside the original SDK semver declaration',
  'No live SMTP provider, OAuth transport, TLS certificate, full authentication UI, or load/concurrency qualification',
  'SMTP sink is a synthetic local test fixture; it is not product email delivery implementation'];
report.source_sha256 = digest(await fs.readFile(new URL(import.meta.url)));
await fs.writeFile('/evidence/nodemailer-9.1.1-qualification.json', JSON.stringify(report, null, 2) + '\n');
await fs.writeFile('/evidence/nodemailer-9.1.1-isolated-lock.json', patchedLock);
console.log(JSON.stringify({passed: report.passed, failed: report.failed, smtp_messages: messages.length,
  npm_audit: report.npm.audit.result.metadata.vulnerabilities, application_files_modified: false}));
process.exitCode = report.failed ? 1 : 0;
