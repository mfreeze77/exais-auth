import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { SMTPService } from 'supertokens-node/recipe/emailpassword/emaildelivery/index.js';
import { createPasswordResetEmailDelivery, PasswordResetDeliveryError } from '../email-delivery.js';

// Local configuration/content/error-boundary tests. No SMTP network is mocked or contacted.
const temporaryBase = isAbsolute(tmpdir()) && existsSync(tmpdir()) ? resolve(tmpdir()) : dirname(fileURLToPath(import.meta.url));
const directory = mkdtempSync(join(temporaryBase, 'expertauth-smtp-unit-'));
let sequence = 0;
function secret(contents = 'Synthetic-password-only\n') {
  const path = join(directory, `credential-${sequence++}`);
  writeFileSync(path, contents, { mode: 0o600 });
  return path;
}
after(() => {
  const target = resolve(directory);
  assert.equal(dirname(target), temporaryBase);
  assert.ok(basename(target).startsWith('expertauth-smtp-unit-'));
  rmSync(target, { recursive: true });
});
const origin = 'https://auth.example.test';
const env = { EXPERTAUTH_SMTP_HOST: 'smtp.example.test', EXPERTAUTH_SMTP_FROM_EMAIL: 'recovery@example.test',
  EXPERTAUTH_SMTP_PASSWORD_FILE: secret() };
const input = { type: 'PASSWORD_RESET', user: { email: 'synthetic@example.test' },
  passwordResetLink: `${origin}/auth/reset-password?token=synthetic-unit-value&rid=emailpassword&tenantId=public`, userContext: {} };
const content = (changes = {}) => createPasswordResetEmailDelivery(env, origin).service.serviceImpl.getContent({ ...input, ...changes });

test('SMTP-UNIT-001 absent settings disable the adapter without reading a file', () => {
  assert.equal(createPasswordResetEmailDelivery({}, undefined), undefined);
});

test('SMTP-UNIT-002 defaults construct the maintained SMTPService without sending email', () => {
  assert.ok(createPasswordResetEmailDelivery(env, origin).service instanceof SMTPService);
  assert.ok(createPasswordResetEmailDelivery({ ...env, EXPERTAUTH_SMTP_PORT: '2465', EXPERTAUTH_SMTP_USERNAME: 'custom-user',
    EXPERTAUTH_SMTP_FROM_NAME: 'Local ExpertAuth' }, origin).service instanceof SMTPService);
});

test('SMTP-UNIT-003 original plain-text template preserves the supplied SDK link and recipient', async () => {
  const result = await content();
  assert.equal(result.toEmail, input.user.email);
  assert.equal(result.subject, 'Reset your ExpertAuth password');
  assert.equal(result.isHtml, false);
  assert.ok(result.body.includes(`\n${input.passwordResetLink}\n`));
  assert.deepEqual(result.body.match(/https?:\/\/\S+/g), [input.passwordResetLink]);
  assert.ok(!/<(?:img|html|a)\b|supertokens\.com/i.test(result.body));
});

for (const [name, changes] of [
  ['missing host', { EXPERTAUTH_SMTP_HOST: undefined }], ['empty host', { EXPERTAUTH_SMTP_HOST: '' }],
  ['host header injection', { EXPERTAUTH_SMTP_HOST: 'smtp.example.test\r\nInjected: x' }],
  ['host URL', { EXPERTAUTH_SMTP_HOST: 'https://smtp.example.test' }], ['host label', { EXPERTAUTH_SMTP_HOST: '-smtp.example.test' }],
  ['host oversized', { EXPERTAUTH_SMTP_HOST: 'a'.repeat(254) }], ['invalid IP', { EXPERTAUTH_SMTP_HOST: '999.999.999.999' }],
  ['zero port', { EXPERTAUTH_SMTP_PORT: '0' }], ['port overflow', { EXPERTAUTH_SMTP_PORT: '65536' }],
  ['nonnumeric port', { EXPERTAUTH_SMTP_PORT: '465junk' }], ['port whitespace', { EXPERTAUTH_SMTP_PORT: ' 465' }],
  ['missing sender', { EXPERTAUTH_SMTP_FROM_EMAIL: undefined }], ['recipient list sender', { EXPERTAUTH_SMTP_FROM_EMAIL: 'a@example.test,b@example.test' }],
  ['invalid sender', { EXPERTAUTH_SMTP_FROM_EMAIL: 'a..b@example.test' }], ['sender header injection', { EXPERTAUTH_SMTP_FROM_EMAIL: 'a@example.test\nBcc: b@example.test' }],
  ['sender oversized', { EXPERTAUTH_SMTP_FROM_EMAIL: `${'a'.repeat(65)}@example.test` }],
  ['sender name injection', { EXPERTAUTH_SMTP_FROM_NAME: 'Name <other@example.test>' }],
  ['sender name newline', { EXPERTAUTH_SMTP_FROM_NAME: 'Name\nOther' }], ['sender name oversized', { EXPERTAUTH_SMTP_FROM_NAME: 'a'.repeat(101) }],
  ['username newline', { EXPERTAUTH_SMTP_USERNAME: 'user\r\n' }], ['username oversized', { EXPERTAUTH_SMTP_USERNAME: 'a'.repeat(255) }],
  ['missing password file', { EXPERTAUTH_SMTP_PASSWORD_FILE: undefined }], ['relative password file', { EXPERTAUTH_SMTP_PASSWORD_FILE: 'credential' }],
  ['nonexistent password file', { EXPERTAUTH_SMTP_PASSWORD_FILE: join(directory, 'missing') }],
  ['directory password file', { EXPERTAUTH_SMTP_PASSWORD_FILE: directory }],
  ['disabled TLS verification', { NODE_TLS_REJECT_UNAUTHORIZED: '0' }],
]) {
  test(`SMTP-UNIT-CONFIG rejects ${name}`, () => {
    assert.throws(() => createPasswordResetEmailDelivery({ ...env, ...changes }, origin),
      error => error.message.startsWith('Invalid ExpertAuth') && !error.message.includes('Synthetic-password'));
  });
}

test('SMTP-UNIT-004 any partial SMTP setting requires the complete configuration', () => {
  for (const setting of ['HOST', 'PORT', 'USERNAME', 'PASSWORD_FILE', 'FROM_EMAIL', 'FROM_NAME']) {
    assert.throws(() => createPasswordResetEmailDelivery({ [`EXPERTAUTH_SMTP_${setting}`]: '' }, origin));
  }
});

test('SMTP-UNIT-005 password file accepts exactly one terminal newline and preserves spaces', () => {
  for (const bytes of ['Synthetic-password', 'Synthetic-password\n', 'Synthetic-password\r\n', '  Synthetic password  ']) {
    assert.ok(createPasswordResetEmailDelivery({ ...env, EXPERTAUTH_SMTP_PASSWORD_FILE: secret(bytes) }, origin));
  }
});

test('SMTP-UNIT-006 malformed password files fail without exposing content or path', () => {
  for (const bytes of ['', '\n', 'Synthetic-password\n\n', 'Synthetic-password\r', 'Synthetic\0password', 'x'.repeat(4099), Buffer.from([0xc3, 0x28])]) {
    assert.throws(() => createPasswordResetEmailDelivery({ ...env, EXPERTAUTH_SMTP_PASSWORD_FILE: secret(bytes) }, origin),
      { message: 'Invalid ExpertAuth SMTP password file' });
  }
});

for (const invalidOrigin of ['https://user:secret@auth.example.test', 'https://auth.example.test/path',
  'https://auth.example.test?query=1', 'https://auth.example.test#fragment', 'https://auth.example.test#', 'file:///tmp/auth', 'invalid']) {
  test('SMTP-UNIT-ORIGIN rejects a non-origin public URL', () => {
    assert.throws(() => createPasswordResetEmailDelivery(env, invalidOrigin));
  });
}

for (const link of ['https://other.example.test/auth/reset-password?token=synthetic-unit-value',
  'http://auth.example.test/auth/reset-password', `${origin}:8443/auth/reset-password`,
  `${origin}/auth/other`, `${origin}/auth/reset-password/`, `${origin}/auth/reset-password#fragment`, `${origin}/auth/reset-password#`,
  'https://user:secret@auth.example.test/auth/reset-password', '/auth/reset-password',
  `${origin}/auth/reset-password?token=x\n`, `${origin}/auth/reset-password?token=%0d%0aHeader`,
  `${origin}/auth/reset-password?token=${'x'.repeat(8192)}`, `${origin}/auth\\reset-password`]) {
  test('SMTP-UNIT-LINK rejects an untrusted reset link without contacting SMTP', async () => {
    await assert.rejects(content({ passwordResetLink: link }));
  });
}

test('SMTP-UNIT-007 rejects unrelated email types and malformed recipients', async () => {
  await assert.rejects(content({ type: 'EMAIL_VERIFICATION' }));
  for (const recipient of ['a@example.test\r\nBcc: b@example.test', 'a@example.test,b@example.test', 'invalid', '']) {
    await assert.rejects(content({ user: { email: recipient } }));
  }
});

test('SMTP-UNIT-008 negative error injection tests sanitization only, not SMTP delivery', async () => {
  const service = createPasswordResetEmailDelivery(env, origin).service;
  const originalWrite = process.stderr.write;
  const recorded = [];
  process.stderr.write = chunk => { recorded.push(String(chunk)); return true; };
  try {
    for (const code of ['EAUTH', 'UNRECOGNIZED-recipient-token-password']) {
      service.serviceImpl.sendRawEmail = async () => { throw Object.assign(new Error('server recipient token password details'), { code }); };
      await assert.rejects(service.sendEmail(input), error => {
        assert.ok(error instanceof PasswordResetDeliveryError);
        assert.equal(error.message, 'ExpertAuth password reset email delivery failed');
        assert.equal(error.cause, undefined);
        return true;
      });
    }
  } finally { process.stderr.write = originalWrite; }
  assert.deepEqual(recorded.map(line => JSON.parse(line)), [
    { code: 'EMAIL_DELIVERY_FAILED', transportCode: 'EAUTH' }, { code: 'EMAIL_DELIVERY_FAILED', transportCode: 'UNKNOWN' },
  ]);
});

test('SMTP-UNIT-009 process-level insecure TLS is rejected even with an isolated config object', () => {
  const previous = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
  try { assert.throws(() => createPasswordResetEmailDelivery(env, origin)); }
  finally {
    if (previous === undefined) delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
    else process.env.NODE_TLS_REJECT_UNAUTHORIZED = previous;
  }
});
