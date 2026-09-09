import { openSync, fstatSync, readFileSync, closeSync } from 'node:fs';
import { isAbsolute } from 'node:path';
import { isIP } from 'node:net';
import { SMTPService } from 'supertokens-node/recipe/emailpassword/emaildelivery/index.js';

const variables = ['HOST', 'PORT', 'USERNAME', 'PASSWORD_FILE', 'FROM_EMAIL', 'FROM_NAME'];
const transportCodes = new Set(['EAUTH', 'ECONNECTION', 'ECONNREFUSED', 'ECONNRESET', 'EDNS', 'EAI_AGAIN',
  'ENOTFOUND', 'EENVELOPE', 'EMESSAGE', 'ESOCKET', 'ETIMEDOUT', 'ETLS', 'CERT_HAS_EXPIRED',
  'DEPTH_ZERO_SELF_SIGNED_CERT', 'SELF_SIGNED_CERT_IN_CHAIN', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
  'UNABLE_TO_GET_ISSUER_CERT_LOCALLY', 'ERR_TLS_CERT_ALTNAME_INVALID']);

function requireValid(condition) {
  if (!condition) throw new Error('Invalid ExpertAuth password reset email configuration or content');
}

function text(value, maximum) {
  requireValid(typeof value === 'string' && value.length > 0 && Buffer.byteLength(value) <= maximum &&
    value === value.trim() && !/[\x00-\x1f\x7f]/.test(value));
  return value;
}

function hostname(value) {
  text(value, 253);
  requireValid(isIP(value) !== 0 || (!/^[\d.]+$/.test(value) && value.split('.').every(label =>
    /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/.test(label))));
  return value;
}

function email(value) {
  text(value, 254);
  const parts = value.split('@');
  requireValid(parts.length === 2 && parts[0].length <= 64 &&
    /^[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*$/.test(parts[0]));
  hostname(parts[1]);
  return value;
}

function passwordFromFile(path) {
  text(path, 4096);
  requireValid(isAbsolute(path));
  let descriptor;
  try {
    descriptor = openSync(path, 'r');
    const stat = fstatSync(descriptor);
    requireValid(stat.isFile() && stat.size > 0 && stat.size <= 4098);
    const raw = readFileSync(descriptor);
    requireValid(raw.length <= 4098);
    // Preserve all credential bytes except one optional LF or CRLF terminator.
    const password = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(raw).replace(/\r?\n$/, '');
    requireValid(password.length > 0 && Buffer.byteLength(password) <= 4096 && !/[\x00-\x1f\x7f]/.test(password));
    return password;
  } catch {
    throw new Error('Invalid ExpertAuth SMTP password file');
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}

function resetContent(input, origin) {
  requireValid(input?.type === 'PASSWORD_RESET');
  const toEmail = email(input.user?.email);
  const link = text(input.passwordResetLink, 8192);
  let url;
  try { url = new URL(link); } catch { requireValid(false); }
  requireValid(url.origin === origin && url.pathname === '/auth/reset-password' &&
    !url.username && !url.password && !link.includes('#') && !link.includes('\\') && !/%(?:0a|0d|00)/i.test(link));
  return { toEmail, subject: 'Reset your ExpertAuth password', isHtml: false,
    body: `A password reset was requested for your ExpertAuth account.\n\nOpen this link to choose a new password:\n${link}\n\nIf you did not request this reset, you can ignore this email.\n` };
}

export class PasswordResetDeliveryError extends Error {
  constructor() {
    super('ExpertAuth password reset email delivery failed');
    this.name = 'PasswordResetDeliveryError';
  }
}

export function createPasswordResetEmailDelivery(env, publicOrigin) {
  if (variables.every(name => env[`EXPERTAUTH_SMTP_${name}`] === undefined)) return undefined;
  requireValid(env.NODE_TLS_REJECT_UNAUTHORIZED !== '0' && process.env.NODE_TLS_REJECT_UNAUTHORIZED !== '0');
  const host = hostname(env.EXPERTAUTH_SMTP_HOST);
  const fromEmail = email(env.EXPERTAUTH_SMTP_FROM_EMAIL);
  const portText = text(env.EXPERTAUTH_SMTP_PORT ?? '465', 5);
  requireValid(/^[1-9][0-9]{0,4}$/.test(portText) && Number(portText) <= 65535);
  const username = text(env.EXPERTAUTH_SMTP_USERNAME ?? fromEmail, 254);
  const name = text(env.EXPERTAUTH_SMTP_FROM_NAME ?? 'ExpertAuth', 100);
  requireValid(!/[<>[\],;:"\\]/.test(name));
  let origin;
  try { origin = new URL(text(publicOrigin, 2048)); } catch { requireValid(false); }
  requireValid(['http:', 'https:'].includes(origin.protocol) && !origin.username && !origin.password &&
    origin.pathname === '/' && !publicOrigin.includes('?') && !publicOrigin.includes('#') && !publicOrigin.includes('\\'));
  const service = new SMTPService({
    smtpSettings: { host, port: Number(portText), secure: true, authUsername: username,
      password: passwordFromFile(env.EXPERTAUTH_SMTP_PASSWORD_FILE), from: { email: fromEmail, name } },
    override: original => ({ ...original, getContent: async input => resetContent(input, origin.origin) }),
  });
  const sendEmail = service.sendEmail.bind(service);
  service.sendEmail = async input => {
    try {
      requireValid(process.env.NODE_TLS_REJECT_UNAUTHORIZED !== '0');
      await sendEmail(input);
    } catch (error) {
      let transportCode = 'UNKNOWN';
      try { const code = error?.code; if (transportCodes.has(code)) transportCode = code; } catch { /* Do not inspect provider details. */ }
      try { process.stderr.write(`${JSON.stringify({ code: 'EMAIL_DELIVERY_FAILED', transportCode })}\n`); } catch { /* Preserve the fixed public exception. */ }
      throw new PasswordResetDeliveryError();
    }
  };
  return { service };
}
