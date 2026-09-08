import { chromium } from 'playwright';
import { randomUUID } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import assert from 'node:assert/strict';

const output = process.env.EVIDENCE_DIR || '/repo/evidence/browser/oss-password';
const origin = process.env.TEST_ORIGIN || 'http://node-app.example.test:3000';
await mkdir(output, { recursive: true });
const browser = await chromium.launch({ headless: true });
const context = await browser.newContext({ viewport: { width: 1280, height: 900 } });
const page = await context.newPage();
page.setDefaultTimeout(10000);
const errors = [];
page.on('pageerror', error => errors.push(error.message));
const checks = [];
async function check(id, action) {
  try { await action(); checks.push({id,status:'passed'}); }
  catch (error) { checks.push({id,status:'failed',error:String(error.message).slice(0,800)}); throw error; }
}
const email = `browser-${randomUUID()}@example.test`;
const password = `Browser-${randomUUID()}-9a!`;
try {
  await check('BROWSER-OSS-001', async () => {
    await page.goto(origin+'/auth');
    await page.getByText('Sign Up', { exact: true }).click();
    await page.getByRole('button', { name: 'SIGN UP', exact: true }).waitFor();
    await page.getByPlaceholder('Email address').fill(email);
    await page.getByPlaceholder('Password', { exact: true }).fill(password);
    assert.equal(await page.getByPlaceholder('Email address').inputValue(),email);
    await page.getByRole('button', { name: 'SIGN UP', exact: true }).click();
    await page.getByRole('button',{name:'Check active session'}).waitFor();
    await page.getByRole('button',{name:'Check active session'}).click();
    await page.getByText('The server confirmed this session is active.').waitFor();
    await page.screenshot({path:output+'/desktop-account.png',fullPage:true});
    const cookies = await context.cookies();
    assert.ok(cookies.some(c=>c.name==='sAccessToken' && c.httpOnly && c.sameSite==='Lax'));
  });
  await check('BROWSER-OSS-002', async () => {
    await page.getByRole('button',{name:'Sign out',exact:true}).click();
    await page.getByRole('button',{name:'SIGN IN',exact:true}).waitFor();
    const cookies = await context.cookies();
    assert.equal(cookies.some(c=>['sAccessToken','sRefreshToken'].includes(c.name)),false);
    assert.equal(await page.evaluate(async()=> (await fetch('/api/session/online')).status),401);
  });
  await check('BROWSER-OSS-003', async () => {
    await page.getByPlaceholder('Email address').fill(email);
    await page.getByPlaceholder('Password',{exact:true}).fill(password+'wrong');
    await page.getByRole('button',{name:'SIGN IN',exact:true}).click();
    await page.getByText('Incorrect email and password combination').waitFor();
    assert.equal((await context.cookies()).some(c=>c.name==='sAccessToken'),false);
    await page.getByPlaceholder('Password',{exact:true}).fill(password);
    await page.getByRole('button',{name:'SIGN IN',exact:true}).click();
    await page.getByRole('button',{name:'Check active session'}).waitFor();
  });
  await check('BROWSER-OSS-004', async () => {
    await page.setViewportSize({width:320,height:720});
    await page.getByRole('button',{name:'Sign out',exact:true}).click();
    await page.getByRole('button',{name:'SIGN IN',exact:true}).waitFor();
    assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth <= innerWidth),true);
    await page.screenshot({path:output+'/mobile-login.png',fullPage:true});
    assert.deepEqual(errors,[]);
  });
} catch {
  await page.screenshot({path:output+'/failure.png',fullPage:true});
  await writeFile(output+'/failure-dom.txt',await page.locator('body').innerText());
} finally {
  await browser.close();
  await writeFile(output+'/results.json',JSON.stringify({checks,errors,pass:checks.filter(x=>x.status==='passed').length,fail:checks.filter(x=>x.status==='failed').length,skipped:0,scope:'Actual Chromium password and cookie-session flow; not native platforms or full React profile'},null,2)+'\n');
}
console.log(JSON.stringify(checks));
process.exitCode = checks.length!==4 || checks.some(c=>c.status!=='passed') ? 1 : 0;
