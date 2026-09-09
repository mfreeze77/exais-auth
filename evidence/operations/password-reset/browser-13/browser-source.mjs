// Real React/Chromium reset flow. The caller owns the browser, synthetic identity,
// trusted CA setup, real mailbox lookup, and durable evidence/identity cleanup.
// This helper records no screenshots, traces, DOM, credentials, tokens, or mail.
export async function runPasswordResetBrowser({ browser, origin, email, oldPassword, newPassword, findResetLink, onProgress = async () => {}, captureSuccess = async () => {}, captureFailure = async () => {} }) {
  const rows = [];
  let context, page, identityId, resetLink, requestedAt, pageErrors = 0, failed = false;
  function require(condition) {
    if (!condition) throw new Error('Password reset browser assertion failed');
  }
  async function check(id, action) {
    const started = performance.now();
    await onProgress({stage:id,event:'started'});
    let deadline;
    try {
      const details = await Promise.race([action(), new Promise((_,reject)=>{
        deadline=setTimeout(()=>reject(new Error('Browser stage deadline exceeded')),25000);
      })]);
      rows.push({ id, status: 'passed', elapsed_ms: Math.round(performance.now() - started), details });
      await onProgress({stage:id,event:'passed'});
    } catch {
      rows.push({ id, status: 'failed', elapsed_ms: Math.round(performance.now() - started),
        error: 'Required password reset browser behavior was not established' });
      await onProgress({stage:id,event:'failed'});
      throw new Error('Password reset browser assertion failed');
    } finally {clearTimeout(deadline);}
  }
  async function submit(button, path) {
    const [response] = await Promise.all([
      page.waitForResponse(value => {
        const url = new URL(value.url());
        return url.origin === origin && url.pathname === path && value.request().method() === 'POST';
      }),
      page.getByRole('button', { name: button, exact: true }).click(),
    ]);
    require(response.status() === 200);
    return response.json();
  }
  async function signin(password) {
    await page.goto(`${origin}/auth`);
    await page.getByRole('button', { name: 'SIGN IN', exact: true }).waitFor();
    await page.getByPlaceholder('Email address', { exact: true }).fill(email);
    await page.getByPlaceholder('Password', { exact: true }).fill(password);
    return submit('SIGN IN', '/auth/signin');
  }
  async function onlineSession() {
    await page.getByRole('button', { name: 'Check active session', exact: true }).waitFor();
    const [response] = await Promise.all([
      page.waitForResponse(value => {
        const url = new URL(value.url());
        return url.origin === origin && url.pathname === '/api/session/online' && value.request().method() === 'GET';
      }),
      page.getByRole('button', { name: 'Check active session', exact: true }).click(),
    ]);
    require(response.status() === 200);
    await onProgress({stage:'online-session',event:'response-received'});
    const result = await response.json();
    await onProgress({stage:'online-session',event:'body-parsed'});
    require(result.userId === identityId && result.tenantId === 'public' && result.verification === 'online-session');
    await page.getByText('The server confirmed this session is active.', { exact: true }).waitFor();
    // Query the owned context, including the refresh cookie's /auth/session/refresh
    // path. cookies(origin + '/') incorrectly filters that cookie out.
    const cookies = await context.cookies();
    require(['sAccessToken', 'sRefreshToken'].every(name => cookies.some(cookie => cookie.name === name && cookie.httpOnly &&
      cookie.sameSite === 'Lax' && (!origin.startsWith('https:') || cookie.secure))));
  }
  async function signedOut() {
    await page.getByRole('button', { name: 'SIGN IN', exact: true }).waitFor();
    await onProgress({stage:'signed-out',event:'signin-form-visible'});
    require(!(await context.cookies()).some(cookie => ['sAccessToken', 'sRefreshToken'].includes(cookie.name)));
    await onProgress({stage:'signed-out',event:'cookies-cleared'});
    let timeout;
    const status = await Promise.race([
      page.evaluate(async () => (await fetch('/api/session/online', { redirect: 'error', signal: AbortSignal.timeout(5000) })).status),
      new Promise((_, reject) => {timeout=setTimeout(()=>reject(new Error('Browser unauthenticated fetch did not settle')),10000);}),
    ]).finally(()=>clearTimeout(timeout));
    require(status === 401);
    await onProgress({stage:'signed-out',event:'online-denied'});
  }
  async function logout() {
    // The application navigates after signout. Assert its HTTP result and actual
    // signed-out state without asking DevTools for a body after navigation.
    const [response] = await Promise.all([
      page.waitForResponse(value => new URL(value.url()).origin === origin &&
        new URL(value.url()).pathname === '/auth/signout' && value.request().method() === 'POST'),
      page.getByRole('button', {name:'Sign out',exact:true}).click(),
    ]);
    require(response.status() === 200);
    await signedOut();
  }
  async function changePassword(password) {
    await page.getByPlaceholder('New password', { exact: true }).fill(password);
    await page.getByPlaceholder('Confirm your password', { exact: true }).fill(password);
    return submit('CHANGE PASSWORD', '/auth/user/password/reset');
  }
  try {
    const parsedOrigin = new URL(origin);
    require(['http:', 'https:'].includes(parsedOrigin.protocol) && parsedOrigin.origin === origin &&
      typeof browser?.newContext === 'function' && typeof findResetLink === 'function' &&
      typeof email === 'string' && /^[^\s@]+@example\.test$/.test(email) &&
      typeof oldPassword === 'string' && typeof newPassword === 'string' && oldPassword !== newPassword &&
      oldPassword.length >= 8 && newPassword.length >= 8);
    context = await browser.newContext({ viewport: { width: 1280, height: 900 }, ignoreHTTPSErrors: false });
    page = await context.newPage();
    page.setDefaultTimeout(15000);
    page.setDefaultNavigationTimeout(20000);
    page.on('pageerror', () => { pageErrors++; });
    page.on('response', response => {
      const url = new URL(response.url());
      if(url.origin===origin && url.pathname.startsWith('/api/') || url.origin===origin && url.pathname.startsWith('/auth/')) {
        void onProgress({event:'response',path:url.pathname,status:response.status()}).catch(()=>{});
      }
    });

    await check('BROWSER-PWDRESET-001-INITIAL-PASSWORD', async () => {
      const result = await signin(oldPassword);
      await onProgress({stage:'initial-password',event:'signin-returned'});
      require(result.status === 'OK' && typeof result.user?.id === 'string' && result.user.id.length > 0);
      identityId = result.user.id;
      await onlineSession();
      await onProgress({stage:'initial-password',event:'online-confirmed'});
      await logout();
      return { signin_http_status: 200, online_session_http_status: 200, logout_http_status: 200, after_logout_http_status: 401 };
    });
    await check('BROWSER-PWDRESET-002-REQUEST-EMAIL', async () => {
      await page.getByText('Forgot password?', { exact: true }).click();
      await page.getByText('Reset your password', { exact: true }).waitFor();
      await page.getByPlaceholder('Email address', { exact: true }).fill(email);
      requestedAt = new Date().toISOString();
      require((await submit('Email me', '/auth/user/password/reset/token')).status === 'OK');
      await page.getByText(/A password reset email has been sent to/).waitFor();
      require(!(await context.cookies()).some(cookie => ['sAccessToken', 'sRefreshToken'].includes(cookie.name)));
      return { generate_reset_http_status: 200, generic_delivery_confirmation_visible: true, authenticated_session_created: false };
    });
    await check('BROWSER-PWDRESET-003-REAL-MAIL-LINK', async () => {
      // The caller must query its real SMTP capture service, matching this owned
      // recipient and request time. A stub callback is not delivery evidence.
      resetLink = await findResetLink({ email, requestedAt });
      require(typeof resetLink === 'string' && resetLink.length <= 8192 && !/[\x00-\x20\x7f\\#]/.test(resetLink));
      const url = new URL(resetLink);
      require(url.origin === origin && url.pathname === '/auth/reset-password' && !url.username && !url.password &&
        url.searchParams.getAll('token').length === 1 && Boolean(url.searchParams.get('token')));
      return { mailbox_callback_completed: true, recipient_and_mail_transport_verification_owned_by_runner: true,
        link_matches_application_origin_and_reset_path: true };
    });
    await check('BROWSER-PWDRESET-004-CHANGE-PASSWORD', async () => {
      await page.goto(resetLink);
      await page.getByText('Change your password', { exact: true }).waitFor();
      require((await changePassword(newPassword)).status === 'OK');
      await page.getByText('Your password has been updated successfully', { exact: true }).waitFor();
      await captureSuccess(page);
      require(!(await context.cookies()).some(cookie => ['sAccessToken', 'sRefreshToken'].includes(cookie.name)));
      return { password_reset_http_status: 200, success_visible: true, authenticated_session_created: false };
    });
    await check('BROWSER-PWDRESET-005-CONSUMED-LINK-REJECTED', async () => {
      await page.goto(resetLink);
      await page.getByText('Change your password', { exact: true }).waitFor();
      require((await changePassword(oldPassword)).status === 'RESET_PASSWORD_INVALID_TOKEN_ERROR');
      await page.getByText('Invalid password reset token', { exact: true }).waitFor();
      require(!(await context.cookies()).some(cookie => ['sAccessToken', 'sRefreshToken'].includes(cookie.name)));
      return { password_reset_http_status: 200, consumed_token_error_visible: true, authenticated_session_created: false };
    });
    await check('BROWSER-PWDRESET-006-OLD-PASSWORD-REJECTED', async () => {
      require((await signin(oldPassword)).status === 'WRONG_CREDENTIALS_ERROR');
      await page.getByText('Incorrect email and password combination', { exact: true }).waitFor();
      await signedOut();
      return { signin_http_status: 200, wrong_credentials_visible: true, online_session_http_status: 401 };
    });
    await check('BROWSER-PWDRESET-007-NEW-PASSWORD-SESSION', async () => {
      const result = await signin(newPassword);
      require(result.status === 'OK' && result.user?.id === identityId);
      await onlineSession();
      return { signin_http_status: 200, online_session_http_status: 200, original_identity_preserved: true,
        http_only_cookie_session_verified: true };
    });
    await check('BROWSER-PWDRESET-008-LOGOUT', async () => {
      await logout();
      return { logout_http_status: 200, online_session_after_logout_http_status: 401, session_cookies_removed: true };
    });
    await check('BROWSER-PWDRESET-009-PAGE-ERRORS', async () => {
      require(pageErrors === 0);
      return { page_error_count: 0 };
    });
  } catch {
    failed = true;
    if(page) {try {await captureFailure(page);} catch { /* Private diagnostics cannot prevent cleanup. */ }}
    if (!rows.some(row => row.status === 'failed')) rows.push({ id: 'BROWSER-PWDRESET-INITIALIZATION', status: 'failed',
      error: 'Browser input validation or context initialization failed' });
  } finally {
    if (context) {
      let deadline;
      try { await Promise.race([context.close(), new Promise((_,reject)=>{deadline=setTimeout(()=>reject(new Error('Context cleanup deadline exceeded')),5000);})]); }
      catch {
        failed = true;
        rows.push({ id: 'BROWSER-PWDRESET-CONTEXT-CLEANUP', status: 'failed', error: 'Owned browser context did not close' });
      } finally {clearTimeout(deadline);}
    }
  }
  if (failed) {
    const error = new Error('Required password reset browser behavior was not established');
    error.rows = rows;
    throw error;
  }
  return rows;
}
