import React, { useState } from 'react';
import { createRoot } from 'react-dom/client';

function App() {
  const [state, setState] = useState({ step: 'idle' });
  const [csrf, setCsrf] = useState('');
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('');
  async function call(path, body, token = csrf) {
    const response = await fetch(path, { method: body ? 'POST' : 'GET', credentials: 'same-origin',
      headers: body ? { 'Content-Type': 'application/json', 'X-CSRF-Token': token } : {}, body: body ? JSON.stringify(body) : undefined });
    const result = await response.json();
    if (!response.ok && result.status !== 'CHALLENGE') throw new Error(result.error || 'Request failed');
    return result;
  }
  async function run(action) {
    setBusy(true); setMessage('');
    try { await action(); } catch (error) { setMessage(error.message); } finally { setBusy(false); }
  }
  async function start() {
    const { csrfToken } = await call('/candidate/csrf'); setCsrf(csrfToken);
    setState(await call('/candidate/start', { tenant: 'alpha' }, csrfToken));
  }
  async function submit(event) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const fields = state.step === 'password' ? { username: form.get('username'), password: form.get('password') } : { otp: form.get('otp') };
    event.currentTarget.reset();
    await run(async () => {
      const next = await call('/candidate/step', { transactionId: state.transactionId, actionToken: state.actionToken, ...fields });
      if (next.csrfToken) setCsrf(next.csrfToken);
      setState(next); setMessage(next.error ? 'Authentication failed. Try again.' : '');
    });
  }
  return <main><p className="eyebrow">ExpertAuth · Keycloak candidate proof</p><h1>Sign in to Alpha</h1>
    <p>Password and authenticator verification use the private identity engine.</p>
    {state.step === 'idle' && <button disabled={busy} onClick={() => run(start)}>Start sign in</button>}
    {state.status === 'CHALLENGE' && <form onSubmit={submit}>
      <h2>{state.step === 'password' ? 'Your account' : 'Authenticator code'}</h2>
      {state.step === 'password' ? <><label>Username<input name="username" autoComplete="username" required /></label>
        <label>Password<input name="password" type="password" autoComplete="current-password" required /></label></> :
        <label>Six-digit code<input name="otp" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6}" required /></label>}
      <button disabled={busy}>{busy ? 'Checking…' : state.step === 'password' ? 'Continue' : 'Verify code'}</button>
    </form>}
    {state.authenticated && <section><h2>Signed in</h2><p>Tenant: {state.identity.tenant}</p>
      <button disabled={busy} onClick={() => run(async () => { const result = await call('/candidate/resource?tenant=alpha'); setMessage(result.message); })}>Open protected resource</button>
      <button disabled={busy} onClick={() => run(async () => { await call('/candidate/refresh', {}); setMessage('Session refreshed by Keycloak.'); })}>Refresh session</button>
      <button disabled={busy} onClick={() => run(async () => { const result = await call('/candidate/logout', {}); setCsrf(result.csrfToken); setState({ step: 'idle' }); setMessage('Signed out.'); })}>Sign out</button>
    </section>}
    <p role="status" aria-live="polite">{message}</p><footer>Candidate integration demonstration. Full SDK, API compatibility and production qualification remain incomplete.</footer>
  </main>;
}
createRoot(document.getElementById('root')).render(<App />);
