import React, { useState } from 'react';
import { createRoot } from 'react-dom/client';
import SuperTokens, { SuperTokensWrapper } from 'supertokens-auth-react';
import EmailPassword from 'supertokens-auth-react/recipe/emailpassword';
import Session, { SessionAuth, useSessionContext, signOut } from 'supertokens-auth-react/recipe/session';
import { EmailPasswordPreBuiltUI } from 'supertokens-auth-react/recipe/emailpassword/prebuiltui';
import { getRoutingComponent } from 'supertokens-auth-react/ui';

SuperTokens.init({
  appInfo: { appName: 'ExpertAuth', apiDomain: location.origin, websiteDomain: location.origin, apiBasePath: '/auth', websiteBasePath: '/auth' },
  style: '[data-supertokens~="container"] { width: 100%; max-width: 420px; } [data-supertokens~="row"] { width: calc(100% - 40px); }',
  recipeList: [EmailPassword.init(), Session.init()],
});

function Account() {
  const session = useSessionContext();
  const [message, setMessage] = useState('');
  if (session.loading) return <p role="status">Loading session…</p>;
  return <section>
    <h2>Your session</h2>
    <dl><dt>User</dt><dd>{session.userId}</dd><dt>Tenant</dt><dd>{session.accessTokenPayload.tId || 'public'}</dd></dl>
    <button onClick={async () => {
      try {
        const response = await fetch('/api/session/online', { signal: AbortSignal.timeout(5000) });
        const details = await response.json();
        const active = response.ok && details.userId === session.userId &&
          details.tenantId === (session.accessTokenPayload.tId || 'public') && details.verification === 'online-session';
        setMessage(active ? 'The server confirmed this session is active.' : 'The server rejected this session.');
      } catch { setMessage('The authentication service is unavailable.'); }
    }}>Check active session</button>
    <button onClick={async () => { await signOut(); location.assign('/auth'); }}>Sign out</button>
    <p role="status">{message}</p>
  </section>;
}

function App() {
  const authPage = location.pathname.startsWith('/auth');
  return <SuperTokensWrapper><main>
    <header><a href="/">ExpertAuth</a><span>Foundation preview</span></header>
    <h1>{authPage ? 'Welcome to ExpertAuth' : 'Account workspace'}</h1>
    <p className="intro">Self-hosted account access. This preview exercises password login and sessions.</p>
    {authPage ? getRoutingComponent([EmailPasswordPreBuiltUI]) : <SessionAuth><Account /></SessionAuth>}
    <footer>Local qualification build · Full parity and production approval remain pending.</footer>
  </main></SuperTokensWrapper>;
}
createRoot(document.getElementById('root')).render(<App />);
