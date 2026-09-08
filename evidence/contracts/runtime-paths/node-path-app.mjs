import express from '/app/node_modules/express/index.js';
import supertokens from '/app/node_modules/supertokens-node/lib/build/index.js';
import Passwordless from '/app/node_modules/supertokens-node/recipe/passwordless/index.js';
import Session from '/app/node_modules/supertokens-node/recipe/session/index.js';
import framework from '/app/node_modules/supertokens-node/framework/express/index.js';
const apiKey = process.env.EXPERTAUTH_CORE_API_KEY;
if (!apiKey) throw new Error('Private Core API key required');
supertokens.init({ framework: 'express', telemetry: false,
 supertokens: { connectionURI: 'http://core-a:3567', apiKey },
 appInfo: { appName: 'ExpertAuth four-path probe', apiDomain: 'http://runtime-path.example.test:3002', websiteDomain: 'http://runtime-path.example.test:3002', apiBasePath: '/auth' },
 recipeList: [Passwordless.init({ contactMethod: 'EMAIL', flowType: 'USER_INPUT_CODE',
   emailDelivery: { service: { async sendEmail() { throw new Error('Delivery disabled in path probe'); } } }
 }), Session.init({cookieSecure: false})]
});
const app=express();
app.use((req,res,next)=>req.method==='GET'?next():res.status(405).json({error:'READ_ONLY_FDI_PATH_PROBE'}));
app.get('/health',(_req,res)=>res.json({status:'OK'}));
app.use(framework.middleware());
app.use(framework.errorHandler());
app.use((_req,res)=>res.status(404).json({error:'ROUTE_NOT_FOUND'}));
app.use((_err,_req,res,_next)=>res.status(500).json({error:'SDK_ERROR'}));
app.listen(3002,'0.0.0.0',()=>process.stdout.write('Four-path SDK probe ready\n'));
