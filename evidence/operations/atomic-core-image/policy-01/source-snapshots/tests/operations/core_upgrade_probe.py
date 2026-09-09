"""Actual engine HTTP continuity across a host-owned upgrade and rollback.

All identities/tokens are private. Only one journaled synthetic user is changed;
the exact original identity set must survive. No SQL or adapter session store.
"""
import argparse
import json
import os
import re
from pathlib import Path
import secrets
import urllib.error
import urllib.request

FIXTURE=Path('/private/fixture.json')
URL='http://core-a:3567'
KEY=os.environ['EXPERTAUTH_CORE_API_KEY']

def need(ok,message):
    if not ok: raise ValueError(message)

def call(path,body=None,recipe='session'):
    request=urllib.request.Request(URL+path,data=None if body is None else json.dumps(body).encode(),
        headers={'api-key':KEY,'cdi-version':'5.4','rid':recipe,'content-type':'application/json'})
    try: response=urllib.request.urlopen(request,timeout=12)
    except urllib.error.HTTPError as error: response=error
    with response:
        raw=response.read(1024*1024)
        try: value=json.loads(raw)
        except (ValueError,UnicodeDecodeError): value=None
        return response.status,value

def ok(reply):
    need(reply[0]==200 and isinstance(reply[1],dict) and reply[1].get('status')=='OK','Expected successful engine operation')
    return reply[1]

def users():
    data=ok(call('/users?limit=500',recipe='emailpassword'))
    need(not data.get('nextPaginationToken') and isinstance(data.get('users'),list),'Identity inventory incomplete')
    return data['users']

def save(state):
    temporary=FIXTURE.with_suffix('.tmp')
    temporary.write_text(json.dumps(state))
    os.replace(temporary,FIXTURE)

def token(session,name): return session[name]['token']

def verify(session,user):
    value=ok(call('/recipe/session/verify',{'accessToken':token(session,'accessToken'),'enableAntiCsrf':False,'doAntiCsrfCheck':False,'checkDatabase':True}))
    need(value['session']['userId']==user,'Session subject changed')

def session_body(user):
    return {'userId':user,'enableAntiCsrf':False,'useDynamicSigningKey':True,'userDataInJWT':{'upgradeProbe':True},'userDataInDatabase':{'syntheticUpgrade':True}}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase',choices=['seed','upgraded','rollback','final','cleanup'])
    parser.add_argument('--report-name')
    args=parser.parse_args(); rows=[]
    report_name=args.report_name or args.phase
    need(re.fullmatch('[a-z-]{1,48}',report_name),'Invalid phase report name')
    def passed(identifier): rows.append({'id':identifier,'status':'passed'})
    state=None
    try:
        if args.phase=='seed':
            need(not FIXTURE.exists(),'Preserve existing private fixture')
            baseline=users()
            state={'baseline_ids':sorted(u['id'] for u in baseline),'email':'upgrade-'+secrets.token_hex(16)+'@example.test',
                   'password':'Synthetic-'+secrets.token_hex(24)+'-9a!'}; save(state)
            state['capability_before']=call('/expertauth/password/session')[0]
            need(state['capability_before'] in [200,404],'Original capability surface unavailable');save(state)
            user=ok(call('/recipe/signup',{'email':state['email'],'password':state['password']},'emailpassword'))['user']
            state['id']=user['id']; save(state)
            need(state['id'] not in state['baseline_ids'],'Fixture ownership collision')
            state['session']=ok(call('/recipe/session',session_body(state['id']))); save(state)
            verify(state['session'],state['id']); passed('UPGRADE-SEED-LEGACY-SESSION')
        else:
            state=json.loads(FIXTURE.read_text())
            if args.phase=='cleanup':
                current=users()
                matches=[u for u in current if state['email'] in u.get('emails',[u.get('email')])]
                need(len(matches)<=1 and all(u['id'] not in state['baseline_ids'] and ('id' not in state or state['id']==u['id']) for u in matches),'Fixture cleanup ownership differs')
                for u in matches: ok(call('/user/remove',{'userId':u['id'],'removeAllLinkedAccounts':False},'emailpassword'))
                need(sorted(u['id'] for u in users())==state['baseline_ids'],'Original identity set changed')
                passed('UPGRADE-EXACT-IDENTITY-SET-RESTORED')
            else:
                need(sorted(u['id'] for u in users())==sorted([*state['baseline_ids'],state['id']]),'Original identity membership changed')
                verify(state['session'],state['id']); passed('UPGRADE-'+args.phase.upper()+'-LEGACY-ONLINE')
                refreshed=ok(call('/recipe/session/refresh',{'refreshToken':token(state['session'],'refreshToken'),'enableAntiCsrf':False,'useDynamicSigningKey':True}))
                state['session']=refreshed; save(state); verify(refreshed,state['id']); passed('UPGRADE-'+args.phase.upper()+'-REFRESH')
                signed=ok(call('/recipe/signin',{'email':state['email'],'password':state['password']},'emailpassword'))
                need(signed['user']['id']==state['id'],'Password identity changed')
                passed('UPGRADE-'+args.phase.upper()+'-PASSWORD')
                if 'atomic_session' in state: verify(state['atomic_session'],state['id'])
                capability=call('/expertauth/password/session')
                if args.phase=='rollback':
                    need(capability[0]==state['capability_before'],'Rollback did not restore original API surface')
                    need('atomic_session' in state,'No upgraded session available for rollback proof')
                    passed('UPGRADE-ROLLBACK-NEW-SESSION-AND-ORIGINAL-API')
                else:
                    need(ok(capability)['policy']=='EXPERTAUTH-PASSWORD-SESSION-1','Installed capability unavailable')
                    state['atomic_session']=ok(call('/expertauth/password/session',{**session_body(state['id']),'email':state['email'],'password':state['password']}))
                    save(state); verify(state['atomic_session'],state['id']); passed('UPGRADE-'+args.phase.upper()+'-ATOMIC-SESSION')
        report={'phase':args.phase,'passed':True,'rows':rows,'complete':False,'private_values_disclosed':False,
                'original_identity_count':len(state['baseline_ids'])}
    except Exception as error:
        report={'phase':args.phase,'passed':False,'rows':rows,'complete':False,'error':str(error) if isinstance(error,ValueError) else type(error).__name__}
    target=Path('/out/'+report_name+'.json')
    need(not target.exists(),'Preserve prior phase evidence')
    target.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report))
    return 0 if report['passed'] else 1

if __name__=='__main__': raise SystemExit(main())
