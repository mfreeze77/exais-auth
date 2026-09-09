"""Pinned-source transformations for dedicated guarded Core session operations.

Original public APIs remain unchanged. Derived APIs retain their Apache header;
all original authorization, token parsing, signing and transaction code remains.
"""
REFRESH='src/main/java/io/supertokens/webserver/api/session/RefreshSessionAPI.java'
VERIFY='src/main/java/io/supertokens/webserver/api/session/VerifySessionAPI.java'
NOTICE='\n/* Modified by ExpertAuth contributors (2026): dedicated guarded route and explicit expected-policy argument. Original authorization, token algorithms and licensing checks retained. */\n'

def replace_once(text,old,new):
    if text.count(old)!=1:raise ValueError('Pinned session-policy source anchor differs')
    return text.replace(old,new,1)

def overload(text,name,body_anchor,end_anchor,last_parameter,forward_args,change_body):
    body_start=text.index(body_anchor)
    start=text.rfind('    public static SessionInformationHolder '+name+'(',0,body_start)
    if start<0:raise ValueError('Pinned method header missing')
    end=text.index(end_anchor,body_start)
    header=text[start:body_start];body=text[body_start:end]
    modified=replace_once(header,' '+name+'(',' '+name+'WithPolicy(')
    modified=replace_once(modified,last_parameter,last_parameter[:-1]+', String expectedSessionPolicy)')
    wrapper=header+'        return '+name+'WithPolicy('+forward_args+', null);\n    }\n\n'
    return text[:start]+wrapper+modified+change_body(body)+text[end:]

def patch_session(text):
    text=overload(text,'getSession','        AccessTokenInfo accessToken = AccessToken.getInfoFromAccessToken(appIdentifier, main, token,',
        '    @TestOnly','boolean checkDatabase, SemVer cdiVersion)',
        'appIdentifier, main, token, antiCsrfToken, enableAntiCsrf, doAntiCsrfCheck, checkDatabase, cdiVersion',
        lambda body:replace_once(body,'        TenantIdentifier tenantIdentifier = accessToken.tenantIdentifier;',
            '        TenantIdentifier tenantIdentifier = accessToken.tenantIdentifier;\n'
            '        if (expectedSessionPolicy != null) io.expertauth.core.SessionPolicy.requireConfig(tenantIdentifier, main, expectedSessionPolicy);'))
    text=overload(text,'refreshSession','        RefreshToken.RefreshTokenInfo refreshTokenInfo = RefreshToken.getInfoFromRefreshToken(appIdentifier, main,',
        '    // True when the presented refresh token','@Nullable Long accessTokenValidity)',
        'appIdentifier, main, refreshToken, antiCsrfToken, enableAntiCsrf, accessTokenVersion, shouldUseStaticKey, cdiVersion, accessTokenValidity',
        lambda body:replace_once(body,'                shouldUseStaticKey, cdiVersion, accessTokenValidity);',
            '                shouldUseStaticKey, cdiVersion, accessTokenValidity, expectedSessionPolicy);'))
    start=text.index('    private static SessionInformationHolder refreshSessionHelper(')
    before,body=text[:start],text[start:]
    body=replace_once(body,'            @Nullable Long accessTokenValidity)\n            throws StorageTransactionLogicException, UnauthorisedException, StorageQueryException,',
        '            @Nullable Long accessTokenValidity, String expectedSessionPolicy)\n            throws StorageTransactionLogicException, UnauthorisedException, StorageQueryException,')
    body=replace_once(body,'                CoreConfig config = Config.getConfig(tenantIdentifier, main);',
        '                CoreConfig config = io.expertauth.core.SessionPolicy.requireConfig(tenantIdentifier, main, expectedSessionPolicy);')
    body=replace_once(body,'                            accessTokenValidity);\n                }\n                return result;',
        '                            accessTokenValidity, expectedSessionPolicy);\n                }\n                return result;')
    body=replace_once(body,'                                accessTokenValidity);\n                    }\n\n                    throw new TokenTheftDetectedException',
        '                                accessTokenValidity, expectedSessionPolicy);\n                    }\n\n                    throw new TokenTheftDetectedException')
    # The candidate requires the tested SQL transaction path. Legacy callers keep
    # their original storage behavior because their expected policy is null.
    body=replace_once(body,'        if (StorageUtils.getSessionStorage(storage).getType() == STORAGE_TYPE.SQL) {',
        '        if (expectedSessionPolicy != null && StorageUtils.getSessionStorage(storage).getType() != STORAGE_TYPE.SQL) throw new io.expertauth.core.SessionPolicy.Rejected();\n'
        '        if (StorageUtils.getSessionStorage(storage).getType() == STORAGE_TYPE.SQL) {')
    return before+body

def guarded_api(text,refresh):
    name='RefreshSessionAPI' if refresh else 'VerifySessionAPI'
    text=replace_once(text,'package io.supertokens.webserver.api.session;','package io.expertauth.core;')
    text=text.replace(name,'Guarded'+name)
    operation='refresh' if refresh else 'verify'
    text=replace_once(text,'return "/recipe/session/'+operation+'";','return "/expertauth/session/'+operation+'";')
    header='    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException, ServletException {\n'
    text=replace_once(text,header,header+
        '        if (!getVersionFromRequest(req).equals(SemVer.v5_6)) { policyUnavailable(resp); return; }\n')
    if refresh:
        text=replace_once(text,'Session.refreshSession(appIdentifier, main,','Session.refreshSessionWithPolicy(appIdentifier, main,')
        text=replace_once(text,'                    accessTokenValidity);','                    accessTokenValidity, SessionPolicy.ID);')
    else:
        text=replace_once(text,'Session.getSession(appIdentifier,','Session.getSessionWithPolicy(appIdentifier,')
        text=replace_once(text,'                    doAntiCsrfCheck, checkDatabase, super.getVersionFromRequest(req));',
            '                    doAntiCsrfCheck, checkDatabase, super.getVersionFromRequest(req), SessionPolicy.ID);')
    catch='        } catch (StorageQueryException | StorageTransactionLogicException | TenantOrAppNotFoundException |'
    text=replace_once(text,catch,'        } catch (SessionPolicy.Rejected e) {\n            policyUnavailable(resp);\n'+catch)
    closing=text.rfind('\n}')
    if closing<0:raise ValueError('Pinned API class boundary missing')
    text=text[:closing]+'''\n    private void policyUnavailable(HttpServletResponse response) throws IOException {
        JsonObject result = new JsonObject(); result.addProperty("status", "SESSION_POLICY_MISMATCH");
        response.setHeader("Cache-Control", "no-store"); sendJsonResponse(503, result, response);
    }
'''+text[closing:]
    return text+NOTICE
