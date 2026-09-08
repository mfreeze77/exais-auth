# Evidence-preserving test corrections

## Node session residual window, 2026-09-08

`evidence/runs/node-live-01` retained a 9/10 result. The residual-window assertion reused
the access token returned immediately by refresh and ignored the new access token
returned by the following protected request. SuperTokens Node 24.0.3
`lib/build/recipe/session/sessionFunctions.js` only takes the offline path when
`parentRefreshTokenHash1` is absent. A token awaiting that handshake still calls Core.
The first correction consumed returned headers but still failed: CDI 5.6 retains the
parent marker and does not return a settled token from verification. Evidence is
`evidence/runs/node-live-02`. Thus the unmodified SDK's default verifier cannot be
advertised as wholly offline for this token lifecycle. The example now labels that
route `sdk-hybrid` and implements a separate, explicit offline profile with maintained
`jose` signature, issuer, audience, algorithm, expiration and tenant checks. Issuer and
audience are set by a server-controlled SDK override; Core remains the sole signer.
The original security assertions remain: online access and refresh denied after
logout, offline token still accepted before expiration. Independent review is pending.

## Keycloak session and membership characterization

The initial probe treated equal realm `sid` values as a tenant-session failure and
tested bare clients without organization scopes. Review found these were insufficient
to reject a supported organization/client mapping. Prior output is retained under
`evidence/foundation/keycloak/attempts`. Current bare-client cases are observations;
real organization membership and scope tests are separate. No engine has passed M1.
# Browser and release evidence corrections

The initial Node UI build used a removed `EmailPasswordPreBuiltUI.SignInAndUp`
component, producing a blank page. The app now uses the exported SDK routing
component. Real browser checks then caught a viewport-width card overflowing its
padded320px parent; a supported style override confines the card to its parent.
Both implementation failures and the final4 passing browser checks are retained.
Test-only fixes selected the actual Sign Up link and waited for the new form before
typing, preventing input into a form being replaced. No failed behavior assertion
was removed. Screenshots were visually inspected.

Source evidence now excludes ignored local runtime secrets, `.env` files and
generated archive output; `.env.example` remains part of source verification.
An adversarial evidence test checks those boundaries. `.gitattributes` disables
newline conversion so immutable baseline and evidence hashes survive Git checkout.
