# API operation accounting — 205 entries

This is an operation-name/method inventory, **not a completed OpenAPI specification**. Names are normalized from the reference navigation inspected on September 8, 2026 [S02, S03]. The original research report also counted 49 FDI and 156 CDI entries [DR]. Numbered IDs below are ours, not upstream operation IDs. Deprecated routes remain in scope for the frozen compatibility profile.

Every `path`, exact schema, header, cookie, error variant and protocol-version field is intentionally unset in the JSON registry until M0 captures the matching published specification and M1 verifies behavior. Missing contract fields are release blockers, not permission to guess. A cached raw CDI specification identified version 5.2.0; it must not be confused with current documentation or whichever version the chosen core actually supports [S21].

FDI is the application/frontend-facing boundary. CDI is a private backend/Core boundary; the inventory does not authorize exposing CDI to browsers. Diagnostic operations must obey least privilege. The GET-labeled WebAuthn recovery entry particularly requires schema and side-effect verification: do not invent an implementation from its label.

Vendor license, enterprise-entitlement and vendor telemetry operations require explicit non-equivalence declarations in our platform. All underlying business functionality stays required. We do not manufacture vendor license status, patch restricted code, or call those differences exact vendor wire parity. SDKs relying on those workflows must be adapted transparently. Deprecated business operations are not covered by this exception.

| Inventory ID | Recipe | Method | Documented operation | Classification |
|---|---|---|---|---|
| FDI-001 | App | GET | Test authentication | required-operation |
| FDI-002 | EmailPassword | GET | Check email exists | required-operation |
| FDI-003 | EmailPassword | GET | Check email exists (deprecated) | required-operation |
| FDI-004 | EmailPassword | POST | Generate password reset token | required-operation |
| FDI-005 | EmailPassword | POST | Reset user password | required-operation |
| FDI-006 | EmailPassword | POST | Sign in with email | required-operation |
| FDI-007 | EmailPassword | POST | Sign up with email | required-operation |
| FDI-008 | EmailVerification | GET | Check verification status | required-operation |
| FDI-009 | EmailVerification | POST | Send verification | required-operation |
| FDI-010 | EmailVerification | POST | Verify email | required-operation |
| FDI-011 | JWT | GET | Get JWT keys | required-operation |
| FDI-012 | MultiFactorAuth | PUT | Get MFA factors information | required-operation |
| FDI-013 | Multitenancy | GET | Get enabled login methods | required-operation |
| FDI-014 | OAuth2Provider | GET | Continue OAuth login | required-operation |
| FDI-015 | OAuth2Provider | POST | End OAuth session | required-operation |
| FDI-016 | OAuth2Provider | GET | End-session redirect | required-operation |
| FDI-017 | OAuth2Provider | POST | Exchange OAuth grant | required-operation |
| FDI-018 | OAuth2Provider | GET | Get OAuth login info | required-operation |
| FDI-019 | OAuth2Provider | GET | Get OAuth user info | required-operation |
| FDI-020 | OAuth2Provider | POST | Introspect OAuth token | required-operation |
| FDI-021 | OAuth2Provider | POST | Logout OAuth user | required-operation |
| FDI-022 | OAuth2Provider | POST | Revoke OAuth token | required-operation |
| FDI-023 | OAuth2Provider | GET | Start OAuth login | required-operation |
| FDI-024 | OpenId | GET | Get OpenID config | required-operation |
| FDI-025 | Passwordless | GET | Check email exists | required-operation |
| FDI-026 | Passwordless | GET | Check email exists (deprecated) | required-operation |
| FDI-027 | Passwordless | GET | Check phone exists | required-operation |
| FDI-028 | Passwordless | GET | Check phone exists (deprecated) | required-operation |
| FDI-029 | Passwordless | POST | Complete passwordless sign-in/up | required-operation |
| FDI-030 | Passwordless | POST | Resend code | required-operation |
| FDI-031 | Passwordless | POST | Start passwordless sign-in/up | required-operation |
| FDI-032 | Session | POST | Refresh user session | required-operation |
| FDI-033 | Session | POST | Sign out | required-operation |
| FDI-034 | ThirdParty | GET | Get third-party auth URL | required-operation |
| FDI-035 | ThirdParty | POST | Handle Apple sign-in | required-operation |
| FDI-036 | ThirdParty | POST | Third-party sign-in/up | required-operation |
| FDI-037 | TOTP | POST | Create device | required-operation |
| FDI-038 | TOTP | GET | List devices | required-operation |
| FDI-039 | TOTP | POST | Remove device | required-operation |
| FDI-040 | TOTP | POST | Verify code | required-operation |
| FDI-041 | TOTP | POST | Verify device | required-operation |
| FDI-042 | WebAuthn | GET | Check email exists | required-operation |
| FDI-043 | WebAuthn | POST | Generate recovery token | required-operation |
| FDI-044 | WebAuthn | POST | Get registration options | required-operation |
| FDI-045 | WebAuthn | POST | Get sign-in options | required-operation |
| FDI-046 | WebAuthn | POST | Recover account | required-operation |
| FDI-047 | WebAuthn | POST | Register credential | required-operation |
| FDI-048 | WebAuthn | POST | Sign in | required-operation |
| FDI-049 | WebAuthn | POST | Sign up | required-operation |
| CDI-001 | Core | DELETE | Hello | required-operation |
| CDI-002 | Core | DELETE | Delete license key | vendor-control-requires-explicit-non-equivalence |
| CDI-003 | Core | POST | Delete user | required-operation |
| CDI-004 | Core | GET | Get active-user count | required-operation |
| CDI-005 | Core | GET | Get API version | required-operation |
| CDI-006 | Core | GET | Get config-file path | required-operation |
| CDI-007 | Core | GET | Get enterprise features | vendor-control-requires-explicit-non-equivalence |
| CDI-008 | Core | GET | Hello | required-operation |
| CDI-009 | Core | GET | Root hello | required-operation |
| CDI-010 | Core | GET | Get license key | vendor-control-requires-explicit-non-equivalence |
| CDI-011 | Core | GET | Get request stats | required-operation |
| CDI-012 | Core | GET | Get search tags | required-operation |
| CDI-013 | Core | GET | Get telemetry ID | vendor-control-requires-explicit-non-equivalence |
| CDI-014 | Core | GET | Get user ID | required-operation |
| CDI-015 | Core | GET | Get users | required-operation |
| CDI-016 | Core | GET | Get users by account info | required-operation |
| CDI-017 | Core | GET | Get users count | required-operation |
| CDI-018 | Core | GET | Get well-known JWT keys | required-operation |
| CDI-019 | Core | POST | Hello | required-operation |
| CDI-020 | Core | PUT | Hello | required-operation |
| CDI-021 | Core | PUT | Set license key | vendor-control-requires-explicit-non-equivalence |
| CDI-022 | Account Linking | GET | Check account-linking possibility | required-operation |
| CDI-023 | Account Linking | GET | Check primary-user-creation possibility | required-operation |
| CDI-024 | Account Linking | POST | Create primary account | required-operation |
| CDI-025 | Account Linking | POST | Link accounts | required-operation |
| CDI-026 | Account Linking | POST | Unlink accounts | required-operation |
| CDI-027 | Bulk Import | POST | Add users | required-operation |
| CDI-028 | Bulk Import | GET | Count staged users | required-operation |
| CDI-029 | Bulk Import | POST | Delete staged users | required-operation |
| CDI-030 | Bulk Import | POST | Import one user directly | required-operation |
| CDI-031 | Bulk Import | GET | List staged users | required-operation |
| CDI-032 | Dashboard | POST | Create dashboard user | required-operation |
| CDI-033 | Dashboard | DELETE | Delete dashboard user | required-operation |
| CDI-034 | Dashboard | GET | List dashboard users | required-operation |
| CDI-035 | Dashboard | GET | List dashboard-user sessions | required-operation |
| CDI-036 | Dashboard | GET | Retrieve Core config | required-operation |
| CDI-037 | Dashboard | DELETE | Revoke dashboard session | required-operation |
| CDI-038 | Dashboard | POST | Dashboard sign-in | required-operation |
| CDI-039 | Dashboard | PUT | Update dashboard user | required-operation |
| CDI-040 | Dashboard | POST | Verify dashboard session | required-operation |
| CDI-041 | EmailPassword | POST | Consume reset token | required-operation |
| CDI-042 | EmailPassword | POST | Generate reset token | required-operation |
| CDI-043 | EmailPassword | GET | Get user (deprecated) | required-operation |
| CDI-044 | EmailPassword | POST | Import with password hash | required-operation |
| CDI-045 | EmailPassword | POST | Reset password (deprecated) | required-operation |
| CDI-046 | EmailPassword | POST | Sign in | required-operation |
| CDI-047 | EmailPassword | POST | Sign up | required-operation |
| CDI-048 | EmailPassword | PUT | Update user info | required-operation |
| CDI-049 | EmailVerification | GET | Check status | required-operation |
| CDI-050 | EmailVerification | POST | Generate token | required-operation |
| CDI-051 | EmailVerification | POST | Remove tokens | required-operation |
| CDI-052 | EmailVerification | POST | Unverify | required-operation |
| CDI-053 | EmailVerification | POST | Verify | required-operation |
| CDI-054 | JWT | POST | Create signed JWT | required-operation |
| CDI-055 | JWT | GET | Get JWT keys (deprecated) | required-operation |
| CDI-056 | Multitenancy | POST | Add user-to-tenant association | required-operation |
| CDI-057 | Multitenancy | POST | Delete tenant | required-operation |
| CDI-058 | Multitenancy | POST | Delete app | required-operation |
| CDI-059 | Multitenancy | POST | Delete third-party provider config | required-operation |
| CDI-060 | Multitenancy | GET | Get tenant config | required-operation |
| CDI-061 | Multitenancy | GET | Get tenant config (deprecated) | required-operation |
| CDI-062 | Multitenancy | GET | List apps | required-operation |
| CDI-063 | Multitenancy | GET | List apps (deprecated) | required-operation |
| CDI-064 | Multitenancy | GET | List connection-URI domains | required-operation |
| CDI-065 | Multitenancy | GET | List connection-URI domains (deprecated) | required-operation |
| CDI-066 | Multitenancy | GET | List tenants | required-operation |
| CDI-067 | Multitenancy | GET | List tenants (deprecated) | required-operation |
| CDI-068 | Multitenancy | POST | Remove connection domain | required-operation |
| CDI-069 | Multitenancy | POST | Remove user-to-tenant association | required-operation |
| CDI-070 | Multitenancy | PUT | Upsert app | required-operation |
| CDI-071 | Multitenancy | PUT | Upsert app (deprecated) | required-operation |
| CDI-072 | Multitenancy | PUT | Upsert connection-URI domain | required-operation |
| CDI-073 | Multitenancy | PUT | Upsert connection-URI domain (deprecated) | required-operation |
| CDI-074 | Multitenancy | PUT | Upsert tenant | required-operation |
| CDI-075 | Multitenancy | PUT | Upsert tenant (deprecated) | required-operation |
| CDI-076 | Multitenancy | PUT | Upsert third-party provider configuration | required-operation |
| CDI-077 | OAuth2Provider | PUT | Accept consent | required-operation |
| CDI-078 | OAuth2Provider | PUT | Accept login | required-operation |
| CDI-079 | OAuth2Provider | PUT | Accept logout | required-operation |
| CDI-080 | OAuth2Provider | POST | Create client | required-operation |
| CDI-081 | OAuth2Provider | GET | Get auth | required-operation |
| CDI-082 | OAuth2Provider | GET | Get client | required-operation |
| CDI-083 | OAuth2Provider | GET | Get consent request | required-operation |
| CDI-084 | OAuth2Provider | GET | Get login request | required-operation |
| CDI-085 | OAuth2Provider | GET | Get sessions/logout state | required-operation |
| CDI-086 | OAuth2Provider | POST | Get token | required-operation |
| CDI-087 | OAuth2Provider | POST | Introspect token | required-operation |
| CDI-088 | OAuth2Provider | GET | List clients | required-operation |
| CDI-089 | OAuth2Provider | PUT | Reject consent | required-operation |
| CDI-090 | OAuth2Provider | PUT | Reject login | required-operation |
| CDI-091 | OAuth2Provider | PUT | Reject logout | required-operation |
| CDI-092 | OAuth2Provider | POST | Remove client | required-operation |
| CDI-093 | OAuth2Provider | POST | Revoke session | required-operation |
| CDI-094 | OAuth2Provider | POST | Revoke token | required-operation |
| CDI-095 | OAuth2Provider | POST | Revoke all client tokens | required-operation |
| CDI-096 | OAuth2Provider | PUT | Update client | required-operation |
| CDI-097 | Passwordless | POST | Check code | required-operation |
| CDI-098 | Passwordless | POST | Consume code | required-operation |
| CDI-099 | Passwordless | GET | Get user (deprecated) | required-operation |
| CDI-100 | Passwordless | GET | List codes | required-operation |
| CDI-101 | Passwordless | POST | Revoke all user codes | required-operation |
| CDI-102 | Passwordless | POST | Revoke one code | required-operation |
| CDI-103 | Passwordless | POST | Start sign-in | required-operation |
| CDI-104 | Passwordless | PUT | Update user | required-operation |
| CDI-105 | Session | POST | Create session | required-operation |
| CDI-106 | Session | POST | Delete session | required-operation |
| CDI-107 | Session | GET | Get JWT data (deprecated) | required-operation |
| CDI-108 | Session | GET | Get database session data (deprecated) | required-operation |
| CDI-109 | Session | GET | Get session info | required-operation |
| CDI-110 | Session | GET | Get user session handles | required-operation |
| CDI-111 | Session | POST | Refresh | required-operation |
| CDI-112 | Session | POST | Regenerate | required-operation |
| CDI-113 | Session | PUT | Update JWT data | required-operation |
| CDI-114 | Session | PUT | Update database session data | required-operation |
| CDI-115 | Session | POST | Verify | required-operation |
| CDI-116 | ThirdParty | GET | Get third-party user (deprecated) | required-operation |
| CDI-117 | ThirdParty | GET | Get users by email (deprecated) | required-operation |
| CDI-118 | ThirdParty | POST | Sign-in/up | required-operation |
| CDI-119 | TOTP | POST | Add device | required-operation |
| CDI-120 | TOTP | POST | Import existing device | required-operation |
| CDI-121 | TOTP | GET | List devices | required-operation |
| CDI-122 | TOTP | POST | Remove device | required-operation |
| CDI-123 | TOTP | PUT | Update name | required-operation |
| CDI-124 | TOTP | POST | Verify code | required-operation |
| CDI-125 | TOTP | POST | Verify device | required-operation |
| CDI-126 | User Metadata | GET | Get metadata | required-operation |
| CDI-127 | User Metadata | POST | Remove metadata | required-operation |
| CDI-128 | User Metadata | PUT | Update metadata | required-operation |
| CDI-129 | User Roles | PUT | Add role to user | required-operation |
| CDI-130 | User Roles | PUT | Create or update role | required-operation |
| CDI-131 | User Roles | POST | Delete role | required-operation |
| CDI-132 | User Roles | GET | List all roles | required-operation |
| CDI-133 | User Roles | GET | Get roles possessing a permission | required-operation |
| CDI-134 | User Roles | GET | Get role permissions | required-operation |
| CDI-135 | User Roles | GET | Get user's roles | required-operation |
| CDI-136 | User Roles | GET | Get users with role | required-operation |
| CDI-137 | User Roles | POST | Remove permissions | required-operation |
| CDI-138 | User Roles | POST | Remove role from user | required-operation |
| CDI-139 | UserIdMapping | POST | Create mapping | required-operation |
| CDI-140 | UserIdMapping | GET | Retrieve mapping | required-operation |
| CDI-141 | UserIdMapping | POST | Remove mapping | required-operation |
| CDI-142 | UserIdMapping | PUT | Update external-user information | required-operation |
| CDI-143 | WebAuthn | POST | Consume recovery token | required-operation |
| CDI-144 | WebAuthn | POST | Generate authentication options | required-operation |
| CDI-145 | WebAuthn | POST | Generate recovery token | required-operation |
| CDI-146 | WebAuthn | POST | Generate registration options | required-operation |
| CDI-147 | WebAuthn | GET | Get credential | required-operation |
| CDI-148 | WebAuthn | GET | Get options | required-operation |
| CDI-149 | WebAuthn | GET | List credentials | required-operation |
| CDI-150 | WebAuthn | GET | Recover user | required-operation |
| CDI-151 | WebAuthn | POST | Register credential | required-operation |
| CDI-152 | WebAuthn | DELETE | Remove credential | required-operation |
| CDI-153 | WebAuthn | DELETE | Remove options | required-operation |
| CDI-154 | WebAuthn | POST | Sign in | required-operation |
| CDI-155 | WebAuthn | POST | Sign up | required-operation |
| CDI-156 | WebAuthn | PUT | Update email | required-operation |
