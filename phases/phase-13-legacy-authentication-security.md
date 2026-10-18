# Phase 13: Legacy Authentication Security

**Source material:** Module 13 of 17, "Authentication Complete Phases Test.md" (17 numbered sections covering legacy authentication security, and the course tracker), with supplementary assessment material drawn from "Authentication Security.md" (Challenge 42).

## Learning Objectives

After completing this phase, you should be able to:

1. Define legacy authentication and explain why an old endpoint is not automatically vulnerable simply because it is old, the vulnerability exists when its behavior violates the application's current security requirements.
2. List the six ordinary software development and maintenance reasons legacy authentication weaknesses exist: backward compatibility, incomplete migrations, forgotten endpoints, independent implementation, trust in internal environments, and security controls implemented only in the interface.
3. Identify the legacy-endpoint MFA bypass pattern, and explain precisely what evidence is required beyond a successful login response to prove it.
4. Explain why account disablement, session revocation, and credential invalidation are three separate operations, and identify a legacy endpoint that checks only the password while ignoring account state.
5. Explain the migration-on-success strategy for upgrading legacy password hashes, and the specific policy question it leaves open for dormant accounts.
6. Explain why two coexisting session or cookie formats are not automatically a vulnerability, and identify the dangerous migration pattern where an old session survives a security event that should have revoked it.
7. Evaluate HTTP Basic and Digest Authentication on their actual configuration and exposure rather than their age alone, and distinguish transport-layer protection from complete authentication security.
8. Identify the OAuth Resource Owner Password Credentials grant as a deprecated flow and explain why it undermines the separation between user, client, and authorization server.
9. Apply the module's systematic discovery method, route definitions, API versions, client review, infrastructure configuration, and logs, to build an inventory of an application's authentication surface.
10. Recognize the six specific false positives this module identifies, and explain why each requires further testing rather than an immediate finding.
11. Apply the module's complete 6-step realistic assessment scenario to compare a modern and a legacy authentication route and establish demonstrated impact.
12. Apply the Phase 1 through Phase 12 impact-validation discipline to legacy-authentication findings: a legacy route returning `200 OK` is a lead, not proof, until it is shown to grant access a current policy says it should not.

## Introduction

Every phase in this course has studied how an application's current, intended authentication design can fail. This phase studies a different source of risk entirely: the authentication paths an application used to rely on, and never fully retired. A company that originally authenticated users with only an email and password later introduces MFA, passkeys, centralized session management, account suspension, and stronger password hashing. The main login page now reflects all of that work. But the original mobile login endpoint, built before any of it existed, may still be reachable, and if it still accepts a password alone and issues a fully authenticated session, it quietly undermines everything the modern login page was built to enforce.

The central lesson threaded through this entire module is stated in its own first section: security controls must protect every authentication path, not merely the primary login page. This phase is not about old code being inherently dangerous. A legacy endpoint is not automatically vulnerable simply because it is old. The vulnerability exists when its behavior violates the application's current security requirements, and proving that requires the same discipline as every earlier phase: a successful login response is evidence worth investigating, not proof of anything, until you have demonstrated what it actually lets you access.

## Core Concepts

The module moves through four stages. First, sections 1 and 2 establish what legacy authentication is and the six ordinary, non-malicious reasons it persists in real applications. Second, sections 3 through 10 examine specific legacy risk categories in turn: the MFA bypass scenario, disabled-account enforcement, password-hash migration, session-format inconsistency, HTTP Basic and Digest Authentication, deprecated OAuth flows and old identity integrations, legacy recovery endpoints, and the broader "weakest link" problem across remembered devices, trusted networks, support-assisted recovery, and service accounts. Third, sections 11 through 13 build the practical discipline: a systematic method for discovering legacy authentication paths, a dangerous legacy-handler source-code review, and a complete six-step realistic assessment scenario. Fourth, sections 14 through 17 close the module with six false positives, severity and reporting guidance, a full testing checklist, and the five principles to remember.

## Lessons

### 1. What Is Legacy Authentication?

Legacy authentication refers to older authentication mechanisms, endpoints, protocols, or implementation paths that remain in an application after newer security controls have been introduced. Consider a company that originally authenticated users using only an email address and password. Later, the company introduces MFA, passkeys, centralized session management, account suspension controls, stronger password hashing, and improved account recovery. The main login page now has modern security controls. However, the original mobile login endpoint still exists:

```text
                    Modern application
                           |
               +-----------+-----------+
               |                       |
         Modern web login        Legacy mobile login
               |                       |
        Password + MFA            Password only
               |                       |
        Secure session?          Full session?
               |                       |
               +-----------+-----------+
                           |
                    Same user account
```

If the legacy endpoint accepts the user's password and issues a fully authenticated session without requiring MFA, the older authentication path may undermine the newer security architecture. The central lesson: security controls must protect every authentication path, not merely the primary login page. A legacy endpoint is not automatically vulnerable simply because it is old. The vulnerability exists when its behavior violates the application's current security requirements.

### 2. Why Legacy Authentication Vulnerabilities Exist

Legacy authentication weaknesses often arise from ordinary software development and maintenance decisions.

**A. Backward compatibility.** A company may need to support an older mobile application that still uses an earlier login API. Developers leave the endpoint operational to avoid breaking existing users. The problem appears when the old endpoint retains security assumptions that no longer hold.

**B. Incomplete migrations.** A team upgrades the main login system but forgets to migrate password-reset endpoints, mobile authentication, administrative login, partner authentication, older API versions, and support and recovery mechanisms. The application now has multiple authentication implementations with different security properties.

**C. Forgotten endpoints.** Developers may remove a login button from the frontend without removing its backend endpoint. An attacker does not need the old button if the endpoint remains reachable and accepts requests.

**D. Independent implementation.** Different teams may have implemented web, mobile, and administrative authentication separately. One implementation checks MFA, another checks only the password.

**E. Trust in internal environments.** An old endpoint may assume that requests originate from a trusted network or internal service. That assumption becomes dangerous if the endpoint is exposed through a reverse proxy, VPN, cloud network, or misconfigured firewall.

**F. Security controls implemented only in the interface.** The modern interface may require an additional verification step, but the backend endpoint might not enforce it. A security requirement implemented only in the user interface is not a reliable authentication control.

### 3. Legacy Login Endpoints: The MFA Bypass Scenario

This is one of the most important patterns to recognize. Imagine an application with two authentication routes, `POST /auth/login`, the modern login endpoint, and `POST /api/v1/mobile/login`, supporting an older mobile client. The application requires MFA for privileged users.

**Modern endpoint.** A request with valid credentials returns:

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "authenticated": true,
  "mfa_required": true,
  "challenge_id": "challenge_demo_81"
}
```

The user has supplied valid primary credentials, but the application has not yet completed authentication. This is a legitimate design when the challenge is enforced server-side. The user must complete the required second factor before receiving a fully authenticated session.

**Legacy endpoint.** Suppose the old mobile endpoint responds differently to the same credentials:

```http
HTTP/1.1 200 OK
Set-Cookie: session=SESSION_DEMO_123; Secure; HttpOnly
Content-Type: application/json

{
  "authenticated": true
}
```

The old endpoint has apparently issued an authenticated session without an MFA challenge.

**What is the potential vulnerability?** If the same controlled account is subject to mandatory MFA through the modern endpoint, but the legacy endpoint allows that account to access protected resources without completing MFA, the legacy route may constitute an MFA bypass. However, the response alone does not prove the vulnerability. You must establish that the account is genuinely required to complete MFA, the legacy endpoint actually authenticates the account, the resulting session can access resources that require MFA, the application does not enforce MFA through another server-side mechanism, and the behavior violates the application's documented or intended authentication policy. A successful login response is not sufficient evidence of full authentication.

**How should the application be designed?** Every login route should enforce the same applicable authentication policy, ideally through a shared authentication service:

```python
def authenticate_user(credentials):
    user = verify_primary_credentials(credentials)

    if user is None:
        return authentication_failed()

    if user.is_disabled:
        return authentication_failed()

    if user.requires_mfa:
        return create_limited_mfa_challenge(user)

    return create_authenticated_session(user)
```

This is illustrative pseudocode, not production-ready code. Real implementations must also handle rate limiting, session generation, challenge expiry, replay prevention, auditing, and other requirements. The important architectural decision is that the legacy endpoint must not implement a weaker authentication policy. It should either use the same trusted authentication service or be retired.

### 4. Legacy Authentication and Disabled Accounts

Another serious weakness occurs when an older login route fails to respect account status. Imagine a user whose account was disabled because of suspected compromise. The modern login endpoint checks account status, `if user.is_disabled: reject_login()`. The legacy endpoint checks only the password: `if verify_password(password, user.password_hash): create_session(user)`. The second implementation may allow the disabled account to authenticate. This is not simply an outdated-code problem. It is an account-lifecycle enforcement failure.

**How to test it safely.** In an authorized staging environment, use a controlled account and compare the behavior of the modern and legacy authentication routes.

| Test condition | Expected behavior |
|---|---|
| Active account, valid credentials | Authenticate according to policy |
| Active account, invalid credentials | Reject authentication |
| Disabled account, valid credentials | Reject authentication |
| Suspended account, valid credentials | Apply the documented suspension policy |
| Deleted account, valid credentials | Reject authentication |
| Account requiring MFA | Enforce MFA through every applicable route |

Also test what happens to existing sessions after account suspension. Rejecting a new login is not sufficient if previously issued sessions remain usable contrary to the application's revocation policy. Key distinction: account disablement, session revocation, and credential invalidation are separate operations. A secure design must define how they interact.

### 5. Legacy Password Storage and Hash Migration

Older authentication systems sometimes store passwords using algorithms that are no longer appropriate for password storage: MD5 used directly on passwords, SHA-1 used directly on passwords, SHA-256 used without a suitable password-hashing construction, unsalted password hashes, weakly configured legacy password-hashing schemes, and plaintext passwords. These approaches do not all have identical risk, but fast general-purpose hashes are unsuitable as standalone password-storage mechanisms, as established in Phase 1. Modern password storage should use a dedicated password-hashing algorithm, such as Argon2id, with suitable parameters.

**Why old password hashes matter.** The security implications depend on the algorithm, whether a unique salt was used, the work factor, password strength and reuse, whether an attacker can access the hash database, and whether the hash has already been exposed. An old hash does not automatically mean the account has been compromised. The primary concern is the increased feasibility of offline password guessing if an attacker obtains the hashes.

**Migration-on-success.** One practical migration strategy is to upgrade a password hash when the user successfully logs in:

```python
def login(email, password):
    user = find_user(email)

    if user is None:
        return reject_login()

    if not verify_password(password, user.password_hash):
        return reject_login()

    if needs_hash_upgrade(user.password_hash):
        upgraded_hash = argon2id_hash(password)
        update_password_hash(user.id, upgraded_hash)

    return continue_authentication_policy(user)
```

This example illustrates the sequence only. The real implementation needs concurrency-safe updates, algorithm metadata, error handling, and secure password verification. The migration should happen only after successful verification of the existing credential.

**What about dormant accounts?** A migration-on-success strategy does not immediately upgrade accounts that never log in. Possible responses include requiring a password reset after a defined deadline, disabling obsolete authentication paths, requiring reauthentication before sensitive actions, and migrating active users progressively while applying a separate policy to dormant accounts. A forced reset may be appropriate when the legacy scheme is especially weak or exposure is suspected. It should be based on risk rather than treated as mandatory for every migration.

**Bug-hunting perspective.** Finding `md5(password)` in source code is useful evidence of a password-storage weakness. However, report the actual behavior and exposure. Do not automatically claim that every account is compromised or that an attacker can log in without the password.

### 6. Old Session Formats and Inconsistent Revocation

Modern applications may introduce a new session format while retaining older cookies or session identifiers, for example a modern `__Host-app_session` alongside a legacy `old_session`. The names are illustrative. The presence of two cookie names is not itself a vulnerability. The question is whether the old session remains trusted and whether it follows the application's current security requirements.

**Dangerous migration pattern.** Consider this sequence: a user authenticates through the old system, the application issues a legacy session, the user changes their password, the modern application revokes modern sessions, the old session remains valid, and the old session can still access protected resources. If the application's security policy requires password changes to revoke existing sessions, the old session's continued access may constitute a session-revocation vulnerability. The same concern applies to account suspension, account recovery, MFA removal or replacement, suspected account compromise, and administrative session termination.

**What to verify.** For each supported session type, determine where the session is validated, whether it maps to the correct account, whether the account is still active, whether the session has expired, whether the session has been revoked, whether the session meets the authentication assurance required for the requested action, whether logout invalidates the session on the server, and whether security-sensitive account changes trigger the appropriate revocation policy. Deleting a browser cookie does not necessarily invalidate a server-side session. Similarly, rotating the modern session does not necessarily revoke an independently validated legacy session. A migration is incomplete if an old session remains usable against the application's current security policy. These principles extend the session-revocation discipline from Phase 6.

### 7. Legacy HTTP Basic and Digest Authentication

Older protocols may survive in internal tools, monitoring dashboards, administrative interfaces, partner integrations, or APIs.

**A. HTTP Basic Authentication.** A request such as `Authorization: Basic <REDACTED>` encodes a username and password using Base64. Base64 is encoding, not encryption. If Basic Authentication is used without TLS, credentials can be exposed to someone able to observe the traffic. With properly configured HTTPS, Basic Authentication can protect credentials in transit, but other risks remain: repeated transmission of reusable credentials, weak password policies, insufficient rate limiting, lack of MFA, credential exposure in logs or debugging tools, broadly shared service credentials, and weak account lifecycle controls. HTTPS is necessary for protecting credentials in transit, but it does not automatically make the complete authentication system secure.

What should an authorized tester examine? Is the endpoint reachable without HTTPS? Does the server redirect insecure requests before accepting credentials, or could credentials be processed over plaintext HTTP? Are credentials reused across services? Are failed attempts rate-limited? Are disabled accounts rejected? Are privileged routes protected by the required authentication policy? Are secrets exposed in application or proxy logs? Use designated test credentials. Do not test with real employee passwords.

**B. HTTP Digest Authentication.** Digest Authentication was designed to avoid sending the password directly in the same way as Basic Authentication. However, it is not equivalent to modern phishing-resistant authentication, and its security properties depend on the algorithm, implementation, nonce handling, and configuration. Depending on the scheme and configuration, captured authentication exchanges may create offline guessing opportunities or other risks. Digest Authentication also does not automatically provide MFA, passkey-based phishing resistance, secure account recovery, modern session lifecycle management, or consistent authorization across application routes. Do not report Digest Authentication as vulnerable merely because it is old. Examine the actual protocol configuration, threat model, and demonstrated weakness.

### 8. Deprecated OAuth Flows and Old Identity Integrations

An application may migrate its login system to a modern identity provider while retaining older authentication flows for compatibility. One important example is the OAuth 2.0 Resource Owner Password Credentials grant, commonly called the password grant. This grant allows a client to obtain tokens using the resource owner's username and password. It is deprecated by modern OAuth security guidance and should not be used in new designs. Why? The flow encourages users to supply their credentials directly to a client that may not be the identity provider. It also undermines the separation between the user, client, and authorization server, the same trust-boundary concerns examined throughout Phase 7. Modern OAuth deployments generally favor authorization-code flow with PKCE where appropriate. But finding an old OAuth flow does not automatically prove account takeover. You must establish whether it remains enabled, what clients can use it, what credentials it accepts, and what privileges the resulting tokens grant.

**Other legacy identity risks.** Examine whether an older integration still accepts tokens from an identity provider that should no longer be trusted, uses obsolete client registrations, relies on a retired signing or trust configuration, maps external identities to local accounts using insufficiently verified attributes, allows an old identity provider to authenticate users after a migration, grants access to accounts that should be deactivated, or uses an older callback or token-exchange implementation with weaker validation. For identity mapping, the application must bind a local account to the correct trusted external identity. Email equality alone is not universally sufficient to establish that two identities belong to the same person, the same principle established for SAML in Phase 10 and OIDC in Phase 7.

**Testing principle.** An old identity integration becomes a security issue when its continued acceptance violates the application's current trust policy or creates a demonstrated authentication or account-linking weakness.

### 9. Legacy Password-Reset and Recovery Endpoints

Password recovery is especially important because it can bypass otherwise strong login protections. Imagine the application has migrated to a modern reset endpoint, `POST /account/recovery/request`, but an older endpoint remains, `POST /api/v1/reset-password`. The older endpoint may use predictable reset tokens, tokens that never expire, reusable tokens, weak account binding, insufficient verification, incomplete session revocation, and old email or phone ownership assumptions. These are potential vulnerabilities, but each must be verified independently.

**Example: old recovery token accepted after migration.** Suppose the current system invalidates recovery tokens when a password is changed. However, the old endpoint validates tokens using a separate database table and does not check whether the token has been consumed. A token that should no longer work might still authorize a password reset. That can become an account-takeover vulnerability if the attacker can obtain or predict an applicable token, or otherwise satisfy the old endpoint's requirements. The existence of a legacy reset endpoint alone is not enough to establish account takeover.

**How to assess the flow.** Using controlled accounts, verify that reset tokens are unpredictable, tokens are bound to the intended account and operation, tokens expire according to policy, tokens cannot be reused, consumed or revoked tokens are rejected, password changes invalidate applicable outstanding recovery tokens, existing sessions are handled according to the revocation policy, recovery cannot bypass required account-status checks, and notifications and audit events reflect security-sensitive changes. The modern and legacy recovery flows should follow a consistent policy. If the old flow is no longer needed, removing it is generally safer than maintaining two independent recovery implementations. This extends the reset-token lifecycle discipline from Phase 2.

### 10. Legacy Fallbacks: The Weakest Link Problem

An application may offer several ways to authenticate or recover an account: password plus MFA, passkey, account recovery, legacy mobile login, support-assisted recovery, and old partner integration, each creating a possible alternative route into the account. The critical question is not whether every route uses identical technology. It is whether each route meets the appropriate security requirements for the access it grants.

**A. Remembered devices.** A remembered device may allow the user to skip a verification step for a defined period. That can be legitimate. However, inspect whether the remembered-device credential is protected, the trust period is bounded, users can revoke remembered devices, account recovery invalidates or reevaluates the trust, and privileged actions still require stronger authentication where appropriate. A remembered-device feature should not accidentally become a permanent bypass of the application's authentication policy.

**B. Trusted IP or network.** An application might allow access from a trusted network without the normal authentication process. Network location alone is generally weak evidence of a user's identity. A corporate network may contain compromised machines, shared systems, VPN users, or other sources of untrusted traffic. If the application uses network location as one risk signal, it should not silently override essential authentication requirements unless that exception is explicitly justified and appropriately controlled.

**C. Support-assisted recovery.** Support personnel may be able to reset passwords, replace MFA devices, or restore access. This can be necessary, but it introduces a sensitive identity-proofing process. Assess what evidence support personnel require, whether sensitive actions require approval, whether privileged overrides are audited, whether the user receives a notification, and whether the process can be abused to replace an authenticator without adequate proof.

**D. Service accounts.** Legacy service accounts may have static credentials or broad privileges. Assess whether the account still has a business purpose, its credentials are rotated and protected, its permissions are appropriately limited, human login is prohibited where unnecessary, and unused credentials have been revoked. Do not assume that every service account is a vulnerability. Demonstrate unnecessary privileges, exposed credentials, weak authentication, or an actual policy violation.

The principle: alternative authentication and recovery paths must be included in the security review.

### 11. Discovering Legacy Authentication Paths

In an authorized assessment, you need a systematic way to identify older authentication routes. The goal is not to brute-force every possible endpoint. It is to build an inventory of the authentication surface.

**A. Examine route definitions.** In a codebase, search for route registrations and authentication-related handlers. For every candidate route, determine whether it is active, whether it is reachable in production, which clients use it, which authentication service it invokes, which account and MFA checks it performs, what session or token it issues, and whether the route has an approved retirement date.

**B. Examine API versions.** A modern endpoint may exist alongside older versions, for example `/api/v1/auth/login`, `/api/v2/auth/login`, `/api/v3/auth/login`. The older version is not automatically less secure. Compare the behavior of each version and determine whether old versions are still supported. Documentation, route definitions, and existing client code can help establish which versions remain in scope.

**C. Review frontend and mobile clients.** Older clients may reveal historical endpoint paths, legacy login flows, obsolete authentication parameters, old identity-provider integrations, and alternative recovery endpoints. Treat these discoveries as leads to investigate, not proof of vulnerabilities.

**D. Review infrastructure configuration.** With appropriate authorization, examine reverse-proxy routes, API gateways, load-balancer rules, internal hostnames, staging and production exposure, authentication middleware, and service-to-service routes. An endpoint may be absent from the public interface yet still be reachable through a different hostname or network path.

**E. Review logs and operational records.** Logs can reveal which authentication routes are still used and whether retired clients continue to call them. Use appropriately authorized, redacted records. Do not expose passwords, session tokens, recovery tokens, or other authentication secrets while investigating.

Practical rule: a discovered route is a candidate for assessment, not automatically a vulnerability, and not automatically in scope for testing.

### 12. Source-Code Review: A Dangerous Legacy Handler

Consider this fictional handler:

```python
def legacy_login(email, password):
    user = find_user(email)

    if user is None:
        return {"error": "Invalid credentials"}, 401

    if verify_password(password, user.password_hash):
        session = create_session(user.id)

        return {
            "authenticated": True,
            "session": session
        }, 200

    return {"error": "Invalid credentials"}, 401
```

At first glance, the handler verifies the password. That is good, but it is not sufficient.

**What is missing?** Depending on the application's requirements, it may fail to enforce account suspension or disablement, mandatory MFA, required reauthentication, risk-based restrictions, centralized session policy, appropriate auditing and rate limiting, and current credential and session lifecycle rules. Some of these controls may exist elsewhere. You must inspect the complete call path before concluding that they are absent.

**A safer architectural approach:**

```python
def legacy_login(email, password):
    return centralized_authentication_service(
        email=email,
        password=password,
        client_type="legacy_mobile"
    )
```

The centralized service should enforce the current authentication policy and apply any explicitly approved client-specific restrictions. It should not simply trust the label `legacy_mobile`. In a real system, additional safeguards might include restricting the route to supported clients, enforcing rate limits, recording authentication outcomes, preventing sensitive credentials from entering logs, issuing sessions with consistent lifecycle and revocation behavior, and rejecting retired or unauthorized client integrations. The strongest long-term solution may be to retire the endpoint entirely. Important: centralization helps only if the shared service itself is secure and every relevant route actually uses it.

### 13. Realistic Assessment Scenario

Imagine you are assessing a fictional financial application in an authorized staging environment. The application has password plus MFA login, passkey login, an older mobile API, a legacy password-reset route, and an administrative interface. Your task is to determine whether the legacy authentication paths comply with the application's current security policy.

**Step 1: establish the baseline.** Using a controlled account that requires MFA, document the expected modern login sequence. A fictional response: `{"authenticated": false, "mfa_required": true, "challenge_id": "TEST_CHALLENGE_01"}`. This establishes the expected intermediate state. It does not yet establish a vulnerability.

**Step 2: compare the legacy route.** In the same authorized environment, submit the same controlled account's credentials through the documented legacy route. Observe whether authentication succeeds, whether an MFA challenge is required, whether a session or token is issued, and whether the resulting credential is limited or fully authenticated. Redact any issued credential in your notes.

**Step 3: test actual access.** Use the resulting session only against a harmless, authorized endpoint designed to establish authentication state, for example a staging-only `GET /account/session-status` that might report `{"authenticated": true, "mfa_verified": false, "access_level": "limited"}`. This indicates that the session may be authenticated but not MFA-verified. That can be the correct design. If the same session can access a protected operation that requires completed MFA, however, the finding becomes more serious. Do not perform a financial transaction or other consequential action to prove the issue when a safe staging endpoint can establish the same authorization boundary.

**Step 4: compare account-state enforcement.** Repeat the comparison using controlled test accounts with approved states: active, MFA-required, disabled, password recently changed, and session explicitly revoked. Record the behavior of each route.

**Step 5: assess the legacy reset flow.** Check whether the old recovery endpoint still accepts valid requests and whether it follows the current requirements for token expiry, single use, account binding, and session handling. Use only recovery tokens generated for your controlled test accounts.

**Step 6: establish impact.** The key is to prove what the weakness permits. Examples: a legacy endpoint authenticates an account without required MFA; a disabled account can still obtain a valid session; a revoked legacy session continues to access protected resources; a retired identity integration can still authenticate an account contrary to policy; an old recovery token can still change a password after it should have been invalidated. Each is a different finding. Do not combine them into a broad claim of "complete authentication bypass" without evidence supporting that conclusion.

### 14. False Positives You Must Avoid

**False positive 1: an old endpoint still exists.** Observation: `/api/v1/login` remains reachable. Why that is insufficient: the endpoint might enforce all current security requirements. Next step: test its authentication behavior and resulting session.

**False positive 2: the old endpoint returns HTTP 200.** Observation: the legacy route returns `200 OK`. Why that is insufficient: the response could represent a challenge, limited session, or application-level failure. Next step: inspect the response body and verify effective access.

**False positive 3: the user has no MFA prompt.** Observation: the legacy client does not display an MFA prompt. Why that is insufficient: MFA might be satisfied by a previously established trusted authentication state, or the session may be restricted. Next step: establish whether the user is required to complete MFA and whether protected operations enforce that requirement.

**False positive 4: a weak hash appears in source code.** Observation: an old password-hashing algorithm appears in a repository. Why that is insufficient: the code may be unused, or the implementation may be part of a controlled migration path. Next step: trace the active password-storage and verification paths and establish actual exposure.

**False positive 5: a legacy session remains after logout.** Observation: an old cookie remains in the browser. Why that is insufficient: the cookie may be invalid on the server. Next step: test whether the session can still access a protected resource.

**False positive 6: a deprecated protocol is enabled.** Observation: the application supports an older authentication protocol. Why that is insufficient: the protocol may be restricted to a controlled, documented integration and may not violate the security policy. Next step: establish its configuration, exposure, authentication guarantees, and practical consequences.

### 15. Severity and Reporting

Severity should follow demonstrated impact, exploitability, affected accounts, and the application's security requirements.

| Finding | What must be established |
|---|---|
| Legacy route without required MFA | The route permits access that should require MFA |
| Disabled account can authenticate | The account's disabled state is not enforced |
| Revoked legacy session remains valid | The session remains usable contrary to the revocation policy |
| Legacy password hashes are weak | The active storage method is weak; impact depends on hash exposure and other factors |
| Old reset token can be reused | The token authorizes an additional operation after it should have been consumed |
| Legacy identity provider remains trusted | The obsolete trust relationship allows unauthorized authentication or account mapping |
| Basic Authentication over plaintext HTTP | Reusable credentials can be exposed in transit under the tested network conditions |
| Old endpoint is merely reachable | Insufficient by itself to establish a vulnerability |

**Example finding.** Title: Legacy mobile login bypasses mandatory MFA. Description: the application requires multi-factor authentication for the tested account through the modern login endpoint. The legacy mobile endpoint accepts the same primary credentials and issues a session without completing the required MFA challenge. Evidence: in the authorized staging environment, the modern route returns an MFA challenge. The legacy route returns a session. A subsequent controlled test establishes that the legacy session can access a resource explicitly protected by the application's MFA requirement. Impact: an attacker who obtains the affected user's primary credentials may be able to bypass the required second authentication factor through the legacy endpoint. The practical risk depends on the account's privileges and the resources accessible through the resulting session. Recommendation: enforce the current MFA policy on every active authentication route; reuse a centralized authentication policy where appropriate; retire the legacy endpoint if it is no longer required; revoke affected legacy sessions where necessary; add regression tests for all supported login routes; monitor and audit authentication through legacy clients. Severity: determine this from the verified access, account privileges, exposure, and exploitability. Do not assign a severity solely because the words "MFA bypass" appear in the title.

### 16. Your Senior AppSec Testing Checklist

When reviewing legacy authentication, work through these categories systematically.

**Endpoint inventory:** identify active login endpoints and versions; identify mobile, administrative, partner, and internal authentication routes; identify old password-reset and recovery routes; confirm which routes are reachable in production; identify deprecated protocols and identity integrations; determine which clients still depend on legacy behavior.

**Authentication policy:** confirm required MFA is enforced consistently; confirm account suspension and disablement are enforced; confirm password verification uses the expected current policy; confirm any required step-up authentication is enforced server-side; confirm alternative authentication routes do not weaken mandatory controls.

**Sessions and tokens:** identify the session or token format issued by each route; verify appropriate session rotation after authentication; verify logout and revocation behavior; verify password changes trigger the appropriate session and recovery-token handling; confirm old session formats are not accepted beyond their intended lifetime.

**Recovery:** verify token unpredictability, expiry, account binding, and single-use behavior; check that retired recovery routes are disabled; confirm recovery cannot bypass required account-state checks; check the handling of existing sessions after recovery.

**Infrastructure and operations:** review proxy and API gateway routes; check obsolete hostnames and versions within authorized scope; review legacy client usage and retirement plans; ensure authentication secrets are not exposed in logs; add tests to prevent regressions.

**Evidence:** use controlled accounts and approved environments; compare behavior across routes; prove actual access rather than relying on status codes; redact credentials, tokens, and personal data; state exactly what you proved and what remains uncertain.

### 17. The Five Principles to Remember

**1. An authentication system is only as strong as its active authentication paths.** A modern login page cannot compensate for a weaker legacy endpoint.

**2. Authentication is more than checking a password.** Account state, MFA requirements, session issuance, and lifecycle controls matter.

**3. A session is not necessarily proof of completed authentication.** The application may need to distinguish between limited authentication, completed MFA, and step-up authentication.

**4. Migration must cover the entire lifecycle.** Login, recovery, password changes, account suspension, logout, and session revocation must all follow the current policy.

**5. Prove impact before assigning severity.** A route that looks old or returns an unexpected response is a lead, not a confirmed vulnerability.

## Assessment

The following assessment is drawn from "Authentication Security.md" and addresses the correct test sequence for proving a legacy endpoint's MFA bypass, and the nuance of inconsistent enforcement across different sensitive endpoints. As with the prior phases, the questions are preserved from the original source, and the answers given are the instructor's corrected, authoritative answers rather than the original learner's submitted answers.

### Assessment Question 1

You are testing a banking-style web application. The main login endpoint requires MFA:

```http
POST /api/auth/login
Content-Type: application/json

{
  "email": "alice@example.test",
  "password": "CorrectPassword!"
}
```

```http
HTTP/1.1 200 OK

{
  "mfa_required": true,
  "mfa_session": "MFA_PENDING_123"
}
```

While reviewing the application, you discover an older endpoint that accepts the same credentials and returns a full session with no MFA challenge:

```http
POST /api/v1/login
Content-Type: application/json

{
  "email": "alice@example.test",
  "password": "CorrectPassword!"
}
```

```http
HTTP/1.1 200 OK
Set-Cookie: session_id=AUTH_789; HttpOnly; Secure

{
  "authenticated": true
}
```

What would you investigate first, and what security property are you testing? Don't just say "MFA bypass," explain what you would actually prove.

<details markdown="1">
<summary><strong>Reveal Answer</strong></summary>

The security property being tested is MFA enforcement, specifically whether `/api/v1/login` can create the same level of authentication that normally requires MFA through the modern endpoint. Simply noting that the second endpoint already returned an authenticated session without MFA is not itself the strongest first test, that response is a lead, not proof.

The correct first test is to use the resulting session against a sensitive, MFA-protected endpoint, not merely confirm that the legacy login succeeded. Concretely: log in through `/api/v1/login`, receive `session_id=AUTH_789`, then use that session on an MFA-protected sensitive endpoint, for example `GET /api/account`, and then on something more consequential still, such as `POST /api/change-password`. If the legacy endpoint gives you access to sensitive functionality that the main login flow protects behind MFA, you have demonstrated a real MFA bypass. This reveals an authentication-state inconsistency: the modern login flow goes password, then MFA pending, then authenticated, with a clear security boundary at the MFA step, while the legacy login flow goes directly from password to authenticated, skipping that boundary entirely. The application has two authentication paths producing different security states for the same account, and proving the bypass requires showing that the weaker path's state actually grants the same sensitive access the stronger path's boundary is meant to protect.

</details>

### Assessment Question 2

Continuing the same scenario, suppose `/api/v1/login` gives you an authenticated session without MFA, but when you test it against `POST /api/change-password`, you receive:

```http
HTTP/1.1 403 Forbidden

{
  "error": "MFA required"
}
```

Is that automatically a vulnerability? Why or why not, and what would you still need to check before concluding there is no finding here at all?

<details markdown="1">
<summary><strong>Reveal Answer</strong></summary>

No, this is not automatically a vulnerability, at least not based on this evidence alone. Bypassing the MFA challenge during login is not enough by itself, you need to prove that the bypass actually crosses a security boundary, and here it apparently does not: the legacy login produces an authenticated session, but `/api/change-password` still independently enforces its own MFA requirement and rejects that session with a `403`. The application appears to be maintaining an MFA-required authorization state at the sensitive-operation level even though the legacy login endpoint itself created the session without MFA. Given only this evidence, you would not report "MFA bypass" based solely on the successful legacy login response, since the actual sensitive operation you tested correctly refused the under-authenticated session.

However, this single negative result at one endpoint does not clear the legacy route entirely, because MFA enforcement might be inconsistent across different sensitive endpoints rather than uniformly applied. You would still need to investigate other sensitive endpoints individually, for example `/disable-mfa`, `/change-email`, `/add-payment-method`, `/view-recovery-codes`, and any `/api/admin/*` routes, since each one independently decides whether to honor the account's MFA requirement. If even one of those accepts the under-authenticated legacy session without requiring MFA, you have found the actual security flaw, just not at the specific endpoint you happened to test first. The general lesson is that proving a legacy-login MFA bypass requires checking the full set of sensitive operations the account's MFA policy is supposed to protect, not just login itself and not just a single downstream endpoint.

</details>

## Remediation and Secure Implementation

The following consolidates the remediation guidance across all seventeen sections of this phase.

1. Route every authentication path, modern and legacy alike, through the same centralized authentication service, so that account status, MFA requirements, and session issuance policy cannot diverge between endpoints.
2. Retire legacy endpoints that are no longer required rather than maintaining them indefinitely, since every additional active authentication path is additional surface that must independently enforce the current security policy.
3. Enforce account suspension, disablement, and deletion status at every authentication route and at the point of accessing protected resources, not merely at the primary login endpoint.
4. Upgrade legacy password hashes using a migration-on-success strategy at minimum, and apply a deliberate, risk-based policy, such as a forced reset deadline, for dormant accounts that never trigger that migration.
5. Ensure that security-sensitive events, password changes, account suspension, MFA removal, suspected compromise, and administrative termination, revoke every session format the application has ever issued, not only the current one.
6. Require TLS for any HTTP Basic or Digest Authentication deployment, and layer in rate limiting, MFA where appropriate, and credential rotation, since transport encryption alone does not make the complete authentication system secure.
7. Disable the OAuth Resource Owner Password Credentials grant and any other deprecated flow unless a specific, documented, and still-justified integration requires it, and prefer authorization-code flow with PKCE for new and migrated clients.
8. Apply the same token unpredictability, expiry, single-use, and account-binding requirements to every password-reset and recovery endpoint, legacy and modern, and ensure a password change invalidates outstanding tokens issued by either one.
9. Review every alternative authentication and recovery path, remembered devices, trusted networks, support-assisted recovery, and service accounts, with the same rigor as the primary login flow, since each is a possible route into the account.
10. Build and maintain a complete inventory of the authentication surface, route definitions, API versions, client code, infrastructure configuration, and logs, so that forgotten or undocumented legacy routes do not go unreviewed.

## Key Takeaways

This module's governing principle is its first stated rule: an authentication system is only as strong as its active authentication paths, and a modern login page cannot compensate for a weaker legacy endpoint sitting alongside it. Every one of the specific risks in this phase, the MFA bypass endpoint, the password-only check that ignores disablement, the old session format nobody remembered to revoke, the deprecated OAuth grant, the legacy reset endpoint with its own separate token table, traces back to the same root cause named in section 2: ordinary, well-intentioned engineering decisions, backward compatibility, incomplete migrations, independent team implementations, that leave an older, weaker authentication assumption still reachable after the application's security model moved on without it.

The assessment in this phase sharpens the same impact-validation discipline carried through every earlier phase, applied specifically to legacy findings: a legacy endpoint issuing a session without MFA is a lead, not a confirmed bypass, until that session is shown to reach something the MFA policy is actually meant to protect. And even a negative result at one sensitive endpoint does not clear the legacy route, since MFA enforcement can be inconsistent across an application's many sensitive operations. Proving a legacy authentication finding means tracing the weak path all the way to a demonstrated security boundary it actually crosses, exactly as every phase before this one has required.

## Review Checklist

- [ ] Can you state why an old endpoint is not automatically vulnerable, and what actually makes a legacy route a finding?
- [ ] Can you list the six ordinary reasons legacy authentication weaknesses exist in real applications?
- [ ] Can you design the correct test sequence to prove a legacy endpoint's MFA bypass, beyond observing a successful login response?
- [ ] Can you explain why account disablement, session revocation, and credential invalidation are three separate operations?
- [ ] Can you describe the migration-on-success password-hash upgrade strategy and its open question for dormant accounts?
- [ ] Can you identify the dangerous session-migration pattern where an old session survives an event that should have revoked it?
- [ ] Can you explain why HTTPS alone does not make HTTP Basic Authentication a complete authentication solution?
- [ ] Can you explain why the OAuth Resource Owner Password Credentials grant is deprecated?
- [ ] Can you apply the module's five-step discovery method to build an authentication-surface inventory?
- [ ] Can you name all six false positives this module identifies and the correct next step for each?
- [ ] Can you explain why a `403` at one sensitive endpoint does not clear a legacy login route of an MFA-bypass finding?
- [ ] Can you walk through the module's six-step realistic assessment scenario from baseline to demonstrated impact?

## References to Related Phases

- The MFA enforcement and authentication-state principles underlying the legacy bypass scenario in sections 3 and 13 were established in **Phase 3, Multifactor Authentication (MFA) Attacks**, and the client-supplied state failure pattern in **Phase 9, Reauthentication and Step-Up Authentication**.
- Password-hash migration-on-success, covered in section 5, directly extends the password-storage principles from **Phase 1, Password Storage and Credential Attacks**.
- Session-format inconsistency and revocation after security-sensitive events, covered in section 6, builds on **Phase 6, Cookie and Session Security**.
- The deprecated OAuth password grant and old identity-provider trust, covered in section 8, connects to **Phase 7, OAuth 2.0 and OpenID Connect Security** and **Phase 10, SAML Security**.
- Legacy password-reset endpoint risks, covered in section 9, extend the reset-token lifecycle discipline from **Phase 2, Password Change and Account Recovery**.
