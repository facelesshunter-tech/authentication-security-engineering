# Phase 14: Federated Logout and Identity Persistence

**Source material:** Module 14 of 17, "Authentication Complete Phases Test.md" (19 numbered sections covering federated logout and identity persistence, and the course tracker). As with several earlier phases, "Authentication Security.md" contains no federated-logout content. The module conveniently ends with its own six-scenario Final Knowledge Check, already paired with correct interpretations, which forms the Assessment section for this phase.

## Learning Objectives

After completing this phase, you should be able to:

1. Distinguish the three independent authentication states in a single sign-on deployment: the identity-provider session, the application session, and browser-stored authentication material, and explain why SSO does not mean one shared session.
2. Define federated logout and distinguish local logout, identity-provider logout, single logout, and global session revocation as related but non-interchangeable behaviors.
3. Explain why "local logout only" is not automatically a vulnerability, and identify the specific conditions, shared devices, explicit global-logout promises, that turn it into one.
4. Trace a complete post-logout verification sequence, and explain why a `302` redirect with a cookie-clearing instruction does not by itself prove server-side session invalidation.
5. Distinguish four commonly confused post-logout observations: a rejected old cookie, a working old cookie, immediate re-authentication through SSO, and a cached page, and identify what each one actually proves.
6. Explain SAML Single Logout and identify the four specific ways its coordination across service providers can fail.
7. Distinguish OIDC RP-initiated, front-channel, and back-channel logout, and explain the specific validation a back-channel logout token requires before an application may trust it.
8. Identify the four dangerous session-correlation patterns that can cause federated logout to invalidate the wrong session, too few sessions, or no session at all.
9. Explain the shared-device account-switching exposure pattern, where one employee silently inherits another's SSO session, and why its root cause is a design mismatch rather than a credential-theft bypass.
10. Distinguish persistent "remember me" credentials and federated session persistence from the ordinary application session, and explain why a password reset or MFA change does not automatically revoke every credential type.
11. Apply the module's 8-phase testing workflow to a federated logout assessment, and avoid conflating session persistence with automatic reauthentication.
12. Apply the Phase 1 through Phase 13 impact-validation discipline to federated logout findings: establish the intended policy first, then demonstrate live authenticated access, not merely an unexpected redirect or a visible cached page.

## Introduction

Every earlier phase in this course studied how a session is created and how it should be protected while active. This phase studies the moment it is supposed to end, and the surprisingly many ways that moment can fail to mean what everyone assumes it means. The problem this module investigates is stated in its own introduction with deliberate simplicity: a user clicks Logout, but the system still knows who they are, or silently authenticates them again. Sometimes this is intended behavior. Sometimes it creates a serious security vulnerability. The entire discipline of this phase is learning to tell the two apart.

The reason this is hard is that single sign-on does not create one session, it creates several independent ones at once: a session at the identity provider, a session at the application, and whatever the browser happens to be holding on to. Logout is not one action that ends all of them together unless the system was specifically designed to coordinate that, and most of the failures in this module come from exactly that gap, a design that assumes logout means something more complete than what the code actually does. As with every phase before it, the standard of proof here is the same: a redirect, a cleared cookie, or a visible logged-out page is a lead, not a conclusion, until you have tested whether the old credential still grants live, authenticated access.

## Core Concepts

The module moves through four stages. First, sections 1 through 5 establish the fundamental architecture: the three distinct sessions involved in SSO, what federated logout actually means, the common "local logout only" pattern, a complete simulated traffic analysis of what happens after a logout click, and four commonly confused post-logout behaviors. Second, sections 6 through 14 examine the protocol-specific and architectural mechanics in turn: SAML Single Logout, OIDC's three logout mechanisms, the dangerous case of an ignored back-channel notification, session correlation failures, account switching on shared devices, persistent "remember me" credentials, federated session persistence through lifecycle events, a front-channel versus back-channel comparison, and logout redirect risks. Third, sections 15 and 16 build the review discipline: what to look for in source code, and how logout events should be logged and monitored. Fourth, sections 17 through 19 close the module with a complete 8-phase testing workflow, severity and reporting guidance, and a final six-scenario knowledge check.

## Lessons

### 1. Understand the Three Different Sessions

Before testing federated logout, you must understand that a single sign-on application can involve several independent authentication states. Consider a company using an identity provider to authenticate employees into an application: the employee visits the dashboard, the dashboard redirects to the identity provider, the identity provider authenticates the employee, it sends an authentication response to the dashboard, and the dashboard creates its own application session. There are at least three distinct concepts to track.

**A. Identity-provider session.** The identity provider, or IdP, maintains its own session, telling the IdP that the user has already authenticated, for example a browser sending `Cookie: idp_session=REDACTED` to `GET /authorize?client_id=company-dashboard`. If the session remains valid, the identity provider may authenticate the user again without requesting a password.

**B. Application session.** The application, or service provider (SP), may create a separate session after successful SSO, for example `Set-Cookie: app_session=REDACTED; Secure; HttpOnly`. The application session authorizes access to the application according to its own session policy. It can remain valid even if the identity-provider session expires, unless the application receives or detects a revocation event or independently expires the session.

**C. Browser authentication state.** The browser stores cookies and may also retain other relevant state, for example an `idp_session` and an `app_session` cookie simultaneously. These cookies usually belong to different origins, and their scope and handling depend on their attributes and browser behavior. Removing one does not automatically remove the other.

**The critical distinction.**

| State | Controlled primarily by | What it means |
|---|---|---|
| IdP session | Identity provider | The IdP recognizes an authenticated user |
| Application session | Application | The application recognizes an authenticated session |
| Browser-stored authentication material | Browser, under server-defined cookie rules | The browser may present credentials that allow either session to continue |

SSO does not mean that every application and identity provider share one session. That distinction explains many logout surprises.

### 2. What Is Federated Logout?

Federated logout is the process of ending authentication sessions across systems that participate in a federated identity relationship. For example, an identity provider serving both an HR application (Session A) and an email application (Session B): an employee signs in once and accesses both. When the employee logs out of the HR application, what should happen to the other session? There is no universal answer. It depends on the system's logout design and documented policy.

Possible behaviors include local logout, which ends the current application's session; identity-provider logout, which ends the user's IdP session; single logout (SLO), which attempts to coordinate logout across participating applications; and global session revocation, which invalidates relevant sessions across multiple systems, potentially through server-side session management or identity-provider events. These concepts overlap, but they are not interchangeable. A logout operation may successfully terminate one session while leaving others active. That is not automatically a vulnerability. It becomes a security issue when the behavior violates the system's stated security requirements, exposes the wrong user to another person, or allows access that should have been revoked.

### 3. The Most Common Failure: Local Logout Only

Consider a web application that uses an external identity provider. The user signs in through the standard SSO sequence. The user clicks Logout, and the application deletes the application session, clears the application cookie, and redirects to the homepage. But the identity-provider session remains active. The user revisits the application and is redirected to the IdP, which recognizes the existing session and immediately authenticates the user again:

```text
User clicks Logout
        |
        v
Application session terminated
        |
        v
IdP session remains active
        |
        v
User revisits application
        |
        v
IdP recognizes existing session
        |
        v
New application session created
```

The user may interpret this as logout not working. But the application may have successfully ended its own session. The remaining behavior depends on the logout policy.

**Is this a vulnerability?** Not necessarily. Many systems deliberately support local logout while preserving the IdP session, allowing users to access other applications without signing in again. However, consider a shared computer in a hospital, financial office, university laboratory, or public workstation. If the user expects a complete sign-out but the identity provider silently reauthenticates them, another person may regain access. The risk depends on whether the device is shared, whether the IdP session is intended to persist, whether the application promises global logout, whether sensitive operations require fresh authentication, whether the user can explicitly end the IdP session, and whether the application exposes sensitive information before the user notices the renewed session. Testing principle: determine what logout is supposed to accomplish before classifying the behavior as a flaw.

### 4. Simulated Burp Analysis: What Actually Happens After Logout?

Investigating a fictional application `portal.example.test` with identity provider `identity.example.test`.

**Step 1: authenticate.** The user completes SSO, and the application returns `302 Found` to `/dashboard` with `Set-Cookie: portal_session=SESSION_REDACTED; Secure; HttpOnly; Path=/`.

**Step 2: request a protected resource.** `GET /dashboard` with the session cookie returns `200 OK` with the dashboard content, establishing that the session can access it.

**Step 3: log out.** `POST /logout` with the session cookie returns:

```http
HTTP/1.1 302 Found
Location: /
Set-Cookie: portal_session=; Max-Age=0; Secure; HttpOnly; Path=/
```

The application asks the browser to remove its cookie. But the response alone does not prove that the server invalidated the session. The server might have invalidated it, or it might merely have instructed the browser to delete the cookie. Those are different operations.

**Step 4: verify the old application session.** In an authorized test, use the original session credential in a controlled request to a protected endpoint. A `401 Unauthorized` response supports the conclusion that the old credential is no longer accepted for this endpoint, though it does not necessarily prove that every session or every protected route has been revoked. A stronger test samples the relevant session validation paths without accessing unnecessary sensitive data. If the response is instead `200 OK`, that is a lead, not yet a complete conclusion, confirm that the response contains authenticated content and is not a cached page or generic public response. If the old session still provides authenticated access after logout, and logout is required to invalidate it, you may have a session-revocation vulnerability.

**Step 5: revisit the application.** The browser visits `/dashboard` without an application cookie. The application redirects to the identity provider. The IdP may already have a valid session, and if it authenticates the user again, the application can create a new session. This is not proof that the old session survived. A newly issued session after SSO is different from a previously issued session that remained valid. Senior-level lesson: always distinguish session persistence from automatic reauthentication.

### 5. Four Behaviors That Look Similar but Mean Different Things

A common testing mistake is to treat every unexpected post-logout result as the same vulnerability. They are not.

| Observed behavior | Possible explanation | What you must establish |
|---|---|---|
| Old cookie is rejected | Logout successfully invalidated the session | Whether the relevant session policy is satisfied |
| Old cookie still works | Session invalidation failure | Whether authenticated access remains possible and should have ended |
| User immediately signs in again | Persistent IdP session | Whether this behavior violates the intended logout policy or creates demonstrable exposure |
| Old page remains visible after logout | Browser cache or back-forward restoration | Whether the user can still retrieve protected data or perform authenticated actions |

**Cached page versus live session.** A browser may display content that was previously loaded, even after the session is revoked. That does not necessarily mean the server is still authorizing the user. Test whether the browser can retrieve current protected content or perform an authenticated operation. Do not use a visually displayed page alone as proof of an active session.

**Immediate SSO versus surviving session.** If an application deletes its session but the IdP automatically creates a new one, the original session may have been correctly terminated. The issue, if any, is the broader logout behavior and the persistence of the IdP session. Your report should identify the actual mechanism rather than incorrectly claiming that logout failed to invalidate the old application session.

### 6. SAML Single Logout (SLO)

In a SAML deployment, the identity provider authenticates the user, the service provider consumes the SAML response, and the service provider creates its own session. Some SAML deployments support Single Logout, which attempts to coordinate session termination across the IdP and participating service providers:

```text
User
 |
 | Clicks logout
 v
Service Provider (SP)
 |
 | Sends LogoutRequest
 v
Identity Provider (IdP)
 |
 | Processes logout
 v
Other participating service providers
```

The exact flow depends on the SAML bindings, configuration, and implementation, as established in Phase 10.

**What can go wrong?**

*A. The SP only deletes its local session.* The application may remove its own session but never initiate or complete the configured federated logout flow. If the IdP session remains active, later SSO may silently authenticate the user again. Whether this is a security defect depends on the intended logout policy and risk.

*B. The IdP processes logout but an SP retains its session.* An application might fail to process the logout notification or might not associate it with the correct local session. A session can then remain active when the deployment expects coordinated termination.

*C. Incorrect session-to-identity mapping.* The application may terminate the wrong session or fail to find the session associated with the federated identity. Session correlation must be implemented according to the relevant protocol and application design.

*D. Incomplete logout processing.* A logout request may be rejected, timed out, or only partially processed. The application should not falsely indicate that every participating session has ended when it knows the operation failed or remains incomplete.

**What should a tester inspect?** Whether SLO is supported and configured, whether the SP initiates logout as expected, whether the IdP processes the request, whether participating SP sessions are invalidated according to policy, whether old SP session credentials remain usable, whether logout failures are handled safely, and whether the application accurately communicates the scope of logout. A SAML `LogoutRequest` appearing in traffic does not prove that all sessions were terminated. Likewise, the absence of SLO does not automatically mean the application is vulnerable if local logout is the documented behavior and the residual sessions are handled appropriately.

### 7. OpenID Connect (OIDC) Logout

OpenID Connect adds an identity layer to OAuth 2.0 and is commonly used for modern SSO, as established in Phase 7. OIDC deployments may use RP-initiated logout, front-channel logout, back-channel logout, or local application logout without federated logout. The relying party (RP) is the application that relies on the identity provider for authentication.

**A. RP-initiated logout.** The application initiates a logout request to the identity provider, potentially using an OIDC end-session endpoint. Depending on the provider and implementation, the request may contain parameters such as `id_token_hint`, `post_logout_redirect_uri`, and `state`, each with specific protocol semantics. The application must use the provider's supported configuration and validate redirect destinations appropriately. A successful redirect to the IdP's logout endpoint does not, by itself, prove that the user's IdP session or all application sessions have been terminated. The complete behavior must be verified.

**B. Front-channel logout.** Front-channel logout uses the browser to help notify participating applications that a user is logging out. This creates dependencies on browser behavior, application endpoints, and session correlation. The implementation must be evaluated against its protocol and deployment requirements. Do not assume that a notification was successfully processed simply because a browser navigated to a logout-related URL.

**C. Back-channel logout.** Back-channel logout allows the identity provider to notify a relying party through a direct server-to-server mechanism. An OIDC Back-Channel Logout Token is a specific protocol artifact. Its validation requirements must be implemented correctly. An application must not accept an arbitrary request claiming that a user has logged out. It must validate the logout token according to the applicable OIDC specification, including the relevant issuer, audience, signature, timing, and event requirements. The application must also associate the notification with the appropriate sessions. A validated logout notification should trigger the intended session invalidation behavior.

**Important distinction.** OIDC logout mechanisms coordinate different pieces of session state. They do not automatically erase every token, revoke every independently issued credential, or invalidate every session in every connected service. The deployment must define what is terminated, how termination is communicated, and what happens when a participant cannot complete logout.

### 8. The Dangerous Case: Logout Notification Is Ignored

Consider a fictional application that supports OIDC back-channel logout. The IdP sends a valid logout notification for a user. The application receives it but does not invalidate the corresponding session. The user has already clicked logout from the identity provider, but the application's original session remains active. If that session can still access protected resources, and the application's policy requires it to be invalidated, this is a genuine session-revocation failure.

**Source-code review.** A suspicious implementation:

```python
def handle_backchannel_logout(request):
    payload = decode_token(request.body)

    return {"status": "logout received"}, 200
```

This is unsafe as a complete implementation because it does not demonstrate cryptographic token validation, issuer and audience validation, validation of the required logout event, or session correlation, and it does not invalidate any session. This example is deliberately incomplete, real OIDC logout-token validation is more specific than simply decoding a token.

**A safer conceptual structure:**

```python
def handle_backchannel_logout(request):
    token = extract_logout_token(request)

    claims = validate_oidc_logout_token(
        token,
        trusted_issuer=CONFIGURED_ISSUER,
        expected_audience=CONFIGURED_CLIENT_ID
    )

    validate_logout_event(claims)

    affected_sessions = find_sessions_for_logout_event(claims)

    invalidate_sessions(affected_sessions)

    record_logout_event(claims)

    return success_response()
```

These helper functions represent required responsibilities, not drop-in library calls. Their implementations must follow the relevant OIDC specification and the identity provider's configuration.

**What must be validated?** At a high level, the relying party must validate the token and required logout claims according to the OIDC Back-Channel Logout specification: the relevant signature and trusted issuer, audience, time-related claims, the logout event claim, subject and/or session identifiers where applicable, and required claim relationships and replay-handling rules. The application must then identify the correct local sessions and invalidate them. A correctly signed token is not automatically sufficient if it is intended for another client, lacks the required logout semantics, or cannot be safely associated with the relevant sessions.

### 9. Session Correlation: Which Session Should Be Terminated?

Federated logout can fail because the application cannot reliably determine which local session belongs to the identity-provider session being terminated. Consider one IdP session with three application sessions across different clients: Session A on Browser 1, Session B on Browser 2, Session C on a mobile client. The application must have a defined policy for handling these sessions when a logout event arrives: terminating a specific federated session, terminating all local sessions associated with the relevant identity, or terminating only sessions associated with a particular client or session identifier. The correct behavior depends on the protocol, identity provider, and application requirements. The important thing is that session correlation must be reliable.

**Dangerous implementation patterns.**

*Pattern 1: matching only an email address.* An application receives a logout event and searches for sessions by email address alone. This may be insufficient, particularly when users can change email addresses, multiple identity providers are supported, or local accounts are linked to external identities. A more robust design maintains explicit relationships between trusted external identities and local sessions, echoing the issuer-plus-subject binding principle from Phases 7, 10, and 11.

*Pattern 2: using an untrusted user ID.* The application accepts a request containing `{"user_id": "1042"}` and terminates that user's sessions without authenticating the origin or validating the protocol message. That is not a safe federated logout mechanism. The application must not treat arbitrary client-supplied identifiers as trusted identity-provider instructions.

*Pattern 3: invalidating only one of several applicable sessions.* The application invalidates the session identifier it happens to find first, while other sessions that should also be revoked remain active. Whether this is a defect depends on the intended scope of the logout operation.

*Pattern 4: revoking the wrong account's sessions.* A session-correlation bug can have consequences beyond incomplete logout. If the application confuses identities or session mappings, it may terminate another user's sessions. That can become an availability or integrity issue, even when it does not enable account takeover.

Testing rule: prove which session was affected and why it should have been affected.

### 10. Account Switching and Identity Persistence

This is a subtle but important SSO issue. Imagine a shared workstation used by two employees. Employee A signs into an application through an identity provider, then logs out of the application but remains signed into the IdP. Employee B then uses the same browser and selects "Sign in with SSO." The identity provider silently authenticates Employee A. The application opens Employee A's account. Employee B may now be viewing someone else's data without having stolen a password. This can be a serious exposure on shared devices. However, the root cause is not necessarily an authentication bypass. It may be a mismatch between the application's account-switching experience and the IdP's persistent-session behavior.

**How should account switching work?** A system may provide an explicit "sign out of all accounts" option, an IdP logout flow, an account chooser, a fresh-authentication requirement for sensitive actions, a warning that the identity-provider session remains active, or a policy that prevents account switching on designated shared devices. These mechanisms serve different purposes. An account chooser does not necessarily terminate the old session. A local logout does not necessarily sign out of the IdP. A fresh-authentication requirement does not automatically guarantee that the user selected the correct account.

**Safe assessment.** In an authorized staging environment, use two controlled test accounts: sign in as Account A, perform the documented logout flow, begin a new login, observe whether the IdP reuses Account A's session, determine whether the user can explicitly choose Account B, check whether the application communicates the actual logout behavior, verify that Account A's old application session has been invalidated, and avoid accessing real users' data or performing sensitive operations. The finding depends on the system's intended behavior and the demonstrated exposure.

### 11. Persistent Authentication: "Remember Me" and Long-Lived Identity

Not all persistent authentication comes from federated sessions. An application may offer a "Remember me" feature, a persistent device credential, or a long-lived refresh token. These mechanisms can keep a user authenticated after the ordinary session ends. They should be assessed separately from the IdP's own session:

```text
User authenticates
       |
       v
Application session created
       |
       +----> Session expires
       |
       +----> Persistent credential remains valid
                         |
                         v
                 New session issued
```

If the persistent credential is still valid, the application may create a new session. That is not necessarily a logout defect. The feature may be designed to restore authentication. But the system must define what logout means for each credential type, extending the remember-me revocation principles from Phase 6.

**What should be checked?** Does logout revoke the persistent credential, or only the current session? Is that behavior documented and consistent with user expectations? Can a persistent credential be revoked remotely? Are persistent credentials rotated where appropriate? Does account recovery invalidate them when required? Are disabled accounts prevented from using them? Are sensitive actions subject to additional authentication requirements? Is the credential stored and transmitted securely? A common mistake is to invalidate the ordinary session while leaving a long-lived authentication credential usable when the intended policy requires it to be revoked. Another mistake is to classify every still-valid persistent credential as a vulnerability even when the application deliberately preserves it and clearly defines the behavior.

### 12. Password Reset, MFA Changes, and Federated Session Persistence

Federated logout is closely connected to account lifecycle security. Consider a user who suspects their account has been compromised. They change their password, replace their MFA authenticator, click logout, and expect the attacker to lose access. But the attacker may still have an application session, a persistent login credential, a session at the identity provider, a refresh token, or an independent session in another connected application. These are distinct credentials or session states. Changing a password does not automatically invalidate every token or every federated session in every architecture. The application and identity provider must define and implement their respective revocation policies, extending the session-revocation discipline from Phase 2 into the federated context.

**What a robust design should consider.** After a high-risk account change, the system should determine which existing credentials need to be invalidated, potentially including application sessions, remembered-device credentials, refresh tokens, recovery tokens, active IdP sessions, sessions in connected applications, and API credentials or other independently issued secrets. Not every credential must always be revoked after every event. The appropriate behavior depends on the credential type, threat model, and security policy.

**Testing scenario.** Use a controlled account in staging: authenticate through SSO, establish the applicable application and IdP session states, perform an approved password change or account-recovery operation, record the documented revocation policy, test the original application session, test whether a new session can be created from persistent credentials, where authorized test the documented federated logout behavior, and record which credentials remain valid and whether that behavior violates policy. Do not claim that an account is fully compromised merely because one session remains active. Identify the actual access that the session permits.

### 13. Front-Channel Versus Back-Channel Logout: A Practical Comparison

| Property | Front-channel logout | Back-channel logout |
|---|---|---|
| Communication path | Browser-mediated | Direct server-to-server notification |
| Browser involvement | Yes | Not required for the notification |
| Main dependency | Browser and participating application behavior | Correct server-side token validation and session correlation |
| Common failure concern | Notification not delivered or not processed as expected | Notification rejected incorrectly or processed without invalidating the correct sessions |
| Session correlation | Must associate notification with appropriate local sessions | Must associate validated logout token with appropriate local sessions |
| Does it automatically invalidate every credential? | No | No |

Neither mechanism is a universal solution to session management. The security outcome depends on correct configuration, protocol compliance, application behavior, and credential lifecycle management.

### 14. Logout Redirects and Return Destinations

Logout flows often involve redirects, for example `302 Found` to `https://identity.example.test/logout`. After logout, the identity provider may redirect the browser back to an application URL. The return destination must be handled according to the provider's supported logout protocol. An unsafe implementation might accept an arbitrary return destination, such as `/logout?return_to=https://untrusted.example.test`. If the application or identity provider redirects users to untrusted destinations without appropriate validation, the result may be an open-redirect vulnerability. This is not the same as a session-revocation flaw. It is an adjacent weakness in logout-flow handling. A redirect issue may be exploitable for phishing or related attacks, depending on the application's behavior and trust relationships. Do not automatically claim that it leaks authentication credentials or enables account takeover.

For federated logout: use registered or otherwise appropriately validated return destinations, follow the identity provider's protocol requirements, avoid placing sensitive authentication material in redirect parameters, and do not treat a redirect to a logout page as proof that logout completed.

### 15. What to Look for in Source Code

When reviewing a federated authentication implementation, trace the full logout path. Search conceptually for local logout handlers, identity-provider logout initiation, SAML logout request and response processing, OIDC end-session handling, OIDC back-channel logout handlers, session stores and invalidation functions, refresh-token revocation, persistent-device credential management, session-to-identity mapping, and account suspension and password-change hooks. The important question is not merely whether a logout function exists. It is whether the function invalidates the right credentials and sessions according to the intended policy.

**Example: weak logout handler.**

```python
def logout(session_id):
    clear_browser_cookie()
    return redirect("/")
```

This illustrates a potential concern: it does not show server-side invalidation. However, the actual implementation might invalidate the session in middleware, a response hook, or another component. Never conclude that server-side invalidation is absent until you trace the full call path.

**Example: stronger conceptual design.**

```python
def logout(session_id, logout_scope):
    session = find_session(session_id)

    if session is not None:
        invalidate_session(session.id)

    clear_session_cookie()

    if logout_scope.requires_federated_logout:
        initiate_configured_federated_logout(session)

    record_logout_result(session, logout_scope)

    return appropriate_logout_response()
```

This is illustrative pseudocode, not a complete implementation. A production system would need robust session handling, safe protocol construction, appropriate validation, error handling, and a clear policy for what happens if federated logout cannot complete. The application should distinguish local session termination, federated logout initiation, confirmed federated logout where the protocol supports such confirmation, and sessions or credentials that remain active under the documented policy. It should not report complete global logout when it has only cleared one local cookie.

### 16. Authentication Logging and Logout Monitoring

Logout events are security-relevant. A system should be able to distinguish user-initiated local logout, federated logout initiation, federated logout completion or failure, session invalidation, refresh-token revocation, administrative session termination, failed logout-token validation, and rejected or uncorrelated logout notifications. These records can help incident responders determine whether sessions were terminated and investigate unexpected access. However, logs must not contain reusable session credentials, bearer tokens, passwords, or recovery tokens, extending the safe-logging discipline from Phase 12.

**What should a tester verify?** Whether logout events are recorded appropriately, whether failed logout processing is visible to administrators, whether the application can correlate relevant sessions without exposing secrets, whether session invalidation results can be investigated, and whether monitoring distinguishes a logout attempt from successful invalidation. A log entry stating `logout_success=true` is not proof that every applicable session was actually invalidated. Verify the underlying behavior.

### 17. Comprehensive Testing Workflow

Use this workflow for an authorized SSO assessment.

**Phase 1: map the authentication architecture.** Identify the IdP, each application relying on it, local application sessions, persistent authentication credentials, supported logout mechanisms, and account recovery and session-revocation rules.

**Phase 2: establish the expected policy.** Determine what each logout action promises to do.

| Action | Expected outcome |
|---|---|
| Local application logout | End the current application session |
| Global IdP logout | End the IdP session according to provider behavior |
| Password change | Apply the documented session-revocation policy |
| Account disablement | Prevent authentication and handle existing sessions as specified |
| Administrative revoke-all | Invalidate the targeted user's applicable sessions |
| MFA replacement | Apply the defined policy for existing sessions and trusted devices |

**Phase 3: observe the normal flow.** Capture the relevant HTTP exchanges and redirects. Record the session cookies involved, which host receives each request, whether local and federated logout mechanisms are invoked, whether the application receives a logout notification, and which responses indicate success or failure. Redact all authentication secrets.

**Phase 4: test local session invalidation.** Verify that the old application session is rejected after logout if policy requires it. Do not rely solely on cookie deletion or a redirect.

**Phase 5: test IdP session behavior.** Determine whether the IdP session persists and whether automatic reauthentication is intended. Do not confuse this with reuse of the old application session.

**Phase 6: test cross-application logout.** Where the deployment claims to support federated logout, use controlled accounts across participating applications. Verify that the relevant sessions are terminated according to the documented scope.

**Phase 7: test lifecycle events.** Where authorized, examine session behavior after password change, account recovery, account disablement, and MFA replacement.

**Phase 8: validate findings.** For every suspected weakness: establish the intended policy, reproduce the behavior using controlled accounts, verify the actual authenticated access, exclude caching and automatic reauthentication as alternative explanations, establish the impact, and document limitations and uncertainty.

### 18. Severity: How to Report Federated Logout Flaws

Do not report every logout inconsistency as critical. Severity depends on what remains accessible, to whom, and under which circumstances.

| Finding | Impact considerations |
|---|---|
| Local session remains usable after logout | Potential unauthorized continued access; depends on intended revocation policy and accessible resources |
| IdP session persists after local logout | May be expected behavior; risk increases when it violates explicit logout expectations or exposes a shared device |
| Back-channel logout notification is ignored | Potential session persistence across applications if the policy requires invalidation |
| Another user's session is terminated | Potential availability or integrity impact |
| Old page remains visible after logout | May be browser caching; establish whether live protected access remains |
| User is silently authenticated again | Distinguish persistent IdP authentication from survival of the old application session |
| Logout redirects to an untrusted destination | Potential redirect abuse; assess separately from session invalidation |

**Example report.** Title: Application session remains valid after required federated logout. Description: in the authorized staging environment, the application is configured to invalidate the relevant application sessions following a successful federated logout. The tested logout flow completes, but the previously issued application session remains usable against a protected resource. Evidence: the original session accesses the protected test resource before logout. After the documented federated logout sequence, the same session credential continues to access that resource. Impact: a person possessing the old session credential may retain access after the logout event that should have invalidated it. The severity depends on the privileges associated with the session and the resources it can access. Recommendation: correct the session-correlation and invalidation logic, verify that the logout event is validated according to the relevant protocol, and add regression tests covering logout across all participating applications. This example is appropriate only if the observed behavior and policy are actually established.

### 19. Final Knowledge Check

Use these as self-assessment prompts.

**Scenario A.** A user logs out of an application. The old application cookie is rejected when reused. The user revisits the application and is silently signed in through the identity provider. Correct interpretation: the original application session appears to have been invalidated. The IdP session may still be active, allowing new authentication. Determine whether that behavior violates the expected logout policy.

**Scenario B.** A user logs out. The application deletes the cookie, but the same session credential continues to access protected resources. Correct interpretation: this may be a session-invalidation failure if logout is supposed to revoke that session. Confirm that the response represents live authenticated access and not cached or public content.

**Scenario C.** An OIDC back-channel logout token is received, but the application simply decodes it and returns success without validating it or invalidating sessions. Correct interpretation: the implementation is unsafe. The exact exploitability depends on whether untrusted notifications can be accepted and whether relevant sessions remain active. Both token validation and session invalidation must be examined.

**Scenario D.** A SAML application does not implement Single Logout, but local logout works and the deployment does not promise global logout. Correct interpretation: the absence of SLO is not automatically a vulnerability. Assess the intended policy, residual sessions, and user expectations.

**Scenario E.** A page remains visible after logout, but the server rejects the old session and does not serve the protected resource again. Correct interpretation: the visible page alone does not prove an active session. Investigate browser caching and sensitive-data exposure separately.

**Scenario F.** A user changes their password, but an old session remains valid. Correct interpretation: determine the application's session-revocation policy. If password changes are required to invalidate existing sessions, and the old session still grants access, this may be a session-lifecycle vulnerability.

## Assessment

Unlike most of the prior phases, this phase has no separate instructor-graded challenge transcript to draw an assessment from. The module conveniently ends with its own Final Knowledge Check, section 19 above, six short scenarios already paired with correct interpretations in the original source. The two exercises below select the two scenarios that most directly test the module's central distinction, live authenticated access versus a merely plausible-looking signal, using the module's own given reasoning as the answer.

### Assessment Question 1

A user logs out of an application. The old application cookie is rejected when reused against a protected endpoint. The user then revisits the application and is silently signed in again, without entering a password, through the identity provider. Has logout failed? What is actually happening, and what would you still need to determine before calling this a vulnerability?

<details markdown="1">
<summary><strong>Reveal Answer</strong></summary>

Logout has not necessarily failed. The evidence that the old application cookie was rejected when reused is strong, direct evidence that the original application session was actually invalidated server-side, not merely that the browser's copy of the cookie was deleted. That is the application doing exactly what local logout is supposed to do.

What is happening on the second visit is a separate mechanism entirely: the identity-provider session is apparently still active, so when the application redirects the browser back to the IdP as part of a fresh SSO attempt, the IdP recognizes the existing session and authenticates the user again without a password prompt, and the application then issues a brand new session. This is not the old session surviving, it is a new session being created through normal SSO behavior, because the IdP's own session was never terminated.

Before calling this a vulnerability, you would need to determine whether that behavior actually violates the expected logout policy. Many systems deliberately preserve the IdP session after a local logout specifically so users can move between applications without re-authenticating at every one, and that is a legitimate, intentional design choice, not a defect. The question that actually determines whether this is a finding is whether the application or the overall deployment promises a complete, global sign-out, and whether the circumstances, for example a shared or public device, make silent reauthentication a meaningful exposure rather than a convenience feature working as designed.

</details>

### Assessment Question 2

An OIDC back-channel logout token is received by an application. The handler decodes the token and immediately returns a success response, without validating the token's signature, issuer, or audience, and without invalidating any session. Is the implementation safe? What exactly needs to be examined before you can state the actual exploitability, and why is decoding the token not the same as validating it?

<details markdown="1">
<summary><strong>Reveal Answer</strong></summary>

No, the implementation is unsafe as described. An application must not accept an arbitrary request merely claiming that a user has logged out, it must validate the logout token according to the applicable OIDC Back-Channel Logout specification before trusting anything it claims. Decoding a token only extracts its claims as data, it establishes nothing about whether those claims are genuine, who issued them, who they were intended for, or whether they represent a legitimate, current logout event, exactly the same decode-is-not-validate distinction examined for ID tokens in Phase 7 and SAML assertions in Phase 10. A handler that decodes and immediately returns success, with no signature check, no issuer check, no audience check, and no session invalidation at all, provides no actual security guarantee regardless of how the response looks to the identity provider sending the notification.

Two separate things must be examined before stating the actual exploitability. First, token validation: whether the signature is checked against a trusted key, whether the issuer matches the configured, trusted identity provider, whether the audience matches this specific client, whether time-related claims and the required logout-event claim are checked, and whether subject or session identifiers are validated as applicable. Second, session invalidation: even if validation were implemented correctly elsewhere in the call path, you still need to confirm that a validated logout notification actually results in the correct local sessions being found and invalidated, since a correctly signed token is not automatically sufficient if it cannot be safely associated with the relevant sessions. The exact severity depends on whether an untrusted or forged notification could be accepted at all, and, separately, whether sessions that genuinely should have been terminated by a legitimate logout event remain active because the invalidation step never runs. Both halves, validation and invalidation, need to be traced independently before concluding what the real-world impact is.

</details>

## Remediation and Secure Implementation

The following consolidates the remediation guidance across all nineteen sections of this phase.

1. Explicitly document what each logout action promises for every credential type it can affect, application session, IdP session, persistent device credential, refresh token, and connected-application sessions, so that "logout" has one clear, testable meaning rather than an assumed one.
2. Invalidate the application session server-side as part of logout, not merely by instructing the browser to delete its cookie, and verify this by replaying the old session against a protected endpoint after logout completes.
3. Validate every OIDC back-channel logout token against the full specification, signature, trusted issuer, audience, timing, and the required logout-event claim, before invalidating any session on its behalf, and never accept an arbitrary client-supplied user or session identifier as a trusted logout instruction.
4. Build session correlation on an explicit, trustworthy relationship between the federated identity and local sessions, never on a mutable attribute like email alone, and verify that a logout event invalidates every session it is supposed to, not merely the first one found.
5. For SAML Single Logout, ensure the service provider actually initiates and completes the configured logout flow rather than silently falling back to a local-only session deletion, and communicate accurately when logout only partially succeeds.
6. Design account-switching and shared-device scenarios deliberately, with an explicit account chooser, an IdP logout option, or a policy restriction, rather than letting a persistent IdP session silently reauthenticate whoever uses the browser next.
7. Define and enforce a revocation policy for persistent "remember me" credentials and refresh tokens separately from the ordinary session, including whether logout revokes them and whether they survive a password reset or MFA change.
8. After a high-risk account event, password reset, MFA replacement, suspected compromise, explicitly decide and implement which credential types must be invalidated, application sessions, persistent credentials, refresh tokens, IdP sessions, and connected-application sessions, rather than assuming one revocation covers all of them.
9. Validate logout return destinations and redirect parameters against a registered or otherwise trusted set of values, treating open-redirect risk in the logout flow as a distinct weakness from session-revocation failures.
10. Log logout-relevant events with enough detail to distinguish an attempted logout from a confirmed invalidation, without recording reusable session credentials, bearer tokens, or other secrets, and do not treat a `logout_success=true` log entry as proof that invalidation actually occurred.

## Key Takeaways

This phase's governing principle is the one stated plainly in its own introduction: a user clicking Logout and the system still knowing who they are, or silently authenticating them again, is sometimes intended behavior and sometimes a serious vulnerability, and the job of an AppSec engineer is to tell the two apart. That distinction is hard specifically because SSO creates three independent authentication states at once, an IdP session, an application session, and whatever the browser is holding, and logout is not automatically one action that ends all three together unless the system was deliberately built to coordinate that.

Nearly every finding in this module traces back to the same evidentiary discipline carried through every earlier phase: a `302` redirect, a cleared cookie, a "logout received" response, or a visible logged-out page is a lead, never proof. The only thing that actually establishes whether logout worked is replaying the old credential against a protected endpoint and confirming, concretely, whether it still grants live authenticated access, and separately, whether an apparent re-authentication is a surviving old session or a brand new one created through a persistent IdP session working exactly as designed. Carrying that same distinction forward, session persistence is not the same thing as automatic reauthentication, is the single most transferable skill this phase teaches.

## Review Checklist

- [ ] Can you name the three independent sessions involved in an SSO deployment and explain why removing one does not remove the others?
- [ ] Can you distinguish local logout, IdP logout, single logout, and global session revocation as four non-interchangeable behaviors?
- [ ] Can you explain why a `302` redirect with a cookie-clearing instruction does not by itself prove server-side session invalidation?
- [ ] Can you distinguish a rejected old cookie, a working old cookie, immediate SSO re-authentication, and a cached page as four different findings requiring different evidence?
- [ ] Can you list the four ways SAML Single Logout coordination can fail?
- [ ] Can you distinguish OIDC RP-initiated, front-channel, and back-channel logout, and state what a back-channel logout token must be validated against?
- [ ] Can you identify the four dangerous session-correlation patterns that can cause federated logout to affect the wrong session?
- [ ] Can you explain the shared-device account-switching exposure, and why its root cause is a design mismatch rather than a stolen credential?
- [ ] Can you explain why a password reset does not automatically revoke every credential type, and list at least four distinct credential types that might survive it?
- [ ] Can you distinguish a session-revocation flaw from a logout-redirect open-redirect flaw, and explain why they require separate evidence?
- [ ] Can you walk through the module's 8-phase testing workflow from architecture mapping to impact validation?
- [ ] Can you correctly interpret all six scenarios in the module's Final Knowledge Check without looking at the given answers?

## References to Related Phases

- The SAML Single Logout mechanics in section 6 directly extend the assertion validation, trust configuration, and session binding principles established in **Phase 10, SAML Security**.
- OIDC logout mechanisms in sections 7 and 8, including back-channel logout token validation, build on the ID-token and trust-boundary discipline from **Phase 7, OAuth 2.0 and OpenID Connect Security**.
- Session correlation and the issuer-plus-subject identity-binding principle referenced in section 9 connects to the external-identity binding problems examined in **Phase 11, Multi-Tenant Identity Isolation**.
- Persistent "remember me" credentials and session revocation after a password change, covered in sections 11 and 12, extend **Phase 6, Cookie and Session Security** and **Phase 2, Password Change and Account Recovery**.
- Logging logout events safely, covered in section 16, extends the secure-logging discipline from **Phase 12, Authentication Information Leakage**.
