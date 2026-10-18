# Phase 6: Cookie and Session Security

**Source material:** Module 6 of 17, "Authentication Complete Phases Test.md" (the 17 numbered sections of Cookie and Session Security, the Module 6 progress table, and the overall course tracker), with supplementary assessment material drawn from "Authentication Security.md" (Challenge 13, Challenge 14, Challenge 15, and Challenge 16).

## Learning Objectives

After completing this phase, you should be able to:

1. Distinguish authentication, sessions, and cookies as three related but non-interchangeable concepts, and explain why seeing an authentication cookie does not by itself tell you anything about session security.
2. Walk through the full session lifecycle state machine and explain why each transition in it must be enforced by the server, not merely represented by client-side state.
3. Explain what session fixation is, why it happens, and design a correct test for it that does not get confused with ordinary authentication-enforcement testing.
4. Explain what makes a session ID suitable as a bearer credential, and identify unsafe session ID generation from source code.
5. Explain what each cookie security attribute, `Secure`, `HttpOnly`, `SameSite`, `Path`, `Domain`, `Max-Age`/`Expires`, and the `__Host-`/`__Secure-` prefixes, actually does and does not protect against.
6. Distinguish idle timeout, absolute timeout, and sliding expiration, and explain why a defensible policy often combines more than one.
7. Prove, rather than assume, whether logout actually invalidates a session server side, and distinguish cached browser display from live server access.
8. Explain why session rotation matters beyond initial login, and identify the specific privilege transitions that should trigger it.
9. Explain why a password reset or MFA change does not automatically revoke existing sessions unless the application deliberately implements that behavior, and describe session versioning as one architecture for doing so.
10. Evaluate concurrent session and "log out all devices" functionality for the specific ways its promised behavior can silently fail.
11. Identify partial authentication and session-state confusion from source code, where an endpoint checks for session existence rather than the specific authentication state it actually requires.
12. Distinguish server-side sessions from stateless sessions architecturally, without assuming either one is automatically more secure.
13. Apply the Phase 1 through Phase 5 impact-validation discipline to session security: separate what source code shows from what you have actually proved through testing.

## Introduction

Every phase so far has studied how an application verifies who someone is, at the moment they prove it: a password, a second factor, a passkey. This phase studies what happens immediately afterward. Logging in proves who you are at a particular moment. A session determines whether the application continues to recognize you as authenticated afterward. An application can implement password authentication, MFA, and even passkeys correctly, and still allow attackers to impersonate users because its session management is broken.

This phase covers session IDs, cookies, fixation, hijacking defenses, session rotation, expiration, logout, revocation, and partial-authentication bugs. The recurring discipline carried over from every prior phase applies with particular force here: a cookie attribute, a changed session ID, or a logout button are all surface-level signals, not proof. The decisive question, asked again and again throughout this phase in slightly different forms, is always the same one: does the server still accept this credential, regardless of what the browser displays or what the client claims?

## Core Concepts

The module moves through four stages. First, sections 1 and 2 establish vocabulary: the distinction between authentication, sessions, and cookies, and the session lifecycle as a state machine whose transitions the server must enforce. Second, sections 3 through 7 examine the session credential itself and its transport: fixation, hijacking and ID quality, the full set of cookie security attributes, and the two major expiration models. Third, sections 8 through 12 examine the events that should change a session's trust, privilege elevation, password resets and MFA changes, concurrent sessions and account-wide revocation, and the specific failure of treating session existence as proof of sufficient authentication. Fourth, sections 13 through 17 bring the module together into a practical discipline: a source-code review exercise, a complete testing checklist, common false positives, and how to write a session-security finding.

## Lessons

### 1. Understand the Difference Between Authentication, Cookies, and Sessions

These concepts are related, but they are not interchangeable.

**Authentication** is the process of verifying a user's identity. For example, the user submits an email and password, the server verifies the credentials, determines they are valid, and the application establishes an authenticated state.

**Session.** A session is the mechanism through which an application maintains state across multiple HTTP requests. HTTP is stateless by default, a server generally does not automatically know that two requests came from the same authenticated user. A session mechanism solves this problem. For example, the server might maintain this illustrative record:

```text
Session ID: 8f2c...a91d
User ID: 1042
Authenticated: true
MFA verified: true
Created: 10:00
Last activity: 10:12
Expires: 18:00
Revoked: false
```

**Session ID.** The session ID is an identifier that allows the application to locate or recognize a particular session. It should be generated using a cryptographically secure random number generator and must be difficult to guess. The session ID is not the user's password, but it can function as a bearer credential: whoever possesses a valid session ID may be able to act as the authenticated user. That makes it sensitive.

**Cookie.** A cookie is one way for the browser to store and transmit the session ID. For example:

```http
HTTP/1.1 200 OK
Set-Cookie: __Host-session=RANDOM_SESSION_VALUE; Path=/; Secure; HttpOnly; SameSite=Lax
```

On a subsequent request, the browser may send:

```http
GET /account HTTP/1.1
Host: example.test
Cookie: __Host-session=RANDOM_SESSION_VALUE
```

The server uses the presented value to locate and validate the session. A cookie is a browser storage and transmission mechanism. A session is the authentication state the application maintains. They are not the same thing. An application can also store session credentials in other ways, but putting session IDs in URLs is generally unsafe.

**Why this matters to a security tester.** When you see an authentication cookie, do not immediately conclude that authentication is secure. You need to establish how the session ID is generated, whether it changes after authentication, whether the server validates the session correctly, whether the session expires, whether logout actually invalidates it, whether privilege changes cause appropriate session rotation, and whether sensitive account changes revoke old sessions. These questions guide the rest of this module.

### 2. Understand the Session Lifecycle

A secure session has a lifecycle, not merely a cookie. Consider this state machine:

```text
ANONYMOUS
    |
    | Successful password authentication
    v
PASSWORD VERIFIED
    |
    | Required MFA succeeds
    v
AUTHENTICATED SESSION
    |
    | Sensitive privilege change
    v
SESSION ROTATED
    |
    | Logout / expiry / revocation
    v
INVALID SESSION
```

This is a simplified model. Real applications may have additional states, such as pending MFA, password-reset-required, or step-up authentication. The key lesson is that each transition must be enforced by the server. For example, after a user submits the correct password but has not completed required MFA, the application must not accidentally grant the same privileges as a fully authenticated session. Likewise, logging out must invalidate the relevant session according to the application's security policy. A session should not remain valid merely because a browser still possesses its cookie.

### 3. Session Fixation

**What is session fixation?** Session fixation occurs when an attacker can cause a victim to authenticate using a session identifier that the attacker already knows or can predict. The danger is that the victim authenticates, but the session identifier does not change. The attacker may then be able to reuse that same identifier.

**Simulated vulnerable flow.** Suppose a poorly designed application accepts an attacker-controlled or otherwise known session ID before login.

Step 1, an unauthenticated session exists:

```http
HTTP/1.1 200 OK
Set-Cookie: sessionid=KNOWN_VALUE; Path=/
```

Step 2, the victim logs in:

```http
POST /login HTTP/1.1
Host: example.test
Cookie: sessionid=KNOWN_VALUE
Content-Type: application/x-www-form-urlencoded

username=victim&password=CORRECT_PASSWORD
```

Step 3, the application authenticates the user but reuses the ID:

```http
HTTP/1.1 302 Found
Location: /dashboard
Set-Cookie: sessionid=KNOWN_VALUE; Path=/
```

The server has now associated a session identifier known to the attacker with an authenticated user. If the attacker can submit that identifier and the server accepts it, the attacker may gain access to the victim's session. This is a simulated example, not evidence of a real vulnerability.

**Why does fixation happen?** Common causes include reusing the anonymous session ID after login, accepting client-selected session IDs without safe handling, failing to rotate the session after authentication, migrating anonymous session data into an authenticated session without replacing the identifier, and preserving an old session across privilege elevation.

**What does the secure implementation do?** The server creates a fresh session ID after successful authentication:

```text
Before login:
sessionid = ANONYMOUS_ID

After successful login:
sessionid = NEW_RANDOM_AUTHENTICATED_ID
```

The old identifier must no longer provide access to the newly authenticated session. A simplified implementation might look like this:

```python
def login(username, password):
    user = verify_credentials(username, password)

    if not user:
        return unauthorized()

    # Never promote the old session ID into an authenticated session.
    invalidate_current_session_if_present()

    new_session = create_cryptographically_random_session(
        user_id=user.id,
        authenticated=True
    )

    return set_secure_session_cookie(new_session.id)
```

This is illustrative pseudocode, not a drop-in implementation. The actual code must correctly handle session storage, cookie creation, errors, and concurrent requests.

**Senior-level nuance.** Session rotation is not simply generating a new cookie value. The server must also ensure that the old identifier cannot continue to access the new authenticated state. If the server creates a new cookie but leaves the old session fully authenticated, the security objective has not been achieved. The old session should be invalidated or stripped of the sensitive state as appropriate.

**How do you test for fixation?** In an authorized test environment: start with an anonymous session, record its session ID, authenticate normally, check whether the session ID changes, if it changes determine whether the old identifier remains valid, and verify the behavior using only your own test account. A changing session ID is a useful security signal, but not conclusive proof of safety. Likewise, an unchanged cookie value is a warning sign, but you must establish whether the session was actually reused and whether an attacker could control or know that identifier. Do not report a critical session-fixation vulnerability merely because the cookie does not visibly change. Demonstrate the unsafe session lifecycle and realistic exploitability.

### 4. Session Hijacking and Session ID Quality

**What is session hijacking?** Session hijacking occurs when an attacker obtains or successfully reuses another user's valid session credential. The attacker may then access the victim's account without needing the victim's password. This is especially serious because the application's normal login controls may not be invoked when the attacker presents an already-valid session.

**Common exposure routes.** A session ID may be exposed through unencrypted network communication, browser or endpoint compromise, application or proxy logs that record sensitive cookies, debugging output or monitoring systems, insecure session storage, predictable or insufficiently random session IDs, improper session sharing between users or tenants, or a session token accidentally exposed through a URL or other observable channel. The important distinction is between obtaining a token and being able to use it. A leaked identifier is exploitable when the server accepts it and the attacker can satisfy any additional requirements. This module focuses on session management itself, not on exploiting browser vulnerabilities.

**Session ID randomness.** A session ID must be generated using a cryptographically secure random number generator. It should not be derived from a username, a sequential database ID, a timestamp, an email address, a predictable combination of user information, or a conventional pseudorandom generator unsuitable for security credentials. For example, this is unsafe:

```python
session_id = str(user.id) + str(current_timestamp())
```

An attacker may be able to infer or enumerate the resulting values. A safer conceptual approach is:

```python
import secrets

session_id = secrets.token_urlsafe(32)
```

This uses Python's `secrets` module to generate a security-oriented random token. With 32 random bytes, the underlying token contains 256 bits of randomness. Its URL-safe text representation is longer than 32 characters. The random source and generation method matter more than simply making a token look complicated.

**Why entropy matters.** Entropy describes uncertainty. A session ID with insufficient entropy may be vulnerable to guessing if an attacker can make enough attempts. However, you should not assume that a token is weak just because it is short, nor assume it is secure just because it is long. Evaluate how it is generated, how many unpredictable bits it contains, whether identifiers are unique, whether the application limits and monitors invalid attempts, whether the token is exposed elsewhere, and whether server-side validation is correct. Rate limiting is an additional defense, not a substitute for sufficiently unpredictable session IDs.

**Never put session IDs in URLs.** Consider:

```text
https://example.test/dashboard?sessionid=SECRET_VALUE
```

This is dangerous because URLs can appear in browser history, logs, analytics, screenshots, copied links, and other systems. Prefer a secure cookie or another appropriately designed credential-transport mechanism. Also avoid recording raw session IDs in application logs. If session correlation is necessary, use an appropriately designed non-reversible or access-controlled identifier rather than exposing the credential itself.

### 5. Cookie Security Attributes

Cookie attributes control how browsers store and send cookies. They do not independently prove that the server's session logic is secure. Consider this cookie:

```http
Set-Cookie: __Host-session=RANDOM_VALUE; Path=/; Secure; HttpOnly; SameSite=Lax
```

**`Secure`.** The browser is instructed to send the cookie only over secure HTTPS connections, subject to browser behavior and cookie rules. Why it matters: it helps prevent the cookie from being transmitted over ordinary HTTP connections. A secure session cookie should generally use HTTPS throughout the application. `Secure` does not encrypt a cookie at rest in every system, and it does not stop a compromised endpoint from accessing the authenticated session.

**`HttpOnly`.** This prevents ordinary client-side JavaScript from reading the cookie through browser APIs such as `document.cookie`. It is a valuable defense for sensitive session cookies. But be precise: `HttpOnly` does not make the cookie impossible to steal in every threat model, and it does not prevent the browser from automatically sending it with applicable requests. It also does not prevent a server-side session-management vulnerability.

**`SameSite`.** Common values include `Strict`, `Lax`, and `None`. At a high level, `SameSite` controls whether a browser sends a cookie in certain cross-site contexts. `Strict` applies the strictest same-site sending policy. `Lax` allows cookies in certain cross-site navigations, with behavior depending on browser rules. `None` permits cross-site cookie sending when the other requirements are satisfied, modern browsers generally require `Secure` with `SameSite=None`. These values affect browser cookie delivery. They are not interchangeable with server-side authentication checks. This module does not cover CSRF.

**`Path`.** For example, `Path=/`. The path attribute determines the URL paths for which the browser sends the cookie. It is a scoping mechanism, not a strong security boundary between applications. Narrowing the path may reduce where a cookie is sent, but it does not replace proper isolation and server-side session validation.

**`Domain`.** For example, `Domain=example.test`. Setting a domain can make a cookie available to matching subdomains, subject to cookie rules. A broader domain scope increases the number of hosts that may receive the cookie. Where practical, avoid setting `Domain` when the cookie does not need to be shared with subdomains. A cookie without a `Domain` attribute is generally host-only.

**`Max-Age` and `Expires`.** These attributes govern the cookie's browser-side lifetime, for example `Set-Cookie: sessionid=VALUE; Max-Age=3600; Secure; HttpOnly`. The browser is instructed to retain the cookie for the specified lifetime. But here is a critical distinction: cookie expiration does not necessarily mean the server-side session has been invalidated. If a copied session ID remains valid in the server's session store, an attacker who already possesses it may still be able to use it. The server must enforce its own session expiration policy.

**`__Host-` and `__Secure-` prefixes.** Modern browsers support special cookie-name prefixes with additional restrictions. A cookie named `__Host-session=VALUE; Path=/; Secure; HttpOnly` must meet the browser's `__Host-` requirements, including that it must be set from a secure context, it must include `Secure`, it must use `Path=/`, and it must not include a `Domain` attribute. This helps constrain the cookie to the setting host rather than allowing domain-wide sharing. The `__Secure-` prefix also requires secure setting conditions, including `Secure`. These prefixes strengthen cookie configuration, but they do not guarantee that the application rotates or revokes sessions correctly.

**Cookie review checklist.**

| Check | What you want to establish |
|---|---|
| `Secure` | Sensitive session cookies are restricted to secure transport. |
| `HttpOnly` | Ordinary client-side JavaScript cannot directly read the cookie. |
| `SameSite` | The cookie's cross-site sending policy matches the intended design. |
| `Domain` | The cookie is not shared more broadly than necessary. |
| `Path` | The cookie is scoped appropriately, without treating path as a strong security boundary. |
| `Max-Age` / `Expires` | Browser persistence matches the application's intended behavior. |
| Prefix | Appropriate `__Host-` or `__Secure-` restrictions are used where suitable. |
| Server validation | The server rejects expired, revoked, invalid, and unauthorized sessions. |

A missing cookie attribute is not automatically a critical vulnerability. Explain the actual exposure and impact.

### 6. Session Expiration: Idle Timeout vs. Absolute Timeout

A session should not remain valid indefinitely without a deliberate security decision. There are two major expiration concepts.

**Idle timeout.** An idle timeout limits how long a session may remain inactive. For example, an idle timeout of 20 minutes with last qualifying activity at 10:00 means the session expires after 10:20. A request does not always count as meaningful activity. For example, background polling or an automatically refreshing page should not necessarily keep a sensitive session alive forever.

**Absolute timeout.** An absolute timeout limits the total lifetime of a session, regardless of activity. For example, an absolute lifetime of 8 hours with session created at 09:00 means absolute expiry at 17:00. Even if the user remains active, the session expires at the absolute deadline unless the application deliberately reauthenticates or establishes a new session.

**Why use both?** Suppose a user logs in and leaves the browser open for two days. With no idle timeout, the session may remain usable long after the user has stopped interacting with the application. Now suppose the application has an idle timeout but resets it for every automated background request, the user may appear continuously active even when they are not. A defensible policy often combines idle expiration, absolute expiration, appropriate reauthentication for sensitive operations, and session revocation when risk changes. Exact timeout values depend on the sensitivity of the application, the threat model, and applicable requirements. Do not claim that one universal timeout is correct for every system.

**Sliding expiration.** A sliding timeout extends the idle expiration when qualifying activity occurs. If each activity event qualifies, the idle deadline may be extended. Sliding expiration is not inherently insecure. The problem arises when sessions can be kept alive indefinitely without an appropriate absolute lifetime or reauthentication policy.

**How do you test expiration?** For an authorized account: authenticate, record the session's expected idle and absolute lifetime, stop interacting with the application, wait for the documented idle timeout, attempt to access a protected resource using the existing session, separately assess absolute expiration where the application specifies it, and confirm whether the server rejects the session, rather than merely whether the browser removes the cookie. Do not confuse a user-interface redirect with proof of server-side expiration. The decisive question is: does the server still accept the old session for protected operations?

### 7. Logout: Does the Session Actually Die?

This is one of the most important tests in session security. Consider a vulnerable logout implementation:

```python
def logout(response):
    response.delete_cookie("sessionid")
    return response
```

This code instructs the browser to delete its cookie. It does not, by itself, revoke the corresponding server-side session. Suppose the server still has this record:

```text
Session ID: ABC123
User ID: 1042
Authenticated: true
Revoked: false
```

If someone has already copied the session ID, deleting the browser's copy does not invalidate the copied value.

**Secure logout design.** A server-side session implementation should invalidate the session before or as part of completing logout:

```python
def logout(request, response):
    session = validate_session(request)

    if session is not None:
        revoke_session(session.id)

    response.delete_cookie(
        "__Host-session",
        path="/"
    )

    return response
```

This is conceptual pseudocode. Production code must correctly manage the session store, cookie attributes, errors, and any concurrent requests. The important sequence is: identify the current session, revoke or invalidate it on the server, clear the browser's cookie using the correct cookie scope, and ensure subsequent protected requests reject the old session.

**What about the browser's Back button?** A user may press Back after logging out and see a previously displayed page. That alone does not prove that the session remains valid, the browser may be showing cached content. Test whether the application can retrieve protected data or perform a protected operation using the old session. There are two distinct outcomes: cached display, where the browser shows content it already received, and live access, where the server accepts the old session and returns protected data or allows an authenticated action. The second is much stronger evidence of a session-revocation failure.

**How to validate logout.** Using your own account: log in, record the session cookie securely, log out normally, using an authorized test request attempt to reuse the old session, request a protected resource, and confirm whether the server rejects the old session. If the application only deletes the cookie, but the server continues accepting the old token, the session has not been effectively revoked. Potential impact: a previously copied session credential may remain usable after the user believes they have logged out. Do not automatically assign critical severity. Consider the token's exposure, the duration of validity, the available privileges, and the realistic attack path.

### 8. Session Rotation After Privilege Changes

Session rotation is important beyond initial login. It may be appropriate after successful authentication, completion of MFA, elevation to administrator privileges, account recovery, a change in authentication assurance, or other significant transitions identified by the application's threat model.

Why? Because the old session identifier may have been issued under a less trusted state. Consider this example:

```text
Session A:
Authenticated: false
MFA verified: false
Privileges: anonymous
```

The user completes login and MFA. The application should establish an appropriate authenticated state, often with a new session identifier:

```text
Session B:
Authenticated: true
MFA verified: true
Privileges: user
```

It must not leave Session A capable of accessing Session B's authenticated state.

**A common implementation mistake.** A developer may add a boolean flag:

```python
session["authenticated"] = True
```

That alone is not necessarily wrong, but it may be unsafe if the application simply promotes an existing session identifier without considering fixation and session lifecycle risks. A safer conceptual pattern is:

```python
def complete_mfa(user, old_session):
    revoke_or_downgrade(old_session)

    new_session = create_session(
        user_id=user.id,
        authenticated=True,
        mfa_verified=True
    )

    return new_session
```

Again, the exact implementation depends on the framework and session architecture. Security principle: when authentication assurance or privileges change, the server must maintain a trustworthy relationship between the session identifier, the user, and the newly granted state.

### 9. Password Resets and Session Revocation

Suppose a user discovers that their password has been compromised. They reset the password successfully. Does that automatically invalidate all existing sessions? No, not unless the application implements that behavior. A password reset changes a credential. Existing sessions may be maintained separately.

Consider this simulated sequence: an attacker obtains a user's session, the user notices suspicious activity, the user resets their password, the application changes the password but leaves all previous sessions valid, and the attacker continues using the stolen session. The password reset may be technically correct, but the account-recovery process has not adequately addressed the existing compromised session.

**What should a secure application do?** The application's policy should consider revoking or invalidating existing sessions after events such as password reset following suspected compromise, password change depending on the intended policy, MFA removal or replacement, account disablement or suspension, confirmed suspicious activity, administrative account recovery, and other changes that invalidate the trust assumptions behind existing sessions. The policy can vary by event and risk, for example a routine password change by a fully authenticated user may use a different policy from an emergency account-recovery event after suspected compromise. The important requirement is that the behavior is deliberate, secure, and consistent with the application's threat model.

**A common architecture: session versioning.** An application may maintain an account-level session version:

```text
User:
ID = 1042
Session version = 7
```

A session contains the version associated with it:

```text
Session:
User ID = 1042
Session version = 7
```

When the application needs to invalidate sessions, it increments the account version, for example to `Current account session version = 8`. The server rejects sessions carrying the old version:

```python
def validate_session(session, user):
    if session.revoked:
        return False

    if session.session_version != user.session_version:
        return False

    if session.is_expired():
        return False

    return True
```

This illustrates the validation logic, not a complete production implementation.

**Important trade-off.** A version check works only if the server has a trustworthy, sufficiently fresh way to compare the session's version with the account's current version. If the application caches account versions indefinitely or fails to apply the check to every protected route, revocation may not work as intended. Also, do not assume that every session must always be revoked after every password change. Assess the application's documented behavior, risk, and recovery requirements.

### 10. Concurrent Sessions and "Log Out All Devices"

Many applications allow a user to remain signed in on multiple devices, for example a laptop, a phone, and a tablet session simultaneously. This is not inherently a vulnerability. The security question is whether the application manages these sessions correctly. A good design should define whether multiple sessions are permitted, how users review active sessions, whether a user can revoke a specific session, whether a user can revoke all sessions, whether revocation takes effect promptly, whether account recovery invalidates the appropriate sessions, and whether sessions are correctly associated with the relevant user and tenant.

**What can go wrong?**

*Case A: "Log out all devices" only removes the current cookie.* The user clicks Log out all devices, but the server only deletes the cookie from the current browser. The phone and tablet sessions remain active. If the feature claims to revoke every session, this is a failure of the promised security behavior.

*Case B: A session is revoked in the UI but remains valid.* The session list marks a device as revoked, but the backend still accepts the corresponding session identifier. The visible interface is not enforcing the actual security boundary.

*Case C: Sessions are not properly isolated.* An application accidentally associates a session with the wrong account or tenant. This may become an account-impersonation or cross-tenant isolation vulnerability, depending on the underlying cause and demonstrated impact.

*Case D: Revocation is delayed.* The system queues revocation but continues accepting the session longer than intended. Whether this is a vulnerability depends on the policy, architecture, and risk.

**How to test multi-session behavior.** With your own account: authenticate in two separate sessions, confirm that both work as expected, revoke one session from the account's session-management interface, test whether the revoked session can still access protected resources, if the application offers "log out all devices" test the remaining sessions, and repeat relevant tests after password recovery or MFA changes. Use separate test sessions that you control. Do not attempt to access another person's session.

### 11. Partial Authentication and Session-State Confusion

This is a subtle but important class of authentication flaw. An application may represent authentication using several states: anonymous, password_verified, mfa_pending, authenticated, step_up_required, recovery_pending. The problem occurs when one part of the application treats an intermediate state as fully authenticated.

**Simulated vulnerable logic:**

```python
def access_sensitive_account_area(session):
    if session.get("user_id"):
        return show_sensitive_data()

    return unauthorized()
```

Why is this dangerous? Because the presence of a user ID does not prove that the user completed all required authentication steps. For example, after a correct password is entered, the server may create a temporary state:

```text
user_id = 1042
password_verified = true
mfa_verified = false
```

If the sensitive endpoint checks only whether `user_id` exists, it may grant access before MFA is completed.

**Safer conceptual logic:**

```python
def access_sensitive_account_area(session):
    if not session:
        return unauthorized()

    if not session.get("authenticated"):
        return unauthorized()

    if session.get("mfa_required") and not session.get("mfa_verified"):
        return unauthorized()

    return show_sensitive_data()
```

This is still simplified. A production application should centralize and consistently enforce authentication-state requirements rather than duplicating fragile checks across many endpoints.

**The senior-level lesson.** Do not ask only "does the user have a session?" Ask "what authentication state does this session represent, and is that state sufficient for this particular operation?" A session may be valid but insufficiently authenticated for a sensitive action. For example, a user might be allowed to view ordinary account information but need recent reauthentication before changing account recovery details. This leads into the next phase on OAuth and OpenID Connect, and later phases on reauthentication and identity lifecycle.

### 12. Server-Side Sessions vs. Stateless Sessions

You do not need to study JWT internals here, that is reserved for a separate module. However, you must understand the architectural distinction.

**Server-side sessions.** The browser holds an identifier, and the server maintains the session record:

```text
Browser
  |
  | Session ID
  v
Application
  |
  | Lookup
  v
Session store
  |
  | User, privileges, expiry, revocation state
  v
Decision
```

Advantages include centralized session revocation, server-controlled session state, and easier tracking of active sessions, depending on the implementation. Challenges include session-store availability, correct synchronization between application instances, cache consistency, and correct invalidation across distributed systems.

**Stateless approaches.** In some architectures, a client presents a self-contained credential whose contents can be verified without a conventional server-side session lookup on every request. The details vary by technology. Advantages may include reduced dependence on a centralized session lookup. However, immediate revocation, account-wide invalidation, and session tracking may require additional design.

Do not conclude that stateless sessions are automatically less secure or that server-side sessions are automatically safer. Security depends on the complete implementation and threat model. A crucial testing question is whether the application can promptly reject credentials that should no longer be valid.

### 13. A Simulated Source-Code Review

You are reviewing a fictional web application. You find:

```python
def login(username, password):
    user = find_user(username)

    if user and verify_password(password, user.password_hash):
        session["user_id"] = user.id
        return redirect("/dashboard")

    return unauthorized()
```

At first glance, the password check appears reasonable. But as an AppSec engineer, you should not stop there.

**Finding 1: Session rotation.** The code does not show whether the session identifier changes after successful authentication. Assessment: a review item, not a confirmed vulnerability. Inspect the framework's session behavior and the surrounding code.

**Finding 2: Session state.** The code assigns a user ID but does not show how the application distinguishes anonymous, password-verified, MFA-pending, and fully authenticated states. Assessment: a review item. Determine whether required authentication steps are enforced elsewhere.

**Finding 3: Session expiry.** No idle or absolute expiration is visible. Assessment: incomplete evidence. Expiration may be implemented by middleware or the session store.

**Finding 4: Logout and revocation.** The snippet does not show logout behavior or whether existing sessions are invalidated after security-sensitive account changes. Assessment: requires examination of the broader session lifecycle.

**Finding 5: Cookie configuration.** The code does not show the cookie attributes. Assessment: inspect the actual HTTP response and framework configuration.

**Finding 6: Password verification.** The snippet does not reveal whether password hashing is appropriate or whether login attempts are adequately protected. Assessment: review separately. The presence of `verify_password()` does not establish that its implementation is secure.

**How a senior engineer reports this.** A weak report says: "The application has insecure sessions because the login code does not regenerate the session." A stronger assessment says: "The login handler associates the authenticated user with the current session. The reviewed snippet does not demonstrate session rotation. Further validation is required to determine whether the framework rotates the session identifier and invalidates the prior session after authentication." If you confirm that an attacker-known session ID survives login and can be reused to access the victim's authenticated account, you have evidence for a much stronger finding. Separate what the code shows from what you have proved.

### 14. Authentication Session Testing Checklist

Use this as a practical checklist during an authorized assessment.

| Test | What to examine | Evidence of a real weakness |
|---|---|---|
| Login rotation | Session ID before and after login | An attacker-known identifier remains associated with authenticated state and is reusable. |
| MFA transition | Session before and after MFA | An intermediate session can access resources that require completed MFA. |
| Session randomness | Token generation and structure | Predictability or insufficient entropy is established, not merely guessed from appearance. |
| Cookie attributes | Actual `Set-Cookie` response | Configuration creates a demonstrable security exposure relevant to the threat model. |
| Idle timeout | Server behavior after inactivity | The server accepts a session beyond its intended idle lifetime. |
| Absolute timeout | Session age and server validation | The server accepts the session beyond the intended absolute lifetime. |
| Logout | Reuse the old session | The server accepts the old session after logout when it should have been invalidated. |
| Password reset | Existing sessions after recovery | Sessions that policy requires to be revoked remain usable. |
| MFA replacement | Other sessions after authenticator changes | A session remains trusted contrary to the defined security policy. |
| Single-session revocation | Revoke one device | The server continues accepting a session marked as revoked. |
| Revoke all sessions | Test other controlled sessions | Sessions remain usable despite a confirmed account-wide revocation action. |
| Account disablement | Use an existing session | The server continues to grant access contrary to the disablement policy. |
| Cross-account isolation | Controlled test accounts | One account's session can access another account's private data due to a proven binding flaw. |

**Evidence you should preserve.** For a well-supported report, capture the relevant request and response, the session's state before the tested transition, the action that should have invalidated or changed the session, the subsequent request using the old session if applicable, the server's response and the protected resource or action involved, the expected behavior and actual behavior, and the scope and limitations of your test. Treat session IDs as secrets. Redact them from reports, screenshots, shared traffic captures, and ordinary logs. Preserve only the minimum evidence necessary.

### 15. False Positives: Mistakes That Weaken Security Reports

Avoid these common errors.

**Mistake 1: "The session cookie does not change, so fixation is confirmed."** Not necessarily. Determine whether the ID was attacker-known or attacker-controlled, whether it was reused, and whether it grants authenticated access.

**Mistake 2: "The browser still displays the dashboard after logout."** The content may be cached. Test server-side access using the old session.

**Mistake 3: "The cookie lacks `HttpOnly`, so account takeover is confirmed."** The missing attribute can increase exposure, but the impact depends on the threat model and how the cookie is used. Do not claim an exploit you have not demonstrated.

**Mistake 4: "The application has a long timeout, so it is vulnerable."** A long lifetime increases the window of exposure, but the severity depends on application sensitivity, session protections, revocation, and applicable requirements.

**Mistake 5: "A user remains logged in after changing their password, so the application is automatically vulnerable."** Not universally. Examine the application's intended policy and the risk associated with the change. A failure to revoke sessions may be serious when compromise recovery requires invalidating existing credentials.

**Mistake 6: "The application uses stateless sessions, so logout cannot work."** Too broad. Stateless architectures can support revocation through additional mechanisms. Inspect the actual design and behavior.

### 16. How to Write a Session-Security Finding

Suppose you have confirmed that logout deletes the browser cookie but leaves the server-side session valid. A report could look like this:

**Title:** Server-side session remains valid after logout.

**Description:** The application removes the current session cookie when the user logs out, but the previously issued session credential continues to authorize requests to a protected endpoint. Consequently, a party that obtained the session credential before logout may retain access to the account.

**Evidence:** Authenticate using a controlled test account. Record the session credential securely. Log out normally. Submit an authorized request to a protected endpoint using the old credential. Observe that the server returns protected account data rather than rejecting the session.

**Impact:** An exposed session credential may remain usable after the legitimate user believes the session has ended. The actual impact depends on the privileges associated with the session, the data available, and the period for which the credential remains valid.

**Remediation:** Invalidate the session on the server during logout, clear the browser cookie using the appropriate scope, and verify that subsequent requests using the old credential are rejected. Apply consistent revocation behavior to other security-sensitive events according to the application's session policy.

**Severity:** Determine severity from demonstrated exploitability, required attacker access, the sensitivity of the affected account, and the resulting impact. Do not assign a critical rating merely because the word "session" appears in the finding.

### 17. Final Mastery Model

You should now be able to reason through the full session lifecycle: authentication, session creation, session validation, privilege transition, rotation, expiration, revocation. At every stage, ask four questions: identity, which user is this session associated with; state, what authentication assurance and privileges does the session represent; lifetime, under what conditions does the session expire or become invalid; and revocation, can the server reject this session immediately when required. If you cannot answer these questions, you do not yet have enough evidence to declare the session implementation secure.

## Assessment

The following assessment is drawn from "Authentication Security.md" and addresses server-side session invalidation after logout, the correct test for session fixation, why a changed session ID does not alone prove fixation is impossible, and whether logout also revokes a persistent "remember me" credential. As with the prior phases, the questions are preserved from the original source, and the answers given are the instructor's corrected, authoritative answers rather than the original learner's submitted answers.

### Assessment Question 1

A normal login flow sets a session cookie:

```http
POST /api/auth/login HTTP/1.1
Host: shop.test
Content-Type: application/json

{
  "email": "alice@example.test",
  "password": "CorrectPassword123!"
}
```

```http
HTTP/1.1 200 OK
Set-Cookie: session_id=9f82ab...; HttpOnly; Secure; SameSite=Lax

{
  "message": "Login successful"
}
```

You use that session to successfully access `GET /api/account`, then click Logout and receive `{"message": "Logged out"}`. You still have the old session cookie, `session_id=9f82ab...`. What is the single most important test you would perform now, and what security property are you testing?

<details markdown="1">
<summary><strong>Reveal Answer</strong></summary>

Replay the old session cookie against a protected endpoint to determine whether it still authenticates:

```http
GET /api/account HTTP/1.1
Host: shop.test
Cookie: session_id=9f82ab...
```

You are testing server-side session invalidation. After logout, the security invariant should be that the old session credential must no longer authenticate the client. There are two possible outcomes. A secure result is `401 Unauthorized` with an error such as "Session expired," confirming the server has invalidated the session. A vulnerable result is `200 OK` with the account data still returned, meaning the old credential remains valid after logout, a session invalidation failure. The senior-level distinction here is that simply seeing the browser's cookie still present is not enough evidence either way, a client-side cookie can remain stored regardless of what happened server side. What matters is whether the server still accepts it.

</details>

### Assessment Question 2

You discover the application issues a session before authentication:

```http
GET /login HTTP/1.1
Host: shop.test
```

```http
HTTP/1.1 200 OK
Set-Cookie: session_id=ATTACKER123; HttpOnly; Secure; SameSite=Lax
```

You then authenticate using that same session:

```http
POST /api/auth/login HTTP/1.1
Cookie: session_id=ATTACKER123

{
  "email": "alice@example.test",
  "password": "CorrectPassword123!"
}
```

```http
HTTP/1.1 200 OK
Set-Cookie: session_id=ATTACKER123; HttpOnly; Secure; SameSite=Lax
```

As a security tester, what would you test next to determine whether this is actually a session fixation vulnerability?

<details markdown="1">
<summary><strong>Reveal Answer</strong></summary>

The key test is not simply bypassing `/login` to see if `/account` can be reached with the same session, that would mainly test authentication enforcement, not fixation. Session fixation is specifically about whether an attacker can choose or know a victim's pre-authentication session ID and have that exact session become authenticated as the victim, so the correct test requires two roles. The attacker obtains or controls a pre-auth session, `session_id=ATTACKER123`, and gets the victim to authenticate while using that same session:

```http
POST /api/auth/login
Cookie: session_id=ATTACKER123

{
  "email": "alice@example.test",
  "password": "CorrectPassword123!"
}
```

Then the attacker reuses that same session:

```http
GET /api/account
Cookie: session_id=ATTACKER123
```

If the attacker now receives `200 OK` with Alice's account data, the pre-auth session was promoted into Alice's authenticated session, and that is the critical vulnerability. A secure application should normally rotate or regenerate the session identifier when authentication occurs, so that the identifier known to the attacker before login, `ATTACKER123`, no longer represents Alice after login. The mental model to keep: session fixation means the attacker fixes the session before authentication, the victim authenticates into that fixed session, and the attacker reuses it after authentication. That is categorically different from simply asking "can I access `/account` without logging in," which is an authentication-enforcement test, not a fixation test.

</details>

### Assessment Question 3

You test the login flow and observe that the session ID changes after login:

```http
POST /api/auth/login
Cookie: session_id=PREAUTH123

{
  "email": "alice@example.test",
  "password": "CorrectPassword123!"
}
```

```http
HTTP/1.1 200 OK
Set-Cookie: session_id=AUTH456; HttpOnly; Secure; SameSite=Lax
```

Does this alone prove that session fixation is impossible? Explain your reasoning.

<details markdown="1">
<summary><strong>Reveal Answer</strong></summary>

No, a changed session ID does not by itself prove fixation is impossible. Do not stop at "the session ID changed, therefore it's secure." You still need to test whether the old pre-authentication session retains any authenticated authority. The verification test is to replay the old pre-login session after the new one has been issued:

```http
GET /api/account HTTP/1.1
Cookie: session_id=PREAUTH123
```

If you receive `401 Unauthorized`, that is good evidence the old session was not promoted. If you instead receive Alice's authenticated account data with `200 OK`, something is seriously wrong despite the apparent session rotation, both the old and new session identifiers are granting access. The senior-level refinement is to test both sessions explicitly and confirm the expected state of each: `PREAUTH123` should be unauthenticated, and `AUTH456` should be the one representing Alice as authenticated. This establishes the session transition invariant: authentication must create a new authenticated security context while invalidating or separating the pre-authentication context, not merely issue a new identifier alongside an old one that still works.

</details>

### Assessment Question 4

A login with "Remember me" enabled returns two cookies:

```http
HTTP/1.1 200 OK
Set-Cookie: session_id=abc123; HttpOnly; Secure; SameSite=Lax
Set-Cookie: remember_token=RMT-82F91...; Secure; HttpOnly
```

You later log out and receive `{"message": "Logged out"}`. You test the old `session_id` and it is correctly rejected. However, you still have the old `remember_token=RMT-82F91...`. What is the first thing you would test with that old `remember_token`, and what security property are you trying to establish?

<details markdown="1">
<summary><strong>Reveal Answer</strong></summary>

Take the old `remember_token` and use it through the application's normal remember-me mechanism, for example by revisiting the application with only that token, to see whether it creates a new authenticated session on its own. The property you are testing is whether logout properly revokes persistent authentication credentials, not just the ordinary session. "Remember me" exists specifically so that even after the normal session disappears, a long-lived credential can establish a new authenticated session, which means after logout you know the ordinary session is invalid, but the remember token's status is still an open question. If the old token creates a new authenticated session after logout, for example the server responds with `200 OK` and a fresh `Set-Cookie: session_id=NEW456`, you have proven that logout killed the normal session but did not kill the persistent authentication credential, which is a remember-me and session revocation flaw. If it is rejected, that is good evidence that logout invalidates the persistent credential too.

As with every other test in this module, do not assume "the cookie still exists" by itself means a vulnerability, the browser can retain a cookie regardless of server state. The real question is always whether the server still trusts that specific credential to authenticate the user. If the old remember token does successfully create a new session, the senior-level follow-up is not to immediately call it account takeover. Instead ask who could realistically obtain that remember token, for example a stolen browser, leaked storage, logs, or malware, and what they could do with it, since that determines the actual security impact rather than just the existence of the flaw.

</details>

## Remediation and Secure Implementation

The following consolidates the remediation guidance across all seventeen sections of this phase.

1. Treat a session ID as a bearer credential: generate it with a cryptographically secure random source carrying sufficient entropy, never derive it from predictable user or timestamp data, and never place it in a URL.
2. Issue a fresh session identifier after every meaningful authentication transition, initial login, MFA completion, privilege elevation, and account recovery, and ensure the superseded identifier can no longer access the newly authenticated state.
3. Configure session cookies with `Secure`, `HttpOnly`, an appropriate `SameSite` value, the narrowest `Path` and `Domain` the application actually needs, and the `__Host-` prefix where the deployment supports it, understanding that these attributes constrain the browser, not the server's own validation responsibility.
4. Enforce both an idle timeout and an absolute timeout on the server, decide deliberately whether sliding expiration is appropriate, and verify expiration by testing whether the server still accepts the session, not by observing the browser's behavior.
5. Make logout revoke the session on the server, not merely delete the browser's cookie, and verify this by replaying the old session against a protected endpoint after logging out.
6. Revoke or appropriately downgrade the pre-authentication session as part of completing login or MFA, rather than simply flipping a boolean flag on the same session record.
7. Define and implement a deliberate session-revocation policy for password resets, MFA changes, account disablement, and confirmed suspicious activity, using a mechanism such as session versioning that the server actually checks on every protected route.
8. Make "log out all devices" and single-session revocation actually reach the server-side trust decision for every affected session, not just the currently active browser's cookie, and verify this with controlled multi-session tests.
9. Enforce the specific authentication state a given operation requires, rather than treating the mere existence of a session or a user ID as sufficient proof of complete authentication.
10. Extend every revocation and expiration guarantee to persistent "remember me" credentials, not only the ordinary session, since a persistent credential that survives logout defeats the purpose of logging out.

## Key Takeaways

This phase's governing principle is the one stated in its own introduction: logging in proves who you are at a particular moment, a session determines whether the application continues to recognize you as authenticated afterward, and those are different guarantees that must be engineered separately. Every lesson in this module is a variation on the same decisive question: does the server still accept this credential, right now, regardless of what the browser displays or what the client claims? A cookie attribute, a changed session ID, a deleted browser cookie, and a "log out all devices" button are all surface signals. None of them substitutes for actually replaying the credential against the server and observing what comes back.

The assessment challenges in this phase sharpen that discipline on four specific, easily confused tests: logout testing means replaying the old session, not trusting the logout response. Fixation testing means fixing a session before authentication and checking whether it becomes authenticated, not merely testing whether authentication is enforced. Rotation testing means confirming the pre-authentication session was actually invalidated, not just observing that a new identifier was issued alongside it. And remember-me testing means checking whether the persistent credential survives logout independently of the ordinary session, since the two are separate credentials with separate revocation responsibilities. Carrying this same discipline, source shows versus test proves, forward into every remaining phase is the single most transferable skill this module teaches.

## Review Checklist

- [ ] Can you explain, in one sentence each, how authentication, a session, and a cookie differ from one another?
- [ ] Can you walk through the session lifecycle state machine and name what should trigger each transition?
- [ ] Can you design a correct session-fixation test, and explain why "try to skip login" is not that test?
- [ ] Can you explain what makes a session ID suitable as a bearer credential, and spot an unsafe generation method in source code?
- [ ] Can you state what each of the seven cookie attributes covered in this phase actually protects against, and what it does not?
- [ ] Can you distinguish idle timeout, absolute timeout, and sliding expiration, and explain why a defensible policy often uses more than one?
- [ ] Can you explain why deleting a browser cookie on logout is not proof that the server-side session was revoked?
- [ ] Can you list at least four events, beyond initial login, that should trigger session rotation or revocation?
- [ ] Can you explain session versioning as one architecture for account-wide revocation, and its trust-freshness trade-off?
- [ ] Can you identify, from a source code snippet, whether an endpoint checks session existence or the specific authentication state it actually needs?
- [ ] Can you explain why stateless sessions are not automatically less secure than server-side sessions, and what question actually determines it?
- [ ] Can you explain why a persistent "remember me" credential needs its own revocation test, separate from the ordinary session?

## References to Related Phases

- MFA transitions and the distinction between password-verified and MFA-verified session states, referenced throughout sections 2, 8, and 11, were covered in depth in **Phase 3, Multifactor Authentication (MFA) Attacks**.
- Session revocation after a password reset or MFA factor change, covered in section 9, connects directly to **Phase 2, Password Change and Account Recovery** and **Phase 4, MFA Enrollment and Recovery Vulnerabilities**.
- Session handling after a passkey authentication, referenced as an open account-takeover path in Phase 5, is the specific session-security discipline this phase provides.
- The authentication-state enforcement principle in section 11, that a valid session is not automatically a sufficiently authenticated one, extends directly into a later phase, **Reauthentication and Step-Up Authentication**.
- Stateless, self-contained credentials, mentioned but explicitly deferred in section 12, are addressed in later phases covering JWT-adjacent and cryptographic authentication failures.
