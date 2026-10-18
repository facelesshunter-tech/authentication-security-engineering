# Phase 12: Authentication Information Leakage

**Source material:** Module 12 of 17, "Authentication Complete Phases Test.md" (30 numbered sections covering authentication information leakage, the Module 12 Progress Tracker, and the overall course tracker), with supplementary assessment material drawn from "Authentication Security.md" (Challenge 01 and its follow-up, and Challenge 02).

## Learning Objectives

After completing this phase, you should be able to:

1. Define authentication information leakage and explain why the vulnerability is not that information exists, but that it is disclosed to an unauthorized recipient in a way that creates meaningful risk.
2. Name the six major categories of authentication leakage and give an example of each.
3. Identify response-based account enumeration in login, registration, and password-reset endpoints, and design a generic response that reduces it.
4. Explain why a generic error message alone does not eliminate enumeration, and identify timing-based enumeration as a distinct, separately testable signal.
5. Distinguish account-existence disclosure from account-state disclosure, including MFA enrollment status, recovery methods, and verification state.
6. Identify where session identifiers, reset tokens, and other bearer credentials can leak beyond their intended flow, and explain the difference between a secret and an identifier.
7. Explain why verbose errors, stack traces, HTTP headers, SSO error details, and exception messages require evaluating what is disclosed and to whom, not simply whether a `500` occurred.
8. Identify authentication data leaking through logs, client-side debugging, source maps, caches, and redirects, and design safer alternatives for each.
9. Distinguish information disclosure from authentication bypass as two separate but related findings, and identify when disclosed state is also trusted as proof of authentication.
10. Apply the module's five-layer defensive architecture, public responses, internal diagnostics, secret lifecycle management, consistent behavior, and monitoring, to an authentication system.
11. Build a reliable, reproducible enumeration test using controlled accounts, and distinguish demonstrated impact from speculative consequence when assigning severity.
12. Apply the Phase 1 through Phase 11 impact-validation discipline to information-leakage findings: identify precisely what is exposed, to whom, and what realistic consequence follows, rather than reporting the mere presence of unfamiliar technical detail.

## Introduction

Every earlier phase in this course studied a failure that an application actively commits: accepting a forged token, skipping a required check, trusting the wrong identity. This phase studies something quieter. Information leakage is often underestimated because the application may appear to work normally. A login page returns an error, a password-reset endpoint responds with a message, or an API exposes a few extra fields. Yet those details can reveal account existence, authentication state, internal identity mappings, reset-token validity, or security controls, all without the application ever doing anything an observer would call broken.

The key skill this phase teaches is learning to distinguish information that is merely visible from information that gives an attacker a meaningful security advantage. A public client ID is not a secret. An internal record ID is not automatically a session token. A `500` response is not automatically an authentication flaw. A stack trace is not automatically remote code execution. This phase's entire discipline is the same one carried forward from every earlier phase, applied to a subtler class of failure: establish precisely what is disclosed, to whom, and what realistic consequence follows, rather than reporting the presence of unfamiliar technical detail as if it were automatically dangerous.

## Core Concepts

The module moves through four stages. First, sections 1 and 2 establish the core concept and the six major categories that organize the rest of the module: account enumeration, credential-state leakage, internal identity leakage, implementation leakage, secret leakage, and authentication-policy leakage. Second, sections 3 through 23 examine twenty specific, named vulnerability patterns in turn, moving from the most direct, login and registration enumeration, through timing side channels, account-state and MFA disclosure, token and secret leakage across URLs, logs, caches, and headers, and into the subtler territory of SSO error detail, administrative API disclosure, and authentication state confusion. Third, sections 24 through 27 build the testing discipline: a reliable enumeration-testing method, severity guidance, a complete source-code review exercise, and the critical distinction between information disclosure and authentication bypass. Fourth, sections 28 through 30 bring the module together into a practical architecture: a five-layer defensive model, a senior testing checklist, and the final retention summary.

## Lessons

### 1. The Core Concept: What Is Authentication Information Leakage?

Authentication information leakage occurs when an application exposes information about its authentication system, users, credentials, sessions, or identity relationships that should not be available to the recipient. The information might appear in HTTP response bodies, HTTP status codes, response timing, HTTP headers, login and password-reset errors, registration responses, SSO error messages, API responses, debugging output, application logs, URLs and redirects, cached pages, or client-side application state.

Consider two login responses. Response A: `401 Unauthorized`, `{"message": "Invalid credentials"}`. Response B: `404 Not Found`, `{"message": "The account alice@example.test does not exist"}`. Response B explicitly reveals that the account does not exist. An attacker could use that information to identify registered users before attempting further attacks. However, the security impact depends on context. A username may already be public, and some applications intentionally expose account-directory information to authorized users.

The vulnerability is not simply that information exists. It is that the application discloses information to an unauthorized recipient in a way that creates meaningful risk.

### 2. The Six Major Categories of Authentication Leakage

| Category | Example | Potential consequence |
|---|---|---|
| Account enumeration | Different responses for registered and unregistered users | Targeted credential attacks |
| Credential-state leakage | Revealing whether a password, OTP, or reset token is valid | Authentication attack refinement |
| Internal identity leakage | Exposing account IDs, tenant mappings, or provider subjects | Account correlation or identity confusion |
| Implementation leakage | Stack traces, internal paths, framework details | More targeted attacks |
| Secret leakage | Tokens or session identifiers exposed in URLs, logs, or responses | Session compromise or account takeover |
| Authentication-policy leakage | Revealing MFA enrollment, recovery methods, or security configuration | Targeted social engineering or attack planning |

These categories overlap. A single response may reveal multiple kinds of information. The severity depends on what the information enables, who can obtain it, and whether additional protections limit its usefulness.

### 3. Vulnerability One: Username and Email Enumeration

This is one of the most common authentication information leaks. A fictional application's login endpoint returns `401 Unauthorized` with `{"message": "Incorrect password"}` for a registered email with the wrong password, but `404 Not Found` with `{"message": "Account not found"}` for an unregistered email. The difference reveals account existence. An attacker could use this distinction to identify which email addresses are registered before targeting those accounts.

**Why enumeration matters.** Enumeration can support credential stuffing against known accounts, targeted phishing, identification of privileged or corporate users, discovery of accounts that may use password recovery, and identification of users registered with a particular service. Enumeration alone does not prove account takeover. It is often a lower-impact vulnerability that can make other attacks more efficient.

**Safer response design.** A login endpoint can return a generic authentication failure for both unknown accounts and incorrect passwords: `401 Unauthorized`, `{"message": "Invalid email or password"}`. The application should also consider timing differences, rate limiting, monitoring, and account-state behavior. Generic messages do not eliminate enumeration if other observable signals reliably distinguish the cases.

### 4. Timing-Based Enumeration

Suppose an application returns the same response body for all login failures. Is enumeration necessarily prevented? No. The application might still take substantially different amounts of time to process different account states:

```python
def login(email, password):
    user = find_user_by_email(email)

    if user is None:
        return invalid_credentials()

    if not verify_password(password, user.password_hash):
        return invalid_credentials()

    return success(user)
```

If an unknown account causes the function to return immediately, while a known account requires an expensive password-hash verification, the response times might differ. An observer may be able to infer account existence from repeated measurements.

The relevant principle: observable behavior can disclose information even when the response body is identical. However, one slow or fast response is not enough to establish timing-based enumeration. Network congestion, caching, database behavior, load, rate limiting, and other sources of variation can obscure the signal.

**What a tester should examine.** Compare the behavior for controlled known and unknown accounts, use the same request structure and comparable conditions, collect repeated measurements rather than relying on one sample, compare distributions rather than just average times, consider rate limiting and background load, and determine whether any observed difference is consistent and practically useful. Do not conclude that a vulnerability exists merely because two requests took different amounts of time.

**Remediation.** Applications can reduce timing discrepancies by using comparable processing paths for authentication failures. For example, a system might perform an appropriately configured password-hash verification against a dummy hash when the account does not exist. That technique can reduce a specific timing difference, but it does not replace rate limiting, monitoring, or careful error handling.

### 5. Vulnerability Two: Enumeration Through Registration

Account enumeration is not limited to login. A registration endpoint might return `409 Conflict` with "This email is already registered" for an existing email, but `201 Created` with "Registration started" for an unregistered address. The endpoint exposes whether an email is already associated with an account.

**Is this always a vulnerability?** No. Some applications deliberately inform users when an email is already registered to prevent duplicate registration and improve usability. The risk depends on whether the endpoint is publicly accessible, whether the disclosed information is sensitive, whether users expect their registration status to be private, whether the service is used by high-risk populations, whether attackers can enumerate large numbers of accounts, and whether effective abuse controls exist. A generic response is often appropriate when account privacy is important.

**Safer design.** The application can respond consistently: "If the address can be registered, further instructions will be provided." The backend can still handle the duplicate-account case internally. Be careful though: returning the same message does not help if one case triggers a visible email-verification flow while the other behaves differently in an easily observable way.

### 6. Vulnerability Three: Password-Reset Enumeration

Password-reset endpoints are especially important because users often assume they can safely enter an email address without revealing whether an account exists. A registered account might receive `200 OK` with "Password reset email sent," while an unregistered account receives `404 Not Found` with "No account exists for this email." This provides a straightforward enumeration signal.

**Why it matters.** An attacker may use password recovery to discover registered customers, employees of a company, accounts associated with a sensitive service, and which addresses are likely to receive authentication-related emails. This information may support subsequent attacks, but the report should not automatically claim account takeover.

**Better behavior.** A generic response could say "If an eligible account exists, recovery instructions will be sent," identical whether the account exists or not. The application should still enforce rate limits, recovery-token security, abuse monitoring, safe email-delivery behavior, and consistent handling of disabled or ineligible accounts.

**A subtle issue: asynchronous delivery.** Suppose the endpoint returns the same generic response in both cases, but only registered accounts trigger a request to an external email service. That may be perfectly reasonable internally. However, if this causes a stable and measurable response-time difference, account enumeration may still be possible. The tester must evaluate the observable result, not assume the message alone determines security.

### 7. Vulnerability Four: Enumeration Through Account State

Account existence is only one kind of disclosure. An application may reveal whether an account is active, disabled, locked, unverified, pending approval, required to enroll MFA, configured for SSO, or temporarily restricted. For example, `403 Forbidden` with `{"error": "Account exists but has not completed MFA enrollment"}` reveals both account existence and part of the user's authentication configuration. Whether that is a vulnerability depends on the application's threat model and disclosure policy. For an internal identity-management portal, such details may be appropriate for an authorized administrator. For a public login endpoint, they may disclose information unnecessarily.

**What to look for.** Compare responses for controlled accounts in different states. Record differences in status code, response body, response length, redirect destination, response timing, cookies and headers, and subsequent application behavior.

**Remediation.** The external response can remain generic while the internal system records the precise failure reason, for example an external `{"message": "Unable to sign in with these details."}` alongside an internal `{"event": "authentication_failed", "reason": "mfa_enrollment_required", "user_id": "usr_104"}`. The internal event must itself be protected by appropriate access controls and retention policies. General principle: detailed diagnostics belong in appropriately protected internal systems, not necessarily in public authentication responses.

### 8. Vulnerability Five: MFA Enrollment and Recovery Disclosure

An authentication endpoint might reveal whether a user has MFA enabled, for example an incorrect-password response that also includes `"mfa_enabled": true, "mfa_method": "authenticator_app"`. If the user has not authenticated successfully, exposing their exact MFA configuration may give an attacker unnecessary information. Other disclosures include the number of registered authenticators, masked phone numbers, recovery-email addresses, the number of backup codes remaining, whether a passkey is registered, and whether a trusted device exists. Some applications reveal limited details after authentication to help users recognize their account. That can be reasonable. The critical distinction is the recipient's authorization and the necessity of the information.

**Safer response design.** Before sufficient authentication, avoid revealing detailed account-security configuration. After authentication, display only the information needed for the user's legitimate task, for example "Additional verification required" rather than the specific method. The application can provide more detailed configuration information after the appropriate authentication step. Do not automatically treat every masked phone number or MFA indicator as a vulnerability. Demonstrate what unauthorized information is exposed and why it matters.

### 9. Vulnerability Six: OTP and Verification-State Leakage

One-time passwords and verification codes introduce another category of information disclosure. A weak implementation might return `{"message": "Incorrect code. The expected code is 739204."}`, an obvious secret disclosure. A less obvious implementation might return `{"message": "The code is valid, but the account is not verified."}`, which may reveal internal authentication state or indicate that one verification stage succeeded. Whether this is a vulnerability depends on the flow and the caller's privileges.

**Additional failure patterns.** Returning an OTP in a registration response. Including verification tokens in frontend debugging output. Exposing backup codes in an ordinary account API response. Returning detailed information about the number of remaining attempts. Revealing whether a code belongs to a specific account. Returning an internal verification-session identifier that can be used as a bearer credential.

**What to distinguish.** A verification endpoint necessarily needs to communicate success or failure to its legitimate user. The problem is not the existence of a success response. The problem is exposing unnecessary secrets or revealing intermediate state in a way that permits an unauthorized person to bypass or materially weaken verification.

**Safer design.** Never return an OTP or recovery secret merely to confirm its generation. Bind verification challenges to the intended account and purpose. Enforce expiry and attempt limits. Avoid exposing sensitive internal verification state. Ensure that an intermediate successful check does not automatically establish a fully authenticated session unless that is the intended policy. These controls complement the MFA and account-recovery lessons from Phases 3, 4, and 2.

### 10. Vulnerability Seven: Password-Reset Token Leakage

Password-reset tokens are bearer secrets: possession may be sufficient to perform the recovery action, depending on the implementation. Putting a token in a URL, such as `https://app.example.test/reset-password?token=EXAMPLE_SECRET`, does not automatically prove a vulnerability. Some recovery flows legitimately use URL tokens. The concern is where that token may travel or be stored: browser history, reverse-proxy logs, application access logs, analytics systems, error-monitoring services, referrer information sent to other destinations, screenshots or copied URLs, support tickets, and third-party scripts operating on the page.

**A realistic leakage scenario.** A password-reset page loads third-party analytics code and then navigates to another resource. If the full reset URL is included in telemetry or sent through a referrer under an unsuitable policy, the token could be disclosed outside the intended recovery flow. The impact depends on the token's validity, scope, single-use behavior, and whether the recipient can access the relevant data.

**Defensive controls.** Use high-entropy, short-lived, purpose-bound tokens. Make tokens single-use and invalidate them after successful recovery. Avoid logging secrets. Redact sensitive URL parameters from telemetry. Set an appropriate `Referrer-Policy`. Avoid unnecessary third-party resources on sensitive recovery pages. Ensure token consumption is enforced server-side. The security objective is not merely to hide the token from the screen. It is to prevent unauthorized parties and systems from obtaining a usable recovery secret.

### 11. Vulnerability Eight: Session and Authentication Token Leakage

Session identifiers, access tokens, and recovery tokens are not interchangeable, but they share an important property: some can act as bearer credentials. If the application uses a returned `session_id` as a valid session credential, returning it unnecessarily may expose the session secret to code, logs, or users who should not receive it. By contrast, a non-secret internal session record identifier may be safe to expose if possession alone grants no access. Do not classify an identifier as a credential based on its name alone. Determine whether it grants authority.

**Common leakage locations.** URLs, browser storage, frontend error reports, debug logs, analytics payloads, HTTP response bodies, Referer headers, third-party monitoring tools, and screenshots or exported diagnostic data.

**What a tester should establish.** What exactly is the exposed value? Is it secret or merely an identifier? Does possession grant access? Which accounts or operations does it authorize? How long is it valid? Can it be revoked? Who can obtain it? Is there evidence of actual unauthorized access? A string that looks like a token is not automatically a working credential. Never claim session hijacking unless the evidence establishes that the exposed value actually functions as a session credential or otherwise grants unauthorized authority.

### 12. Vulnerability Nine: Verbose Authentication Errors and Stack Traces

Consider a `500 Internal Server Error` response that reveals internal file paths, framework or exception details, database infrastructure information, query structure, and potentially sensitive authentication input. The primary issue is not that the server returned a `500`. Servers sometimes encounter unexpected errors. The problem is that the response exposes internal information to a recipient who does not need it.

**Why it matters.** Depending on the information disclosed, an attacker may learn which framework or component is used, how authentication is implemented, which internal systems exist, how account records are queried, which code paths handle authentication failures, and whether sensitive values are being included in diagnostic output. These details may help refine subsequent attacks. However, a stack trace alone does not establish account takeover or code execution.

**Safer error handling.** An external response of `{"message": "An unexpected error occurred."}` paired with a protected internal log containing a correlation ID, exception type, and component name. The internal log should avoid recording passwords, reset tokens, session secrets, or unnecessary personal information. A correlation identifier allows authorized responders to connect the user's error to protected diagnostic records without exposing the full stack trace. Testing rule: a `500 Internal Server Error` is not, by itself, a security vulnerability. You must examine what information is disclosed and whether it creates meaningful risk.

### 13. Vulnerability Ten: Authentication Leakage Through HTTP Headers

Headers can disclose authentication implementation details or, in some cases, actual secrets. Each header needs to be evaluated separately. `X-Powered-By` may reveal a framework or server technology; such disclosure is generally low impact by itself, especially when the technology is already obvious from public behavior, but it may still be worth removing unnecessary headers as part of reducing information exposure.

A custom header such as `X-Auth-Debug: user=alice@example.test; mfa=false` could reveal account or authentication state. Whether this is a vulnerability depends on where it appears, who receives it, and what the information enables. An internal request identifier is not necessarily sensitive, it may be useful for debugging and incident response. The risk arises if it exposes secrets, grants access to internal systems, or allows unauthorized retrieval of sensitive logs.

**What to investigate.** Are debug headers enabled in production? Do responses contain internal user identifiers or authentication state? Are tokens or secrets included in headers unnecessarily? Do error responses disclose different information from normal responses? Are internal request IDs safely scoped and non-authorizing? Avoid reporting every technology-identification header as a significant security issue.

### 14. Vulnerability Eleven: SSO Error Leakage

Connecting this module to Phase 10. A failed SSO attempt might return `{"error": "SAML_RESPONSE_INVALID", "detail": "Signature validated but audience did not match tenant_B", "expected_issuer": "https://idp-b.example.test", "received_issuer": "https://idp-a.example.test"}`. This response reveals internal trust configuration. The exact details may help an attacker understand how the application selects identity providers or tenants. However, detailed errors can be useful to administrators during configuration and troubleshooting. The correct design depends on who receives the response.

**Public login experience.** A user may only need to know `{"message": "Unable to complete sign-in."}`.

**Protected diagnostic interface.** An authorized administrator may need detailed information about issuer mismatches, audience failures, certificate or signing-key problems, invalid request correlation, expired assertions, and identity-provider configuration errors. These details should be available through appropriately protected logs or administrative tools, not indiscriminately exposed to anonymous users.

**Security distinction.** A generic public error should not cause the application to accept an invalid assertion. The application must still perform the same required validation and reject invalid authentication attempts. Reducing information disclosure must never weaken the underlying authentication checks.

### 15. Vulnerability Twelve: Redirect-Based Token Leakage

Some authentication flows use redirects to return the user to an application after login. A badly designed flow might place sensitive authentication material in the redirect URL, for example `Location: https://app.example.test/callback?access_token=EXAMPLE_SECRET`. Whether a particular token-in-URL pattern is vulnerable depends on the protocol, token type, exposure paths, and client architecture. The concern is that URLs may be copied, logged, retained in browser history, or included in telemetry.

**What a tester should ask.** Is the value a genuine credential or merely an opaque identifier? Is it an access token, authorization code, session identifier, or state parameter? Does possession grant authority? Is the token short-lived and appropriately scoped? Can it be redeemed more than once? Can it leak through browser history, logs, or referrer information? Does the flow follow the relevant protocol's recommended security practices?

**Important distinction.** An authorization code is not the same as an access token. Its security depends on the code's lifetime, client binding, redirect URI validation, PKCE where applicable, and other protocol requirements, as covered in Phase 7. Likewise, a random-looking `state` value is not automatically a secret with independent authorization power. Do not describe every authentication-related URL parameter as a leaked credential. Identify the parameter's actual role and demonstrate the risk.

### 16. Vulnerability Thirteen: Authentication Data Leaking Through Logs

Logs are often overlooked because users cannot ordinarily access them. However, logs may be available to support personnel, developers, operations staff, third-party monitoring vendors, centralized logging systems, and incident-response teams. If sensitive authentication data is written to logs, it can be exposed to a broader audience than intended.

**Dangerous example:**

```python
logger.info(
    "Login attempt: email=%s password=%s",
    email,
    password,
)
```

This records the password. A similar issue occurs when applications log full session cookies, reset tokens, MFA recovery codes, authorization headers, entire SAML responses, and unredacted identity-provider assertions.

**Why this matters.** A log may be retained for weeks or months. Even if a credential is short-lived, a captured value may remain useful during its validity period. Some leaked information may also assist account correlation or future attacks.

**Better logging:**

```python
logger.info(
    "Authentication attempt failed",
    extra={
        "user_id": safe_internal_user_id,
        "reason_code": "invalid_credentials",
        "request_id": request_id,
    },
)
```

This is illustrative pseudocode. Production logging should use structured events, appropriate access controls, retention limits, redaction, and privacy safeguards. A subtle point: logging an internal user ID is not automatically a vulnerability. The identifier's sensitivity depends on the application and surrounding access controls. The highest priority is to prevent the logging of actual authentication secrets and unnecessary personal information.

### 17. Vulnerability Fourteen: Client-Side Debugging and Source Maps

Authentication data may leak through frontend debugging. A production JavaScript bundle might contain `console.log("Authentication response:", response);`. If `response` contains tokens, personal information, or internal authentication state, the browser console may expose those values to anyone who can inspect the running application. The code might also send the response to an error-monitoring service.

**Source maps.** Source maps can expose original source code and internal file structure. They are not automatically vulnerabilities. Many production applications legitimately publish source maps. The relevant question is whether the exposed material includes hardcoded secrets, internal endpoints intended to remain private, sensitive authentication logic, personal data, or token-handling behavior that creates a demonstrated security weakness. A frontend cannot keep a secret from the user who downloads and executes its code. A client-side API key intended to be public is not the same as a backend secret. Never report a public client identifier as a leaked secret unless it actually grants authority that should remain confidential.

**Testing focus.** Review production console output, error-monitoring payloads, source maps, browser storage, authentication-related network responses, and client-side error messages. Do not expose real user tokens or private information while gathering evidence.

### 18. Vulnerability Fifteen: Cache Leakage of Authenticated Responses

Authentication-related pages and responses may contain sensitive information. Imagine an authenticated endpoint returns account-specific data (`email`, `mfa_enabled`, `recovery_methods`) with `Cache-Control: public, max-age=600`. The response includes account-specific information, yet the cache policy permits public caching. Whether the information can actually be retrieved by another user depends on the caching infrastructure, cache keys, intermediary behavior, and deployment. Still, this is a significant review lead.

**Questions to investigate.** Does the response contain user-specific information? Can a shared cache store it? Is the cache key correctly scoped? Can another user receive the cached response? Are authorization headers or cookies handled correctly by the cache? Does the application use suitable cache-control directives for sensitive responses?

For highly sensitive authenticated responses, an application may use `Cache-Control: no-store`. The appropriate policy depends on the data and intended caching behavior. `no-store` is a useful directive, but it does not eliminate every possible exposure path, such as screenshots, logs, or data already copied elsewhere. A questionable cache header is not sufficient proof of cross-user disclosure. Establish whether the shared cache can actually serve one user's protected response to another user.

### 19. Vulnerability Sixteen: Account Enumeration Through Different Redirects

Not every authentication response contains a descriptive error message. Some applications reveal account state through redirect behavior. For example, an unauthenticated request might produce `Location: /mfa/setup` for one account, while another account produces `Location: /login`. If the difference depends on whether an account exists or has a particular authentication state, the redirect may expose information.

**Other signals.** Different redirect destinations, different numbers of redirect hops, different cookies being set, different response lengths, different error-page templates, different cache behavior, and different network requests triggered by the frontend.

**How to validate.** Use controlled accounts with known states and compare the full response sequence. Do not stop at the first HTTP status code. The browser's final page may conceal differences in intermediate responses, while the network trace may expose them.

**Remediation.** Where the account's state is meant to remain private, use consistent external behavior until the requester has completed the appropriate authentication step. Internal state transitions can remain detailed and explicit.

### 20. Vulnerability Seventeen: Authentication Information in API Responses

Consider a user-profile endpoint response containing `id`, `email`, `tenant_id`, `identity_provider_subject`, `mfa_enabled`, `last_password_reset`, `failed_login_count`, and `internal_auth_state`. Some of these fields may be legitimate for an authenticated user. Others may disclose more than the frontend needs. The question is not whether a field is internal. The question is whether the recipient should receive it and whether disclosure creates meaningful risk.

**Field-by-field assessment.**

| Field | Potential concern |
|---|---|
| Internal user ID | Usually context-dependent; may enable correlation |
| Tenant ID | May be appropriate if the user belongs to that tenant |
| External identity subject | Could expose internal identity mappings |
| MFA status | May reveal security configuration |
| Password-reset timestamp | Could disclose account-security history |
| Failed-login count | Could reveal monitoring or authentication state |
| Internal authentication state | Could expose implementation details or partial-authentication status |

**A common misconception.** An application does not need to hide every internal identifier. Internal IDs are often useful in normal API design. The issue arises when the exposed information enables unauthorized access, violates privacy expectations, reveals sensitive security configuration, or creates a meaningful attack advantage.

**Safer response design.** Return only the fields needed for the intended client functionality. Keep internal authentication state in server-side storage unless the client has a legitimate reason to receive a carefully designed representation of it.

### 21. Vulnerability Eighteen: Information Leakage Through User Enumeration in Administrative APIs

Not all account enumeration happens through public login forms. Suppose an authenticated ordinary user can call `GET /api/admin/users/alice@example.test` and receives `{"exists": true, "status": "active", "role": "administrator", "mfa_enabled": true}`. The first issue to investigate is whether this endpoint is intended to be available to that user. If it is an administrative endpoint and authorization is missing, the problem may extend beyond information disclosure. It could be a broken access-control issue.

**Distinguish the findings.** Information disclosure: the user can obtain sensitive information they should not receive. Broken authorization: the user can perform an operation or access a resource outside their permitted privileges. Authentication bypass: the user can establish an authenticated identity without satisfying the required authentication conditions. A single weakness can produce more than one impact, but the report should describe the actual demonstrated behavior.

**Testing approach.** Verify which role is required, whether the endpoint checks that role, whether tenant scope is enforced, which fields are exposed, and whether the response permits further unauthorized actions. This connects directly to Phase 11's tenant-isolation principles.

### 22. Vulnerability Nineteen: Leaking Secrets Through Exception Messages

Suppose an authentication service calls an external identity provider. The provider returns an error, and the application forwards it directly to the client, including fields such as `client_id`, `request_id`, `internal_endpoint`, and `token_endpoint_error`. Some information may be harmless, such as a public client identifier or request ID. Other information may reveal internal topology, identity configuration, or sensitive error conditions. If the upstream response contains credentials or tokens, forwarding it may be substantially more serious.

**Correct design.** The application should translate internal failures into appropriate public errors while retaining necessary diagnostics in protected logs. It should also ensure that sensitive upstream response bodies are not automatically exposed.

**Important distinction.** An internal hostname is not automatically a high-severity vulnerability. A public client ID is not automatically a secret. A `500` response is not automatically an authentication flaw. Report the information actually disclosed and the realistic consequence, not the mere presence of unfamiliar technical terminology.

### 23. Vulnerability Twenty: Authentication State Confusion

This category is especially important because it can overlap with authentication bypass. Imagine an application uses internal states `ANONYMOUS`, `PASSWORD_VERIFIED`, `MFA_PENDING`, `AUTHENTICATED`, with intended transitions from anonymous through password verification through required MFA to authenticated. A partially authenticated user should not receive all the privileges of a fully authenticated user.

Now imagine the application returns `{"user_id": "usr_104", "auth_state": "MFA_PENDING", "session_id": "session-example"}`. The response exposes internal state. That disclosure alone may not be a vulnerability. But if the application also lets the client submit `{"auth_state": "AUTHENTICATED"}` and trusts it, the issue is no longer merely information leakage. It becomes a trust-boundary failure that may allow authentication bypass.

**How to classify correctly.** Ask two separate questions: does the application disclose internal authentication state unnecessarily, and does the application trust client-controlled state when deciding whether authentication is complete? The first is information disclosure. The second may be an authentication bypass. Do not conflate the two. This echoes the client-supplied state flag failure examined in Phase 9.

### 24. Building a Reliable Enumeration Test

A senior tester needs a repeatable method for determining whether responses disclose account information. Use controlled test accounts such as `known-active@example.test`, `known-disabled@example.test`, `known-unverified@example.test`, and `unknown-address@example.test`, whose actual states are known through authorized setup. Then compare behavior across the same endpoint and operation.

**Record these signals.**

| Signal | Why it matters |
|---|---|
| HTTP status | May distinguish account states |
| Response body | May reveal existence or state |
| Response length | May expose different response templates |
| Redirect chain | May reveal different authentication paths |
| Cookies | May indicate session or partial-authentication changes |
| Timing | May reveal different backend processing paths |
| Rate-limit behavior | May reveal whether states are handled differently |
| Subsequent behavior | May confirm what the response actually means |

**Keep the test controlled.** Use test accounts you own or are authorized to assess. Avoid mass enumeration of real users. Do not use leaked credentials. Avoid excessive requests that could trigger account lockouts or service disruption. Account for network and server variability. Repeat observations where timing is relevant. Record both the expected policy and the actual result.

**What constitutes convincing evidence?** For a response-based enumeration issue, a strong finding usually demonstrates a reliable difference between known and unknown accounts, where the difference exposes information that should not be public. For timing-based enumeration, the evidence must show a repeatable, meaningful distinction rather than random latency. For a token leak, demonstrate what the token authorizes and who can access the exposed value, without compromising real accounts.

### 25. Vulnerability Severity: What Actually Matters?

Information disclosure is not a single severity category. The same technical mechanism can have very different consequences.

| Finding | Factors affecting severity |
|---|---|
| Framework identification | Whether it enables a meaningful additional attack |
| Account enumeration | Sensitivity of the user population and abuse controls |
| MFA-state disclosure | Whether the information supports targeted attacks |
| Stack trace | Sensitivity of disclosed data and exploitability |
| Reset-token leakage | Token authority, lifetime, and accessibility |
| Session-token leakage | Whether the token works and what it permits |
| SAML configuration leakage | Whether trust relationships or secrets are exposed |
| Cross-tenant identity disclosure | Tenant sensitivity and resulting attack opportunities |
| Authentication-state leakage | Whether it reveals sensitive state or enables bypass |
| Password or OTP logging | Secret validity, access to logs, and account impact |

**A severity mistake to avoid.** Do not claim that account enumeration automatically allows account takeover. Enumeration may make credential stuffing or phishing more efficient, but additional conditions are generally required. Likewise, do not claim that a stack trace enables remote code execution unless you have evidence supporting that conclusion. A professional report distinguishes directly demonstrated impact, plausible secondary impact, and speculative consequences. That distinction is part of senior-level security judgment.

### 26. Comprehensive Source-Code Review Exercise

Review this fictional authentication handler:

```python
def login(email, password):
    user = database.find_user_by_email(email)

    if user is None:
        return {
            "status": 404,
            "body": {
                "error": "Account does not exist"
            }
        }

    if user.status == "disabled":
        return {
            "status": 403,
            "body": {
                "error": "This account has been disabled"
            }
        }

    if not verify_password(password, user.password_hash):
        logger.info(
            "Login failed for %s with password %s",
            email,
            password,
        )

        return {
            "status": 401,
            "body": {
                "error": "Incorrect password",
                "mfa_enabled": user.mfa_enabled,
            }
        }

    if user.mfa_enabled:
        return {
            "status": 200,
            "body": {
                "message": "Password accepted",
                "auth_state": "MFA_PENDING",
                "user_id": user.id,
            }
        }

    return create_authenticated_session(user)
```

There are several review leads.

**Finding A: account enumeration.** Unknown accounts return `404`, while known accounts with incorrect passwords return `401`. This exposes account existence. Disabled accounts also receive a distinct response, revealing account status.

**Finding B: password leakage in logs.** The code writes the supplied password to the application logs. This is a direct secret-handling concern. If those logs are accessible to unauthorized personnel or third-party systems, the disclosure may expose credentials. Even if access is restricted, storing plaintext passwords in logs creates unnecessary risk.

**Finding C: MFA-state disclosure.** The incorrect-password response includes `{"mfa_enabled": true}`. This exposes the account's MFA configuration before successful authentication. The risk depends on the application's disclosure policy, but the information is generally unnecessary for an unsuccessful login response.

**Finding D: partial-authentication information.** The successful password-check response includes `{"auth_state": "MFA_PENDING", "user_id": "usr_104"}`. This exposes internal authentication state. That alone does not establish an authentication bypass. You must inspect whether the partial session is securely managed and whether protected endpoints reject it until MFA is completed.

**Finding E: password-verification processing.** The example returns immediately for unknown accounts. Depending on the actual implementation and processing costs, this could create a timing distinction between unknown accounts and known accounts with incorrect passwords. This requires measurement, the code alone does not prove a practical timing side channel.

**Finding F: session behavior is not shown.** The final line creates an authenticated session when MFA is disabled. A full review must determine whether the session is properly established, whether its identifier is protected, and whether any previous unauthenticated session is rotated when appropriate. These are important authentication checks, but they are not all information-disclosure findings.

**A safer conceptual design:**

```python
def login(email, password):
    user = database.find_user_by_email(email)

    password_hash = (
        user.password_hash
        if user is not None
        else DUMMY_PASSWORD_HASH
    )

    password_ok = verify_password(
        password,
        password_hash,
    )

    if user is None or not password_ok:
        logger.info(
            "Authentication failed",
            extra={
                "reason": "invalid_credentials",
            },
        )

        return generic_login_failure()

    if user.status != "active":
        return generic_login_failure()

    if user.mfa_enabled:
        return begin_server_side_mfa_challenge(user)

    return establish_authenticated_session(user)
```

This is illustrative pseudocode, not a production-ready authentication implementation. It demonstrates several improvements: a generic external failure response, no plaintext password logging, no unnecessary disclosure of MFA state, a distinct server-side MFA challenge, and no direct reliance on a client-supplied authentication state. A production system still needs appropriate rate limiting, monitoring, secure session management, account-state policy, and safe MFA handling.

### 27. Advanced Distinction: Information Disclosure Versus Authentication Bypass

These findings are related, but they are not interchangeable.

**Case A: the application reveals that an account exists.** This is potentially account enumeration. The attacker learns information but does not necessarily gain access.

**Case B: the application reveals that MFA is enabled.** This is potentially authentication-configuration disclosure. It may support targeting, but it does not automatically defeat MFA.

**Case C: the application returns an MFA-pending session identifier.** This is not automatically a vulnerability. You must determine whether the identifier grants any authority and whether the application protects partial-authentication state correctly.

**Case D: the application accepts that identifier as a fully authenticated session.** If the application permits protected operations without completing the required MFA step, the issue may be an authentication bypass.

**Case E: the application exposes a usable reset token.** This may be a sensitive-token disclosure. If an unauthorized person can use it to reset the victim's password, the demonstrated impact may include account takeover.

The correct classification follows the demonstrated security consequence, not the name of the leaked field.

### 28. Authentication Information Leakage: Defensive Architecture

A mature application should have an explicit strategy for controlling authentication-related disclosures.

**Layer 1: public responses.** Use consistent, appropriately generic responses where account privacy requires it. Avoid revealing whether an account exists, whether its password is correct, which MFA methods are enrolled, and whether a recovery token belongs to a particular account. The precise level of detail depends on the application's user experience and security requirements.

**Layer 2: internal diagnostics.** Record useful security events without storing passwords, session secrets, reset tokens, or unnecessary authentication payloads. Use structured logs, redaction, correlation identifiers, appropriate access controls, retention limits, and monitoring for suspicious activity.

**Layer 3: secret lifecycle management.** For authentication secrets: avoid unnecessary exposure, restrict access, limit lifetime and scope where applicable, support revocation, prevent reuse where the protocol or design requires it, and avoid including secrets in URLs or diagnostic data without a justified design.

**Layer 4: consistent behavior.** Review the entire authentication lifecycle, including login, registration, password recovery, email verification, MFA enrollment, SSO, logout, session expiration, and account disablement. A secure login response does not compensate for an enumeration flaw in password recovery.

**Layer 5: monitoring.** Monitor patterns such as high volumes of failed logins, repeated password-reset requests, large numbers of unique email addresses, repeated verification failures, unusual authentication error rates, and attempts to access protected diagnostic endpoints. Monitoring is a defense in depth. It does not eliminate a disclosure that is already exposed to every unauthenticated caller.

### 29. Your Senior-Level Testing Checklist

Before reporting authentication information leakage, answer these questions.

**A. What information is exposed?** Be precise. Is it an account-existence signal, authentication state, token, internal identifier, configuration detail, or stack trace?

**B. Who can obtain it?** An anonymous visitor, authenticated user, tenant administrator, internal support user, or privileged operator?

**C. Is the recipient authorized to receive it?** Some information is legitimately visible to the account holder or administrator.

**D. Is the information actually sensitive?** A public client ID is different from a private client secret. An internal record ID is different from a bearer session token.

**E. Is the disclosure reliable?** For enumeration or timing, establish that the difference is repeatable and not just noise.

**F. What can the recipient do with the information?** Can it support targeting, account correlation, unauthorized access, token redemption, or a meaningful subsequent attack?

**G. Is the impact demonstrated?** Distinguish actual consequences from speculative possibilities.

**H. What is the smallest sufficient proof?** Use controlled accounts and minimal evidence. Do not unnecessarily access or expose real users' data.

**I. What is the correct remediation?** The fix may involve response normalization, secret redaction, access control, safe parsing, token handling, or stronger authentication-state enforcement.

**J. Does the remediation introduce another weakness?** For example, hiding account-existence errors should not cause password recovery to become unreliable or allow recovery requests without appropriate abuse controls.

### 30. Final Assessment: What You Must Retain

This module has covered a broad set of information-leakage patterns. The most important concepts are these:

**1. Enumeration is about observable differences.** The difference may appear in messages, status codes, redirects, cookies, response length, or timing.

**2. Generic responses are useful but insufficient by themselves.** Other observable behavior may still disclose account state.

**3. Authentication secrets must be handled differently from ordinary identifiers.** A bearer token can grant authority, a non-secret database ID usually does not.

**4. Internal errors belong in protected diagnostics.** Public responses should not expose unnecessary stack traces, infrastructure details, or authentication secrets.

**5. Authentication state is not the same as authenticated access.** A response may disclose that a password check succeeded or MFA remains pending. The real security issue arises if the application improperly grants authority before the required authentication steps are complete.

**6. Severity follows impact.** Account enumeration, a framework header, a reset-token leak, and a working session-token disclosure are not equivalent findings.

**7. Verify before reporting.** A suspicious field, error message, or header is a lead. A strong report establishes what is disclosed, who can obtain it, and why it matters.

## Assessment

The following assessment is drawn from "Authentication Security.md" and addresses response-based account enumeration, establishing reproducibility, timing-based enumeration surviving a generic-message fix, and the source-code execution-path analysis behind the dummy-hash remediation. As with the prior phases, the questions are preserved from the original source, and the answers given are the instructor's corrected, authoritative answers rather than the original learner's submitted answers.

### Assessment Question 1

A fictional e-commerce application, ShopSphere, behaves differently depending on whether a submitted email belongs to an existing account. Submitting an incorrect password for a registered account, `alice@example.test`, returns:

```http
HTTP/1.1 401 Unauthorized
Content-Type: application/json

{
  "error": "Incorrect password",
  "code": "INVALID_PASSWORD"
}
```

Submitting the same incorrect password for an unregistered account, `unknown@example.test`, returns:

```http
HTTP/1.1 404 Not Found
Content-Type: application/json

{
  "error": "Account does not exist",
  "code": "USER_NOT_FOUND"
}
```

What security weakness might these two responses reveal, and what specific observation would convince you that this is a genuine, reproducible account-enumeration vulnerability rather than an isolated response?

<details markdown="1">
<summary><strong>Reveal Answer</strong></summary>

The weakness is username and email enumeration. The application reveals account existence through two structurally different responses: an existing email with the wrong password returns `401 Incorrect password`, while a non-existing email returns `404 Account does not exist`. An attacker could automate requests to determine which email addresses have registered accounts, using only the status code and body, without needing a correct password at all.

Identifying the weakness is only the first step. A senior tester must establish whether the behavior is consistently exploitable, which requires more than a single observed pair of responses. The specific observation that would convince you is reproducibility: submitting further requests, for example another incorrect password against the same registered account, and confirming that the distinction between existing and non-existing accounts holds consistently, using the same incorrect password and equivalent request conditions each time, and that the difference is actually observable through response status codes, messages, or error codes. The evidence needs to be consistent (repeated requests produce the same distinction), comparable (the same incorrect password and equivalent request conditions are used), observable (the difference is visible through status codes, messages, error codes, or timing), and security-relevant (an unauthenticated attacker can use the distinction to identify registered accounts). Identifying a vulnerability without validating it this way is not sufficient for professional security testing.

</details>

### Assessment Question 2

Suppose the application changes both responses to the identical body:

```http
HTTP/1.1 401 Unauthorized

{
  "message": "Invalid email or password"
}
```

But you notice that registered accounts consistently take 800ms to respond, while unregistered accounts take 80ms. Has the application completely fixed account enumeration? Why or why not, and what would a senior tester need to establish before concluding the timing difference is a real vulnerability?

<details markdown="1">
<summary><strong>Reveal Answer</strong></summary>

No, the application has not fixed account enumeration, even though it changed both responses to an identical message. Removing the difference in response bodies does not eliminate every observable signal, there are still other ways to distinguish the two cases, and in this scenario it is response timing specifically. Changing the error messages does not necessarily eliminate information disclosure if another observable difference still reveals account existence. This is timing-based account enumeration: an attacker may be able to identify registered accounts without receiving different response messages or status codes at all, purely by measuring how long the server takes to respond.

However, a single 800ms versus 80ms observation does not conclusively establish a timing vulnerability on its own. A senior tester would repeat requests under comparable conditions, compare response-time distributions across registered and unregistered accounts rather than single samples, account for network latency and server load, and establish whether the timing difference is consistent and statistically distinguishable rather than coincidental. What this demonstrates is an important AppSec skill: moving beyond examining response bodies and recognizing that HTTP timing itself can leak authentication-related information.

</details>

### Assessment Question 3

A financial application has introduced generic login errors, but its backend logic looks like this:

```javascript
const user = await findUser(email);

if (!user) {
    return genericError();
}

const valid = await verifyPassword(password, user.passwordHash);

if (!valid) {
    return genericError();
}

return createSession(user);
```

Both failure paths return the identical generic error message. Identify the specific design decision that could still expose registered accounts despite the identical messages, and explain why the two execution paths can be distinguished even though the responses look the same.

<details markdown="1">
<summary><strong>Reveal Answer</strong></summary>

The implementation can still introduce a timing-based account enumeration vulnerability, and the vulnerability is not in the error message at all, it is in the difference between the two execution paths. For a non-existing account, execution stops immediately after the user lookup: `findUser(email)` returns nothing, and the function returns the generic error right away. For an existing account with an incorrect password, the application performs an additional, more expensive step first, the actual password-hashing verification via `verifyPassword(password, user.passwordHash)`, before it returns that same generic error. Consequently, the two requests may have measurably different response times, even though their bodies are byte-for-byte identical.

This is an important source-code review skill: understanding how internal implementation details, specifically which operations execute on which path, become externally observable security weaknesses, independent of anything visible in the response itself. You cannot determine whether this is actually exploitable just by reading the two `return genericError()` statements, you have to trace which expensive operations occur before each one is reached.

</details>

### Assessment Question 4

Continuing the same scenario, what would you recommend changing in the implementation to reduce the timing difference between existing and non-existing accounts, and once you apply that fix, why must the application still explicitly check `!user` even after successfully verifying the password against a dummy hash?

<details markdown="1">
<summary><strong>Reveal Answer</strong></summary>

The correct remediation is to perform password-hash verification even when the account doesn't exist, so that both paths do comparable work. Instead of returning immediately when `findUser` finds nothing, the application selects a dummy password hash in that case and still runs the verification function against it:

```javascript
const user = await findUser(email);

const hash = user
    ? user.passwordHash
    : DUMMY_PASSWORD_HASH;

const valid = await verifyPassword(password, hash);

if (!user || !valid) {
    return genericError();
}

return createSession(user);
```

The `DUMMY_PASSWORD_HASH` must be generated using the same password-hashing algorithm and comparable cost parameters as real user hashes, otherwise the timing still differs. This does not guarantee perfectly identical timing, database lookups, infrastructure behavior, and other execution differences can still leak information, so it should be paired with generic error messages, rate limiting, consistent response behavior, and monitoring of suspicious login attempts.

The `!user` check remains essential because of what the `||` (OR) actually evaluates: the condition is true, and a generic error is returned, whenever the user does not exist, regardless of what the dummy-hash verification returned, or whenever the password is invalid for a user that does exist. If that `!user` check were removed, leaving only `if (!valid) { return genericError(); } return createSession(user);`, then a dummy-hash verification that happened to evaluate as valid, or any logic error that let `valid` become true for a nonexistent user, could cause the application to attempt to create a session for a user that does not exist at all. The `!user` check ensures that successful password verification alone is never sufficient on its own, authentication must establish both the existence of a legitimate identity and successful verification of its credentials, and removing either half of that conjunction breaks the security property even if the other half still looks correct.

</details>

## Remediation and Secure Implementation

The following consolidates the remediation guidance across all thirty sections of this phase.

1. Return the same generic response for every authentication failure, unknown account, wrong password, disabled account, unless a specific, deliberate exception is justified and its risk accepted, and verify that status code, body, length, and redirect behavior are all actually identical, not just the visible message.
2. Equalize the processing cost of every authentication failure path, for example by verifying a submitted password against a dummy hash of comparable cost when no account exists, to close timing side channels that survive a generic response.
3. Keep detailed diagnostic information, exact failure reasons, MFA configuration, account state, in protected internal logs and administrative tools, never in the public response, and connect the two only through a correlation identifier.
4. Never log passwords, session secrets, reset tokens, recovery codes, authorization headers, or unredacted identity-provider assertions, and use structured, redacted logging with appropriate access controls and retention limits instead.
5. Treat every URL parameter, HTTP header, and redirect destination that could carry a token as a potential leakage path, and verify whether the value is a genuine bearer credential or merely an opaque identifier before deciding how to protect it.
6. Set `Cache-Control: no-store` or an equivalently restrictive policy on any response containing account-specific or authentication-sensitive data, and verify that shared caches cannot actually serve one user's response to another.
7. Strip unnecessary debug headers, verbose stack traces, and upstream error details from production responses, translating internal failures into generic public errors while preserving full diagnostics in protected logs.
8. Return only the fields an API response's legitimate client actually needs, and keep internal authentication state, failed-login counts, and identity-provider subjects out of ordinary client-facing responses unless there is a specific, justified need.
9. Separately verify, for any endpoint exposing user or account information, whether the recipient is authorized to receive it at all, since an enumeration finding on an improperly accessible administrative endpoint may actually be a broken-authorization finding.
10. Never trust client-supplied authentication state, such as an `auth_state` field, as proof that a required step was completed, since disclosing internal state is information leakage, but trusting client-supplied state is authentication bypass, a materially more serious and separately reportable finding.

## Key Takeaways

This phase's governing distinction, stated in its own first section, is that the vulnerability is never simply that information exists. It is that the application discloses information to an unauthorized recipient in a way that creates meaningful risk. A public client ID, an internal record ID, a `500` status code, and a stack trace are none of them automatically dangerous, and treating them as if they were produces weak, easily dismissed reports. The skill this phase builds is precision: naming exactly what is exposed, to whom, and what realistic consequence follows.

The assessment in this phase demonstrates why that precision matters at every layer of a fix. A visibly different error message is the easiest leak to find and the easiest to patch, but patching it is not the same as closing the underlying channel, a timing difference can survive an identical response body entirely unchanged. And fixing the timing difference correctly still leaves a structural trap: a dummy-hash check that succeeds for a nonexistent user is not itself a vulnerability, but removing the explicit `!user` guard that sits beside it would turn that same code into an authentication bypass. The lesson that carries forward from this module is that a remediation is only as complete as the full execution path it covers, not just the field or message that prompted the finding.

## Review Checklist

- [ ] Can you state, in one sentence, what makes authentication information leakage a vulnerability rather than merely visible information?
- [ ] Can you name the six major categories of authentication leakage with an example of each?
- [ ] Can you explain why a generic error message alone does not eliminate account enumeration, and what signal can survive it?
- [ ] Can you distinguish a bearer credential from a non-secret identifier, and explain why the distinction determines severity?
- [ ] Can you explain why a `500` response, a stack trace, or a public client ID are not automatically high-severity findings?
- [ ] Can you list at least five of the common locations a session or reset token can leak beyond its intended flow?
- [ ] Can you distinguish information disclosure from authentication bypass, using the `auth_state` disclosure-versus-trust example?
- [ ] Can you design a reliable, controlled enumeration test using known and unknown accounts, and explain what makes timing evidence convincing?
- [ ] Can you apply the five-layer defensive architecture, public responses, internal diagnostics, secret lifecycle, consistent behavior, monitoring, to a login flow?
- [ ] Can you trace, from source code, which execution path differences between a known and unknown account could create a timing side channel?
- [ ] Can you explain why the `!user` check remains necessary even after adding dummy-hash password verification?
- [ ] Can you answer all ten questions in the module's senior-level testing checklist for a disclosure finding of your choosing?

## References to Related Phases

- The client-supplied authentication state failure examined in section 23, where disclosed state becomes trusted state, is the same pattern examined in depth in **Phase 9, Reauthentication and Step-Up Authentication**, and for MFA specifically in **Phase 3, Multifactor Authentication (MFA) Attacks**.
- Password-reset token lifecycle and leakage, covered in section 10, extends the reset-token principles from **Phase 2, Password Change and Account Recovery**.
- SSO error leakage in section 14 and the OAuth/OIDC parameter leakage discussed in section 15 connect directly to **Phase 7, OAuth 2.0 and OpenID Connect Security** and **Phase 10, SAML Security**.
- Administrative API disclosure in section 21, which can overlap with broken tenant-scoped authorization, connects to **Phase 11, Multi-Tenant Identity Isolation**.
- The dummy-password-hash remediation technique for timing-based enumeration was first introduced as a password-storage concept in **Phase 1, Password Storage and Credential Attacks**.
