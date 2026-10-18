# Phase 2: Password Change and Account Recovery

**Source material:** Module 2 of 17, "Authentication Complete Phases Test.md" (Lessons 2.1 through 2.9, the Additional Password Change and Recovery Subtopics, the Final Review, and the Progress Tracker), with supplementary explanatory material folded in from two pre restart sections of the same file ("Unknown Host Redirect and Host Header Injection" and "Password Reset Email Injection"), and supplementary assessment material drawn from "Authentication Security.md" (Challenge 06 and its continuation on reset token and account binding, Challenge 11, and Challenge 12).

## Learning Objectives

After completing this phase, you should be able to:

1. Walk through the complete lifecycle of a password reset, from request to finalization, and explain the security property each stage is responsible for.
2. Explain why password reset token reuse is a distinct failure from token expiration, and test for each separately.
3. Explain why a password reset token must be bound to the account it was issued for, and identify the source code pattern that signals a binding failure.
4. List the channels through which a reset token can leak, beyond the obvious case of a stolen email.
5. Distinguish password reset email injection, password reset poisoning, and reset token leakage as three different problems that are often grouped together under a single confusing label.
6. Explain why an application's Host header is not a trustworthy input, and why that matters specifically for password reset link generation.
7. Explain how account enumeration can occur through a recovery flow even when the response wording is generic.
8. Explain why changing a password, invalidating a reset token, and revoking existing sessions are three separate operations that a secure recovery flow must each decide on deliberately.
9. Identify the distinct root causes that can all produce the same surface level outcome of "account takeover," and explain why a strong vulnerability report names the specific failure rather than the generic impact.
10. Apply the same impact validation discipline from Phase 1 to a recovery flow: distinguish a suspicious response from proven account compromise, including when an alternate, weaker recovery mechanism undermines an otherwise secure primary reset flow.

## Introduction

Phase 1 established that offline password attacks, online credential attacks, and credential lifecycle weaknesses are three separate attack surfaces. Password recovery sits inside the third surface, and it deserves its own phase because of a principle introduced at the end of Phase 1's lesson on security questions: an attacker should not be able to defeat a strong login mechanism simply by choosing a weaker recovery path.

Password recovery exists because people forget passwords, but the moment an application builds a path into an account that does not require the normal password, it has built a second authentication mechanism. That second mechanism needs the same rigor as the first. A perfectly designed login page, protected by strong hashing and sensible rate limiting, is only as strong as its weakest recovery path. This phase walks through every point in that recovery path where the rigor can quietly disappear: a token that is never actually consumed, a token that is not checked against the right account, a token that leaks through a channel nobody thought to secure, or a second recovery endpoint that nobody protected as carefully as the first.

## Core Concepts

The module is organized in three movements. First, Lessons 2.1 through 2.9 walk through the password reset lifecycle stage by stage: requesting a reset, generating a token, validating a token, setting a new password, and finalizing the recovery, followed by the specific ways each stage can fail (reuse, expiration, account binding, leakage, email handling, enumeration, and session behavior). Second, the Additional Subtopics address five supporting distinctions that do not fit neatly into a single lifecycle stage: password change versus password reset, temporary passwords, password history, reset link host trust, and the difference between an impact label and a root cause. Third, the assessment section applies the impact validation discipline from Phase 1 to several recovery scenarios, including a case where a second, weaker recovery mechanism undermines an otherwise well built primary reset flow.

## Lessons

### Lesson 2.1: Understanding the Password Reset Lifecycle

Password recovery is one of the most important parts of authentication security, because recovery provides an alternative route into an account. An attacker may be unable to defeat the normal login mechanism but still succeed if the recovery process is weaker.

Consider a fictional application called `ShopSecure`. A user forgets their password and requests a reset. A properly designed flow has several stages.

**Stage 1: Request a reset.**

```http
POST /forgot-password HTTP/1.1
Host: shopsecure.example
Content-Type: application/json

{
  "email": "user@example.com"
}
```

A privacy conscious response might be:

```http
HTTP/1.1 202 Accepted
Content-Type: application/json

{
  "message": "If an eligible account exists, recovery instructions will be sent."
}
```

This response avoids directly revealing whether an account exists. The application can then send a recovery message if appropriate. Notice the phrase "if an eligible account exists." The server should not promise that a message was sent when it has not actually sent one, but it can use a generic response to reduce account enumeration.

**Stage 2: Generate a recovery token.**

The server generates a high entropy, unpredictable token. A recovery record might conceptually contain:

```text
user_id: 481
token_hash: [stored token verifier]
created_at: [timestamp]
expires_at: [timestamp]
used_at: null
purpose: password_reset
```

This is an illustrative schema, not a required database design. The important properties are that the token is sufficiently unpredictable, it is associated with the correct account, its purpose is restricted to password recovery, it expires, it can be invalidated, and it cannot be reused after successful consumption. Storing a verifier of the token rather than the raw token can reduce the impact of certain database exposures, provided the implementation uses an appropriate design.

**Stage 3: Validate the token.**

The user opens the recovery link and submits the token. The server must verify that the token exists, is authentic, belongs to the intended account, is valid for password recovery, has not expired, has not already been consumed, and has not been revoked or invalidated. A valid token must not automatically be treated as proof of authority for unrelated actions.

**Stage 4: Set a new password.**

The application validates the new password and securely stores its verifier. It must not accidentally log the raw password or expose it in error messages.

**Stage 5: Finalize recovery.**

After the password changes, the application should mark the recovery token as consumed, invalidate applicable outstanding reset tokens, apply the intended session revocation policy, notify the account owner through an appropriate channel, ensure the old password no longer works, ensure the new password works, and prevent recovery tokens from authorizing unrelated operations.

Changing the password and revoking existing sessions are separate operations. Do not assume that one automatically performs the other. Session revocation is studied in depth in Phase 6.

### Lesson 2.2: Password Reset Token Reuse

This is a common recovery flow design mistake.

**The vulnerable behavior.** Suppose a user receives a reset link:

```text
https://shopsecure.example/reset?token=EXAMPLE_TOKEN
```

The user opens it and successfully changes their password. Later, the same token is submitted again. If the application accepts it and permits another password change, the token has not been properly consumed. This is a password reset token reuse vulnerability.

**Why it matters.** Imagine an attacker obtains a valid recovery token before the legitimate user completes the reset. If the token remains usable after the legitimate user changes their password, the attacker may still be able to reset the password afterward. The impact depends on how the token was obtained, whether it remains valid, and what additional controls the application enforces. A reusable token does not automatically prove that an attacker has obtained a victim's account. However, it can undermine the recovery process and prolong the usefulness of a leaked token.

**The vulnerable implementation pattern.**

```python
async def reset_password(token, new_password):
    reset = await find_reset_token(token)

    if not reset:
        raise Unauthorized()

    await update_password(reset.user_id, new_password)

    return {"message": "Password updated"}
```

The code checks whether the token exists, but it does not visibly check whether the token has expired, has already been used, or has been revoked. It also does not visibly consume the token after success. This is a deliberately incomplete example. In a real application, you must inspect the complete execution path before concluding that the checks do not exist elsewhere.

**Secure implementation logic.**

```python
async def reset_password(token, new_password):
    reset = await find_reset_token(token)

    if reset is None:
        raise Unauthorized()

    if reset.used_at is not None:
        raise Unauthorized()

    if reset.expires_at <= current_time():
        raise Unauthorized()

    if reset.revoked_at is not None:
        raise Unauthorized()

    user = await find_user(reset.user_id)

    if user is None:
        raise Unauthorized()

    validate_password(new_password)

    await store_password_hash(user.id, new_password)
    await mark_reset_token_used(reset.id)
    await invalidate_other_reset_tokens(user.id)

    return {"message": "Password updated"}
```

This illustrates the required logic, not production ready code. In particular, the password update and token consumption must be designed to maintain consistent state if an operation fails. Merely calling two functions sequentially does not guarantee that both changes are committed together.

**How a bug hunter validates this.** Using an account and reset token you are authorized to test: request a password reset, complete the reset, submit the same token again, determine whether the application accepts it, and confirm whether the second request actually changes the password. A generic success response alone is insufficient evidence. The application might return a success shaped response while rejecting the operation internally.

**Correct remediation.** Implement server side token validation and reliable single use semantics. The server must enforce token consumption, the frontend must never be the sole mechanism preventing reuse.

### Lesson 2.3: Reset Token Expiration Failures

Expiration limits how long a recovery token remains valid. Imagine the application generates a token and records:

```text
created_at: 2026-10-17 10:00
expires_at: 2026-10-17 10:20
```

The token is intended to be valid for twenty minutes. At 10:30, the user submits the token. The application should reject it.

**What can go wrong?**

1. Expiration is not checked. The server verifies only that the token exists. An old token may remain valid indefinitely.
2. Expiration is checked only in the frontend. The interface disables the reset button after a certain time, but the server continues accepting expired tokens. Security decisions must be enforced on the server.
3. The expiration timestamp is calculated incorrectly. The system may use inconsistent time zones, incorrect units, or a timestamp that is never updated as intended. For example, milliseconds and seconds can be confused in timestamp calculations.
4. The application checks the wrong token record. If several reset requests exist, the application may validate one record but use another record's account association or expiration status.
5. Expiration does not account for invalidation. A token may still be within its time limit but should have been revoked after a successful reset, account change, or another security event. Expiration and revocation are separate controls.

**Security testing.** Assess whether the application enforces expiration on the server. Use controlled test cases involving valid, expired, used, and revoked tokens. Do not assume that a reset link's continued presence in an email means it remains valid.

**Remediation.** Use a consistent server side time source, enforce expiration during validation, and reject expired or revoked tokens regardless of what the interface displays.

### Lesson 2.4: Reset Token Account Binding

A recovery token must be bound to the account for which it was issued. This sounds obvious, but it is a crucial security property.

Imagine two users:

```text
User A: alice@example.com
User B: bob@example.com
```

The application issues a reset token for Alice. A vulnerable implementation might accept Alice's token but use a separately supplied email address to select which account receives the new password. Consider this fictional request:

```http
POST /reset-password HTTP/1.1
Host: shopsecure.example
Content-Type: application/json

{
  "token": "ALICE_RESET_TOKEN",
  "email": "bob@example.com",
  "new_password": "NewPassword!88"
}
```

If the server validates Alice's token but changes Bob's password, the token account relationship has been broken. This can lead to account takeover.

**Root cause.** The server treats two separate pieces of information as independently trustworthy: the recovery token, and the client supplied account identifier. Instead, the validated recovery record should determine which account can be changed.

**Correct design.**

```text
Submitted token
      |
      v
Validate token record
      |
      v
Read user_id from trusted record
      |
      v
Change password for that user_id
```

The application should not let an untrusted account identifier override the account associated with the validated token.

**Source code review clue.** Look for patterns such as:

```python
reset = await validate_reset_token(token)
user = await find_user(request.email)
await update_password(user.id, new_password)
```

This is suspicious because the user identified by the request is not visibly connected to the validated reset record. It is not enough to spot those three lines, however. Check whether the application separately verifies that `user.id == reset.user_id` or otherwise enforces the binding.

**Remediation.** Use the validated recovery record as the authoritative source of the target account. Validate the token and account association on the server.

### Lesson 2.5: Reset Token Leakage

A reset token is a temporary credential. If an attacker obtains a valid token, they may be able to exercise the authority granted by that token. Therefore, recovery links must be protected against unnecessary exposure.

**Where can tokens leak?**

1. **Application logs.** Suppose the application logs the full request URL, `GET /reset?token=SECRET_VALUE`. If logs are accessible to people or systems that should not see recovery tokens, the token may be exposed.
2. **Browser history.** Tokens embedded in URLs can remain in browser history or other browser associated records.
3. **Referrer information.** If a recovery page loads external resources, the browser's referrer behavior can expose URL information in certain circumstances. This is a token leakage issue, separate from the excluded topics of cross site scripting, CORS, and CSRF.
4. **Analytics and monitoring tools.** Third party analytics or monitoring systems may collect page URLs, query parameters, or navigation data. If recovery tokens are included in the collected information, they may be exposed beyond the intended recovery system.
5. **Email and messaging accounts.** A reset link sent to an email account may be exposed if that email account is compromised. This is not necessarily an application vulnerability by itself, but it is part of the recovery threat model.
6. **Support tickets and screenshots.** Users and support personnel may inadvertently copy complete reset links into tickets, chat messages, or screenshots. Sensitive tokens should be redacted before such material is shared.

**How to reduce token leakage.** Avoid unnecessarily placing sensitive tokens in URLs when a suitable alternative exists. If a URL based recovery token is required, make it short lived and single use. Avoid logging full recovery URLs. Redact tokens in monitoring and error reporting. Apply an appropriate restrictive referrer policy. Avoid unnecessary third party resources on sensitive recovery pages. Invalidate the token after successful use. Provide a safe process for revoking exposed tokens.

Hiding a token from the user interface does not make it secret if the browser, application, logs, or other systems still expose it.

### Lesson 2.6: Password Reset Email Injection and Email Abuse

Email related recovery vulnerabilities require careful distinction, because several different weaknesses are often grouped under the term "email injection."

**Problem A: Recipient manipulation.** Suppose the application allows the requester to supply an email address and uses it as the recipient of the recovery message. If the server sends a legitimate reset token to an address controlled by the requester, that is not automatically a vulnerability. Users should generally be able to request recovery for their own accounts. The problem arises when the system can be made to send another user's sensitive recovery material to an unauthorized recipient. For example, if the server validates one account but sends that account's reset token to an attacker controlled address, the recovery flow has a serious account binding failure.

**Problem B: Email header injection.** Email header injection occurs when untrusted input is incorporated into email headers without appropriate handling. Depending on the email library and implementation, malformed input may affect recipient or header fields. Modern email libraries often prevent raw newline characters from being used to inject additional headers, but developers must still use APIs correctly and validate the expected address format.

**Problem C: Password reset message abuse.** An attacker may repeatedly trigger recovery messages for another person's address. Possible consequences include unwanted email floods, user confusion, increased support burden, and abuse of the application's email sending resources. This is an abuse prevention problem even when no account takeover is possible.

**Problem D: Reset token disclosure through email content.** The recovery message itself might expose sensitive information through incorrect recipient selection, accidental copying of another user's token, unsafe logging, misconfigured email templates, or inadequate access controls in the email delivery workflow.

**How to review the implementation.** Trace the complete flow:

```text
User input
    |
    v
Account lookup
    |
    v
Recovery record creation
    |
    v
Recipient selection
    |
    v
Email template construction
    |
    v
Email provider
    |
    v
Delivery
```

At each step, determine which data is trusted and where the recipient and token are obtained. The recipient should be derived from the appropriate verified account record, not arbitrarily overridden by an unrelated client supplied value.

**Remediation.** Use established email libraries, validate input appropriately, prevent header injection, bind recovery tokens to their intended accounts, rate limit recovery requests, and ensure tokens cannot be disclosed through logs or templates. Do not confuse a generic email delivery issue with a confirmed account takeover vulnerability. Demonstrate the actual security consequence.

#### Supplement: Host Header Trust and Password Reset Poisoning

This supplement folds in material from two related topics covered earlier in the course material, because both concern the same underlying problem referenced above in Problem A and later in the Additional Subtopics: an application trusting the wrong source of information when it decides where a recovery link should point.

**What is the HTTP Host header?** A normal HTTP request might look like this:

```http
GET /login HTTP/1.1
Host: app.example.com
User-Agent: Mozilla/5.0
Accept: text/html
```

The `Host` header identifies the requested host. However, the application or its infrastructure may use host related request information when constructing absolute URLs, deciding which virtual host to serve, or performing redirects. That creates a trust boundary problem. The hostname received from a request is not automatically a trusted configuration value.

**Unknown host redirect.** Imagine an application receives a request for an unrecognized hostname and redirects the visitor somewhere. A redirect is not necessarily a vulnerability. The important questions are whether an attacker can influence the destination, whether the application redirects users to an untrusted domain, whether the redirect affects a sensitive workflow, whether it can expose credentials, tokens, or other information, and whether it undermines a security control.

For example, a fictional application contains this logic:

```python
def after_login(request):
    host = request.headers.get("Host")
    return redirect(f"https://{host}/dashboard")
```

The application assumes the supplied hostname is trustworthy, but request headers can be manipulated by clients. If the server uses an attacker controlled hostname to generate a redirect, a visitor might be sent to an unintended destination. This is a potential host header or redirect handling weakness, and the exact classification depends on the behavior and impact.

**Host header injection.** Host header injection occurs when the application or infrastructure trusts an attacker controlled host value in a security sensitive operation. Potential consequences include password reset poisoning, incorrect absolute URL generation, cache poisoning, access to functionality exposed through flawed host based trust, and routing problems or, in some architectures, server side request forgery related behavior. These are distinct outcomes. A manipulated Host header does not automatically produce all of them.

Simulated request:

```http
GET / HTTP/1.1
Host: unexpected.example
```

Possible response:

```http
HTTP/1.1 302 Found
Location: https://unexpected.example/login
```

This indicates that the destination may be derived from the request's hostname. It is not sufficient by itself to establish a high impact vulnerability. You would need to determine whether the behavior is unintended, whether an attacker can influence it in practice, and what security impact follows.

**Secure implementation.** Use an explicitly configured canonical hostname:

```python
CANONICAL_ORIGIN = "https://app.example.com"

def password_reset_link(token):
    return f"{CANONICAL_ORIGIN}/reset?token={token}"
```

For production applications: validate permitted hostnames, configure trusted hosts at the framework or proxy layer, avoid constructing sensitive absolute URLs from untrusted request headers, configure reverse proxies to handle host related headers securely, do not trust `X-Forwarded-Host` simply because it appears to originate from a proxy, and ensure caches and routing infrastructure use consistent host validation.

**Open redirect versus host header injection.**

| Open redirect | Host header injection |
|---|---|
| An attacker can influence a redirect destination. | An attacker can influence how a system uses host related request data. |
| Often involves parameters such as `?next=` or `?returnUrl=`. | Often involves `Host` or trusted proxy host headers. |
| May occur entirely in redirect logic. | May affect redirects, emails, routing, caches, or other behavior. |
| Can sometimes be exploited without manipulating HTTP headers. | Depends on the system's use of host related values. |

A single issue may involve both. Do not automatically label every host header problem an open redirect.

**How to assess severity.** Consider three examples. In Example A, an unrecognized hostname causes a harmless redirect to a public landing page, and the impact may be low or nonexistent. In Example B, a redirect sends users to an attacker controlled domain after they click a trusted site's login link, which may enable phishing depending on the context. In Example C, a password reset email contains a link to an attacker controlled domain and includes a valid reset token, which can potentially lead to account takeover. The third scenario is substantially more serious because it crosses a critical security boundary, the reset token itself.

**Password reset poisoning in detail.** A secure password reset flow generally works as follows: a user requests a reset, the server generates a strong unpredictable token, the token is associated with the correct account, the server sends an email containing a reset link, the user opens the link and resets their password, and the token becomes invalid. Now consider an application that constructs reset links using untrusted host information.

Simulated vulnerable behavior:

```http
POST /forgot-password HTTP/1.1
Host: app.example.com
Content-Type: application/x-www-form-urlencoded

email=alice%40example.com
```

Suppose the server uses the request hostname instead of a configured canonical domain when generating the email. A dangerous implementation might produce a reset link pointing to an unintended hostname. If the victim follows that link, the reset token could be exposed to an attacker controlled destination. This is known as password reset poisoning.

The critical security boundary is the reset token itself, a temporary credential whose possession may allow the holder to change the password for a specific account. If an attacker obtains a valid token and the application fails to enforce additional protections, the attacker may be able to take over the account. But a complete assessment must still verify whether the token is valid, bound to the intended account, expired, already used, exchangeable for a password reset, whether resetting the password invalidates the token, and what happens to existing sessions afterward. Do not report account takeover merely because a token appears in a URL. Prove the token's actual capability in an authorized environment.

Email injection more broadly refers to improperly handling untrusted input when constructing email messages. Depending on the implementation, unsafe input may affect email headers, recipients, subject lines, message content, or reset link destinations. The precise behavior depends on the mail library and how input is processed. Modern email libraries usually provide structured APIs that avoid many classic header injection problems, and those APIs should be used instead of constructing raw email headers manually.

The key lesson of this supplement is that a password reset system is an authentication mechanism, not merely an email feature. A defect in URL generation, token handling, or account binding can undermine the entire account security model.

### Lesson 2.7: Account Enumeration Through Recovery

Account enumeration occurs when an attacker can determine whether a particular account exists. Consider two requests.

For an existing account:

```http
POST /forgot-password HTTP/1.1
Host: shopsecure.example
Content-Type: application/json

{
  "email": "alice@example.com"
}
```

Response:

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "message": "Password reset email sent"
}
```

For a nonexistent account:

```http
POST /forgot-password HTTP/1.1
Host: shopsecure.example
Content-Type: application/json

{
  "email": "unknown@example.com"
}
```

Response:

```http
HTTP/1.1 404 Not Found
Content-Type: application/json

{
  "message": "Account not found"
}
```

The second response explicitly confirms that the account does not exist. That difference may enable account enumeration.

**Why account enumeration matters.** An attacker can use the information to identify registered users, prepare targeted phishing campaigns, prioritize credential attacks against known accounts, discover employees or customers of a service, and correlate accounts across services. Enumeration is not automatically a critical vulnerability. Its impact depends on the application's sensitivity, the information disclosed, and the realistic consequences.

**Response body differences.** Generic wording alone is not enough if the application reveals account existence elsewhere. Examine HTTP status codes, response bodies, redirect behavior, response sizes, response headers, timing differences, whether an email is actually sent, and subsequent application behavior. For timing based enumeration, repeatable measurements are important. A single slow response does not establish a vulnerability.

**Correct design.** Use a generic externally visible response for eligible and nonexistent accounts, where appropriate. However, generic responses do not require the server to perform exactly the same internal work for every request. The goal is to avoid creating a reliable account existence signal while maintaining correct functionality and abuse protection.

### Lesson 2.8: Password Reset Session Behavior

A subtle but important question is: what should happen to existing sessions when a password is reset?

Imagine a user has three active sessions:

```text
Session A — Laptop
Session B — Mobile phone
Session C — Old browser
```

An attacker somehow obtains Session C. The legitimate user resets their password. If the application changes the password but leaves all previously issued sessions valid, the attacker may retain access through Session C. This can undermine the value of password recovery.

**Three separate operations.** Do not treat these as the same thing: changing the password, invalidating reset tokens, and revoking existing sessions and persistent authentication tokens. A secure recovery workflow needs an explicit policy for each.

**Should every session always be revoked?** Not necessarily in every product design, but password recovery is a high risk event and should trigger an appropriate session revocation decision. For high risk systems, revoking existing sessions is often a sensible default. If the product permits some sessions to remain active, the design should be deliberate, risk appropriate, and supported by effective controls.

**How session revocation might work.** One approach is to maintain a session version or authentication version field associated with the account. Conceptually, `user.session_version = 7`, and a session is issued with `session.session_version = 7`. After a password reset, the account version changes to `user.session_version = 8`, and the application rejects sessions carrying the old version. This is only one possible design. It works only if the application checks the relevant value when validating sessions or otherwise ensures that old sessions become invalid. Merely incrementing a database field without connecting it to session validation accomplishes nothing.

**Persistent authentication.** Remember me cookies and other persistent authentication mechanisms may outlive a normal browser session. The application must account for those credentials as well. A password reset that invalidates ordinary sessions but leaves long lived persistent credentials usable may leave an important access path open. These mechanisms are covered in Phase 6.

### Lesson 2.9: Password Reset Implementation, Complete Security Review

Return to the simplified example used throughout this phase:

```python
async def reset_password(token, new_password):
    reset = await find_reset_token(token)

    if not reset:
        raise Unauthorized()

    await update_password(reset.user_id, new_password)

    return {"message": "Password updated"}
```

This code is incomplete as shown. A senior reviewer should ask whether the full implementation enforces the following properties.

| Security property | Question |
|---|---|
| Token authenticity | Was the token generated securely and validated correctly? |
| Account binding | Does the token identify the account that can be changed? |
| Expiration | Is the token rejected after its expiry time? |
| Single use | Is a previously consumed token rejected? |
| Revocation | Can invalidated tokens no longer be used? |
| Purpose restriction | Can the token authorize only the intended recovery operation? |
| Password policy | Is the new password validated appropriately? |
| Password storage | Is the new password stored using the approved hashing scheme? |
| Session handling | Are existing sessions treated according to the recovery security policy? |
| Token invalidation | Are outstanding recovery tokens handled appropriately after success? |
| Notifications | Is the account owner informed of the password change? |
| Error handling | Are failures handled safely without leaking sensitive information? |
| Logging | Are raw passwords and recovery tokens excluded from logs? |
| Consistency | Can a partial failure leave the password and token state inconsistent? |
| Abuse protection | Are recovery requests and token submissions appropriately protected against abuse? |

**A note on implementation consistency.** Suppose the application updates the password successfully but fails before marking the reset token as consumed. The token may remain usable. Alternatively, suppose it marks the token as consumed but fails before updating the password. The user may be left with an unusable recovery token and no password change. The implementation must be designed to handle these failures safely, often using a database transaction or an equivalent consistency mechanism appropriate to the architecture. This is an implementation reliability concern with direct security consequences.

## Additional Subtopics

### 1. Password Changes Versus Password Resets

A password change generally occurs when an authenticated user wants to replace an existing password. A password reset is usually a recovery process for someone who cannot authenticate normally. The security requirements differ. A password change may rely on a valid session plus suitable reauthentication. A password reset relies on a recovery mechanism that must independently establish adequate proof of control. The application should not accidentally let a recovery token function as a normal authenticated session unless that behavior is explicitly designed and constrained.

### 2. Temporary Passwords

Temporary passwords can be risky if they are predictable, shared, long lived, or not replaced promptly. If an organization uses temporary passwords, the design should restrict their use, provide a secure delivery mechanism, and require the user to establish a proper credential when appropriate. A temporary password should not become a permanent administrative backdoor.

### 3. Password History and Reuse

Password history requirements can help prevent users from immediately returning to previously used passwords, particularly after certain security incidents. However, password history controls should be designed around the organization's threat model and current password guidance. They should not be treated as a substitute for strong authentication, secure password storage, or protection against compromised credentials.

### 4. Password Reset Poisoning Through Untrusted Host Information

An application may construct a recovery link using information from the incoming HTTP request. If it trusts an attacker controlled host value when generating the link, the resulting email might contain a recovery URL pointing to an unintended domain. This is sometimes called password reset poisoning, and it is covered in full detail in the supplement under Lesson 2.6 above. The core issue is that the application uses untrusted request information to determine a security sensitive destination. A secure implementation should construct recovery links using a configured, trusted canonical origin rather than blindly relying on arbitrary host information from the request. The reset token must also remain bound to the intended account and be protected against leakage. This topic is separate from CORS and CSRF, which remain excluded from this course.

### 5. Password Recovery and Account Takeover

Account takeover is the possible impact, not the name of every underlying weakness. For example, a reusable reset token is a token lifecycle flaw, a reset token bound to the wrong account is an account binding flaw, a predictable recovery token is a token generation flaw, a recovery email sent to the wrong recipient is a recipient selection flaw, and a recovery process that trusts weak security question answers is a recovery assurance flaw. These weaknesses may have different root causes, evidence requirements, and fixes. A strong bug report identifies the actual failure instead of merely labeling everything account takeover.

## Assessment

The following assessment is drawn from "Authentication Security.md" and addresses the same subject as the lessons above: reset token reuse and impact validation, reset token and account binding, and what happens when a secondary recovery mechanism is weaker than the primary one. As with Phase 1, the questions are preserved from the original source, and the answers given are the instructor's corrected, authoritative answers rather than the original learner's submitted answers.

### Assessment Question 1

A fictional application sends this request when Alice requests a password reset:

```http
POST /api/auth/forgot-password HTTP/1.1
Host: shop.example.test
Content-Type: application/json

{
  "email": "alice@example.test"
}
```

Response:

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "message": "If the account exists, a reset link has been sent."
}
```

Alice receives a link containing `token=7f82c9a1...`. She opens it and submits a new password. Now imagine you successfully reset Alice's password, and the application does not visibly invalidate the reset token. Without immediately calling this a vulnerability, what specific test would you perform to determine whether reuse of the reset token creates an actual security issue?

**Answer**

Test the token again after it has already been used successfully, and determine whether the server still accepts it. Also test it again after waiting past the token's intended lifetime, to separately establish whether expiration is functioning. These are two different security properties: single use and time limited validity, and a token can fail one while passing the other. If you reset Alice's password successfully and then immediately resubmit the same token with a different new password, and the server returns a success response again, you have obtained strong evidence of a reusable password reset token. That alone establishes a token management weakness, but not yet account takeover, the actual security impact still needs to be proven separately.

### Assessment Question 2

You reuse the token immediately and receive `HTTP/1.1 200 OK` with the message "Password reset successful." What would you test next to determine whether this is merely a token management weakness or whether it can actually lead to account takeover?

**Answer**

Attempt to log in using the account's email and the password that was set through the reused token. If authentication succeeds, you have moved from "the token can be reused" to "the reused token actually changed the account's authentication credential," which is the distinction between finding a weakness and proving security impact. The full controlled sequence is: obtain a reset token, reset the password successfully, reuse the same token, reset the password again, log in using the second password, and confirm successful authentication. Do not call this account takeover solely because the password changed. A true account takeover finding requires establishing that an attacker who possesses the reset token can gain unauthorized control of the victim's account without requiring the legitimate user's cooperation, and successful authentication with the attacker selected password is strong evidence of exactly that capability. You should also check the session lifecycle afterward: if an old authenticated session remains valid after the password reset, that reveals an additional, separate security weakness.

### Assessment Question 3

Suppose the reset token is single use and expires correctly, but the reset endpoint looks like this:

```http
POST /api/auth/reset-password HTTP/1.1
Host: shop.example.test
Content-Type: application/json

{
  "token": "7f82c9a1...",
  "email": "alice@example.test",
  "newPassword": "NewPassword456!"
}
```

You notice the server accepts an email value supplied by the client alongside the token. What security property would you investigate next, and what test would prove whether the server is actually using the attacker controlled email rather than binding the token to Alice's account?

**Answer**

Investigate whether the reset token is cryptographically and logically bound to the account it is supposed to reset, or whether the server separately and independently trusts the client supplied email field. In a dangerous implementation, the token only proves that some reset is valid, while the email field is what actually tells the server which account to change. If the server does not verify that those two values belong together, an attacker who possesses a valid reset token could potentially manipulate the email parameter to reset a different account entirely.

Using only controlled test accounts, take a reset token legitimately issued for one account, for example `alice@example.test`, and submit it together with a different, attacker controlled account's email, for example `attacker@example.test`, and a new password. A `200 OK` response alone does not prove anything, since the server might return success while internally rejecting the operation. The proof is behavioral: afterward, attempt to authenticate to the attacker controlled account using the new password that was submitted. If that authentication succeeds, you have demonstrated that the server changed the password of the account named in the client supplied email field rather than the account the token was actually issued for. That is a confirmed password reset account binding flaw, and it can lead to account takeover if an attacker is able to obtain a valid reset token usable in this way.

### Assessment Question 4

A fictional banking style application has a password reset flow where the reset token is cryptographically random, expires after fifteen minutes, is single use, is bound to the correct account, and cannot have its target account changed by modifying the request. The primary reset mechanism looks solid. However, you discover a second endpoint:

```http
POST /api/auth/recover-account HTTP/1.1
Host: bank.test
Content-Type: application/json

{
  "email": "alice@example.test",
  "recoveryCode": "482913",
  "newPassword": "NewPassword123!"
}
```

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "message": "Account recovered successfully"
}
```

You also learn that users can normally obtain their `recoveryCode` from their account's security settings only after authenticating. Testing as an unauthenticated attacker, what is the single highest priority thing to investigate about this endpoint, and why?

**Answer**

Investigate what authentication or security control is supposed to prevent an unauthenticated attacker from using this endpoint at all, since the recovery code is described as something a legitimate user can only obtain after already authenticating. The reasoning is that the primary reset token mechanism has already been shown to be secure, so the highest value question is not about that mechanism, it is about whether this second, apparently weaker, recovery path reintroduces the exact weakness the primary mechanism was designed to avoid. The first concrete test is to submit a known or guessed recovery code to this endpoint without being authenticated at all, and determine whether the endpoint actually requires any proof that the requester legitimately obtained that code through the authenticated settings page, or whether it accepts the code on its own.

After receiving a `200 OK` with "Account recovered successfully," the response itself is evidence, not proof of impact. Attempt to authenticate using the email and the attacker selected new password. If login succeeds, you have moved from "the endpoint appears vulnerable" to "an unauthenticated attacker can reset another user's password and authenticate as that user," which is a demonstrated authentication bypass and potential account takeover. You should also determine the root cause behind why it worked: whether the recovery code was predictable, whether it was not actually required to be verified at all, whether it was accepted without proper account binding, whether a code belonging to one account could be used against a different account, whether the code was obtainable without authentication in the first place, and more generally whether this recovery mechanism is weaker than the application's primary password reset mechanism.

### Assessment Question 5

Continuing the same scenario, you discover that `482913` is Alice's valid recovery code. You then submit:

```http
POST /api/auth/recover-account HTTP/1.1
Host: bank.test
Content-Type: application/json

{
  "email": "bob@example.test",
  "recoveryCode": "482913",
  "newPassword": "AttackerPassword123!"
}
```

and receive `HTTP/1.1 200 OK` with "Account recovered successfully." What would you do next to determine whether this is a real cross account authentication flaw, and what underlying security property are you actually testing?

**Answer**

Take a recovery code that is legitimately associated with one account, Alice's, and deliberately pair it with a different account's identifier, Bob's, then verify whether Bob's password actually changed. The verification step is to attempt to authenticate as Bob using the attacker selected password. If the code belongs to Alice, is used against Bob, Bob's password changes, and you can then authenticate as Bob, you have demonstrated a cross account recovery code binding flaw, potentially resulting in account takeover. A single controlled cross account success is sufficient to prove the core flaw; testing many additional accounts is not required to establish that the vulnerability exists, once one has been confirmed with proof of changed credentials and successful authentication.

The underlying security property being tested is not merely whether different email values happen to work. It is that a recovery credential must be cryptographically and logically bound to exactly one account, and must not be interchangeable between accounts. This is the same account binding principle introduced in Lesson 2.4 for password reset tokens, applied here to a different recovery mechanism, which is exactly why a strong security review of recovery functionality must check every recovery path an application exposes, not only the one it labels as the main password reset flow.

## Remediation and Secure Implementation

A secure password recovery system should provide the following properties together. No single property compensates for every other failure.

1. Appropriate account recovery verification.
2. Secure and unpredictable tokens.
3. Correct account binding, for every recovery mechanism the application exposes, not only the primary one.
4. Enforced expiration.
5. Reliable single use semantics.
6. Revocation of invalidated tokens.
7. Safe password storage, per the design established in Phase 1.
8. Appropriate session and persistent token handling after recovery.
9. Protection against information leakage, including account enumeration and token leakage through logs, referrers, and analytics.
10. Protection against recovery message abuse.
11. Safe handling of host information when constructing recovery URLs, using a configured canonical origin rather than request supplied host data.
12. Reliable state transitions when an operation fails partway through.
13. Appropriate notifications and security logging.

## Key Takeaways

Password recovery is a second authentication mechanism, and it must be held to the same standard as the first. This phase adds a specific, recurring lesson on top of the three attack surfaces introduced in Phase 1: a recovery flow can fail at any one of several independent points, token generation, token validation, account binding, expiration, session handling, or the trustworthiness of the information used to build the recovery link itself, and a weakness at any single point can undermine an otherwise well designed system.

The assessment in this phase reinforces a second recurring principle, first introduced with security questions in Phase 1 and demonstrated here with a secondary recovery code endpoint: an attacker does not need to defeat your strongest authentication mechanism if your application offers a weaker alternative path to the same outcome. Every recovery mechanism an application exposes must be reviewed, not only the one documented as the primary flow.

Finally, "account takeover" is an impact, not a diagnosis. A reusable token, a broken account binding check, a predictable recovery code, and a misdirected recovery email can all produce the same headline outcome while requiring completely different fixes. A professional report names the actual failure.

## Review Checklist

- [ ] Can you walk through all five stages of a password reset lifecycle and name the security property each stage protects?
- [ ] Can you explain why token reuse and token expiration are tested as two separate properties, not one?
- [ ] Can you identify, from a source code snippet, whether a reset token's account binding is actually enforced or merely assumed?
- [ ] Can you list at least four distinct channels through which a reset token can leak?
- [ ] Can you distinguish password reset email injection, password reset poisoning, and reset token leakage from each other?
- [ ] Can you explain why an application's Host header should not be trusted when generating a password reset link, and what a secure alternative looks like?
- [ ] Can you explain how account enumeration can occur through a recovery flow even when the visible response wording is generic?
- [ ] Can you name the three separate operations a secure recovery flow must decide on: password change, token invalidation, and session revocation?
- [ ] Can you explain why "account takeover" is an impact label rather than a root cause, using at least three different underlying flaws that could each produce it?
- [ ] Can you explain why a secondary recovery mechanism must be reviewed with the same rigor as the primary password reset flow?

## References to Related Phases

- Session revocation after a password reset, and persistent authentication mechanisms such as remember me cookies, are referenced in Lessons 2.1 and 2.8 but are covered in full in **Phase 6, Cookie and Session Security**.
- Security questions as a weak account recovery mechanism, referenced by the same underlying principle tested in Assessment Questions 4 and 5, are covered in **Phase 1, Password Storage and Credential Attacks**.
- The trust boundary problem of relying on client supplied request data, demonstrated here through the Host header and reset link generation, recurs in a different form in Phase 1's assessment on `X-Forwarded-For` and rate limiting, and again in later phases dealing with proxy trust.
- Account recovery as part of the broader account lifecycle, including identity proofing during registration, is covered in a later phase, **Account Lifecycle and Identity Proofing**.
