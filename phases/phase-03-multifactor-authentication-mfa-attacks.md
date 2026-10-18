# Phase 3: Multifactor Authentication (MFA) Attacks

**Source material:** Module 3 of 17, "Authentication Complete Phases Test.md" (Lessons 3.1 through 3.12, the Module 3 Final Summary, and the Progress Tracker), with supplementary assessment material drawn from "Authentication Security.md" (Challenge 05 and its two direct follow-ups, Challenge 32, and Challenge 33).

## Learning Objectives

After completing this phase, you should be able to:

1. Explain what multifactor authentication actually requires, and why two pieces of evidence from the same factor category do not constitute multifactor authentication.
2. Explain the concept of authentication state, and why a session existing is not the same thing as a session having completed the required second factor.
3. Distinguish MFA fatigue and push bombing as related but separate concepts, and explain what number matching does and does not solve.
4. Explain why real-time phishing through an adversary in the middle can defeat manually entered one-time codes even when those codes are single-use, and why HTTPS alone does not solve this.
5. Distinguish OTP relay from OTP replay, and explain why a TOTP code is not inherently bound to a specific browser transaction.
6. Explain the specific implementation failure that allows a TOTP replay vulnerability, separate from the code's time-based validity.
7. Explain SIM swapping as an attack on the phone number itself rather than on the OTP algorithm, and describe a realistic end-to-end attack chain.
8. Identify the five common MFA downgrade patterns and explain why a weaker fallback is not automatically a vulnerability.
9. Evaluate backup codes, email-based recovery, and support-assisted recovery as MFA fallback mechanisms, and explain what evidence each one should actually require.
10. Trace authentication state transitions across an application, and identify the specific failure where a client-supplied field is trusted as proof that MFA succeeded.
11. Use the Phase 1 and Phase 2 impact-validation discipline to evaluate an MFA enforcement question: distinguish a password-only session reaching a sensitive endpoint from a confirmed MFA bypass.

## Introduction

Phase 1 established that offline attacks, online attacks, and credential lifecycle weaknesses are three separate surfaces. Phase 2 showed that a recovery mechanism is a second authentication path that must be held to the same standard as the first. This phase extends both lessons to multifactor authentication: an application can implement MFA correctly at the login form and still be vulnerable to account takeover, because MFA is not one control, it is an entire lifecycle spanning enrollment, login, fallback, recovery, session handling, and factor replacement, and a weakness at any single point in that lifecycle can undermine the whole design.

The central theme of this phase, repeated across nearly every lesson, is that MFA is only as strong as its enforcement. A security key, an authenticator app, or a TOTP code can be cryptographically sound and still fail to protect an account if a single endpoint treats session existence as proof of complete authentication, if a fallback mechanism accepts weaker evidence than the primary method, or if a client supplied field is trusted to declare that the second factor was verified. This phase teaches you to examine the entire lifecycle, not just the login page.

## Core Concepts

The module is organized around three movements. First, Lessons 3.1 through 3.6 establish MFA fundamentals and the major categories of attack against the second factor itself: authentication state, push bombing and MFA fatigue, real-time phishing, OTP relay, TOTP replay, and SIM swapping. Second, Lessons 3.7 and 3.8 examine how an application's own design can quietly reduce the assurance it promised, through downgrade attacks and weak fallback mechanisms. Third, Lessons 3.9 through 3.12 bring these ideas together into a single discipline: how authentication state must be tracked and enforced server side across every protected route, a complete source code review checklist, a table distinguishing the different MFA vulnerabilities from each other, and a full practical case study.

## Lessons

### Lesson 3.1: Understanding MFA Properly

**What is MFA?** Multifactor authentication requires evidence from at least two distinct authentication factor categories.

| Factor | Meaning | Examples |
|---|---|---|
| Something you know | Information the user knows | Password, PIN |
| Something you have | An authenticator or possession-based credential | Security key, authenticator app, registered device |
| Something you are | A biometric characteristic | Fingerprint, facial recognition |

Two passwords do not constitute two independent authentication factors. They are both knowledge factors. Likewise, two pieces of information stored in the same compromised system do not necessarily provide meaningful independent assurance.

Consider a user logging in with a password plus an authenticator code:

```http
POST /login HTTP/1.1
Host: accounts.example
Content-Type: application/json

{
  "username": "alice",
  "password": "REDACTED"
}
```

The server verifies the password and requests another factor. The user then submits an authenticator code:

```http
POST /mfa/verify HTTP/1.1
Host: accounts.example
Content-Type: application/json

{
  "code": "REDACTED"
}
```

The intended sequence is:

```text
Password verified
       |
       v
MFA required
       |
       v
Second factor verified
       |
       v
Authentication completed
       |
       v
Full authenticated session issued
```

The crucial security property is that verifying the password must not be enough to obtain the privileges of a fully authenticated user when MFA is required. This sounds obvious, but mistakes in the implementation can break that guarantee.

**The most important MFA security concept: authentication state.** Consider an application that creates a session after the password is verified, storing:

```text
user_id = 481
authenticated = true
mfa_verified = false
```

The user has passed the password stage but has not completed MFA. This can be a valid intermediate state, provided the application treats it as incomplete authentication. Now consider a protected endpoint:

```python
async def view_sensitive_records(session):
    if session is None:
        raise Unauthorized()

    return await get_sensitive_records(session.user_id)
```

What is wrong? The endpoint checks whether a session exists, but it does not check whether the session has satisfied the required MFA step. If a password-only session can reach this endpoint, MFA may be bypassed. The relevant distinction is that a session existing, a password having been verified, MFA having been verified, and the required authentication assurance having been achieved are four separate, non-interchangeable conditions.

Correct conceptual logic:

```python
async def view_sensitive_records(session):
    if session is None:
        raise Unauthorized()

    if not session.mfa_verified:
        raise Forbidden()

    return await get_sensitive_records(session.user_id)
```

This is illustrative code. Real applications may represent authentication state differently, and `mfa_verified` alone may not capture every assurance requirement. The underlying rule remains the same: every protected operation must enforce the authentication requirements applicable to that operation.

**A subtle mistake.** Suppose `/dashboard` checks MFA, but `/billing/export` only checks for a valid session. The application may appear to enforce MFA because its primary dashboard is protected. However, an attacker might access the export endpoint using an incomplete session. This is an example of inconsistent enforcement. It is not necessarily an MFA cryptographic failure, it is a security state enforcement failure.

**What should a bug hunter inspect?** Examine whether password verification creates an incomplete session or an appropriately restricted authentication state, whether MFA completion transitions the user into the correct state, whether sensitive endpoints reject incomplete authentication, whether MFA requirements are enforced on alternate routes, whether authentication state is validated server side, whether a client controlled value cannot declare MFA complete, and whether session renewal or restoration preserves the correct authentication state. Do not judge MFA security by examining the login page alone. Examine the authorization consequences of every relevant authentication state.

### Lesson 3.2: MFA Push Bombing and MFA Fatigue

**What is push-based MFA?** Some authentication systems send a notification to a registered device when a user attempts to sign in. The user approves or rejects the request.

```text
User enters password
        |
        v
Server verifies password
        |
        v
Push notification sent
        |
        v
User reviews the request
        |
        v
User approves
        |
        v
Authentication completes
```

Push authentication can be convenient, but approval-based systems introduce a human decision into the authentication process. Attackers may try to manipulate that decision.

**What is MFA fatigue?** MFA fatigue is an attack in which an attacker repeatedly triggers authentication prompts in the hope that the legitimate user eventually approves one. Suppose an attacker has obtained a user's password and attempts to sign in repeatedly. The legitimate user receives a sequence of prompts, for example at 09:14, 09:15, 09:16, and 09:17. The user becomes frustrated or assumes the prompts are legitimate and approves one. If the application accepts the approval, the attacker may complete authentication. The weakness is not necessarily that MFA cryptography has been broken, it is that the approval process can be manipulated.

**What is push bombing?** Push bombing is the repeated triggering of authentication push notifications. It is closely related to MFA fatigue: push bombing describes the notification-flooding behavior, MFA fatigue describes the pressure or habituation that may cause the victim to approve a request. The terms are sometimes used interchangeably. Potential contributing factors include unlimited or excessive authentication prompts, no meaningful throttling, no notification of repeated suspicious requests, poor user interface context, approval flows that provide insufficient information, no effective way for users to report suspicious prompts, and no detection of repeated failed or rejected approvals.

**Number matching.** Some push-based authentication systems require the user to match a number displayed on the sign-in screen with a number shown on the authenticator device. This is stronger than a plain approval prompt and helps reduce accidental approvals and some forms of prompt manipulation. However, number matching is not a universal solution to phishing or session theft. If a user is interacting with a malicious authentication flow and knowingly or unknowingly supplies the requested number, the attack may still succeed, depending on the design. Push prompts can provide contextual information such as approximate location, device or application name, time of request, and a number-matching challenge. Location information should be treated as an indicator, not definitive proof, since IP-based geolocation can be inaccurate.

**How to identify MFA fatigue vulnerabilities.** During an authorized assessment, evaluate whether repeated authentication requests are throttled, whether users can reject suspicious prompts, whether excessive prompt activity generates alerts, whether approval is bound to the intended login attempt, whether a stale approval can authorize a different request, whether the system provides adequate context for the approval decision, and whether failed authentication attempts are handled consistently. Do not assume a vulnerability merely because an application uses push notifications. The vulnerability must involve a meaningful weakness, such as the absence of necessary abuse controls or an approval mechanism that can be reused in an unintended context.

**Remediation.** Effective defenses include rate limiting push challenges, applying risk-based throttling, using number matching or stronger challenge binding, providing useful sign-in context, detecting repeated rejected or ignored prompts, notifying users about suspicious authentication activity, giving users an accessible way to report fraudulent prompts, and using phishing-resistant authentication for high-risk accounts and operations. A report that says "the application sends multiple push notifications" is incomplete. A stronger report establishes how the excessive prompts can be triggered, which controls are absent or ineffective, whether a legitimate user's approval can result in unauthorized authentication, what access the resulting authentication grants, and how the behavior can be mitigated. The goal is to demonstrate a security weakness, not merely an inconvenient user experience.

### Lesson 3.3: Real-Time Phishing and Adversary-in-the-Middle Attacks

This is one of the most important MFA topics for a bug hunter to understand.

**Traditional phishing versus real-time phishing.** In traditional phishing, an attacker creates a deceptive page to collect credentials. The user may enter their username and password into that page. The attacker then attempts to use the stolen credentials against the legitimate service. MFA may prevent the attacker from completing authentication if the second factor is not available to them. Real-time phishing changes the situation: an adversary-in-the-middle system can act as a relay between a victim and a legitimate authentication service.

```text
Victim's browser
       |
       v
Attacker-controlled intermediary
       |
       v
Legitimate authentication service
```

The intermediary passes information between the victim and the legitimate service. If the victim completes a login through the intermediary, the attacker may be able to observe or relay authentication material that the victim submits. Depending on the authentication mechanism and implementation, the attacker may also obtain a session credential after successful authentication. This is a more serious threat than simply collecting a password.

**Why OTP-based MFA may not stop it.** Consider a legitimate flow: the user enters their password, the service requests a one-time code, the user obtains the code from their authenticator, the user submits the code, and the service accepts it and establishes a session. A real-time intermediary may relay the password and the OTP while they remain valid, and the legitimate service can then accept the authentication. The key point is that a one-time code can be single-use and still be phished in real time. Single-use protection helps prevent a code from being reused after consumption. It does not guarantee that the person submitting the code is communicating directly with the legitimate service.

A victim visits a deceptive site imitating the real sign-in page at `https://login.example`, enters their credentials, and completes an OTP challenge. The real service accepts the authentication. If the intermediary can obtain the resulting session credential, the attacker may be able to use that credential, subject to its restrictions and the application's protections. This is why an assessment must distinguish between stealing a password, relaying an OTP, completing a legitimate authentication flow through an intermediary, obtaining a session credential, and reusing that credential successfully. These are separate stages. Evidence for one does not automatically prove the others.

**Why HTTPS alone is not enough.** HTTPS protects communication between a browser and the domain to which the browser is connected. It does not establish that the domain itself is the legitimate service the user intended to visit. A deceptive website can also use HTTPS. Therefore, a secure connection to a malicious domain does not make the domain trustworthy. The security problem is the victim's trust in the wrong origin and the ability of the intermediary to relay authentication.

**How phishing-resistant authentication changes the situation.** Phishing-resistant authentication mechanisms bind authentication to the legitimate relying party or origin. Passkeys using WebAuthn are an important example. In a correctly implemented WebAuthn flow, the authenticator and browser enforce relying-party and origin-related constraints, so a credential registered for one legitimate relying party cannot simply be used by an unrelated phishing origin as though it were the same service. This is a major security advantage over manually entered OTPs, and is examined in detail in Phase 5. However, phishing-resistant authentication reduces the risk of credential phishing and real-time authentication relay, but it does not eliminate every account-takeover path. An attacker may still target account recovery, enrollment and replacement of authenticators, weak administrative procedures, compromised endpoints, existing authenticated sessions, and other vulnerabilities in the application. Security must protect the entire authentication lifecycle.

**Bug bounty assessment.** When evaluating a suspected phishing weakness, distinguish between the authentication method's inherent properties and a specific application vulnerability. An application using manually entered OTPs may be susceptible to phishing as a general property of the mechanism. An application that incorrectly accepts authentication from an unauthorized origin may have a separate implementation flaw. An application that exposes session credentials through an unintended channel may have an additional vulnerability. A weak recovery flow may allow an attacker to replace the victim's authenticator. These should not automatically be reported as one undifferentiated issue. A useful report identifies the actual root cause, the demonstrated security impact, and the applicable remediation.

### Lesson 3.4: OTP Interception and Relay

OTP stands for one-time password, describing a password or code intended for limited use. Depending on the system, the code may be delivered through a message or generated by an authenticator. Not all OTP mechanisms have identical security properties.

**SMS OTP.** A service sends a code to a registered phone number, and the user submits the code to complete authentication. The security of this approach depends partly on the protection of the phone number, the messaging infrastructure, and the application's verification logic. Potential threats include SIM swapping, phone number reassignment, compromised messaging accounts, telecommunications interception, social engineering of support staff, and real-time phishing and OTP relay. SMS OTP can provide additional protection against password-only compromise, but it should not be treated as equivalent to phishing-resistant authentication.

**Email OTP.** An application may send a code to the user's email address. This can be useful, but its security depends on the email account and the surrounding authentication design. If the same email account is also used for password recovery, compromising that mailbox may undermine multiple protections at once. This is a form of dependency concentration, where several security controls rely on the same underlying account.

**Authenticator-generated OTP.** Time-based one-time passwords, or TOTP, are generated using a shared secret and a time-derived value. The application and authenticator independently calculate the expected code, and the service accepts the submitted code if it matches an allowed time window and satisfies the applicable validation rules. TOTP avoids dependence on SMS delivery, but manually entered codes can still be phished or relayed in real time.

**What does OTP relay mean?** OTP relay is the forwarding of a one-time code from the legitimate user to the system that is attempting to authenticate. The user might believe they are entering the code into the legitimate service, while an intermediary passes it to the actual service. If the service accepts the code, the intermediary may help complete the authentication. This attack does not necessarily break the OTP algorithm, it exploits the fact that a manually entered code is a transferable value.

A strong verification design should bind the authentication response to the appropriate authentication challenge and account context. Depending on the mechanism, relevant properties include the intended user or account, the authentication transaction, the purpose of the challenge, the validity period, whether the code has already been consumed, and the required authentication state. For TOTP, the code is derived from a shared secret and time step. It is not inherently a unique cryptographic response to a particular browser transaction, and that distinction matters.

### Lesson 3.5: TOTP Replay Vulnerabilities

This topic is closely related to OTP relay, but the underlying implementation failure is different.

**How TOTP works conceptually.** A TOTP authenticator and the server share a secret, and they calculate a value based on that secret and a time-derived counter:

```text
TOTP = Truncate(HMAC(K, T)) mod 10^d
```

Where K is the shared secret, T is the time-step counter, d is the number of displayed digits, and HMAC is the keyed hash-based calculation used by the TOTP construction. The exact implementation is standardized, the formula above is conceptual. The authenticator displays the resulting code, and the server calculates the expected code for an allowed time step or window and compares it with the submitted value.

**What is a replay attack?** A replay attack occurs when an authentication value that was previously valid is submitted again in a context where the system should reject it. Suppose the service accepts a code for `alice@example.com` and the result is accepted. The same code is submitted again before it expires. If the application accepts it again when its policy requires one-time use, the verification logic may be vulnerable to replay.

**Why this happens.** Some implementations check only whether a submitted code matches a valid TOTP value. They do not track whether the matching time-step value has already been accepted for that account. As a result, the same code may be accepted multiple times during its validity period. TOTP codes naturally remain mathematically valid during a time step, subject to the server's configured acceptance window. The standard's time-based construction does not automatically mean that an application will enforce single-use behavior. The service must implement appropriate replay protection if it intends to prevent repeated acceptance of a code.

**How to validate this safely.** Using a dedicated test account and authorized scope: complete an MFA verification with a valid code, submit the same code again within its valid time window, observe whether the second submission is accepted, confirm whether it creates a new authenticated state or merely returns an irrelevant response, and check whether the application has any documented policy that explains the behavior. Do not confuse the frontend's success message with proof that the server accepted the code a second time. Likewise, avoid drawing conclusions from a code submitted after its time window has expired, that tests expiration behavior rather than replay protection.

**What is the impact?** The impact depends on the authentication flow. A replay weakness may allow repeated completion of MFA challenges, weaken the intended one-time property, enable reuse of an observed code while it remains valid, and increase the risk associated with leaked OTPs. However, it does not automatically establish account takeover. The tester must determine what access the repeated verification grants and whether an attacker can realistically obtain the code.

**Remediation.** A server can track the relevant accepted TOTP time step for each enrolled authenticator and reject duplicate acceptance, while still accommodating the configured time window. The implementation should verify the code against the appropriate time window, track the accepted counter or equivalent replay state, reject duplicate use as required by policy, associate the verification with the correct account and authenticator, protect the state update against inconsistent concurrent processing, and avoid logging raw OTP values. Race-condition exploitation is reserved for a separate course. The general implementation requirement is that replay protection must remain reliable under normal concurrent requests.

### Lesson 3.6: SMS Interception and SIM Swapping

**What is SIM swapping?** A SIM swap occurs when a phone number is transferred to a SIM or eSIM controlled by another party. There are legitimate reasons to transfer a number, such as replacing a damaged SIM or changing devices. The security problem occurs when an attacker fraudulently convinces a telecommunications provider to transfer the victim's number. If the application uses that number for SMS-based authentication or recovery, the attacker may receive messages intended for the legitimate user.

**A typical attack chain.** The attacker learns the victim's username and password, obtains control of the victim's phone number through fraudulent transfer or another compromise, requests a login, the service sends an OTP to the number, the attacker receives the code, the service accepts the code, and the attacker completes authentication. Every step matters. If the attacker does not know the password and the system requires it, obtaining the phone number alone may not be sufficient. If the service has other independent protections, the attack may fail.

Potential contributing factors include overreliance on SMS as a high-assurance factor, weak phone-number change verification, recovery processes that treat phone-number control as sufficient for every action, inadequate alerts for SIM-related changes where such signals are available, weak controls around support-assisted account recovery, and failure to require stronger verification for sensitive account changes.

**Is SMS always insecure?** No, the correct assessment is more nuanced. SMS can provide useful additional protection compared with password-only authentication. However, it is generally less resistant to phishing and certain telecommunications attacks than properly implemented phishing-resistant methods. The appropriate method depends on the application's risk, users, recovery model, and available alternatives. For high-value accounts, stronger authenticators should be preferred where practical.

**How to investigate a suspected weakness.** Examine how the phone number is initially registered, whether changes require appropriate verification, whether a newly added number can immediately be used for sensitive recovery, whether existing factors must be verified before replacement, whether users are notified when a number changes, whether old recovery factors are invalidated appropriately, and whether the application treats SMS as sufficient proof for high-risk actions. A missing notification is not automatically an account-takeover vulnerability, it may be a defense-in-depth or monitoring issue, depending on the circumstances. The strongest finding demonstrates a specific weakness in authentication or recovery and its actual consequence.

### Lesson 3.7: MFA Downgrade Attacks

This is one of the most important topics in the module.

**What is an MFA downgrade?** An MFA downgrade occurs when an attacker can cause the authentication system to use a weaker method or lower assurance level than the policy requires. Imagine an organization supports password plus security key, password plus authenticator code, and password-only access for certain legacy accounts. A user is expected to authenticate with a security key. If the application permits an attacker to force the account into a password-only flow, the attacker may bypass the intended protection. The weakness is not necessarily a flaw in the security key itself, it may be a failure to enforce the required authentication policy.

**Common downgrade patterns.**

*A. Weak fallback authentication.* The primary authentication method is strong, but a weaker alternative is always available, for example a security key as the primary method with a "use another method" fallback that leads to password only. If the fallback permits full authentication without sufficient verification, the stronger primary method may provide little practical protection.

*B. Inconsistent MFA enforcement.* The application enforces MFA on one endpoint but not another, for example `/login` and `/admin/login` requiring MFA while a fictional `/legacy-login` does not. The important issue is inconsistent enforcement across supported authentication paths.

*C. Recovery-based downgrade.* A user has enrolled a strong authenticator. An attacker exploits weak account recovery to remove it or replace it with a weaker factor, then authenticates through the replacement method. This links MFA downgrade directly to the account recovery vulnerabilities covered in Phase 2.

*D. Remembered-device bypass.* Some applications allow users to mark a device as trusted so they do not have to complete MFA on every login. This can be a legitimate usability feature, but the remembered-device mechanism must be appropriately protected, and the application must enforce the intended policy. If a weak or easily forged device marker suppresses MFA, an attacker may be able to bypass the additional factor.

*E. Legacy protocol or endpoint bypass.* A modern authentication flow may enforce MFA, while a legacy route continues to accept weaker credentials, and the attacker targets the weakest supported path. This is an authentication-policy consistency failure, and legacy authentication is revisited in a later phase.

**How to detect MFA downgrade.** Build an authentication-path inventory. For each supported route, document:

| Property | What to establish |
|---|---|
| Entry point | Which route begins authentication? |
| Primary factor | What proves initial identity? |
| Required second factor | Which additional factor must be verified? |
| Fallback | What happens if the preferred factor is unavailable? |
| Resulting session | What authentication state is issued? |
| Protected actions | Which operations are allowed in that state? |
| Recovery | Can the factor be removed or replaced? |
| Policy enforcement | Are the same requirements applied consistently? |

Then assess whether the weaker paths are intentionally designed, appropriately protected, and consistent with the application's security requirements.

A source code review example:

```python
async def complete_login(user, password_verified, mfa_code=None):
    if not password_verified:
        raise Unauthorized()

    if mfa_code is not None:
        if not verify_mfa_code(user, mfa_code):
            raise Unauthorized()

    return create_authenticated_session(user.id)
```

What is wrong? The code verifies the password, but MFA is checked only when a code is supplied. If the application requires MFA for this account, omitting the code must not result in a fully authenticated session. Better conceptual logic:

```python
async def complete_login(user, password_verified, mfa_code=None):
    if not password_verified:
        raise Unauthorized()

    if user.mfa_required:
        if mfa_code is None:
            return create_pending_mfa_session(user.id)

        if not verify_mfa_code(user, mfa_code):
            raise Unauthorized()

    return create_authenticated_session(user.id)
```

This is still simplified. A real application must also handle factor enrollment, permitted fallback methods, session state, authentication assurance, and factor-specific validation. The important change is that an account requiring MFA cannot obtain a fully authenticated session merely by omitting the second factor.

**Is fallback always a vulnerability?** No. A well-designed fallback may be necessary for accessibility, device loss, or recovery. The question is whether the fallback provides adequate assurance and is subject to the correct policy. An application may permit recovery codes that were securely generated and stored, with appropriate rate limits and single-use enforcement, which is different from allowing an attacker to skip MFA by selecting a fallback option that simply returns a full session. A weaker authentication method is not automatically a vulnerability, an unjustified reduction in required assurance is the concern.

### Lesson 3.8: Weak MFA Fallbacks

MFA downgrade describes the broader reduction in authentication assurance. This lesson examines common fallback mechanisms more closely.

**Backup codes.** Backup codes allow a user to authenticate when their normal authenticator is unavailable. They should generally be unpredictable, sufficiently difficult to guess, associated with the correct account, stored securely, protected against brute-force attempts, consumed after use, and revocable when necessary. If backup codes are reusable when they are intended to be single-use, the recovery mechanism may be weakened. If backup codes are predictable, an attacker may be able to guess them. If backup codes are stored in plaintext and the database is exposed, the attacker may obtain working recovery credentials. The exact risk depends on the implementation.

**Email-based MFA recovery.** An application may allow users to regain access through a verified email address. This can be useful, but the assurance depends on the security of that email account and the recovery process. If the email account is already compromised, the fallback may be vulnerable. A particularly dangerous design is one where the application requires strong MFA during normal login but permits an attacker to disable it using only a weakly protected email recovery process.

**Support-assisted recovery.** Some services let support staff restore access after a user reports losing an authenticator. Support-assisted recovery can be necessary, but it introduces a human-controlled trust boundary. Risks include social engineering, inadequate identity verification, excessive support-agent privileges, weak approval processes, poor audit logging, and inadequate notification of factor changes. The solution is not necessarily to eliminate support recovery, it is to make the process appropriately secure, auditable, and resistant to impersonation.

**Factor replacement.** Imagine an account currently has a registered authenticator. A secure replacement process should establish that the requester has sufficient authority to change the factor. Depending on the application's risk, this may require recent reauthentication, verification through an existing factor, a securely designed recovery process, a notification to the account owner, and restrictions on sensitive actions immediately after the change. An attacker should not be able to replace a victim's MFA factor simply because they have access to a low-assurance session.

**What should you report?** A report should establish which fallback mechanism is involved, what assurance the primary authentication policy requires, what evidence the fallback actually checks, why that evidence is insufficient for the intended operation, what the attacker can achieve, and which change would restore the intended security policy. Avoid reporting every alternative authentication method as an MFA bypass. Demonstrate the policy failure.

### Lesson 3.9: MFA Enforcement Across Authentication States

This lesson brings the previous topics together.

Consider an application with the following conceptual states: unauthenticated, password verified, MFA pending, fully authenticated, reauthentication required, and session revoked. Actual applications may use different representations. A secure implementation should define the transitions between them:

```text
Unauthenticated
      |
      v
Password verified
      |
      v
MFA pending
      |
      v
MFA verified
      |
      v
Fully authenticated
```

But not every transition should be allowed. A password-only state must not transition directly into a fully authenticated state if the account's policy requires MFA. Similarly, a revoked session must not become valid merely because the browser still possesses an old cookie.

**The partial-authentication session problem.** A system may create a session-like object before MFA is complete. That is not automatically insecure. It becomes dangerous if the application grants it the privileges of a fully authenticated session. A partial-authentication session should be constrained to the operations required to finish authentication, such as submitting the required second factor. It should not provide unrestricted access to protected account functionality.

**Client-controlled MFA state.** Suppose the browser sends:

```http
POST /mfa/complete HTTP/1.1
Host: accounts.example
Content-Type: application/json

{
  "mfa_verified": true
}
```

If the server trusts that field as proof that MFA was completed, the design is fundamentally broken. The field is supplied by the client, it is a claim, not proof. The server must determine authentication state based on its own validated records and verification process. Changing a browser field must not independently grant authentication privileges.

**Session renewal and authentication state.** Suppose the user completes MFA and receives a fully authenticated session. Later, the application renews the session. The renewal process must preserve the appropriate authentication properties. Conversely, if the user has not completed MFA, renewing a partial session must not silently elevate it to full authentication. Session creation, rotation, renewal, and restoration must all preserve the intended authentication state. These matters are explored more deeply in Phase 6.

**MFA and sensitive operations.** Not every application requires the same authentication assurance for every action. A system might permit a user to view a public profile after password verification but require stronger authentication before changing account recovery settings. The important point is to define the required assurance for each sensitive action and enforce it consistently. A valid session alone is not always sufficient proof for every operation. This leads naturally into a later phase covering reauthentication and step-up authentication.

### Lesson 3.10: MFA Source Code Review Checklist

When reviewing an MFA implementation, examine the entire lifecycle.

**Enrollment:** Can an attacker enroll a new factor without sufficient verification? Is the factor associated with the correct account? Is enrollment completed only after successful verification? Can an unverified factor be used for authentication? Are users notified of significant factor changes?

**Login:** Is MFA required for accounts whose policy demands it? Can password verification produce a fully authenticated session prematurely? Are the correct factors checked? Are challenges bound to the intended account and authentication flow? Are failed attempts handled appropriately?

**OTP verification:** Is the code validated correctly? Is the accepted time window appropriate? Is replay handled according to the intended policy? Are attempts limited appropriately? Are raw codes excluded from logs?

**Push authentication:** Are prompts protected against abuse? Is approval tied to the correct authentication request? Are suspicious repeated prompts detected? Does the interface provide useful context?

**Recovery:** Can recovery bypass the intended assurance requirements? Are backup codes secure and appropriately consumed? Can an attacker replace a factor without sufficient proof? Are factor changes audited and communicated?

**Session handling:** Is partial authentication distinguished from full authentication? Do protected endpoints enforce the required authentication state? Does session renewal preserve that state? Are revoked sessions rejected?

**Fallback and legacy routes:** Does every supported authentication route enforce the intended policy? Can a weaker fallback provide unjustified access? Do older routes continue to accept weaker authentication? Are trusted-device mechanisms implemented securely?

This checklist is not a substitute for understanding the application's architecture, but it provides a structured starting point for source code review and authorized testing.

### Lesson 3.11: Distinguishing MFA Vulnerabilities

These terms are related, but they describe different failure mechanisms.

| Vulnerability | Core failure | Typical security consequence |
|---|---|---|
| MFA fatigue | User is manipulated into approving repeated prompts | Unauthorized authentication |
| Real-time phishing | Credentials or authentication responses are relayed through a deceptive intermediary | Authentication or session compromise |
| OTP relay | A submitted one-time code is forwarded to complete another authentication flow | Unauthorized authentication if the relay succeeds |
| OTP replay | A previously accepted code is accepted again when it should be rejected | Weakening of one-time verification |
| SIM swapping | An attacker gains control of the victim's phone number | Interception of SMS-based authentication or recovery |
| MFA downgrade | The application accepts a weaker authentication path than policy requires | Authentication with insufficient assurance |
| MFA enrollment takeover | An attacker can enroll or replace a factor without sufficient proof | Persistent account compromise |
| Partial-session bypass | A password-only or MFA-pending session accesses protected resources | MFA bypass |
| Weak recovery | Recovery provides insufficient proof to restore access or replace factors | Account takeover |
| Weak remembered-device controls | A trusted-device mechanism bypasses required verification without sufficient protection | Unintended authentication bypass |

One incident may involve several of these weaknesses. For example, an attacker might obtain a password through phishing, trigger push prompts, exploit weak fallback behavior, and then retain access through a persistent session. A good security assessment identifies each demonstrated failure without confusing the attack chain with its individual components.

### Lesson 3.12: Practical Case Study

**Scenario: a fictional financial application.** The application requires a password and authenticator code for normal login. During review, you observe the following fictional source code fragments.

Login handler:

```python
async def login(username, password):
    user = await find_user(username)

    if not verify_password(user, password):
        raise Unauthorized()

    session = await create_session(user.id)
    session.mfa_verified = False

    return session
```

Protected account endpoint:

```python
async def export_account_data(session):
    if session is None:
        raise Unauthorized()

    return await export_data(session.user_id)
```

MFA endpoint:

```python
async def verify_mfa(session, code):
    if verify_totp(session.user_id, code):
        session.mfa_verified = True
        return {"message": "MFA verified"}

    raise Unauthorized()
```

These examples are deliberately simplified.

**Analysis.** The login handler creates a session before MFA is complete. That may be acceptable if it is a restricted, partial-authentication session. The MFA endpoint updates the session state after successful verification. However, the export endpoint checks only whether a session exists, it does not enforce the required MFA state. If the framework and session implementation permit the password-only session to access the export endpoint, the application has an MFA enforcement flaw.

**What is the root cause?** The endpoint treats session existence as sufficient proof of authentication. It fails to enforce the application's required assurance level.

**What is the potential impact?** Depending on the data and the application's other controls, an attacker who has valid credentials but has not completed MFA may be able to access sensitive account data. The impact could be serious if the endpoint exports financial or personal information.

**What would you recommend?** The application should represent partial authentication explicitly, restrict partial sessions to the necessary authentication operations, enforce the required MFA state on the export endpoint, apply consistent enforcement across all protected routes, ensure that session renewal and restoration do not remove the MFA requirement, and test that password verification alone cannot access protected account functionality.

**What evidence would strengthen the finding?** In an authorized test environment, evidence should establish that a valid test account requires MFA, that password verification succeeds, that the second factor has not been completed, that the endpoint returns protected data despite the incomplete authentication state, and that completing MFA is not necessary to obtain that data. A source code observation can establish a serious implementation concern, but a confirmed runtime impact strengthens the report when safely testable. Do not use another person's credentials or access their private data to validate the issue.

## Assessment

The following assessment is drawn from "Authentication Security.md" and addresses MFA enforcement across authentication states, and OTP brute force and lifecycle testing. As with Phases 1 and 2, the questions are preserved from the original source, and the answers given are the instructor's corrected, authoritative answers rather than the original learner's submitted answers.

### Assessment Question 1

A fictional application has this endpoint:

```http
POST /api/auth/verify-otp HTTP/1.1
Host: securebank.example.test
Content-Type: application/json
Cookie: session=pending_8af31

{
  "otp": "123456"
}
```

```http
HTTP/1.1 200 OK

{
  "verified": true,
  "redirect": "/dashboard"
}
```

The normal flow is password login, then OTP verification, then an authenticated session, then the dashboard. Without assuming there is a vulnerability, what is the single most important first test to perform to determine whether OTP verification actually protects access to the dashboard?

**Answer**

The single highest priority test is to try to access protected resources without completing OTP verification at all, using the pending session that only reflects a verified password. For example:

```http
GET /api/account HTTP/1.1
Host: securebank.example.test
Cookie: session=pending_8af31
```

The core security question is not initially "can the OTP be reused" or "can the OTP work for another account," even though both are legitimate follow-up hypotheses. The priority question is whether the application actually enforces the authentication state before granting access to protected functionality at all. If the server responds `200 OK` with account data, that is a major finding, because a supposedly pending session already has access to protected functionality. If the server responds `403 Forbidden` with an error such as "MFA verification required," then the OTP state is being enforced at that endpoint. A senior tester isolates one security property at a time rather than testing OTP reuse, cross-account binding, and state enforcement simultaneously. The underlying question to keep asking is: what security state does the server believe the requester is in, and does every sensitive endpoint enforce that state?

### Assessment Question 2

Suppose `GET /dashboard` with `Cookie: session=pending_8af31` correctly returns `302 Found` with `Location: /verify-otp`, confirming that the dashboard page itself redirects to MFA. What would you test next to determine whether the application has a real, centrally enforced MFA mechanism rather than merely protecting this one URL?

**Answer**

Look for alternate routes and APIs that might supply the same functionality without the same check, since the real question is whether MFA is enforced centrally or whether each endpoint implements its own check independently. Specific categories to investigate include the underlying API endpoints that supply data to protected pages, such as `/api/account`, `/api/profile`, `/api/transactions`, `/api/settings`, `/api/payments`, and `/api/beneficiaries`; alternate web routes such as `/settings`, `/profile`, `/account`, and `/transactions`; different HTTP methods on the same route, since an application might protect `GET /api/profile` but forget the identical check on `PUT /api/profile`; and legacy or alternate authentication endpoints such as `/api/v1/...`, `/api/v2/...`, `/mobile/...`, or `/legacy/...`. If every sensitive endpoint independently decides whether a session is authenticated, inconsistent enforcement becomes much more likely, because a single centrally enforced check is far harder to accidentally omit than dozens of endpoint-specific checks.

### Assessment Question 3

You discover that `GET /api/account` with `Cookie: session=pending_8af31` (a password-authenticated but MFA-incomplete session) returns `200 OK` with account data including a balance. Without stating a severity yet, what is the security flaw and the broken security assumption here, and what would you test next before concluding this is a confirmed MFA bypass?

**Answer**

The flaw is an authentication-state inconsistency: the pending session, which should only reflect a verified password and an incomplete MFA step, is being treated by this particular endpoint as sufficiently authenticated to return protected account data. The broken assumption is that session existence or password verification alone is equivalent to the full authentication assurance the application's policy requires for protected functionality. However, evidence of this inconsistency is not automatically proof of an MFA bypass. The response needs further investigation along three lines: first, determine exactly what the endpoint allows, since reading limited account information may be an intentional, low-risk design decision for a pre-MFA state; second, test security-sensitive functionality specifically, for example whether the pending session can initiate a transfer, modify account settings, add a beneficiary, or change authentication factors, using only controlled test data; and third, check consistency across the attack surface, since `/api/account` might allow limited access while `/api/transactions` or `/api/settings` correctly requires MFA. The deeper question to resolve is what the pending session actually authorizes, and whether that authorization is consistent with the application's intended MFA state. The `200 OK` response is evidence worth investigating, it is not by itself sufficient to establish an MFA bypass. If you eventually demonstrate that a password-authenticated-but-MFA-pending session can perform an action that the application's security model requires MFA to protect, you have established the vulnerability.

### Assessment Question 4

An application sends a 6-digit phone verification code through this endpoint:

```http
POST /api/phone/verify
Cookie: session_id=ALICE

{
  "phone": "+2348011111111",
  "code": "123456"
}
```

You submit 20 incorrect codes and all 20 return `400 Bad Request`. There is no CAPTCHA, no lockout, no visible delay, no `429`, and no indication of attempt limits. Would you immediately report this as an "OTP brute-force vulnerability"? Explain why or why not.

**Answer**

No, not immediately. Observing 20, 100, or even 1000 requests with no `429` proves only that there may be insufficient rate limiting. It does not yet prove that OTP brute force is practically exploitable. A 6-digit OTP has up to 1,000,000 possible codes, so the determining factor is whether an attacker can realistically make enough attempts before the OTP expires or becomes invalid. An OTP with a 5-minute lifetime, unlimited attempts, and an achievable rate of 100 attempts per second is a dramatically different risk than an OTP with a 30-second lifetime, unlimited attempts, and a rate of 2 attempts per second. The senior testing sequence is: determine whether the OTP has an effective attempt limit, test whether repeated guesses are accepted, check for rate limiting, lockout, expiration, and attempt counters, and then assess whether the attacker can realistically guess the correct code within the OTP's lifetime and whether successful verification unlocks something sensitive. Only if the answer to that combined question is yes do you have a strong OTP brute-force vulnerability. It is also important to test limits per account or per phone number, not just per IP address, since an attacker may otherwise distribute requests across IPs to bypass an IP-based limit entirely.

### Assessment Question 5

Alice requests an OTP, `OTP_A = 483921`. She then requests another, `OTP_B = 716204`, and the application says "a new verification code has been sent." You test `OTP_A` against the verification endpoint and receive `400 Invalid verification code`. You then test `OTP_B` and receive `200 Verified`. So far everything looks correct. What would you test next to determine whether the application correctly invalidates old OTPs across the entire verification flow?

**Answer**

Use the same phone number and account and submit the old code, `OTP_A`, again, to establish whether a previously superseded OTP remains permanently invalid once a newer OTP has been issued, rather than merely being invalid because `OTP_B` happened to be entered afterward. The expected secure behavior is that `OTP_A` is rejected and `OTP_B` is accepted, every time, including on repeated attempts. If `OTP_A` is ever accepted later, that indicates a stale OTP or token lifecycle flaw, distinct from the OTP-to-phone-number binding question. Testing `OTP_A` against a different phone number entirely tests a different security property, namely whether an OTP is properly bound to the account or number it was issued for, which is a valid test but not the one this scenario is asking about. These should be kept as separate, clearly labeled test cases: old OTP used after a new OTP is issued tests OTP invalidation and lifecycle; an OTP used against a different account or number tests OTP-to-account binding; many guesses against the same OTP tests brute-force resistance; and an OTP used after its expiration time tests expiration enforcement. Each of these is a distinct security property, and conflating them produces an imprecise finding even when the underlying test instinct is correct.

## Remediation and Secure Implementation

The following consolidates the remediation guidance across all twelve lessons in this phase.

1. Verify that a session has completed every required factor before granting the privileges of full authentication, on every protected endpoint, not only the primary ones.
2. Rate limit and apply risk-based throttling to push notification challenges, and use number matching or stronger challenge binding where push approval is used.
3. Treat manually entered, phishable OTPs as a general property of that mechanism, and prefer phishing-resistant authentication, such as WebAuthn-based passkeys, for high-risk accounts and operations.
4. Implement deliberate replay protection for TOTP codes by tracking the accepted time step per authenticator, rather than relying on the code's natural time-based expiry alone.
5. Avoid treating SMS as a high-assurance factor on its own, and require stronger verification before a phone number change can be used for sensitive recovery actions.
6. Build and maintain a complete authentication-path inventory covering every login route, fallback, and legacy endpoint, and verify that MFA policy is enforced consistently across all of them.
7. Require strong, specific proof of authority, such as recent reauthentication or verification through an existing factor, before allowing backup codes to be issued, an email-based recovery to succeed, support-assisted recovery to proceed, or any MFA factor to be replaced.
8. Determine authentication state exclusively from server-side, validated records. Never allow a client-supplied field to declare that MFA has been completed.
9. Ensure session renewal, rotation, and restoration all preserve the authentication state that was actually achieved, rather than silently restoring or elevating a partial session.
10. Define the required authentication assurance for each sensitive operation individually, rather than assuming a single valid session is sufficient proof for every action in the application.

## Key Takeaways

The eight lessons from the module's own final summary remain the clearest statement of what this phase teaches: MFA is only as strong as its enforcement, since a strong authenticator cannot protect an endpoint that accepts an incomplete authentication session. OTPs can be phished, because single-use behavior does not guarantee resistance to real-time relay. Push approval can be manipulated through repeated prompts, poor contextual information, and weak abuse controls. Replay protection must be implemented deliberately, since time-based validity does not automatically prevent a code from being accepted multiple times. Recovery must preserve authentication assurance, because a weak fallback can undermine a strong primary factor. Factor enrollment is security sensitive, since an attacker who can replace the legitimate user's authenticator may establish persistent access. Authentication state must be enforced server side, because a client-supplied field cannot prove that MFA succeeded. And finally, MFA is a lifecycle, not a checkbox: enrollment, login, fallback, recovery, session handling, and factor replacement all matter together.

## Review Checklist

- [ ] Can you explain why two knowledge factors do not constitute multifactor authentication?
- [ ] Can you name the four distinct authentication state conditions, and explain why they are not interchangeable?
- [ ] Can you distinguish MFA fatigue from push bombing, and explain the limits of number matching as a defense?
- [ ] Can you explain why a single-use OTP can still be defeated by real-time phishing, and why HTTPS does not prevent this?
- [ ] Can you distinguish OTP relay from OTP replay as two separate failure mechanisms?
- [ ] Can you explain the specific implementation gap that allows a TOTP code to be accepted more than once?
- [ ] Can you describe a complete SIM-swapping attack chain and identify where it could be interrupted?
- [ ] Can you list the five common MFA downgrade patterns from memory?
- [ ] Can you identify, from a source code snippet, whether MFA is actually enforced or merely optional?
- [ ] Can you explain why a client-supplied `mfa_verified` field must never be trusted by the server?
- [ ] Can you explain why a password-verified-but-MFA-pending session returning account data is evidence, not proof, of an MFA bypass?
- [ ] Can you explain why observing no rate limiting on an OTP endpoint does not, by itself, prove a brute-force vulnerability?

## References to Related Phases

- Weak account recovery as an MFA downgrade path, referenced in Lessons 3.7 and 3.8, connects directly to **Phase 2, Password Change and Account Recovery**.
- Phishing-resistant authentication through WebAuthn, introduced in Lesson 3.3, is covered in full in **Phase 5, Passkeys, WebAuthn, and FIDO2**.
- Session creation, rotation, renewal, and restoration, referenced throughout Lesson 3.9, are covered in full in **Phase 6, Cookie and Session Security**.
- Defining required authentication assurance per sensitive operation, introduced in Lesson 3.9, is covered in full in a later phase, **Reauthentication and Step-Up Authentication**.
- Legacy endpoint bypass of MFA policy, referenced in Lesson 3.7, is covered in full in a later phase, **Legacy Authentication Security**.
