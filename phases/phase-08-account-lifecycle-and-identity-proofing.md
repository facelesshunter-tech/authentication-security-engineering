# Phase 8: Account Lifecycle and Identity Proofing

**Source material:** Module 8 of 17, "Authentication Complete Phases Test.md" (17 numbered sections covering account lifecycle and identity proofing, and the course progress tracker), with supplementary assessment material drawn from "Authentication Security.md" (Challenge 26, Challenge 27, Challenge 29, Challenge 30, and Challenge 31).

## Learning Objectives

After completing this phase, you should be able to:

1. Walk through the account lifecycle as a state machine and apply the five governing questions, identity, ownership, state, transition, and revocation, to any lifecycle operation.
2. Explain why registration proves that someone submitted data but does not prove ownership of every identity attribute in that data, and identify a registration flow that grants trust before verification.
3. Distinguish the two distinct verification-flow failures: a token that can be reused after it has fulfilled its purpose, and a token or verification action that is not bound to the correct account.
4. Explain why a single rate limit dimension is insufficient for verification-code brute force protection, and design layered defenses across account, channel, and network dimensions.
5. Evaluate account enumeration during registration with the same nuance as earlier phases: identify the disclosure, but do not assign severity without assessing the affected population and realistic consequence.
6. Explain how inconsistent identity normalization between registration, login, and recovery can create duplicate-account or identity-confusion problems, and design a single consistent normalization policy.
7. Explain why account recovery based on a submitted identifier alone is unsafe, and why a recovery credential must remain bound to its original account even if other account details change.
8. Explain why changing a primary email or phone number is as security-sensitive as changing a password, and design a safe change process that does not grant the new channel privileges before it is verified.
9. Distinguish account deactivation from deletion, and identify the four specific ways each one can fail: live sessions surviving deactivation, cached credentials surviving deletion, unsafely reclaimed identifiers, and reactivation restoring excessive trust.
10. Identify an orphaned account or stale identity relationship by tracing a single identity across every system that holds a record of it, not just the primary user table.
11. Distinguish identity proofing from authentication as two separate properties, and identify an application that substitutes one for the other without a deliberate policy.
12. Apply the Phase 1 through Phase 7 impact-validation discipline to account lifecycle findings: distinguish an unusual response from a demonstrated crossing of a security boundary.

## Introduction

Every phase up to this point assumed an account already exists and studied how it is accessed, recovered, or extended through a second factor or a delegated identity provider. This phase studies the account itself, how it comes into existence, how its identity relationships are established and maintained, and how it ends. An application can have excellent passwords, MFA, passkeys, and session management, and still allow account takeover because it mishandles registration, verification, identity linking, or account recovery.

The central principle stated at the start of this module carries through every lesson in it: an application must correctly establish who controls an account, maintain that identity relationship, and safely change or terminate it throughout the account's lifetime. The module's own closing idea frames an account not as a row in a database but as a collection of linked security relationships, authentication credentials, verified contact methods, recovery mechanisms, external identities, active sessions, roles and privileges, and lifecycle state, and the most common root cause this phase identifies is updating one of those relationships while leaving another, security-relevant one unchanged.

## Core Concepts

The module moves through four stages. First, sections 1 through 5 examine the front door: the lifecycle state machine itself, registration vulnerabilities, email and phone verification flaws, verification-code brute force, and account enumeration during registration. Second, sections 6 through 9 examine identity integrity during an account's active life: duplicate accounts and normalization, account recovery and identity binding, email and phone changes as an account-takeover vector, and the distinction between deactivation and deletion. Third, sections 10 through 12 examine what happens after an identity relationship goes stale: orphaned accounts, reactivation and identity reassignment, and identity proofing versus authentication as two properties that must not be substituted for one another. Fourth, sections 13 through 17 bring the module together into a practical discipline: authorization flaws specific to lifecycle operations, a complete source-code review exercise, a testing checklist, common false positives, and the final mastery model.

## Lessons

### 1. Understand the Account Lifecycle

An account is not simply a username and password. It moves through several states. A typical lifecycle looks like this:

```text
             REGISTRATION
                  |
                  v
          UNVERIFIED ACCOUNT
                  |
                  | Verification succeeds
                  v
           ACTIVE ACCOUNT
                  |
                  | Security restriction
                  v
          RESTRICTED ACCOUNT
                  |
                  | Account restored
                  v
           ACTIVE ACCOUNT
                  |
                  | Deactivation
                  v
         DEACTIVATED ACCOUNT
                  |
                  | Permitted reactivation
                  v
           ACTIVE ACCOUNT
                  |
                  | Deletion
                  v
           DELETED ACCOUNT
```

Real applications may use different states, and some transitions may be irreversible. The security requirement is that every transition has explicit rules and is enforced by the server. For example, an unverified account should not automatically receive every privilege of a fully verified account if verification is required for those privileges. Likewise, a deactivated account should not continue to access protected resources simply because it has a previously issued session cookie.

**The five questions to ask.** When reviewing an account lifecycle, ask: identity, what establishes the account's identity; ownership, what proves that someone controls the email address, phone number, or external identity associated with it; state, what permissions are available in the account's current state; transition, what evidence is required to change that state; and revocation, what happens to existing sessions, credentials, and recovery methods when the account changes state. These five questions guide the entire module.

### 2. Registration Vulnerabilities

Registration creates a new identity relationship between a person and an application. Consider this fictional endpoint:

```http
POST /register HTTP/1.1
Host: accounts.example.test
Content-Type: application/json

{
  "username": "hunter01",
  "email": "hunter@example.test",
  "password": "EXAMPLE_PASSWORD"
}
```

A successful response might be:

```http
HTTP/1.1 201 Created
Content-Type: application/json

{
  "message": "Registration successful",
  "account_status": "unverified"
}
```

This is reasonable if the application requires email verification before enabling certain features. But registration can fail in several ways.

**Vulnerability A: the account becomes fully trusted before verification.** Imagine the application accepts the registration request and immediately marks the account as fully verified:

```python
def register(data):
    user = create_user(
        email=data.email,
        password_hash=hash_password(data.password),
        email_verified=True
    )

    return user
```

The problem is that the application sets `email_verified=True` without demonstrating that control of the email address has been established. An attacker could register an email address they do not control and have the application treat it as verified. The consequences depend on what the verified status permits, potentially including receiving account notifications intended for someone else, bypassing features that require verified contact information, creating an identity relationship the application incorrectly trusts, and complicating future recovery or account ownership disputes.

Secure design:

```python
def register(data):
    user = create_user(
        email=normalize_email(data.email),
        password_hash=hash_password(data.password),
        email_verified=False
    )

    send_verification_message(user)

    return user
```

This is illustrative pseudocode. The verification token must itself be generated and validated securely. The key principle is that registration proves that someone submitted data, it does not prove ownership of every identity attribute in that data.

**What should you test?** Using an account and email address you control: register normally, inspect the account's status, determine which functions are available before verification, attempt the documented verification process, confirm that the server changes the account state only after successful verification, and test whether unverified accounts can perform actions that explicitly require verification. Do not report every application that permits unverified registration as vulnerable. Many applications intentionally allow limited access before verification. The vulnerability exists when the application fails to enforce its own security requirements.

### 3. Email and Phone Verification Flaws

Email and phone verification establish control over a communication channel. They do not necessarily establish a person's legal identity. Email verification demonstrates control over an email address at the time of verification. Phone verification demonstrates control over a phone number at the time of verification. Neither automatically proves a person's real-world identity. Neither guarantees that the same person will control that channel indefinitely. This distinction becomes especially important in account recovery.

**Vulnerability A: verification tokens can be reused.** Suppose the application sends this link: `https://accounts.example.test/verify?token=SECRET_TOKEN`. A vulnerable implementation might do this:

```python
def verify_email(token):
    record = find_verification_token(token)

    if not record:
        return reject()

    mark_email_verified(record.user_id)
    return success()
```

The code does not demonstrate that the token expires, is bound to the correct purpose, or is consumed after use. A safer design checks token validity, expiration, account binding, purpose, revocation status, and single-use status where required:

```python
def verify_email(token):
    record = find_valid_verification_token(token)

    if not record:
        return reject()

    mark_email_verified(record.user_id)
    consume_verification_token(record.id)

    return success()
```

This is still conceptual pseudocode. The complete implementation must correctly enforce token properties and handle concurrent requests.

**Testing methodology.** Use your own verification token. Complete a normal verification, replay the same token, determine whether the application accepts it again, and check whether the replay can change account state or affect another account. A second request returning a success message does not necessarily prove that the token remains usable, the server might return an idempotent response while refusing to perform the operation again. The important question is whether the token can still authorize an unintended state change.

**Vulnerability B: a verification token is not bound to the correct account.** Suppose a token is intended for Account A, but the verification endpoint applies it to whichever account ID the client supplies:

```http
POST /verify-email HTTP/1.1
Host: accounts.example.test
Content-Type: application/json

{
  "token": "TOKEN_FOR_ACCOUNT_A",
  "user_id": 2048
}
```

If the token belongs to Account A but the server verifies Account B because the client supplied a different `user_id`, the application has a binding flaw. The server must derive the target account from the validated token or otherwise enforce a trustworthy association between the token and the intended account. Security rule: do not let untrusted client input override the account identity established by the verification credential.

### 4. Verification-Code Brute Force and Rate Limiting

Some applications use short verification codes instead of long tokens, for example a six-digit code with one million possible values. That does not automatically make it vulnerable. The practical risk depends on the code's lifetime, attempt limits, generation, and surrounding controls. A poorly designed endpoint might allow unlimited attempts:

```http
POST /verify-phone HTTP/1.1
Host: accounts.example.test
Content-Type: application/json

{
  "phone": "+2348000000000",
  "code": "482193"
}
```

If the server accepts unlimited guesses and the code remains valid for a long time, an attacker may be able to guess the code.

**Defenses.** A defensible implementation should consider cryptographically secure code generation, short validity periods appropriate to the use case, strict attempt limits, rate limits across relevant dimensions rather than just one client-controlled identifier, one-time use where required, invalidation of older codes when a new code is issued according to policy, monitoring for repeated failures, and binding the code to the intended account, phone number, and purpose.

**Why one rate limit is not enough.** Suppose the application limits each IP address to five attempts but allows unlimited attempts across many accounts. Or suppose it limits each account but permits an attacker to generate excessive verification messages. The first problem concerns verification attempts, the second concerns resource abuse and messaging costs, different controls address different risks. Also, rate limits based exclusively on a client-supplied user ID can be ineffective if the attacker can simply change that value.

**What counts as evidence?** A confirmed weakness would involve demonstrating, within an authorized test, that the application allows more attempts than its stated policy permits or otherwise makes guessing realistically feasible. Do not attempt high-volume guessing against a production account. Establish the control through source-code review, a staging environment, or an approved, limited test.

### 5. Account Enumeration During Registration

Account enumeration occurs when an application reveals whether an account or identity already exists. Consider two registration attempts. For an existing email, the server might return `409 Conflict` with "This email address is already registered." For a new email, it returns `201 Created` with "Registration successful." The difference reveals account existence. Whether that is a vulnerability depends on the application and the sensitivity of its user population, the risk may differ substantially between a public social platform, a medical portal, a financial service, or a private employee system.

**Safer response design.** An application might return a generic response such as `200 OK` with "If this address can be registered, the next steps will be sent." However, a generic message alone is not enough if the application leaks the same information through different response timing, different status codes, different response sizes, different redirects, distinctive error messages, or observable side effects. Perfectly identical behavior is not always practical, but meaningful differences should be assessed in the relevant threat model.

**How to report it.** Do not automatically label account enumeration high severity. Explain what identity information is disclosed, whether the affected population is sensitive, whether the disclosure can be automated, what further attacks the information enables, and what protections already limit exploitation. Enumeration can be a supporting weakness in a larger attack chain without independently constituting account takeover.

### 6. Duplicate Accounts and Identity Normalization

Applications must decide when two submitted identifiers refer to the same identity. Consider `User@example.test` and `user@example.test`, depending on the application's identity policy and email handling, these may be treated as equivalent. But developers can implement normalization inconsistently, for example registration may lowercase an email address while login or account recovery uses a different normalization process. That can produce inconsistent account lookup, duplicate records, or unexpected account binding.

**Vulnerable conceptual design:**

```python
def register(email):
    if not user_exists(email):
        create_user(email=email.lower())
```

The lookup uses the original value, but account creation stores a normalized value. Depending on the database constraints and other code, this inconsistency can create duplicate-account or identity-confusion problems.

**Safer approach.** Establish one documented normalization policy and apply it consistently to registration, login, account recovery, email changes, external identity linking, uniqueness constraints, and administrative account operations. Use appropriate database constraints to enforce uniqueness at the persistence layer, not just application-level checks.

**Important nuance about email addresses.** Do not assume every email provider treats every variation as equivalent, for example provider-specific rules involving dots or plus signs should not be generalized to all domains. The application should use a deliberate identity policy rather than inventing equivalence rules based on assumptions about one email provider.

A duplicate record is not automatically an account takeover vulnerability. Demonstrate a security boundary failure, such as recovery being delivered to the wrong party or one identity gaining control of another user's account.

### 7. Account Recovery and Identity Binding

Account recovery is a transition from a state in which a user may lack normal authentication credentials to one in which they regain access. This makes it one of the most sensitive lifecycle operations. The application may allow recovery through a verified email address, a verified phone number, backup codes, an approved identity provider, an administrator-assisted process, or another explicitly supported recovery method. The key issue is whether the recovery evidence is sufficient for the requested action.

**Vulnerable example: trust based on a submitted email.**

```python
def recover_account(email):
    user = find_user_by_email(email)

    if user:
        mark_account_recovered(user.id)
        return success()

    return reject()
```

This is unsafe if merely submitting an email address is enough to regain access. Knowing an identifier is not the same as proving control of the account. A secure recovery flow requires an appropriate proof of control and must enforce the resulting account-state transition on the server.

**Recovery should not silently change identity.** Imagine this sequence: a user requests account recovery, the application issues a recovery token for Account A, the user submits the token and a new email address, and the server applies the recovery action to Account B because it trusts the submitted email or account ID. This is an identity-binding flaw. The recovery credential must be associated with the correct account and purpose. Client-supplied identifiers must not override that association.

**Testing checklist.** Using controlled accounts: confirm the recovery credential is bound to the intended account, confirm the required proof is actually checked, verify that expired or revoked credentials are rejected, test whether the recovery credential can be reused, check whether the application changes contact details only after adequate proof, confirm whether existing sessions and authenticators are handled according to policy, and check whether security notifications are sent where appropriate. For deeper reset-token lifecycle weaknesses, revisit Phase 2.

### 8. Email and Phone Changes: Account Takeover Through Identity Replacement

Changing the primary email address or phone number can be as sensitive as changing a password, because those channels may be used for password recovery, verification, login, and security notifications. Consider this fictional endpoint:

```http
POST /account/change-email HTTP/1.1
Host: accounts.example.test
Content-Type: application/json
Cookie: __Host-session=VALID_SESSION

{
  "new_email": "attacker@example.test"
}
```

The request is not necessarily unsafe. The problem depends on what the server requires before accepting it. If an authenticated user can change the account's primary email without the verification or reauthentication required by the application's policy, an attacker who has obtained a session may be able to change the account's recovery channel.

**Safer process.** A secure email-change flow may involve verifying the user's current authentication state, requiring recent authentication or additional proof for a high-risk change, recording the new address as pending, sending a verification message to the new address, confirming control of the new address, activating the new address only after the required verification, notifying the previous address when appropriate, and updating recovery and identity bindings consistently. The exact policy depends on the application and threat model.

**A subtle testing point.** An application may accept a new email address but keep the old address active until verification finishes. That is not automatically a flaw. You need to establish whether the new address gains sensitive privileges before verification, whether the old address is prematurely disabled, or whether the account becomes recoverable by someone who has not proved control of the new address.

### 9. Account Deactivation Versus Deletion

These terms have different meanings. Deactivation usually means that the account is temporarily or indefinitely disabled while its underlying record may remain. Deletion generally means that the account is removed or that its personal data is deleted or handled according to the application's retention policy, some records may need to be retained for legal, security, or operational reasons. The exact semantics must be defined by the application.

**What can go wrong?**

*Case A: deactivated accounts retain working sessions.* The account is marked disabled, but existing sessions continue to access protected resources. A secure implementation should check account status when authorizing access or otherwise reliably invalidate the relevant sessions.

*Case B: deleted accounts retain active credentials.* An account is deleted from the main user table, but an authentication cache or separate session store still accepts old credentials. This can create unexpected access or inconsistent identity handling.

*Case C: deleted identifiers can be reclaimed unsafely.* A new user registers with an email address previously associated with a deleted account. The application then accidentally grants access to old orders, private records, or resources because it relies on the email address instead of the proper account identifier and ownership checks. This can be a serious identity-binding flaw.

*Case D: reactivation restores excessive trust.* An old account is reactivated without the verification or security checks required by the application's policy. Whether this is a vulnerability depends on what the reactivation process restores and who can initiate it.

**The key security principle.** An email address or username is an identifier, not a permanent proof of ownership of every historical record associated with that identifier. Applications should bind private resources to stable internal account identities and apply appropriate access checks.

### 10. Orphaned Accounts and Stale Identity Relationships

An orphaned account or identity relationship occurs when the application retains a record whose intended owner, status, or associated identity is no longer valid. Examples include an external identity remaining linked after the local account has been deleted, an employee account remaining active after employment ends, a deactivated account retaining privileged sessions, an account retaining a recovery phone number that no longer belongs to its owner, an external identity link pointing to the wrong local account, and a service account with no clear owner.

These issues often arise because different systems maintain separate records, for example:

```text
Application database:
Account 1042 = deactivated

Session store:
Session ABC123 = authenticated

Identity mapping:
External identity XYZ = linked to Account 1042
```

If the application disables only the database account but does not enforce that status in session validation, the account may remain accessible. If it deletes the local account but leaves an external identity mapping, the next login might create an unexpected identity relationship.

**What should a tester examine?** Trace the account across the relevant systems: user record, authentication sessions, recovery credentials, external identity mappings, privilege assignments, verification records, and account status and lifecycle events. Determine whether all components enforce the same intended account state. Do not assume that deleting a database row invalidates every related credential or relationship.

### 11. Account Reactivation and Identity Reassignment

Consider an organization that deactivates an employee's account. Months later, the employee's email address is reassigned to a new employee. The application uses the email address as its only identity key. The new employee logs in or completes recovery and receives access to the previous employee's records. That would be a serious identity-binding failure. The problem is not simply that the email address was reused. The problem is that the application treated a recycled identifier as proof of ownership of an existing account and its data.

**Safer architecture.** Use stable internal account identifiers, for example `Account ID: 1042`, `Email: former.employee@example.test`, `Status: deactivated`. If the address is reassigned, the new person should not automatically inherit Account 1042. Instead, the application should establish a new account or apply a carefully defined, authorized reactivation process.

**Test scenarios.** In a controlled environment: create an account with a test email, deactivate the account, change or reassign the email according to the test plan, attempt normal login and recovery flows, confirm that the new identity cannot access the old account's private records, and confirm that reactivation requires the appropriate authority and verification. This type of flaw may affect business applications, education platforms, employee portals, and systems that use recycled contact details.

### 12. Identity Proofing Versus Authentication

These terms are related but distinct. Identity proofing establishes confidence in a person's claimed identity, according to the application's requirements. Authentication establishes that a person or system controls the credentials or authenticators associated with an account. For example, a website may authenticate a user successfully with a passkey, that does not necessarily establish the user's legal name or real-world identity. Likewise, a government service may require identity proofing before granting access to certain benefits, even after the user successfully authenticates.

**What can go wrong?** An application may treat an unverified email as a verified real-world identity, allow self-asserted profile data to determine privileged access, treat possession of a phone number as sufficient proof for a high-risk identity claim, accept an identity-provider claim without checking its issuer or intended use, or fail to distinguish between an authenticated account and an account that has completed additional identity verification.

Suppose a financial service has these states: account created, email verified, identity documents reviewed, approved for sensitive transactions. If the application checks only `email_verified` before allowing transactions that require identity proofing, it is enforcing the wrong condition. The correct requirement depends on the operation.

Senior-level rule: authentication assurance, contact-channel verification, and real-world identity proofing are separate properties. Do not substitute one for another without a deliberate, defensible policy.

### 13. Account Lifecycle Authorization Flaws

This module focuses on identity and account state, but account lifecycle operations also require authorization. For example, consider:

```http
POST /admin/users/1042/deactivate HTTP/1.1
Host: accounts.example.test
Cookie: __Host-session=VALID_SESSION
```

A security tester must determine whether the server verifies that the authenticated user is authorized to deactivate the specified account. It is not enough to check whether the request contains a valid session. A regular user should not be able to perform an administrative account action merely by changing an account ID in a request. Likewise, a user who is permitted to deactivate their own account should not automatically be allowed to deactivate other users' accounts.

**What to test.** Using accounts and permissions you are authorized to test: can a regular user access an administrative lifecycle operation, does the server enforce the caller's role and scope, can one tenant affect another tenant's accounts, does a user ID supplied by the client override the authenticated identity, does account reactivation require the proper authority, and are account-state changes enforced consistently across all access paths? These issues may overlap with broken access control, which is examined in depth in a later phase on authentication-adjacent authorization flaws.

### 14. A Complete Source-Code Review Exercise

Consider this fictional account-recovery handler:

```python
def recover_account(request):
    email = request.json["email"]
    new_email = request.json["new_email"]

    user = find_user_by_email(email)

    if not user:
        return error("Account not found")

    user.email = new_email
    user.email_verified = True

    save(user)

    return success()
```

This implementation raises several concerns.

**Problem 1: no visible proof of account control.** The code finds the account using an email address but does not demonstrate that the requester controls the account. Knowing an email address is not sufficient proof of ownership.

**Problem 2: the recovery process changes the primary email immediately.** The code assigns the new address without showing any verification of the new address. This may allow the recovery channel to be transferred to an address controlled by someone else.

**Problem 3: the new address is immediately marked verified.** The code sets `user.email_verified = True` without demonstrating verification of the new address.

**Problem 4: account enumeration.** The response explicitly distinguishes an existing account from a nonexistent one. Whether that is a vulnerability depends on the application's risk and disclosure policy.

**Problem 5: no visible session or credential policy.** The code does not show whether recovery revokes existing sessions, handles MFA, or sends security notifications. Those controls may exist elsewhere, so further investigation is needed.

**A safer conceptual approach:**

```python
def request_account_recovery(request):
    email = normalize_email(request.json["email"])

    user = find_user_by_email(email)

    # Use an appropriate generic response.
    if not user:
        return generic_recovery_response()

    issue_account_bound_recovery_token(user)
    return generic_recovery_response()


def complete_account_recovery(request):
    token = request.json["token"]
    new_email = normalize_email(request.json["new_email"])

    recovery = validate_recovery_token(token)

    if not recovery:
        return reject()

    user = get_user_bound_to_recovery(recovery)

    set_pending_email(user, new_email)
    send_new_email_verification(user, new_email)

    consume_or_advance_recovery_token(recovery)

    return success()
```

This illustrates the separation between requesting recovery and completing it. A production implementation must define token expiry, purpose binding, one-time behavior, appropriate proof of control, transaction handling, and the policy for existing sessions and authenticators. The exact design depends on the application's requirements. Do not treat pseudocode as production-ready merely because it contains security-oriented function names.

### 15. Practical Testing Checklist

Use this during authorized assessments.

| Area | What to test | What establishes a meaningful flaw |
|---|---|---|
| Registration | Verification requirements | Unverified accounts receive privileges that explicitly require verification. |
| Email verification | Token lifecycle | A token authorizes an unintended action after expiry, revocation, or consumption. |
| Phone verification | Attempt limits | Verification can be guessed or abused beyond the intended controls. |
| Account enumeration | Response behavior | Sensitive account-existence information is disclosed with meaningful risk. |
| Duplicate identities | Normalization and uniqueness | Inconsistent identity handling causes a real ownership or access failure. |
| Account recovery | Proof of control | A requester can recover an account without the required evidence. |
| Email change | New-address verification | An unverified address gains sensitive account-control privileges. |
| Phone change | Number ownership | A new number is trusted without the required proof. |
| Deactivation | Existing sessions | Disabled accounts retain access contrary to policy. |
| Deletion | Related credentials and records | Deleted-account credentials or mappings create unintended access. |
| Reactivation | State transition | An unauthorized party can reactivate or inherit an account. |
| Identity proofing | Required assurance | The application grants a privilege based on weaker evidence than required. |
| External identity mapping | Issuer and subject | An external identity becomes associated with the wrong local account. |
| Administrative lifecycle actions | Authorization | A user can change another account's state without the required authority. |

**Evidence to preserve.** For a report, record the starting account state, the exact lifecycle operation, the relevant request and response, the expected behavior, the actual state change, whether the change persists after a new login or session, which account and data are affected, and any required attacker capabilities. Redact passwords, verification codes, recovery tokens, session cookies, and other secrets.

### 16. Common False Positives

Avoid these mistakes.

**Mistake 1: registration does not require immediate email verification, so the application is vulnerable.** Not necessarily. Determine what unverified accounts can access and what the application claims to require.

**Mistake 2: the same email address can be used again after account deletion, so account takeover is confirmed.** Not without evidence that the new owner gains access to the previous account or its private data.

**Mistake 3: a verification token can be submitted twice, so replay is confirmed.** Determine whether the second request can actually authorize another action. An idempotent response may be harmless.

**Mistake 4: the application reveals that an email is registered, so the finding is high severity.** Assess the sensitivity of the population, the scale of disclosure, and the consequences.

**Mistake 5: a new email is accepted before verification, so the account is compromised.** Determine whether the address remains pending or immediately gains recovery, login, or other sensitive privileges.

**Mistake 6: the application retains a deactivated account record, so deletion is broken.** Retention may be intentional. Evaluate the actual lifecycle policy, data handling, and access behavior.

### 17. Module 8 Mastery Model

The most important idea is that an account is a collection of linked security relationships:

```text
Local account
    |
    +---- Authentication credentials
    |
    +---- Verified contact methods
    |
    +---- Recovery mechanisms
    |
    +---- External identities
    |
    +---- Active sessions
    |
    +---- Roles and privileges
    |
    +---- Account lifecycle state
```

When any relationship changes, the application must update the relevant security state consistently. For example, changing a phone number may require updating verification and recovery records. Deactivating an account may require revoking sessions. Deleting an account may require cleaning up external identity mappings. A common root cause is updating one record while leaving another security-relevant record unchanged. When testing, follow the identity relationship across the whole lifecycle, not just the individual endpoint.

## Assessment

The following assessment is drawn from "Authentication Security.md" and addresses email verification bypass, cross-account verification state modification, verification-token reuse as distinct from account binding, a stale verification token surviving an email change, and a phone verification code not bound to the phone number it was issued for. As with the prior phases, the questions are preserved from the original source, and the answers given are the instructor's corrected, authoritative answers rather than the original learner's submitted answers.

### Assessment Question 1

A fictional application requires email verification before sensitive actions. You create your own account, `attacker@example.test`, but do not click the verification link. You then submit:

```http
POST /api/account/change-email
Cookie: session_id=ATTACKER_SESSION

{
  "newEmail": "newattacker@example.test"
}
```

```http
HTTP/1.1 200 OK

{
  "message": "Email changed successfully"
}
```

What exactly would you conclude from this response? Identify the security control being tested, what the `200` response actually proves, and what you would test next to determine whether this is a real vulnerability.

<details markdown="1">
<summary><strong>Reveal Answer</strong></summary>

The security control being tested is email-verification enforcement, specifically whether the application correctly gates sensitive actions on a verified email state. The `200` response proves only that the application accepted the email-change request from an unverified account, it does not by itself prove that any verification control was bypassed.

An application may legitimately allow an unverified user to change their email, and then simply require the new email to also be verified before treating the account as verified. So the real question is whether changing the email allows the attacker to obtain a security-sensitive state that should require verification. The correct next step is to check the account's actual state after the change, for example `GET /api/account` returning `{"email": "newattacker@example.test", "email_verified": false}`, and then attempt a verification-dependent action directly, such as `POST /api/account/enable-sensitive-feature`. If the server allows that sensitive action despite `email_verified` being `false`, that is much stronger evidence of an actual verification-enforcement flaw. Testing whether you can log in using the new email, while a reasonable instinct, does not by itself prove the verification control was bypassed. The senior AppSec mindset is to never stop at "I got HTTP 200," but to ask what security boundary that 200 actually allowed you to cross.

</details>

### Assessment Question 2

You are logged in as the attacker, with `email_verified = false` on your own account. You submit:

```http
POST /api/auth/verify-email
Cookie: session_id=ATTACKER_SESSION

{
  "email": "victim@example.test"
}
```

```http
HTTP/1.1 200 OK

{
  "message": "Email verified successfully"
}
```

What would you test next, and what security property are you trying to prove? And if, more simply, you are logged in as Alice but send a verification request containing Bob's email, and Bob's account becomes `email_verified = true`, what security boundary was broken?

<details markdown="1">
<summary><strong>Reveal Answer</strong></summary>

The application needs to answer "whose email is being verified." A secure application should establish that the email being verified belongs to the currently authenticated user, or that the verification token itself proves ownership of that email. Here, the authenticated user is the attacker, but the email being verified belongs to the victim, those are two different identities, and the request should be rejected on that basis alone.

The test is to check the victim's account state afterward using a separate, controlled account representing the victim, for example `GET /api/users/victim` with the victim's own session, and look for whether `email_verified` became `true` even though the attacker was the one who made the request. If it did, that is a serious account-binding and authorization flaw in the verification flow: Alice should never be able to alter Bob's verification state. The security boundary broken is specifically that the verification action is not properly tied to the authenticated account, it trusts a client-supplied target identity instead of deriving the target from the authenticated session or the token itself.

Having identified that, the strongest immediate proof is simply the fact of cross-account state modification itself, Alice submitted Bob's email, and Bob became verified. You do not necessarily need a further impact test to establish the binding flaw exists. But to establish the full severity, ask what security-sensitive privilege email verification unlocks on this specific application, for example whether `email_verified = true` subsequently permits password reset, sensitive account recovery, changing the email again, enabling payments, or accessing a gated feature. If Alice causing Bob to become verified unlocks one of those privileges for Bob's account in a way that benefits Alice or harms Bob, the impact becomes substantially stronger. The general mental model for any verification flow is a chain of relationships that must each be correctly bound: authenticated identity, verification token or proof, target identity, verification state, and security-sensitive privilege.

</details>

### Assessment Question 3

Alice receives a verification token and clicks it once, resulting in `email_verified = true`. Later, the same token is submitted again, `GET /api/auth/verify?token=VERIFICATION_TOKEN_ABC`, and the server again responds `200 OK` with "Email verified successfully." What would you test next, and what security property are you trying to establish?

<details markdown="1">
<summary><strong>Reveal Answer</strong></summary>

This is verification-token reuse. A verification token should generally be single-use, consumed after successful verification; time-limited, expiring after a reasonable period; bound to the intended account; and unpredictable or cryptographically strong. The specific test is to submit the exact same token again after it has already been successfully used, and determine whether the server accepts it again or correctly rejects it as already used, then separately test it again after its intended expiration period.

One important distinction to hold onto: token reuse and account binding are separate properties that do not automatically imply each other. If Alice uses her own token twice and it is accepted both times, that is token reuse. It only becomes an account-binding problem as well if a different account, for example Bob's, can submit Alice's token and have it affect Bob's account, that is a distinct test requiring a second, separate account. The two flaws can exist together, but proving one does not prove the other. The key security property being established here specifically is that a verification credential must not remain valid after it has fulfilled its intended purpose.

</details>

### Assessment Question 4

A user has `email_verified = false`, requests a verification email, and receives `TOKEN_A`. Before clicking it, they change their email:

```http
POST /api/auth/change-email
Cookie: session_id=ALICE_SESSION

{
  "newEmail": "attacker@example.test"
}
```

```http
HTTP/1.1 200 OK

{
  "message": "Email changed successfully"
}
```

They then use the old token:

```http
GET /api/auth/verify?token=TOKEN_A
```

```http
200 Email verified successfully
```

What relationship would you investigate here? Think specifically about the old verification token, the changed email, and the current account.

<details markdown="1">
<summary><strong>Reveal Answer</strong></summary>

The old token should normally be invalidated when the email changes, because it was issued for the previous email address and verification state, and confirming that is part of the answer, but it is incomplete on its own. The deeper issue is state consistency: what exactly does `TOKEN_A` verify? If it was generated to verify `alice@example.com`, but the account has since been changed to `attacker@example.com`, and the token still succeeds, the application may have a broken relationship running from the verification token, through the email it was generated for, to the account, to the account's current authentication state.

The correct testing sequence is to determine, in order: whether changing the email invalidates the previously issued token at all; if it does not, what email the token actually ends up verifying when used; after using the stale token, which account or email becomes marked as verified; and whether that resulting verified state can unlock a sensitive action. This is best classified as an authentication state-machine flaw, potentially combined with a stale-token invalidation issue or an account-binding failure, depending on exactly which relationship turns out to be broken. As with every other finding in this phase, do not automatically label every stale token a critical vulnerability on its own, the task is to prove specifically what security boundary the stale token actually lets you cross.

</details>

### Assessment Question 5

A bank-like fictional application requires phone verification before enabling withdrawals. Alice requests a code for `+2348011111111` and receives `483921` by SMS. Normal verification using that same phone number and code succeeds. You then discover that submitting a different phone number with the same code also succeeds:

```http
POST /api/phone/verify
Cookie: session_id=ALICE

{
  "phone": "+2348099999999",
  "code": "483921"
}
```

```json
{
  "verified": true
}
```

What is the first thing you would investigate, and what security property are you testing? Don't jump straight to "account takeover."

<details markdown="1">
<summary><strong>Reveal Answer</strong></summary>

The immediate observation is that a code generated for `+2348011111111` was accepted when submitted alongside a completely different number, `+2348099999999`. That means the property under investigation is phone-number-to-verification-code binding, specifically whether the application actually checks that the code presented corresponds to the specific phone number it was generated for, rather than simply checking that the code matches something valid for the authenticated session in general.

A weird or incorrect verification response is not automatically a vulnerability on its own, the next step is to establish what security boundary it actually crosses. After confirming the binding failure, for example by observing that the account now shows `phone_verified = true` for a number that was never actually proven to belong to that session, test a phone-verification-dependent action specifically, such as a withdrawal request or a phone-number change request, whatever operation the application explicitly gates behind phone verification. If the attacker can now perform that operation, which should require proof of control over the specific phone number, you have established real security impact, not merely an unusual response. The precise, specific question a senior AppSec engineer asks here is not "can I make some request I shouldn't be able to," it is "what privilege or security-sensitive operation does successful phone verification unlock, and can I reach it with a code that was never actually bound to my phone number?"

</details>

## Remediation and Secure Implementation

The following consolidates the remediation guidance across all seventeen sections of this phase.

1. Treat registration as proof that someone submitted data, not proof of ownership of any identity attribute in that data, and require actual verification before marking an email or phone number as verified.
2. Enforce token validity, expiration, account binding, purpose, revocation status, and single-use consumption on every verification token, and derive the target account from the validated token itself rather than trusting a client-supplied account ID or email alongside it.
3. Apply layered rate limiting to verification codes across multiple dimensions, per account, per channel, and appropriate network-level controls, rather than relying on any single client-controlled identifier.
4. Use a generic registration response where account enumeration poses meaningful risk, and ensure timing, status codes, response size, and side effects don't quietly leak the same information a generic message tries to hide.
5. Define one documented identity-normalization policy and apply it consistently across registration, login, recovery, email changes, external identity linking, and uniqueness constraints, enforced at the database layer, not only in application code.
6. Require proof of control, not merely a submitted identifier, before granting account recovery, and keep the recovery credential bound to its originally issued account even if the account's other details change during the process.
7. Treat email and phone number changes with the same rigor as a password change: verify the new channel before granting it sensitive privileges, and do not prematurely disable the old channel before the new one is confirmed.
8. Enforce account status, deactivated, deleted, or otherwise restricted, at every point that authorizes access, including session validation, authentication caches, and identifier reuse, not only at the primary user record.
9. Bind private resources and history to a stable internal account identifier, never to a recyclable identifier like an email address or username, so a reassigned or reused identifier cannot inherit a previous owner's data or privileges.
10. Trace every identity relationship, authentication credentials, verified contact methods, recovery mechanisms, external identities, active sessions, and privileges, across the entire account lifecycle whenever one of them changes, rather than updating a single record in isolation.

## Key Takeaways

This phase's governing idea is that an account is not a single row in a database, it is a collection of linked security relationships that must be updated consistently whenever any one of them changes. The most common root cause behind the vulnerabilities in this module is exactly that inconsistency: a phone number changes but the recovery record does not, an account is deactivated but the session store does not know, an email address is reassigned but the application still treats it as proof of ownership of the previous owner's history.

The assessment challenges in this phase sharpen a distinction that recurs throughout: a `200 OK` response, a successful-looking state change, or an unusual verification outcome is evidence worth investigating, never proof of a vulnerability by itself. Email verification bypass testing means proving that a specific security-sensitive privilege became reachable, not just that a request succeeded. Cross-account verification testing means proving that one authenticated identity's request changed a different account's state. Token-reuse testing and account-binding testing are two separate properties that must be tested separately, since one does not imply the other. And every verification mechanism, whether an email token or an SMS code, must be checked for the same underlying property: does the proof actually correspond to the specific account, channel, and purpose it claims to verify, or does the application just assume that it does.

## Review Checklist

- [ ] Can you name the five governing questions for any account lifecycle operation: identity, ownership, state, transition, and revocation?
- [ ] Can you explain why registration proving that someone submitted data is not the same as proving they own every identity attribute in it?
- [ ] Can you distinguish verification-token reuse from verification-token account-binding as two separate, independently testable properties?
- [ ] Can you explain why a single rate-limiting dimension is insufficient to protect a short verification code?
- [ ] Can you explain why account enumeration severity depends on the affected population, not just on the fact of disclosure?
- [ ] Can you identify an inconsistent identity-normalization policy across registration, login, and recovery, and explain the duplicate-account risk it creates?
- [ ] Can you explain why a submitted email or identifier alone is insufficient proof of control for account recovery?
- [ ] Can you list the four specific ways deactivation, deletion, and reactivation can each fail?
- [ ] Can you trace a single account's identity relationship across multiple systems to identify an orphaned or stale record?
- [ ] Can you explain why identity proofing and authentication are separate properties, and name an application mistake that substitutes one for the other?
- [ ] Can you explain, from the assessment, why a stale verification token surviving an email change is a state-machine flaw rather than simply an expiration bug?
- [ ] Can you explain why a verification code accepted for the wrong phone number is a binding flaw, and what test proves its actual security impact?

## References to Related Phases

- Reset-token lifecycle weaknesses referenced throughout sections 3 and 7, including reuse, expiration, and account binding, were covered in depth in **Phase 2, Password Change and Account Recovery**.
- External identity mapping by issuer and subject, referenced in the testing checklist, is the same stable-identity principle introduced for OAuth account linking in **Phase 7, OAuth 2.0 and OpenID Connect Security**.
- MFA factor enrollment and recovery as a parallel identity-relationship concern, referenced implicitly throughout this phase's account-relationship model, was covered in **Phase 4, MFA Enrollment and Recovery Vulnerabilities**.
- Session revocation after deactivation or a sensitive account change, referenced in sections 1, 9, and 10, is covered in full in **Phase 6, Cookie and Session Security**.
- Account lifecycle authorization flaws, referenced in section 13 as overlapping with broken access control, are examined in depth in a later phase, **Authentication-Adjacent Authorization Flaws**.
