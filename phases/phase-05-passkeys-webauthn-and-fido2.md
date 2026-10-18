# Phase 5: Passkeys, WebAuthn, and FIDO2

**Source material:** Module 5 of 17, "Authentication Complete Phases Test.md" (Lessons 5.1 through 5.20, the Module 5 Final Knowledge Summary, and the Progress Tracker). Unlike Phases 1 through 4, "Authentication Security.md" contains no passkey or WebAuthn-specific challenges to draw on for supplementary assessment material, its only related content concerns JWT algorithm confusion, which is a separate, explicitly out-of-scope topic. The Assessment section in this phase is instead built from the module's own embedded exercises, Lesson 5.11's source-code mistake and Lesson 5.20's complete case study, using the module's own given reasoning as the answer.

## Learning Objectives

After completing this phase, you should be able to:

1. Explain why passkeys use a fundamentally different authentication model from passwords and OTPs, and what the private key and public key each do.
2. Explain the role of the cryptographic challenge in a WebAuthn ceremony, and why a signature can be mathematically valid yet unacceptable for the current authentication attempt.
3. Distinguish FIDO2, WebAuthn, and CTAP, and state what each one is actually responsible for.
4. Walk through the full registration and authentication ceremonies step by step, and identify the specific server-side validation each step depends on.
5. Explain precisely why WebAuthn is phishing-resistant, and why that resistance does not mean passkeys eliminate every account-takeover path.
6. Distinguish user presence from user verification, and avoid assuming that every successful WebAuthn authentication satisfies the same assurance level.
7. Explain what a server must check during challenge validation, origin validation, relying-party ID validation, and signature validation, and why none of these four checks substitutes for the others.
8. Explain the account-binding requirement for WebAuthn credentials, and identify the specific risks introduced by discoverable credentials.
9. Explain what attestation does and does not prove, and why its absence is not automatically a vulnerability.
10. Recognize at least five of the seven specific false-positive reporting mistakes this module identifies, and explain why each one is a mistake.
11. Apply a complete registration, authentication, and recovery testing checklist to a WebAuthn implementation, in the same disciplined, impact-focused style used throughout this course.

## Introduction

Every prior phase in this course examined authentication mechanisms built on a secret the user has to submit: a password, a TOTP code, an SMS code, a backup code. Every one of those mechanisms shares a common weakness, the secret is transferable. A password can be typed into a phishing page. A one-time code can be relayed by an adversary in the middle, even while remaining single-use. Passkeys change the underlying model entirely. Instead of proving identity by submitting a reusable secret, the user proves possession of a private key by responding to a cryptographic challenge, and that private key never leaves the authenticator.

This phase studies passkeys, WebAuthn, and FIDO2 with the same discipline applied throughout the course: distinguish a genuine vulnerability from a legitimate design choice, a configuration weakness, or a theoretical concern that has not been demonstrated to be exploitable. Passkeys solve a specific, important problem, phishability, extremely well. They do not solve every authentication problem, and this phase spends as much attention on what can still go wrong, weak enrollment, incomplete server-side validation, and account recovery that undermines the whole mechanism, as it does on explaining how the cryptography works.

## Core Concepts

The module moves through four stages. First, Lessons 5.1 through 5.3 establish the fundamentals: why passkeys exist, how public-key cryptography is used in authentication, and what FIDO2, WebAuthn, and CTAP each actually are. Second, Lessons 5.4 through 5.7 walk through the registration and authentication ceremonies themselves, and explain precisely why the resulting protocol resists phishing. Third, Lessons 5.8 through 5.17 form the core of the security analysis: challenge validation, origin validation, relying-party ID validation, signature validation, credential and account binding, authenticator flags, enrollment and recovery, revocation, synchronized passkeys, and attestation, each examined as a place where an otherwise sound cryptographic protocol can still be implemented insecurely. Fourth, Lessons 5.18 through 5.20 bring the module together into a practical discipline: a complete testing checklist, a catalog of specific reporting mistakes to avoid, and a full case study.

## Lessons

### Lesson 5.1: Why Passkeys Exist

**The problem with passwords.** Passwords have several fundamental weaknesses: they can be guessed, reused across websites, stolen through phishing, exposed in data breaches, cracked offline if an attacker obtains password hashes, and captured by malware. MFA helps, but not all MFA methods are equally resistant to phishing. A manually entered OTP can be relayed in real time. A push notification can be approved accidentally. SMS can be exposed to phone-number takeover. Passkeys use a different authentication model, public-key cryptography. Instead of proving identity by submitting a reusable secret, the user proves possession of a private key by responding to a cryptographic challenge. That difference is fundamental.

**What is a passkey?** A passkey is a passwordless authentication credential based on public-key cryptography. Depending on the implementation and ecosystem, passkeys may be synchronized across a user's devices or bound to a particular device or authenticator. A passkey has two cryptographic components:

| Component | Purpose | Where it belongs |
|---|---|---|
| Private key | Creates a cryptographic signature | Protected by the authenticator |
| Public key | Verifies the signature | Stored by the service |

The service should not need the user's private key to verify authentication. That means a database containing correctly stored public keys does not, by itself, provide an attacker with the private keys needed to impersonate users. This is a major difference from systems that store password verifiers or shared authentication secrets.

A passkey is not simply a password saved in a browser. It uses a different authentication protocol and different trust properties. A password manager may store ordinary passwords, but that does not automatically make those passwords passkeys.

### Lesson 5.2: Public-Key Cryptography in Authentication

Before learning WebAuthn, understand the cryptographic relationship between a key pair. Suppose an authenticator creates a key pair, a private key that remains under the authenticator's control, and a public key that the service stores. During authentication, the service sends a challenge: a value that should be unpredictable and intended for that authentication attempt. The authenticator signs the relevant authentication data with its private key. The service verifies the signature using the registered public key.

```text
                 AUTHENTICATION

Service creates challenge
          |
          v
Authenticator receives challenge
          |
          v
Private key signs authentication data
          |
          v
Service receives signature
          |
          v
Service verifies using public key
          |
          v
Authentication succeeds or fails
```

The service does not need to receive the private key.

**Why does the challenge matter?** Suppose the server accepted a signature without checking that it corresponded to a fresh challenge. An attacker might attempt to reuse previously captured authentication data. A properly implemented challenge-response protocol prevents this by requiring the response to match the current authentication transaction. The challenge should be generated using a cryptographically secure random source, unpredictable, associated with the intended account or authentication ceremony, valid only for the appropriate purpose, and rejected after expiration or consumption, according to the protocol and implementation. A signature can be mathematically valid yet unacceptable for the current authentication attempt. Cryptographic validity and protocol validity are different requirements.

### Lesson 5.3: What Are FIDO2 and WebAuthn?

These terms are related, but they are not interchangeable.

**FIDO2** is an authentication standards framework designed to enable strong, passwordless authentication. Its central components include WebAuthn, a web API through which websites and applications interact with authenticators, and CTAP, a protocol used for communication between a client platform and an external authenticator, such as a security key. The details depend on the platform and authenticator.

**WebAuthn**, Web Authentication, defines how a relying party can register and authenticate public-key credentials through a supported client. A relying party is generally the website or service requesting authentication, for example a website `shop.example` with relying party ID `shop.example`. The exact relationship between the website origin and relying-party ID is governed by WebAuthn's rules. The server creates registration or authentication options, the browser interacts with the authenticator, and the server verifies the resulting response.

**CTAP** supports communication between clients and compatible external authenticators, for example a browser interacting with a hardware security key through a supported connection. You do not need to memorize every transport detail to assess a WebAuthn implementation, but you should understand the separation of responsibilities: the website requests authentication, the browser enforces relevant WebAuthn origin rules, the authenticator performs cryptographic operations, and the server validates the response and its application-specific context. Security depends on the complete system.

### Lesson 5.4: How Passkey Registration Works

Registration establishes a new public-key credential for an account. A typical WebAuthn registration ceremony proceeds as follows.

**Step 1: The server creates registration options.** The server generates a challenge and specifies the relying-party information, user information, supported parameters, and relevant authenticator requirements.

```json
{
  "challenge": "BASE64URL_CHALLENGE",
  "rp": {
    "name": "Example Service",
    "id": "example.com"
  },
  "user": {
    "id": "OPAQUE_USER_IDENTIFIER",
    "name": "alice@example.com",
    "displayName": "Alice"
  },
  "pubKeyCredParams": [
    {
      "type": "public-key",
      "alg": -7
    }
  ]
}
```

This is an illustrative fragment, not a complete WebAuthn request. The challenge and user identifiers are placeholders. The parameters shown represent one supported public-key algorithm, not a complete algorithm policy.

**Step 2: The browser invokes WebAuthn.** The website calls the browser's WebAuthn API, typically through `navigator.credentials.create()`. The browser and authenticator perform the relevant operations.

**Step 3: The authenticator creates a credential.** The authenticator creates the credential's key pair. The public key is included in the registration response. The private key remains under the authenticator's control. The exact protection and synchronization properties depend on the authenticator and platform.

**Step 4: The browser returns the registration result.** The browser returns a credential object containing registration data and an attestation object. The server must validate the response rather than treating the mere existence of a response as proof of successful registration.

**Step 5: The server validates registration.** Depending on the implementation and policy, validation includes checking the challenge, the expected origin, the relying-party ID hash, the ceremony type and required flags, the credential public key, credential identifier consistency, and any attestation requirements the service actually enforces.

**Step 6: The server stores the credential.** After successful validation, the service stores the information needed to recognize and verify the credential later. This normally includes the credential identifier, public key, associated account, and relevant credential metadata. The private key should not be stored by the relying party as part of ordinary WebAuthn registration.

**Registration security principle.** A public key should become trusted for an account only after the application has authorized the enrollment and successfully validated the registration ceremony. An attacker who can register their own credential against someone else's account may obtain persistent access even though the cryptographic protocol works exactly as designed.

### Lesson 5.5: How Passkey Authentication Works

Registration creates a credential. Authentication proves possession of that credential. These are separate ceremonies with different purposes.

**Step 1: The server creates an authentication challenge.** The server generates a fresh challenge and supplies the expected relying-party context and other options.

```json
{
  "challenge": "FRESH_BASE64URL_CHALLENGE",
  "rpId": "example.com",
  "userVerification": "required",
  "timeout": 60000
}
```

This is a simplified example of authentication options. The `userVerification` setting expresses a requested verification policy. It does not mean that the server can ignore the response or assume the authenticator satisfied that policy.

**Step 2: The browser invokes WebAuthn.** The website uses `navigator.credentials.get()` to request authentication. The browser selects or identifies an eligible credential, according to the options and available credentials.

**Step 3: The authenticator creates an assertion.** The authenticator signs the required authentication data with the private key associated with the credential. The response includes data the server needs to validate the assertion.

**Step 4: The server validates the assertion.** The server must verify that the assertion corresponds to the intended authentication attempt. This includes checking the relevant challenge, origin, relying-party context, credential, signature, and required flags. The server must also apply its own account and authentication policy.

**Step 5: The application establishes the correct authentication state.** Only after successful verification should the application grant the authentication privileges associated with the credential. A valid WebAuthn signature does not automatically mean that every account-security requirement has been satisfied. For example, an application may still need to determine which account the credential belongs to, whether the credential has been revoked, whether additional authentication is required, whether the account is disabled, and whether the requested operation requires a higher assurance level.

### Lesson 5.6: Why Passkeys Are Phishing-Resistant

This is one of the most important lessons in the course.

**Passwords and OTPs are transferable.** A password can be entered into a deceptive website. A manually entered OTP can also be submitted to a deceptive website or relayed to a legitimate service. The server may receive a valid password or code without having reliable proof that the user was interacting with the intended website.

**WebAuthn binds authentication to the relying-party context.** WebAuthn uses origin and relying-party information as part of the protocol. During authentication, the browser provides authenticator data that includes a hash of the relying-party ID, and the client data includes the challenge and origin. The server validates these values against what it expects. A credential created for one relying party cannot simply be used by an unrelated phishing origin as though it were a credential for that other relying party. This is a central reason WebAuthn offers phishing resistance.

Suppose a passkey is registered for `example.com`, and a phishing website operates at `example-login.attacker.test`. The phishing site cannot ordinarily obtain a valid assertion for `example.com` merely by asking the victim's browser to authenticate to the phishing origin. The browser and authenticator enforce the applicable relying-party rules. The attacker cannot simply relay a manually entered OTP because WebAuthn is not based on a reusable code that the victim types into an arbitrary website.

**What if a phishing site uses HTTPS?** HTTPS protects the connection to the domain in the address bar. It does not make that domain the legitimate service. WebAuthn's relying-party and origin protections are what help prevent a credential for the legitimate service from being used as if the phishing domain were that service.

**Does phishing resistance mean invulnerability?** No. Passkeys do not eliminate every account-takeover path. Applications may still be vulnerable to unauthorized passkey enrollment, weak account recovery, incorrect server-side assertion validation, insecure session handling after authentication, account-linking errors, weak administrative recovery, compromised user devices, and poor implementation of credential revocation. A passkey protects a particular authentication mechanism. It does not automatically secure the entire account lifecycle.

### Lesson 5.7: User Verification Versus User Presence

These concepts are easy to confuse.

**User presence (UP)** indicates that the authenticator detected the user's participation in the ceremony, according to the authenticator's behavior and the protocol. Examples may include touching a security key or interacting with an authenticator. User presence does not necessarily establish that the user was verified through a PIN or biometric.

**User verification (UV)** indicates that the authenticator performed an appropriate local verification step, where supported and required. Examples include entering an authenticator PIN or providing a biometric verification. The precise behavior depends on the authenticator.

**Why does this distinction matter?** Imagine a service's policy requires user verification for a sensitive operation. If the server accepts an assertion that does not satisfy that requirement, the application may fail to enforce its intended authentication policy. However, whether a particular assertion is acceptable depends on the configured options, the response flags, the authenticator, and the service's requirements. Do not assume that every successful WebAuthn authentication must have both flags set in the same way. A correct assessment compares the actual response with the policy the service intended to enforce.

### Lesson 5.8: WebAuthn Challenge Validation

A WebAuthn challenge helps bind an assertion to a particular authentication ceremony. If challenge validation is incorrect, the application may fail to establish that the response belongs to the current request.

**What should be checked?** The server should ensure that the challenge was generated by the server using an appropriate secure random source, the challenge corresponds to the current ceremony, the response contains the expected challenge, the challenge has not expired, the challenge is associated with the correct purpose, and the response is rejected if it does not satisfy the application's challenge policy. Registration and authentication challenges should not be casually interchangeable. A challenge intended for registration should not be accepted as proof of a separate authentication ceremony.

**A conceptual implementation mistake.** Suppose the server stores a challenge when a login begins but validates only the signature later. A valid signature alone is not enough. The server must verify that the signed data corresponds to the current expected challenge and that the rest of the assertion is valid.

**Challenge lifetime and reuse.** Challenges should not remain valid indefinitely. The application should expire or consume them according to its design. A stale challenge may create opportunities for replay or confusion between authentication transactions if the surrounding validation is inadequate. However, merely finding a challenge record in storage does not prove a vulnerability. The question is whether the application can accept an assertion that should no longer be valid.

**Testing methodology.** In an authorized test environment: initiate a WebAuthn authentication ceremony, record the expected challenge in a safe test harness, complete the ceremony normally and confirm success, examine how the application handles a response associated with an incorrect or expired challenge, confirm whether the server rejects the invalid response, and inspect the relevant server-side validation logic. Do not assume a challenge is accepted merely because the endpoint returns a generic response. Establish the actual authentication outcome.

### Lesson 5.9: Origin Validation

Origin validation is a fundamental part of WebAuthn security. An origin generally identifies a web origin using its scheme, host, and port. For example, `https://example.com` is a different origin from `http://example.com` and from `https://login.example.com`. Origin validation helps the server determine whether the browser response came from the expected web context.

**What can go wrong?** A server might fail to check the origin, accept origins that should not be trusted, use an overly broad origin allowlist, trust an attacker-controlled domain, confuse development and production origins, or validate a different origin than the one associated with the authentication transaction. These are potential implementation flaws.

**Why broad allowlists can be dangerous.** Suppose a service trusts `*.example.com`. The security implications depend on how the wildcard is implemented and which subdomains it covers. If an attacker can control or compromise a subdomain that falls within the accepted trust boundary, the service may be trusting a less secure origin than intended. However, a wildcard is not automatically exploitable. The assessment must establish what the matching rule actually accepts and whether an attacker can control an accepted origin.

**Correct validation.** A secure implementation should validate the received origin against the exact expected origin or a carefully defined allowlist. The allowed origins should correspond to domains the organization intentionally trusts for that application. Avoid blindly trusting an origin supplied by the request itself, the server needs an independently defined expectation. The browser enforces important WebAuthn rules, but the relying party must still correctly validate the returned data. Security cannot depend on blindly trusting a JSON object merely because it was produced by a browser API.

### Lesson 5.10: Relying-Party ID Validation

The relying-party ID, often abbreviated RP ID, defines the WebAuthn relying-party scope for a credential. For example, a service may use `example.com` as its RP ID for an appropriate HTTPS origin. The RP ID is not simply an arbitrary string chosen independently of the website's origin. WebAuthn imposes rules on the relationship between the origin and RP ID.

**Why does it matter?** The RP ID helps scope credentials to the intended service. During authentication, the authenticator data contains a hash of the RP ID. The server validates that value against the expected RP ID. If the server accepts an unexpected RP ID hash, it may undermine the credential's intended relying-party binding.

**Common implementation questions.** Is the expected RP ID configured correctly? Does the server validate the RP ID hash? Is the RP ID consistent across registration and authentication? Are multiple subdomains intentionally part of the same relying-party scope? Are development and production environments separated appropriately? Does the server derive the expected value from trusted configuration rather than blindly accepting client input? The correct RP ID may be a parent domain in some legitimate configurations, so do not treat every difference between a hostname and RP ID as a vulnerability.

### Lesson 5.11: Signature Validation

A WebAuthn authentication assertion includes a signature that the server verifies using the public key registered for the credential. Signature validation is essential, but it is only one part of the complete verification process.

**What must the server establish?** The server should determine that the credential is registered, the credential belongs to the account or login context being authenticated, the signature verifies using the stored public key, the signed data is the data expected by the WebAuthn protocol, the challenge is correct, the origin and RP ID context are correct, required flags and policy conditions are satisfied, and the credential has not been revoked. The exact validation details depend on whether the operation is registration or authentication.

**A dangerous conceptual mistake.** Consider this simplified function:

```python
async def authenticate_with_passkey(credential_id, signature):
    credential = await find_credential(credential_id)

    if credential is None:
        raise Unauthorized()

    if verify_signature(credential.public_key, signature):
        return create_session(credential.user_id)
```

This is incomplete as a WebAuthn implementation. The function does not visibly validate the challenge, origin, RP ID hash, required authenticator flags, or other protocol requirements. It also hides what data is actually signed. A real implementation must validate the complete WebAuthn assertion, not merely verify an isolated signature. In a real application, the omitted checks might be implemented in a dedicated WebAuthn library or an earlier validation layer. A reviewer must inspect the complete call path before concluding that the vulnerability exists.

**Prefer established WebAuthn libraries.** WebAuthn verification is sufficiently complex that implementing it from scratch creates unnecessary risk. Use a well-maintained library that supports the relevant WebAuthn specification and correctly validates the ceremony. Then verify that the application configures and invokes it correctly. Using a library does not guarantee security if the application ignores validation errors or supplies the wrong expected origin, challenge, or RP ID.

### Lesson 5.12: Credential Identifiers and Account Binding

A WebAuthn credential has an identifier that allows the service to recognize it. The server associates that credential with an account. That association is security-sensitive.

**The account-binding requirement.** A credential registered to Alice's account must not automatically authenticate Bob. The application must verify that the credential is associated with the account or authentication context being authenticated.

**Discoverable credentials.** Some passkeys support discoverable credentials, allowing the authenticator to identify an eligible credential without the user first providing an account identifier. In such flows, the server must identify the credential correctly and associate it with the correct account. The presence of a user handle or credential identifier does not eliminate the need for server-side validation.

**Potential weaknesses.** Investigate whether the credential lookup can return a credential belonging to the wrong account, credential identifiers are treated as proof of identity without signature verification, the account association is changed without authorization, the same credential is improperly linked to multiple accounts, a revoked credential remains accepted, or account discovery reveals unnecessary private information. Some applications legitimately support multiple credentials per account, and discoverable credentials may be used for passwordless login. Those features are not inherently vulnerabilities. The question is whether the association and authentication rules are correctly enforced.

### Lesson 5.13: Authenticator Flags and Policy Enforcement

WebAuthn authenticator data contains flags that communicate properties of the ceremony. Two particularly important flags are UP, user presence, and UV, user verification. Other data may also be relevant, including backup-related flags for supported credential types.

**Why flags matter.** Suppose the service's policy requires user verification for a particular authentication operation. The service must not simply assume that verification occurred because the signature is valid. It should inspect the appropriate response data and enforce its requirements.

**A common mistake.** An application requests a particular authentication policy from the browser but never checks whether the returned assertion satisfies the relevant server-side requirement. The configuration alone does not establish that the policy was met. The application needs to validate the response and apply the correct decision.

**Avoid overgeneralization.** Not every service must require the same flags in every context. Some authentication flows may permit user presence without local user verification, while others require stronger verification. The correct test is whether the server enforces the assurance level its policy requires, not whether all possible WebAuthn flags are set in every successful response.

### Lesson 5.14: Passkey Enrollment and Account Recovery

Passkeys can provide strong phishing resistance, but the application must protect the process that adds new credentials. Suppose an attacker cannot authenticate with the victim's existing passkey. However, the application allows passkey enrollment after a weak recovery process. The attacker might use recovery to add a new credential under their control. The passkey's cryptography may be entirely correct, the weakness lies in the application's enrollment and recovery controls.

**What should a secure design consider?** Authorization to add a new passkey, verification of the intended account, recent authentication or a sufficiently secure recovery process, a properly validated registration ceremony, clear distinction between pending and active credentials, notification of new credential enrollment, revocation of credentials that are no longer trusted, and a recovery process that does not silently undermine the required assurance. These requirements connect directly to the MFA enrollment and recovery weaknesses covered in Phase 4.

The key lesson: phishing-resistant authentication cannot compensate for an account-recovery process that allows an attacker to register their own credential.

### Lesson 5.15: Passkey Revocation and Credential Lifecycle

A passkey can become untrusted for several reasons: the user loses the device, a device is stolen, an authenticator is compromised, the user removes the credential, an administrator revokes access, or the account is disabled. The service needs a reliable way to stop accepting a revoked credential.

**What to investigate.** Does credential removal take effect immediately or according to a defined policy? Does the server reject assertions from revoked credentials? Can a user remove another user's credential? Are credential changes audited? Are users notified of significant changes? Does account recovery handle lost authenticators securely? Are credential records associated with the correct account?

A credential that has been removed from the account's trusted credential list should not continue to authorize authentication merely because the authenticator can still produce a valid signature. The server's trust decision matters.

### Lesson 5.16: Backup-Eligible and Synchronized Passkeys

Not every passkey has identical storage or synchronization properties. Some authenticators can create credentials that are eligible for backup or synchronization. Others create device-bound credentials. The WebAuthn backup-related flags can communicate relevant properties.

**Why does this matter?** A device-bound credential may be difficult to recover if the device is lost. A synchronized passkey may offer better recovery and usability, but its security also depends on the platform's credential synchronization and account-security mechanisms. Neither category should automatically be described as insecure. The appropriate choice depends on the threat model, user needs, and the security requirements of the application.

**What should a security engineer evaluate?** Which authenticator types the application supports, whether the service has a requirement for local user verification, whether credential backup or synchronization affects its policy, whether the application relies on attestation or authenticator characteristics, whether those requirements are actually enforced, and whether the recovery process matches the expected security level. Do not assume that every synchronized passkey is compromised or that every device-bound key is automatically more secure in every scenario.

### Lesson 5.17: Attestation, What It Does and Does Not Prove

Attestation can provide information about the authenticator used during credential registration. Depending on the attestation format and configuration, it may help the relying party establish properties of the authenticator or its provenance. However, attestation is not required in every WebAuthn deployment. Many consumer passkey deployments deliberately use privacy-preserving configurations that do not identify a specific authenticator model to the relying party.

**Common misconception.** "If a website does not require attestation, its WebAuthn implementation is insecure." That conclusion is incorrect. Attestation is a policy choice with trade-offs involving assurance, privacy, compatibility, and operational requirements. A service may legitimately accept credentials without identifying the precise authenticator model.

**When should attestation matter?** It may matter when an organization has a specific requirement to restrict enrollment to particular authenticator classes or to obtain additional information about authenticator provenance. In that case, the server must validate and enforce the relevant attestation policy correctly. The absence of attestation is not automatically a vulnerability. The issue is whether the implementation meets its stated security requirements.

### Lesson 5.18: Testing a WebAuthn Implementation

A bug hunter should evaluate the registration and authentication ceremonies separately.

**Registration checklist.** Examine whether the application authorizes enrollment for the correct account, generates an unpredictable challenge, validates the expected challenge, validates the origin, validates the RP ID hash, verifies the registration response using an appropriate WebAuthn implementation, associates the credential with the correct account, stores the public key and credential metadata appropriately, prevents unverified credentials from becoming trusted, and applies its intended authenticator and attestation policy.

**Authentication checklist.** Examine whether the application generates a fresh challenge, uses the expected RP ID, looks up the correct registered credential, verifies the signature using the stored public key, checks the challenge and ceremony context, validates the expected origin, validates the RP ID hash, enforces required authenticator flags, rejects revoked or unknown credentials, and establishes the appropriate authentication state only after successful verification.

**Recovery checklist.** Examine whether new passkeys can be enrolled without adequate authorization, recovery bypasses the expected account-security requirements, lost credentials can be revoked, factor replacement is auditable, users are notified of important changes, and account ownership and credential ownership remain consistent.

### Lesson 5.19: False Positives and Reporting Mistakes

Experienced security engineers do not report every unusual implementation detail as a vulnerability.

**Mistake 1: "The public key is exposed."** The public key is intended to be available to the relying party. Its presence in the database is normal. The private key is the sensitive credential material.

**Mistake 2: "The application does not require attestation."** That is not automatically a vulnerability. Determine whether the service has a justified policy requiring attestation.

**Mistake 3: "The RP ID differs from the exact hostname."** A legitimate RP ID may cover an appropriate parent domain. Verify the applicable WebAuthn rules and the service's intended scope before reporting.

**Mistake 4: "The browser accepted the credential."** Browser-side success does not prove that the server correctly validated the complete registration or authentication response.

**Mistake 5: "The application uses passkeys, so it is phishing-proof."** Passkeys are designed to resist phishing, but account recovery, credential enrollment, session handling, and implementation errors can still undermine account security.

**Mistake 6: "The challenge is visible."** A challenge is not necessarily secret in the same way a private key is secret. The relevant questions are whether it is unpredictable, bound to the intended ceremony, and validated correctly.

**Mistake 7: "The credential is synchronized."** Synchronization is not automatically a vulnerability. Evaluate the authenticator's actual security properties and the service's requirements.

### Lesson 5.20: Complete Case Study

**Scenario: a fictional cloud-storage service.** The service supports passkeys. During a source-code review, you find this simplified authentication function:

```python
async def login_with_passkey(credential_id, signature):
    credential = await find_credential(credential_id)

    if credential is None:
        raise Unauthorized()

    if verify_signature(
        credential.public_key,
        signature
    ):
        return create_authenticated_session(
            credential.user_id
        )

    raise Unauthorized()
```

**Step 1: Identify what the code establishes.** The function looks up a credential, obtains its public key, attempts to verify a signature, and creates a session if verification succeeds. Those operations may be part of a legitimate implementation.

**Step 2: Identify what is missing from the visible code.** The function does not show challenge validation, origin validation, RP ID hash validation, authenticator flag validation, complete WebAuthn response validation, or credential revocation checks.

**Step 3: Avoid premature conclusions.** The code may be calling a signature-verification function that validates only a signature. Alternatively, the snippet may omit validation performed by a surrounding library. You cannot determine which is true from this function alone.

**Step 4: Inspect the complete call path.** Trace the request from the HTTP handler to the WebAuthn library and back. Determine whether the full assertion is validated against the expected challenge, origin, RP ID, credential, and policy.

**Step 5: Establish impact.** If the server genuinely accepts assertions without validating essential WebAuthn properties, investigate whether an attacker can use that flaw to authenticate as another user. Do not claim an account-takeover vulnerability based solely on a truncated code fragment.

**Step 6: Recommend remediation.** Use a maintained WebAuthn implementation and ensure the application correctly configures expected values and enforces all required validation outcomes. Then test registration, authentication, revocation, and recovery as separate security boundaries.

## Assessment

Unlike Phases 1 through 4, this phase has no separate instructor-graded challenge transcript to draw an assessment from. The two exercises below are instead drawn directly from the module's own embedded material, Lesson 5.11's source-code mistake and Lesson 5.20's complete case study, using the module's own given reasoning as the answer.

### Assessment Question 1

A WebAuthn authentication function is implemented as follows:

```python
async def authenticate_with_passkey(credential_id, signature):
    credential = await find_credential(credential_id)

    if credential is None:
        raise Unauthorized()

    if verify_signature(credential.public_key, signature):
        return create_session(credential.user_id)
```

Is this a complete and acceptable WebAuthn authentication implementation? Identify specifically what is missing, and explain why finding this code alone is not sufficient evidence of a vulnerability.

**Answer**

No, this is incomplete as a WebAuthn implementation. The function does not visibly validate the challenge, the origin, the relying-party ID hash, required authenticator flags, or other protocol requirements, and it hides what data is actually signed. A real implementation must validate the complete WebAuthn assertion, not merely verify an isolated signature, because signature validation is only one of several required checks; the server must also establish that the credential is registered, that it belongs to the account or login context being authenticated, that the challenge and ceremony context are correct, that the origin and relying-party ID context are correct, that required flags and policy conditions are satisfied, and that the credential has not been revoked.

However, finding this function alone does not prove a vulnerability exists. In a real application, the omitted checks might be implemented in a dedicated WebAuthn library or an earlier validation layer that this particular snippet simply does not show. A reviewer must inspect the complete call path, from the HTTP handler through the WebAuthn library and back, before concluding that the application genuinely accepts assertions without validating these properties. Prefer using an established, well-maintained WebAuthn library rather than implementing verification from scratch, since the protocol is sufficiently complex that a custom implementation creates unnecessary risk. Using a library does not guarantee security on its own if the application ignores its validation errors or supplies the wrong expected origin, challenge, or relying-party ID.

### Assessment Question 2

Continuing the same scenario in a fictional cloud-storage service: you have confirmed, by tracing the complete call path, that the server genuinely does not validate the challenge, origin, relying-party ID hash, or authenticator flags, and accepts any correctly signed assertion from a known credential. What is the resulting impact, and what would a complete remediation recommendation include?

**Answer**

The impact depends on what the missing validation actually allows an attacker to do, and this must be established rather than assumed. If the server accepts assertions without validating essential WebAuthn properties, investigate specifically whether an attacker can use that flaw to authenticate as another user, for example by replaying a previously captured, mathematically valid signature outside its intended ceremony, or by exploiting the absence of origin and relying-party checks to accept an assertion that should have been scoped to a different context. Do not claim an account-takeover vulnerability based solely on a truncated code fragment; the claim must be backed by a demonstrated authentication bypass against a controlled test credential.

A complete remediation recommendation is to replace the custom verification logic with a maintained WebAuthn implementation, and to ensure the application correctly configures the expected origin, relying-party ID, and challenge values and enforces every required validation outcome rather than treating a successful signature check as sufficient on its own. Beyond the immediate fix, registration, authentication, revocation, and recovery should each be tested as separate security boundaries, since a correct authentication ceremony does not imply that enrollment, credential revocation, or account recovery are equally well protected.

## Remediation and Secure Implementation

The following consolidates the remediation guidance across all twenty lessons in this phase.

1. Validate the complete WebAuthn assertion on every registration and authentication ceremony: the challenge, the origin, the relying-party ID hash, the signature against the stored public key, required authenticator flags, and credential revocation status. No single one of these checks substitutes for the others.
2. Generate every challenge using a cryptographically secure random source, bind it to the specific ceremony and purpose it was issued for, and reject any response that does not contain the expected, unexpired challenge.
3. Validate the received origin against an exact expected origin or a carefully and narrowly defined allowlist that corresponds only to domains the organization intentionally trusts, never by blindly trusting a value the request itself supplies.
4. Derive the expected relying-party ID from trusted server-side configuration, keep it consistent across registration and authentication, and validate the relying-party ID hash on every ceremony.
5. Prefer an established, well-maintained WebAuthn library over a custom implementation, and verify that the application actually enforces the library's validation results rather than ignoring errors or supplying incorrect expected values.
6. Enforce the specific authenticator flags, such as user verification, that the service's own policy requires for a given operation, rather than assuming a valid signature implies every intended assurance level was met.
7. Treat passkey enrollment, replacement, and recovery with the same authorization rigor required for MFA enrollment and recovery in Phase 4: require recent authentication or a sufficiently secure recovery process, verify the registration ceremony fully, and distinguish pending credentials from active, trusted ones.
8. Build a reliable, immediate path to reject assertions from a revoked credential, and ensure credential records are correctly associated with their owning account so a removed or compromised credential cannot continue to authenticate.
9. Set attestation policy deliberately based on the organization's actual requirements, rather than treating its presence or absence as an automatic indicator of security, and if attestation is required, validate and enforce that policy correctly.
10. Apply the registration, authentication, and recovery testing checklists from Lesson 5.18 as three separate security boundaries, since a well-implemented authentication ceremony does not guarantee that enrollment or recovery are equally well protected.

## Key Takeaways

Passkeys solve a specific, well-defined problem extremely well: they remove the transferable secret that makes passwords and manually entered OTPs phishable, by binding authentication to a relying-party and origin context that the browser and authenticator enforce on the protocol's behalf. That is a genuine and significant security improvement, and it is the central reason this phase exists.

But passkeys protect a particular authentication mechanism, they do not automatically secure the entire account lifecycle. Every lesson on enrollment, recovery, revocation, and server-side validation in this phase exists because the cryptography can be flawless while the surrounding application logic still fails. An attacker who cannot defeat a victim's passkey directly may still succeed by registering their own credential through a weak enrollment path, by exploiting a recovery process that does not require sufficient proof of authority, or by relying on a server that checks the signature but skips the challenge, origin, and relying-party ID validation that give WebAuthn its phishing resistance in the first place.

Lesson 5.19's seven reporting mistakes capture the discipline this phase asks you to carry forward: do not treat an exposed public key, a missing attestation requirement, an RP ID that covers a parent domain, browser-side success, the mere use of passkeys, a visible challenge, or credential synchronization as an automatic vulnerability. In every case, the question is whether the implementation meets the security requirements it was actually designed to satisfy, not whether it differs from an unexamined assumption about how WebAuthn should look.

## Review Checklist

- [ ] Can you explain why a database of public keys does not, by itself, give an attacker what they need to impersonate users?
- [ ] Can you explain why a signature can be mathematically valid yet still be rejected by a correct WebAuthn implementation?
- [ ] Can you state what FIDO2, WebAuthn, and CTAP are each actually responsible for?
- [ ] Can you walk through the five steps of a WebAuthn authentication ceremony and name the validation each step depends on?
- [ ] Can you explain, in your own words, why a credential registered for one relying party cannot be used by an unrelated phishing origin?
- [ ] Can you distinguish user presence from user verification, and explain why a correct assessment compares the actual response against the service's intended policy rather than assuming a fixed flag combination?
- [ ] Can you identify, from a source code snippet, whether challenge, origin, relying-party ID, and signature validation are all actually being enforced?
- [ ] Can you explain why discoverable credentials still require server-side account-binding validation?
- [ ] Can you explain why the absence of attestation is not automatically a vulnerability?
- [ ] Can you list at least five of the seven false-positive reporting mistakes from Lesson 5.19, and explain why each one is a mistake?
- [ ] Can you explain why a well-implemented passkey authentication ceremony does not, by itself, prove that enrollment and recovery are equally secure?

## References to Related Phases

- The underlying principle that phishing-resistant authentication cannot compensate for a weak enrollment or recovery process, stated directly in Lesson 5.14, connects back to **Phase 4, MFA Enrollment and Recovery Vulnerabilities**, and to the recovery-path principle first introduced in **Phase 1, Password Storage and Credential Attacks** and **Phase 2, Password Change and Account Recovery**.
- Establishing the correct authentication state only after successful verification, referenced in Lesson 5.5, connects to the authentication-state enforcement discipline covered in **Phase 3, Multifactor Authentication (MFA) Attacks**.
- Session handling after a successful passkey authentication, referenced in Lesson 5.6's list of remaining account-takeover paths, is covered in full in **Phase 6, Cookie and Session Security**.
- Requiring a higher assurance level for specific sensitive operations, referenced in Lesson 5.5, is covered in full in a later phase, **Reauthentication and Step-Up Authentication**.
