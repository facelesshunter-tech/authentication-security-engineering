# Phase 16: Authentication Cryptographic Failures

**Source material:** Module 16 of 17, "Authentication Complete Phases Test.md" (17 numbered sections covering authentication cryptographic failures, and the course tracker), with supplementary assessment material drawn from "Authentication Security.md" (Challenge 23 and Challenge 24). Both source files independently scope out deep JWT internals: the module explicitly states that deep JWT attack techniques remain outside it, and the supplementary file's own instructor pauses JWT at exactly this point, "we'll treat JWT as its own dedicated vulnerability class later." The two challenges used here fall before that pause and illustrate the same general algorithm-confusion principle the module itself teaches, not deep JWT territory.

## Learning Objectives

After completing this phase, you should be able to:

1. Distinguish confidentiality, integrity, authenticity, and unpredictability as four separate cryptographic properties, and explain why providing one does not automatically provide the others.
2. Distinguish ordinary pseudorandomness from cryptographically secure randomness, and identify an unsuitable random source in source code.
3. Explain entropy as a property of the generation process, not of a token's length or appearance, and identify weak-seeding and time-based token generation as specific failure patterns.
4. List the seven properties a secure authentication token lifecycle requires: unpredictability, account binding, purpose binding, expiration, single use, revocation, and transaction consistency.
5. Explain why storing a hash of a high-entropy random token differs fundamentally from hashing a human-chosen password, and when constant-time comparison actually matters.
6. Distinguish hashing from encryption for password storage, and trace a legacy password-hash migration strategy.
7. Identify weak cryptographic primitives and incorrect usage modes, MD5/SHA-1 collision risk, AES-ECB pattern leakage, and encryption without integrity, and explain why authenticated encryption is not automatically foolproof.
8. Distinguish nonces, IVs, salts, authentication challenges, and session IDs by their actual security requirements, and explain the specific danger of nonce reuse in AES-GCM.
9. Explain HMACs and digital signatures as trust mechanisms, and list the verification steps a digital signature alone does not satisfy.
10. Explain algorithm confusion as a verification-policy failure, distinguish decoding from verification, and trace the correct order of operations before an application trusts a signed message's claims.
11. Apply the module's 6-step cryptographic assessment methodology, protected asset, required property, full lifecycle, attacker control, trust boundary, and demonstrated consequence, to a real finding.
12. Apply the Phase 1 through Phase 15 impact-validation discipline to cryptographic findings: distinguish an algorithm's name from its actual role, and avoid the module's nine specific false positives.

## Introduction

Every earlier phase in this course examined authentication failures that are visible in behavior: a missing check, a trusted claim, a session that should have been revoked. This phase studies failures that hide inside the cryptography an application is already using, the password hashing, the reset tokens, the signed assertions, the TLS connection, precisely because those mechanisms look secure on the surface. The module's own first principle states the governing idea directly: cryptography is not one security property. An application can use encryption, hashing, signatures, and HTTPS, and still fail, because the specific property each mechanism provides is not the property the application actually needed.

This phase carries forward the same evidentiary discipline established in every earlier phase, applied specifically to cryptographic claims. A beginner who finds `sha256(timestamp)` reports "SHA-256 is insecure." A senior reviewer recognizes that SHA-256 is a legitimate hash function, that the actual defect is a predictable input, and that the real question is whether the server accepts a reconstructed token and what that token authorizes. The module's closing lesson states this precisely: the core skill is not recognizing cryptographic names, it is tracing how cryptographic operations influence authentication decisions and proving when a failure changes the security outcome.

## Core Concepts

The module moves through five stages. First, sections 1 and 2 establish the foundation: the four cryptographic properties and why they are not interchangeable, and cryptographically secure randomness as one of the most important topics in the module. Second, sections 3 and 4 build out the full token lifecycle and password-storage cryptography specifically. Third, sections 5 through 10 examine weak primitives, non-interchangeable cryptographic values, HMACs and signatures, algorithm confusion, TLS in transit, and key management, each as a distinct way a cryptographically sound building block can still be misused. Fourth, sections 11 through 13 build the practical discipline through a complete code-review case study and a 6-step assessment methodology. Fifth, sections 14 through 17 close the module with nine false positives, a remediation-priority table, a full senior review checklist, and the final comparison between a beginner's and a senior reviewer's diagnosis.

## Lessons

### 1. First Principle: Cryptography Is Not One Security Property

Before examining vulnerabilities, understand what cryptography is supposed to accomplish. There are four major security properties to distinguish.

| Property | What it provides | Authentication example |
|---|---|---|
| Confidentiality | Keeps information secret | Encrypting a stored credential that must later be recovered |
| Integrity | Detects unauthorized modification | Detecting changes to protected authentication data |
| Authenticity | Establishes that data came from a trusted source | Verifying an identity provider's signed assertion |
| Unpredictability | Makes a secret value difficult to guess | Generating a password-reset token |

These properties are related, but one does not automatically provide the others.

**Example 1: encryption without authenticity.** Suppose an application encrypts a value before storing it, `ciphertext = encrypt(user_id)`. The developer assumes that because the value is encrypted, an attacker cannot manipulate it. That conclusion is not necessarily valid. Some encryption constructions protect confidentiality without reliably detecting modification. Depending on the scheme and how the application processes decrypted values, modification may produce dangerous behavior. For sensitive data, use a vetted authenticated-encryption construction, such as AES-GCM or ChaCha20-Poly1305, implemented through a maintained cryptographic library. Correct implementation also requires respecting the algorithm's requirements, including nonce handling and authentication-tag verification.

**Example 2: integrity without secrecy.** Consider a message protected with a message authentication code, or MAC. A MAC can allow a recipient with the appropriate secret key to detect whether a message has been altered. However, the message itself may remain readable. A MAC does not automatically encrypt the message.

**Example 3: a secure hash is not a secure password-storage scheme.** Consider `password_hash = sha256(password)`. SHA-256 is a legitimate cryptographic hash function. The problem is not that SHA-256 is universally broken. The problem is that it is designed to calculate hashes efficiently. If a password database is stolen, an attacker can test guesses against those hashes at very high speed. Password storage requires a purpose-built, adaptive password-hashing function.

Senior-engineer principle: never conclude that an application is secure merely because it uses encryption, hashing, signatures, or tokens. Identify the exact security property required, then verify that the implementation actually provides it.

### 2. Cryptographically Secure Randomness

This is one of the most important topics in authentication security. Applications generate random-looking values for password-reset links, email-verification tokens, session identifiers, MFA recovery codes, passwordless login challenges, OAuth `state` values, OIDC `nonce` values, SAML request identifiers, and temporary authentication challenges. If these values are predictable, an attacker may be able to anticipate or reproduce a value that grants access or validates an authentication transaction. However, the impact depends on what the value authorizes and how the server validates it.

**2.1 Ordinary pseudorandomness versus cryptographic randomness.** Applications commonly use pseudorandom number generators. A conventional PRNG produces a sequence based on an internal state. Given sufficient information about that state or its output, some generators permit future or previous outputs to be predicted. This is acceptable for many ordinary programming tasks, randomizing a game, shuffling a display, generating sample data, selecting a non-security-sensitive animation. It is not appropriate for generating authentication secrets. A cryptographically secure pseudorandom number generator, or CSPRNG, is designed to make its output computationally unpredictable under its security assumptions.

Vulnerable example:

```javascript
const token = Math.random()
  .toString(36)
  .slice(2);
```

This is unsuitable for security-sensitive token generation. There are two separate concerns: `Math.random()` is not intended to provide cryptographically secure randomness, and the string conversion and truncation make the output length and security properties unsuitable to assume without further analysis. A token that looks complicated is not necessarily unpredictable.

Safer conceptual example:

```javascript
import { randomBytes } from "node:crypto";

const token = randomBytes(32).toString("hex");
```

This uses Node.js's cryptographic random-byte generator. The generated value contains 32 random bytes before encoding. When those bytes have 256 bits of cryptographic entropy, the hexadecimal representation contains 64 characters, each byte represented by two hexadecimal characters. The important property is the underlying random-byte source, not the fact that the result looks long.

**2.2 What is entropy?** Entropy is a way of describing uncertainty. For a uniformly generated secret with n independent random bits, there are `2^n` possible values.

| Random bits | Number of possible values |
|---:|---:|
| 32 | 2^32 |
| 64 | 2^64 |
| 128 | 2^128 |
| 256 | 2^256 |

For a uniformly random 128-bit value, an attacker making one independent guess has a probability of `1 / 2^128` of guessing it correctly. This calculation assumes the value is genuinely uniform, the attacker has no additional information, and the server accepts that value. It is not a guarantee that every 128-bit token implementation is secure. A developer might generate a 128-bit-looking token using a weak generator, a timestamp, or a predictable account identifier. The output's appearance does not prove it contains 128 bits of entropy. Token length is not token entropy.

*Encoding does not create entropy.* Suppose an application generates 16 random bytes, providing at most 128 bits of entropy. Converting the bytes into 32 hexadecimal characters does not create additional entropy, it merely changes their representation. Likewise, Base64 encoding does not increase the underlying uncertainty. A long token generated from a timestamp and a sequential database ID may have far less entropy than its length suggests.

**2.3 Weak seeding.** Some developers attempt to generate random tokens by combining predictable information, `token = hash(str(current_time) + str(user_id))`. This is not a secure token-generation design. The timestamp may be approximately known, the user ID may be known or discoverable, the possible inputs may be small enough to enumerate, and a cryptographic hash does not turn predictable inputs into unpredictable secrets. A secure hash function can protect certain properties of its input, but it cannot manufacture substantial secret entropy from public or predictable data. A cryptographic hash is not a substitute for a CSPRNG.

**2.4 Time-based values.** Consider `token = str(int(time.time()))`. This produces a value related to the current time and is not suitable as a password-reset token. If the creation time is known or can be estimated, the possible values may be highly constrained. Making the value look more complicated by hashing it, `token = sha256(str(int(time.time())).encode()).hexdigest()`, remains unsafe as a general token-generation method. Hashing a predictable timestamp does not make the timestamp unpredictable. The same principle applies to sequential IDs, usernames, email addresses, birth dates, public account identifiers, process identifiers, counters, and predictable combinations of these values. These values can be useful as identifiers. They should not serve as authentication secrets.

**2.5 UUIDs: an important distinction.** Not all UUIDs have the same security properties. A UUID may be designed primarily for uniqueness rather than secrecy. UUIDv1 incorporates time-related information and a node identifier, it should not be assumed to be an unpredictable authentication secret. UUIDv4 is designed around random data, but its security depends on the implementation and random source. A UUID can be an excellent identifier, some UUID versions may be appropriate for particular security uses when generated correctly, but the label "UUID" alone does not establish that a value is a secure bearer token. For authentication secrets, use a documented cryptographic random API and generate sufficient random material for the intended purpose.

**2.6 Where weak randomness creates authentication vulnerabilities.** Consider a password-reset flow. The application generates a reset token and emails a link to the account owner. The server later accepts that token as proof that the requester possesses the reset link. The token is therefore an authentication credential, even if it is temporary. If an attacker can predict the token, the attacker may be able to reset another user's password without controlling the victim's email account. But the complete vulnerability depends on several conditions: the token is generated predictably, the attacker can estimate or reconstruct valid tokens, the application accepts the predicted value, the token is bound to the victim's account, and no other required verification prevents the unauthorized reset. Weak randomness is the cryptographic defect. Unauthorized password reset is the potential security impact. These are related but distinct findings.

| Token | Potential consequence if predictable |
|---|---|
| Session identifier | Session impersonation, if the predicted ID is accepted |
| Password-reset token | Unauthorized password change |
| Email-verification token | Unauthorized verification or account-state changes |
| MFA recovery code | Bypass of the intended recovery proof |
| OAuth `state` | Authentication transaction confusion or request forgery, depending on the implementation |
| OIDC `nonce` | Failure to bind an identity response to the intended authentication transaction |
| WebAuthn challenge | Weakened transaction freshness or replay resistance if other checks also fail |
| SAML request ID | Weakened request correlation or replay protection if protocol validation is defective |

A weak random value does not automatically produce a complete authentication bypass. You must establish how the application uses and validates it.

### 3. Token Design: Randomness Is Only the Beginning

Even a perfectly unpredictable token can be implemented insecurely. A secure authentication token needs a correct lifecycle. For a password-reset token, review seven properties: unpredictability, generated using a suitable cryptographic random source; account binding, the server must associate the token with the intended account, and a client must not be able to change a user ID and thereby redirect the reset operation to another account; purpose binding, a password-reset token should authorize password reset, not general login, MFA removal, or account deletion, and different token purposes should be represented and enforced explicitly; expiration, the server must enforce the token's expiry, displaying an expiration time in the frontend is insufficient; single use, once successfully used, the token must no longer authorize the operation; revocation, the system needs a way to invalidate outstanding tokens when circumstances require it, such as a new reset request or an account-security event, according to its documented policy; and transaction consistency, the application must not mark the token as consumed while failing to complete the intended password update, or update the password while leaving the same token reusable.

**3.1 Simulated vulnerable reset flow.** Suppose a fictional application stores reset tokens in a table with `user_id`, `token`, `expires_at`. Its handler performs:

```python
def reset_password(token, new_password):
    record = find_token(token)

    if record is None:
        return error()

    if record.expires_at < now():
        return error()

    update_password(record.user_id, new_password)

    return success()
```

What is missing? The code does not show a check that the token has already been used. It also does not show revocation, a transaction, or protection against two concurrent requests using the same token. The important distinction is that the missing checks are not proven absent from the entire application merely because they are absent from this snippet. A reviewer must trace the surrounding implementation.

A safer conceptual flow:

```python
def reset_password(token, new_password):
    validate_password_policy(new_password)

    with database_transaction():
        record = find_valid_unused_reset_token(token)

        if record is None:
            return generic_error()

        mark_token_used(record.id)

        update_password(
            user_id=record.user_id,
            password_hash=hash_password(new_password)
        )

        revoke_other_reset_tokens(record.user_id)
        apply_session_revocation_policy(record.user_id)

    return success()
```

This is illustrative pseudocode, not drop-in production code. A real implementation must ensure that token consumption and password update occur atomically, with the database isolation and locking behavior appropriate to the system. It must also ensure that password hashing occurs through a vetted password-hashing library and that the reset token is not logged.

**3.2 Should the database store the raw reset token?** Often, the server can store a cryptographic hash of a high-entropy reset token rather than the raw token. The browser or email recipient receives the original token. The server computes the corresponding hash and compares it with the stored value:

```python
token = secure_random_token()

stored_token_hash = sha256(token)
save_reset_record(
    user_id=user.id,
    token_hash=stored_token_hash,
    expires_at=expiry
)

send_reset_link(token)
```

When the token is presented, `candidate_hash = sha256(presented_token)` and the record is found by that hash. This can reduce the consequences of a database-only disclosure, the attacker does not automatically obtain usable reset tokens merely by reading the reset-token table. Important assumptions: the original token has sufficient entropy, the hash is applied consistently, the database lookup and token-state checks are correct, the token is not also exposed in logs, analytics, email-processing systems, or other places, and the application does not expose an endpoint that converts the stored hash into the original token. A fast hash such as SHA-256 is generally unsuitable for password storage, but can be suitable for storing a properly generated, high-entropy random token because the attacker cannot efficiently guess the original value if the entropy is sufficient. That is an important distinction between human-chosen passwords and cryptographically random tokens.

**3.3 Constant-time comparison: when does it matter?** You may encounter advice that every secret comparison must be constant-time. That is too broad. A constant-time comparison attempts to avoid revealing information through data-dependent execution time, especially relevant to comparisons involving secret values such as MACs or authentication tags. However, the practical risk depends on whether comparison time varies with the matching prefix or other secret-dependent data, whether an attacker can make repeated measurements, network and system noise, rate limits, the protocol and implementation, and whether another control prevents the information from being useful. Use a vetted constant-time comparison primitive where the cryptographic API or protocol requires it. Do not replace standard equality checks everywhere indiscriminately and assume that this alone secures the authentication flow. Most importantly, a constant-time comparison cannot fix a predictable token, a missing expiry check, a token bound to the wrong account, or a token that can be reused.

### 4. Password Storage: Hashing, Encryption, Salts, and Work Factors

This topic overlaps with Phase 1, but here the focus is the cryptographic implementation failures that cause authentication weaknesses.

**4.1 Hashing versus encryption.** Hashing is designed to produce a one-way representation of data. Encryption is designed to protect confidentiality while permitting recovery of the original data with the appropriate key. Password verification normally does not require recovering the original password. Therefore, applications should normally store passwords using a dedicated password-hashing function rather than reversible encryption. Consider this unsafe design: `encrypted_password = encrypt(password); save(encrypted_password)`. If the encryption key is also exposed, the stored passwords may be recoverable, the system has created an unnecessary decryption capability. A better design uses a password-hashing library, `password_hash = password_hasher.hash(password); save(password_hash)`. During login, the library verifies the supplied password against the stored hash. The application should not attempt to decrypt a password to compare it with the submitted value. OWASP recommends dedicated password-hashing algorithms such as Argon2id, scrypt, bcrypt, and PBKDF2 rather than reversible encryption or fast general-purpose hashes.

**4.2 Why SHA-256 alone is not enough.** Consider a stolen password database containing plain SHA-256 password hashes. An attacker can take a candidate password, calculate its SHA-256 hash, and compare the result with the stolen values. Because SHA-256 is fast, the attacker can test many candidates rapidly, potentially using specialized hardware. This is an offline guessing attack. Application login rate limits do not protect a stolen database from offline guessing. A slow, adaptive password-hashing function makes each guess more expensive. A memory-hard function also imposes memory requirements that can make large-scale parallel guessing more costly.

**4.3 Why salts matter.** A salt is a unique value used in the password-hashing process. Suppose two users choose the same password. Without unique salts, the same password under the same hashing configuration produces the same hash. With unique salts, the resulting password hashes differ. A salt helps prevent attackers from reusing precomputed tables and makes each password hash a separate guessing target. A salt is not normally required to be secret. It should, however, be generated appropriately and stored with the hash. Modern password-hashing libraries usually manage salts automatically. A salt does not make a weak password strong. It makes large-scale precomputation less useful and prevents direct identification of matching passwords from identical unsalted hashes.

**4.4 Work factors.** Adaptive password hashing deliberately consumes computational resources. Its parameters determine how much work is required to verify a password. A work factor that is too low makes offline guessing cheaper. A work factor that is too high can exhaust application resources and create a denial-of-service risk under heavy authentication load. The correct parameters depend on the algorithm, available resources, concurrency, and operational requirements.

**4.5 Pepper management.** A pepper is an additional secret used in a password-storage design. Unlike a salt, it is intended to remain secret and should be stored separately from the password database. A pepper may provide additional protection if the password database is exposed but the pepper remains protected. However, it introduces operational complexity. If the pepper is compromised, the response may require key rotation, password resets, or a carefully designed migration strategy. A pepper cannot generally be changed for all existing passwords without either knowing those passwords or requiring users to reset them. A pepper is an additional control, not a replacement for a modern password-hashing function.

**4.6 Migrating legacy password hashes.** Imagine a production application that originally stored passwords using SHA-256 and now wants to migrate to Argon2id. A sensible migration strategy: identify the old password-hash format and algorithm; introduce a versioned password-hash representation; verify the user's submitted password using the correct legacy verifier; after successful verification, hash the supplied password using the new algorithm; replace the old hash with the new representation; track remaining legacy accounts; and establish a policy for dormant accounts that never log in. The application must not assume that all stored hashes have the same format during migration. It must also avoid silently accepting malformed or unknown hash formats. A legacy hash does not automatically prove that an account is compromised, its risk depends on the algorithm, parameters, password quality, exposure, and other controls. For accounts that never return to complete migration, the organization may need a password-reset policy or another secure migration mechanism.

### 5. Weak Cryptographic Primitives and Incorrect Modes

Knowing the algorithm name is not enough. You must understand its purpose and how it is used.

**5.1 MD5 and SHA-1: distinguish the failure modes.** MD5 and SHA-1 have important cryptographic weaknesses, particularly involving collision resistance. A collision occurs when different inputs produce the same hash. That does not mean every use of MD5 or SHA-1 produces an immediate authentication bypass. MD5 or SHA-1 used as a password-storage hash is generally unsuitable because these functions are fast and lack password-specific cost controls. A legacy signature scheme that relies on broken collision resistance may have a different and potentially more serious integrity risk. An ordinary file checksum has a different threat model from a digital signature or authentication token. A good security assessment identifies the algorithm's role rather than simply reporting its name.

**5.2 AES-ECB.** AES is a block cipher, not a complete encryption scheme by itself. Electronic Codebook mode, or ECB, encrypts each block independently. When identical plaintext blocks are encrypted under the same key, the resulting ciphertext blocks are identical. This can reveal patterns in structured data. For example, an application that encrypts repetitive structured records with ECB may expose relationships between the records even if the plaintext is not directly readable. ECB is generally inappropriate for encrypting ordinary multi-block application data. For authentication-sensitive data, use a vetted authenticated-encryption construction that provides both confidentiality and integrity. Do not conclude that a production authentication bypass exists merely because you discover ECB in a codebase. Establish what data is encrypted, whether an attacker can influence that data, how decryption is used, and what consequences follow.

**5.3 Encryption without integrity.** Suppose a system encrypts an authentication-related value and later decrypts it before using it. If the encryption scheme does not provide adequate integrity protection, the application may fail to detect malicious modification. Depending on the construction and the application, this can create opportunities for data manipulation or decryption-oracle weaknesses. The correct remediation is not to invent an additional custom checksum and hope it is sufficient. Use a vetted authenticated-encryption scheme, follow its API requirements, and ensure the application rejects failed authentication tags before consuming decrypted data.

**5.4 Authenticated encryption is not magic.** AES-GCM and ChaCha20-Poly1305 are examples of authenticated-encryption constructions. They provide confidentiality and integrity when used correctly. However, implementations can still fail through nonce reuse where the algorithm requires nonce uniqueness, incorrect tag verification, incorrect handling of authentication failures, weak or exposed keys, incorrect association of ciphertext with the intended account or record, misuse of associated data, incorrect key rotation, and reusing the same key for unrelated purposes without a sound design. A secure algorithm does not compensate for an insecure surrounding protocol.

### 6. Nonces, IVs, Salts, and Challenges Are Not Interchangeable

These terms are often confused.

| Value | Main purpose | Must it be secret? | Key security concern |
|---|---|---|---|
| Salt | Makes password-hash computations distinct | Usually no | Appropriate uniqueness and generation |
| Nonce | Provides uniqueness or freshness in a cryptographic protocol | Usually not inherently secret | Follow protocol-specific uniqueness and replay requirements |
| Initialization vector (IV) | Initializes a cryptographic mode | Depends on the mode; often not secret | Follow the mode's exact requirements |
| Authentication challenge | Binds a response to a particular authentication attempt | Usually not secret | Unpredictability, freshness, binding, and replay handling |
| Session ID | Identifies an authenticated session and often acts as a bearer credential | Yes, in the sense that unauthorized disclosure can grant access | Unpredictability, secure handling, rotation, and revocation |

The same byte string could technically be used to represent different kinds of values, but their security requirements are not the same.

**6.1 Nonce reuse in AES-GCM.** AES-GCM requires careful nonce management. Under a given key, nonce uniqueness is a critical security requirement. If a system repeatedly uses the same nonce with the same key, it can undermine the security of the encryption scheme, potentially exposing plaintext relationships and damaging integrity protection. This can be especially dangerous when encrypted data protects authentication or identity information. Review where nonces are generated, whether generation is random or counter-based, whether uniqueness is maintained across all application instances sharing a key, whether deployment restarts or distributed workers can cause reuse, and whether key rotation and nonce limits are properly managed. Do not assume that a random nonce is automatically safe in every deployment. Follow the cryptographic library and protocol guidance for the chosen construction. Also distinguish this issue from a password-reset token problem: a nonce used for encryption is not necessarily an authentication credential, although its misuse can weaken the confidentiality or integrity of authentication data.

### 7. HMACs, Digital Signatures, and Trust Decisions

Authentication systems frequently need to establish whether data has been altered or whether it came from a trusted source. Two commonly used mechanisms are message authentication codes and digital signatures.

**7.1 HMAC.** A keyed-hash message authentication code, or HMAC, uses a secret key and a hash function to authenticate a message: `message + secret key → HMAC`. A verifier with the appropriate secret key can recompute the MAC and compare it with the supplied value. A plain hash does not provide the same guarantee, if an attacker can modify both the message and its unkeyed digest, the digest alone does not establish that the message was created by a trusted party. An HMAC can provide message integrity and authentication, assuming the key is appropriately protected and the implementation is correct.

Authentication use case: suppose an application creates a protected authentication record with `account_id`, `purpose`, `expires_at`. The application must ensure that an attacker cannot alter the account ID or purpose while retaining a valid authentication tag. The exact format and verification procedure matter. If the application authenticates one representation but later interprets a different representation, inconsistent parsing may undermine the protection.

**7.2 Digital signatures.** Digital signatures use a private key to sign data and a corresponding public key to verify it. They are useful in federated identity systems because a service can verify an assertion without possessing the identity provider's private signing key, as established in Phase 10. But the signature is only one part of the trust decision. The verifier must also establish that the signing key belongs to a trusted issuer, the signed data is the data actually being consumed, the signature covers the security-relevant fields, the assertion is intended for this recipient, the assertion is valid for the relevant time, the assertion has not been improperly replayed, and the identity is mapped to the correct local account. A mathematically valid signature from an untrusted key does not establish a trusted identity. Likewise, a valid signature over an irrelevant field does not protect an unsigned identity field that the application later trusts. These principles are particularly important when reviewing SAML, OIDC, signed authentication messages, and other federated identity systems.

### 8. Algorithm Confusion and Verification Mistakes

A cryptographic implementation may fail even when its algorithms and keys appear individually strong. The defect may be in how the verifier decides which algorithm, key, or representation to trust. This section covers the general principle. Deep JWT attack techniques remain outside this module.

**8.1 Never trust a claimed algorithm without enforcing policy.** Suppose a signed authentication message contains metadata indicating which algorithm was used. The application must not blindly allow untrusted message data to determine the verification algorithm without checking it against an explicit policy. The verifier should determine the allowed algorithms from trusted configuration, select the appropriate trusted key, verify the cryptographic operation using the intended algorithm, reject unsupported or disallowed algorithms, and validate the claims and transaction context after successful cryptographic verification. The exact implementation differs across protocols and libraries. The central principle is that the sender's claim about how a message was signed is not, by itself, proof that the signature is trustworthy.

**8.2 Key confusion.** Consider an application that supports multiple key types or multiple identity providers. A vulnerability may arise if the application uses a key in an unintended role or selects a verification key based on attacker-controlled metadata. Review whether key types are constrained by configuration, keys are associated with the intended issuer and purpose, public keys and secret keys are not accidentally interchanged, the application rejects keys or algorithms outside the intended policy, and the trusted key source cannot be replaced through untrusted input. Do not confuse a theoretical configuration concern with an exploitable vulnerability. You need to show that an untrusted party can influence the verification process and that the application accepts a message it should reject.

**8.3 Verification must happen before trust.** A dangerous pattern is to decode an authentication message and use its identity claims before completing verification. Decoding and verification are different operations. A decoder may simply parse the message format. It does not necessarily validate the signature or establish trust. A secure flow is conceptually: receive message, parse safely, select trusted verification configuration, verify signature or MAC, validate issuer, audience, expiry and transaction context, apply identity mapping and account policy, create or update authentication state. An application that creates a session before completing the required verification can expose an authentication bypass. This is a general review principle for signed tokens and federated identity, not a claim that every decoded token is dangerous.

### 9. TLS and Authentication Credentials in Transit

Cryptographic failures also occur when authentication secrets are transmitted or validated incorrectly.

**9.1 Credentials over cleartext connections.** Consider a login request sent over ordinary HTTP. Without appropriate transport protection, someone capable of observing the traffic may be able to read the submitted credentials. HTTPS uses TLS to protect traffic in transit and authenticate the server through certificate validation. However, using HTTPS somewhere in the application does not establish that the entire authentication flow is protected. Check the login endpoint, password-reset and account-recovery endpoints, MFA enrollment and verification, session-cookie transmission, redirects between HTTP and HTTPS, API endpoints and alternate hostnames, reverse-proxy and load-balancer configuration, and certificate and hostname validation in clients.

**9.2 Certificate validation.** A client must not merely establish an encrypted connection. It must verify that it is communicating with the intended server. A client that disables certificate validation may accept a connection to an impersonated endpoint. That can expose credentials and authentication tokens even though the connection appears encrypted. In source-code review, look for custom TLS configurations that disable certificate or hostname validation, particularly in mobile applications, desktop clients, internal service-to-service clients, authentication SDKs, and custom HTTP wrappers. A self-signed certificate is not automatically a vulnerability. The question is whether the client establishes trust securely through an appropriate certificate-validation mechanism.

**9.3 Reverse proxies and forwarded-protocol headers.** Many applications terminate TLS at a reverse proxy and then communicate with an internal application server. The application may need to know whether the original request used HTTPS. A common mistake is to trust a client-supplied forwarding header without ensuring that the header was set or sanitized by a trusted proxy. This can affect security decisions involving secure redirects, absolute URLs in password-reset emails, cookie security configuration, and authentication callback URLs. The fix is architectural: define trusted proxies, sanitize forwarding headers at the boundary, and derive security-sensitive origin information from trusted configuration and validated request context. A header such as `X-Forwarded-Proto: https` is not inherently trustworthy simply because it contains the word "https."

### 10. Key Management: Strong Algorithms Cannot Rescue Exposed Keys

Cryptographic security depends on more than algorithms. Suppose an application uses AES-256 correctly but stores the encryption key in the same database as the ciphertext. If an attacker obtains both, the encryption may offer little protection against that attacker. Likewise, a perfectly designed digital-signature scheme cannot protect the identity system if an attacker steals the trusted signing private key.

**10.1 Hardcoded keys.** Consider `ENCRYPTION_KEY = "my-super-secret-production-key"`. This is a dangerous design for a production secret. The key may be exposed through source-control history, code review systems, build artifacts, container images, developer workstations, deployment packages, and error messages or diagnostic endpoints. Deleting the string from the latest source file does not necessarily remove it from repository history or previously distributed artifacts. A reviewer should establish whether the value is actually used as a key or secret, whether it is active in a deployed environment, whether it is a placeholder or test-only value, whether an unauthorized person could obtain it, what information or operations the key protects, and whether the key has already been rotated or revoked. If an active production key is exposed, remediation generally requires treating it as compromised, rotating it, and assessing the data or authentication operations protected by it.

**10.2 Environment variables.** Environment variables are frequently used to inject secrets into applications. They are often better than hardcoding secrets into source code, but they are not a complete secrets-management strategy. Depending on the environment, secrets may be exposed through process inspection, diagnostic output, misconfigured debugging tools, deployment configuration, logs, crash dumps, and overly broad access to the runtime environment. A mature design uses an appropriate secret-management mechanism, limits access, avoids unnecessary secret exposure, and supports rotation.

**10.3 Separate keys by purpose.** Imagine an application uses one secret for encrypting user records, signing authentication data, creating reset-token MACs, and protecting internal service messages. This design increases the consequences of key compromise and makes rotation more difficult. Where appropriate, use separate, independently generated keys for distinct cryptographic purposes, known as key separation. It reduces unintended coupling between systems and helps limit the impact of a compromised key.

**10.4 Key rotation and revocation.** Key rotation is not simply replacing a string in a configuration file. A correct rotation process must account for which services use the key, which records or tokens were created under it, whether old data must remain decryptable, whether old signatures should still be trusted, whether the old key must be retained temporarily for a controlled migration, how a compromised key will be revoked, whether cached credentials or authentication state remain valid, and how the organization verifies that the new key is active. For encryption, an application may need to decrypt old data using a retired key and encrypt new data with a new one. For signing keys, the system needs a deliberate policy for how and when old signatures remain trusted. For authentication tokens, key rotation may require rejecting tokens signed with compromised keys and forcing affected users to reauthenticate. The correct behavior depends on the token format, key distribution model, and threat scenario.

### 11. Practical Code-Review Case Study

Apply the principles to a fictional application's password-reset implementation.

**11.1 Vulnerable example.**

```python
import hashlib
import random
import time

def request_password_reset(user):
    token = hashlib.sha256(
        f"{user.id}:{int(time.time())}:{random.random()}".encode()
    ).hexdigest()

    database.save_reset_token(
        user_id=user.id,
        token=token,
        expires_at=time.time() + 3600
    )

    email_user(
        user.email,
        f"https://accounts.example.test/reset?token={token}"
    )
```

At first glance, this code contains SHA-256, a long hexadecimal token, an expiry time, and account binding. It may appear secure to an inexperienced reviewer. A senior reviewer asks different questions.

**Finding A: insecure random source.** The code uses `random.random()` rather than a cryptographically secure random source. The security of the token should not depend on an ordinary PRNG.

**Finding B: predictable inputs.** The token is derived from the user ID and a timestamp, combined with the ordinary PRNG output. Hashing these inputs does not make them secure secrets.

**Finding C: token lifecycle is not demonstrated.** The snippet stores an expiry time, but does not show the reset handler. We cannot conclude from this code alone that the token is reusable, that expiry is ignored, or that account binding is broken. Those are additional checks that must be reviewed.

**Finding D: raw token storage.** The database stores the original token. If the reset-token table is exposed, the attacker may obtain usable tokens. Storing a hash of a sufficiently high-entropy token can reduce this risk.

**Finding E: URL exposure risk.** The token is included in a URL. That is common in password-reset links, but it creates exposure risks through logs, browser history, analytics, monitoring, and other systems that process URLs, as established in Phase 12. The design must limit those risks. The token should not be treated as ordinary non-sensitive URL data.

**Finding F: missing surrounding controls.** The snippet does not demonstrate single-use enforcement, transactional token consumption, revocation of prior tokens, secure token handling in logs, rate limiting, session-revocation policy after password reset, and notification and monitoring. The absence of these controls from the snippet is not proof that the complete application lacks them. Code-review discipline: report what the code demonstrates, then investigate the surrounding implementation before claiming additional vulnerabilities.

**11.2 Safer conceptual implementation.**

```python
import hashlib
import secrets
import time

def request_password_reset(user):
    raw_token = secrets.token_urlsafe(32)

    token_hash = hashlib.sha256(
        raw_token.encode("utf-8")
    ).hexdigest()

    database.create_reset_record(
        user_id=user.id,
        token_hash=token_hash,
        purpose="password_reset",
        expires_at=time.time() + 1800,
        used=False
    )

    send_reset_email(
        user.email,
        build_reset_link(raw_token)
    )
```

This is still illustrative code, not a complete production implementation. Improvements include: `secrets` is designed for security-sensitive random values; the token is not derived from the user ID or timestamp; the database stores a token hash rather than the raw token; the record includes an explicit purpose; the token has a limited lifetime. The reset handler must still enforce account binding, purpose, expiration, single use, revocation, and transactional state changes. The system also needs to ensure that the raw token is not inadvertently logged and that the reset URL is generated from a trusted canonical origin.

### 12. How to Assess Authentication Cryptographic Flaws

When reviewing an application, do not start by asking "which algorithms are used?" Start by asking "which security decision depends on this cryptographic operation?" Use the following method.

**Step 1: identify the protected asset.** Examples: passwords, reset tokens, session identifiers, MFA secrets, federated identity assertions, encryption keys, account-recovery credentials.

**Step 2: identify the required property.** Is the system trying to provide confidentiality, integrity, authenticity, unpredictability, password-guessing resistance, or replay protection? One operation may need several properties.

**Step 3: trace the complete lifecycle.** For a reset token: generation, storage, delivery, presentation, validation, consumption, revocation. For a signing key: generation, secure storage, distribution or access, signing, verification, rotation, revocation and retirement. A secure generation method cannot compensate for insecure storage or validation.

**Step 4: identify attacker control.** Ask which inputs the attacker can influence: token values, encoded claims, request headers, identity-provider metadata, encrypted input, key-selection metadata, authentication challenges. Then determine whether attacker-controlled data influences a cryptographic decision or is trusted before verification.

**Step 5: identify the trust boundary.** Determine which component is responsible for the security decision: the browser, the mobile application, the reverse proxy, the application server, the identity provider, a shared authentication service, a background worker. Client-side validation alone cannot establish a server-side authentication decision. Similarly, a secure identity provider cannot compensate for an application that incorrectly trusts its assertions.

**Step 6: prove the security consequence.** A finding becomes stronger when you can demonstrate that the defect changes a real security outcome. A token-generation defect becomes more serious when valid tokens can actually be predicted. A key-exposure finding becomes more serious when the key is active and protects production authentication. A signature-validation defect becomes more serious when an invalid or untrusted message is accepted. A password-storage defect becomes more serious when the exposed hashes can be attacked efficiently and protect active accounts. Do not overstate an impact that has not been demonstrated.

### 13. Simulated Evidence: What Proves the Issue?

Suppose an authorized review identifies an application that appears to use a weak token generator, `const token = Math.random().toString(36).slice(2);`. This is meaningful evidence that an unsuitable random API is being used. However, the complete finding should establish that the value is used as a security-sensitive token, the token is accepted by the server as proof of authorization or authentication, the token's effective unpredictability is insufficient for the threat model, the attacker can realistically exploit that weakness, and relevant expiry, binding, and verification controls do not prevent the claimed consequence. A good report separates the observed fact from the demonstrated impact.

**Example report structure.** Title: Predictable password-reset token generation may permit unauthorized account recovery. Observed behavior: the password-reset handler derives its token from a timestamp, account identifier, and non-cryptographic random output. Security concern: the token-generation process does not provide a sound basis for unpredictable authentication secrets. Evidence: source-code location, token-generation logic, and relevant server-side validation behavior. Impact: if an attacker can predict or reconstruct a valid victim token and the reset endpoint accepts it without additional proof, the attacker may be able to change the victim's password. Remediation: generate reset tokens using a cryptographically secure random source, store a hash of the high-entropy token where appropriate, and enforce expiry, account and purpose binding, single-use consumption, revocation, and secure handling. Notice the phrase "if an attacker can predict or reconstruct." It avoids claiming a complete account takeover when the available evidence proves only a weak generator.

### 14. Common False Positives

A competent AppSec engineer must know when not to report a vulnerability.

**False positive 1: a long token is automatically secure.** Incorrect, length does not establish entropy.

**False positive 2: every use of SHA-256 is unsafe.** Incorrect, SHA-256 is unsuitable by itself for password storage, but can be appropriate for other purposes, including hashing high-entropy random tokens.

**False positive 3: a token is in a URL, so account takeover is proven.** Incorrect, URL placement creates exposure risks, but exploitation depends on whether the token leaks to an attacker and whether it grants sufficient authority.

**False positive 4: a UUID is always predictable.** Incorrect, UUID versions and implementations differ. Assess the generation method and intended use.

**False positive 5: a key is present in a configuration file, so production is compromised.** Incorrect, establish whether the key is real, active, exposed to unauthorized parties, and capable of protecting sensitive data or operations.

**False positive 6: a signature is valid, so the identity is trustworthy.** Incorrect, the signing key, issuer, audience, intended recipient, validity period, transaction context, and identity mapping must also be validated.

**False positive 7: HTTPS proves the authentication flow is secure.** Incorrect, HTTPS does not prove correct certificate validation in every client, secure token generation, safe key management, or correct server-side authentication logic.

**False positive 8: the application uses a legacy algorithm, so exploitation is immediate.** Incorrect, establish what the algorithm protects, its parameters, the relevant attack model, and the resulting impact.

**False positive 9: a token is accepted twice, so the entire account is compromised.** Incorrect, establish the token's purpose and scope, what operation replay permits, and whether the repeated request creates a meaningful unauthorized outcome.

### 15. Remediation Priorities

When you discover cryptographic weaknesses, remediation should be proportional to the risk.

| Finding | Primary remediation |
|---|---|
| Passwords stored in plaintext or reversible encryption | Migrate to dedicated password hashing and remove unnecessary recoverable copies |
| Passwords stored using fast hashes | Introduce modern adaptive password hashing and migrate safely |
| Reset tokens generated predictably | Use a cryptographically secure random source |
| Reset tokens stored in recoverable plaintext | Consider storing hashes of high-entropy tokens |
| Tokens never expire or can be reused | Enforce expiry, single-use consumption, and revocation |
| Encryption without adequate integrity protection | Use a vetted authenticated-encryption construction |
| Nonce reuse | Correct nonce management, assess affected data, and rotate keys when required |
| Untrusted algorithm or key selection | Enforce explicit algorithm policy and trusted key selection |
| Signing key exposed | Treat as potentially compromised, rotate or revoke, and assess dependent authentication flows |
| Hardcoded production secret | Move to appropriate secrets management and rotate the exposed secret |
| TLS certificate validation disabled | Restore proper certificate and hostname validation |
| Credentials transmitted over cleartext HTTP | Protect the entire credential-bearing flow with correctly configured TLS |
| Cryptographic secrets logged | Remove secret logging, restrict access to existing logs, and assess exposure |
| Legacy password hashes | Use a controlled migration strategy and an appropriate dormant-account policy |

### 16. Senior AppSec Review Checklist

**Randomness and tokens:** security-sensitive values come from an appropriate CSPRNG; tokens do not depend on timestamps, sequential IDs, or predictable seeds; token entropy is evaluated independently of displayed length; UUID version and implementation are known if UUIDs are used as secrets; tokens are bound to the correct account and purpose; expiry is enforced server-side; single-use and replay controls are enforced where required; revocation behavior is defined; raw secrets are not unnecessarily stored or logged.

**Password storage:** passwords are not stored in plaintext or reversibly encrypted; a dedicated password-hashing algorithm is used; salts are unique and managed correctly; work factors are suitable for the current environment; legacy hash migration is planned; pepper management, if used, is sound.

**Encryption and integrity:** established cryptographic libraries are used; custom ciphers and improvised cryptographic schemes are avoided; encryption provides integrity protection where required; authentication tags are verified before decrypted data is trusted; nonces and IVs follow the selected algorithm's requirements; algorithms and parameters are appropriate for the intended purpose.

**Signatures and MACs:** verification uses trusted keys; allowed algorithms are explicitly constrained; the verified data is the same data the application consumes; issuer, audience, recipient, expiry, and transaction context are checked where applicable; identity is not trusted merely because a message can be decoded; key separation and rotation policies exist.

**Transport and key management:** credentials and tokens are protected in transit; clients validate certificates and hostnames correctly; reverse-proxy trust boundaries are correctly configured; production secrets are not hardcoded or committed to source control; key access is restricted and audited appropriately; key rotation and revocation are operationally possible; compromise response covers affected tokens, sessions, data, and dependent services.

### 17. Final Lessons: What Separates a Beginner from a Senior Reviewer?

A beginner sees `token = sha256(str(time.time()).encode()).hexdigest()` and might report "SHA-256 is insecure." That is the wrong diagnosis. A stronger reviewer explains: SHA-256 is a legitimate cryptographic hash function; the input is derived from a predictable timestamp; hashing a predictable value does not provide the entropy needed for an authentication secret; the code uses the result as a token, so its unpredictability matters; the impact depends on whether the server accepts a reconstructed token and what that token authorizes; and the correct fix is to generate the token using a cryptographically secure random source, then implement appropriate token lifecycle controls.

A beginner sees an encrypted value and says "it is encrypted, so it is safe." A senior reviewer asks whether the application needs confidentiality, integrity, authenticity, or all three, and whether the chosen construction and implementation provide them.

A beginner sees a signed identity assertion and assumes the signature proves the user is legitimate. A senior reviewer verifies the signing key, issuer, intended recipient, validity period, transaction binding, replay controls, and local account mapping.

A beginner sees a secret in a configuration file and immediately declares a critical compromise. A senior reviewer establishes whether the secret is real, active, exposed, and capable of authorizing access or decrypting protected data.

The core skill is not recognizing cryptographic names. It is tracing how cryptographic operations influence authentication decisions and proving when a failure changes the security outcome.

## Assessment

The following assessment is drawn from "Authentication Security.md" and addresses algorithm confusion, the exact topic of Section 8.1 of this phase. Both source files independently scope out deep JWT internals at the same point, the module explicitly reserves them for elsewhere, and the supplementary file's own instructor pauses immediately after these two challenges with "we'll treat JWT as its own dedicated vulnerability class later." As with the prior phases, the questions are preserved from the original source, and the answers given are the instructor's corrected, authoritative answers rather than the original learner's submitted answers.

### Assessment Question 1

A server normally issues signed tokens using an asymmetric algorithm:

```json
{
  "alg": "RS256",
  "sub": "1042",
  "role": "user"
}
```

RS256 means a private key signs the token and the corresponding public key verifies it. You discover the server's verification library supports both RS256 and HS256. As an AppSec tester, what security property would you investigate here? Specifically, if the server expects RS256 but blindly trusts the token's own claimed algorithm, what could go wrong if an attacker switches the algorithm to HS256?

<details markdown="1">
<summary><strong>Reveal Answer</strong></summary>

The security property to investigate is whether the server enforces an explicit, trusted verification algorithm, or whether it instead lets the token's own `alg` field dictate how the token gets verified. The attack mechanism works as follows: normally the server expects RS256, where a private key signs and the corresponding public key verifies. An attacker changes the token's `alg` field from `"RS256"` to `"HS256"`. HS256 is a symmetric algorithm, meaning the same secret value is used for both signing and verifying. If the vulnerable server blindly uses its own RSA public key as the HMAC secret for HS256 verification, an attacker who already knows that public key, which is by definition not secret, could use it to compute a valid HS256 signature over a forged token, for example one claiming `{"sub": "1042", "role": "admin"}`. If the server accepts that forged, HS256-signed token because it blindly honored the attacker-supplied `alg` field, the attacker has crossed the critical boundary: an attacker-controlled token, with a signature the server accepts, containing attacker-controlled claims, resulting in an authentication or authorization compromise.

One precise correction worth noting: the attacker is not using the public key "for signing" in the RSA sense, with HS256 the public key material is instead being reused as the HMAC secret, a symmetric algorithm's secret, not an asymmetric signing key. That is a meaningful technical distinction even though the practical attack is the same. It is also not enough merely to observe that the `alg` field changed from RS256 to HS256, the vulnerability is only proven once you demonstrate that the server actually accepts the forged token under that wrong algorithm and key interpretation, rather than rejecting it.

</details>

### Assessment Question 2

Continuing the same scenario, you discover the application's verification library also accepts an algorithm called `none`, meaning a token can be submitted with no cryptographic signature at all:

```json
{
  "alg": "none",
  "typ": "JWT"
}
```

paired with claims such as `{"sub": "1042", "role": "admin"}`. What security property should the server actually enforce to prevent an attacker from simply removing the signature and changing the claims? Don't just say "reject `none`," explain what the server should actually be enforcing, and why.

<details markdown="1">
<summary><strong>Reveal Answer</strong></summary>

Rejecting `none` as a special case is the immediate, surface-level control, but it is not the actual property the server needs to enforce. The real requirement is that the server must enforce an explicit, trusted verification algorithm, determined by its own configuration, not by the incoming token, and require valid cryptographic verification to actually succeed before accepting the token at all. Concretely, if the application is designed to use RS256, the check should be: is the expected algorithm RS256, does the token's claimed algorithm say RS256, and if so, verify the RSA signature, if not, reject, regardless of what algorithm the token claims. Under that model, a token claiming `"alg": "none"` is rejected not because the server has a special-cased blocklist entry for the literal string `"none"`, but because it fails the more general requirement of matching the one explicitly trusted, configured algorithm and passing real cryptographic verification under it.

The underlying security principle is that the claims inside the token, `{"sub": "1042", "role": "admin"}`, are attacker-controlled data right up until the moment the server successfully, cryptographically verifies the token's authenticity. The correct mental model is a strict sequence: token claims, then cryptographic verification, then, only after that step succeeds, trusted identity and claims. The dangerous, incorrect model treats the claims as trustworthy as soon as the token merely "looks valid" or parses correctly, skipping the verification step entirely. Enforcing one explicit trusted algorithm and requiring successful verification under it is what makes `alg: none` fail along with every other unauthorized algorithm or forged signature, not a special exception carved out just for that one value.

</details>

## Remediation and Secure Implementation

The following consolidates the remediation guidance across all seventeen sections of this phase.

1. Identify the exact cryptographic property, confidentiality, integrity, authenticity, or unpredictability, a given authentication mechanism actually needs, and verify the chosen construction provides that specific property rather than assuming any cryptography is sufficient.
2. Generate every authentication secret, reset tokens, session identifiers, MFA recovery codes, protocol state and nonce values, from a documented cryptographically secure random API, never from timestamps, sequential IDs, or predictable seeds, regardless of how the result is encoded.
3. Enforce the full token lifecycle on the server for every security-sensitive token: unpredictability, account binding, purpose binding, expiration, single-use consumption, revocation, and transactionally consistent state changes.
4. Store a hash of a high-entropy random token rather than the raw value where practical, while storing passwords exclusively through a dedicated, adaptive password-hashing algorithm such as Argon2id, never through reversible encryption or a fast general-purpose hash.
5. Use vetted authenticated-encryption constructions such as AES-GCM or ChaCha20-Poly1305 for sensitive data, follow their nonce-uniqueness and tag-verification requirements exactly, and never substitute a custom integrity scheme.
6. Treat salts, nonces, IVs, authentication challenges, and session IDs as distinct values with distinct requirements, never assume one kind of randomness satisfies the security property another kind is responsible for.
7. Enforce an explicit, server-configured, trusted algorithm policy for every signature or MAC verification, never allow an incoming message's own metadata to select the verification algorithm or key, and complete full cryptographic verification before trusting any claim inside a signed or encoded message.
8. Protect authentication credentials and tokens across the entire transport path, not just the login endpoint, validate certificates and hostnames correctly in every client, and only trust forwarded-protocol headers that a defined, trusted proxy boundary actually controls.
9. Never hardcode production cryptographic secrets or commit them to source control, use an appropriate secrets-management mechanism with restricted, audited access, and separate keys by purpose so a single compromise has bounded impact.
10. Build a real key-rotation and revocation process that accounts for every service using the key, every token or record created under it, and whether old data or signatures must remain valid during a controlled migration.

## Key Takeaways

This phase's governing principle is stated in its own first section: cryptography is not one security property, and one property does not automatically provide the others. Encryption without integrity can still be tampered with. A hash without adaptive cost controls does not protect a password. A valid signature from an untrusted key proves nothing about trust. Every vulnerability pattern in this module is a variation on the same mistake: assuming that because a cryptographic mechanism is present, the specific property the application actually needed is also present.

The assessment in this phase demonstrates the module's companion principle just as directly: a token's claims, whether inside a password-reset flow or a signed authentication message, are attacker-controlled data until the server completes real cryptographic verification against an algorithm and key the server itself trusts, not one the incoming data claims to have used. The module's closing comparison between a beginner and a senior reviewer captures the skill this entire phase builds: the question is never "which algorithm is this," it is "which security decision depends on this cryptographic operation, and does the complete implementation actually deliver it."

## Review Checklist

- [ ] Can you name the four cryptographic properties and give an authentication example of each?
- [ ] Can you explain why `Math.random()` or a hashed timestamp is unsuitable for generating an authentication token, even when the output looks long and complex?
- [ ] Can you list the seven properties a secure token lifecycle requires beyond unpredictability?
- [ ] Can you explain why storing a hash of a random reset token differs from hashing a human-chosen password?
- [ ] Can you distinguish hashing from encryption for password storage, and explain why reversible encryption is the wrong choice?
- [ ] Can you explain the specific risk of AES-ECB and the specific risk of nonce reuse in AES-GCM?
- [ ] Can you distinguish salts, nonces, IVs, authentication challenges, and session IDs by their actual secrecy and uniqueness requirements?
- [ ] Can you list the verification steps a valid digital signature alone does not satisfy?
- [ ] Can you explain why an application must never let a message's own metadata select its verification algorithm?
- [ ] Can you apply the module's 6-step assessment methodology, protected asset through demonstrated consequence, to a cryptographic finding?
- [ ] Can you explain, from the assessment, how an RS256-to-HS256 algorithm confusion attack actually works, including the precise role of the public key?
- [ ] Can you explain why rejecting `alg: none` as a special case is the wrong framing, and what the server should enforce instead?

## References to Related Phases

- Password hashing, salting, peppering, and legacy migration in sections 4.1 through 4.6 directly extend the password-storage foundations established in **Phase 1, Password Storage and Credential Attacks**.
- Reset-token lifecycle properties in section 3 build on the token reuse, expiration, and account-binding principles from **Phase 2, Password Change and Account Recovery**.
- Digital signature trust decisions in section 7.2 and algorithm confusion in section 8 extend the assertion-validation discipline from **Phase 7, OAuth 2.0 and OpenID Connect Security** and **Phase 10, SAML Security**.
- TLS, certificate validation, and trusted forwarding headers in section 9 connect to the trust-boundary principles examined for client-supplied data throughout **Phase 1** and **Phase 11, Multi-Tenant Identity Isolation**.
- Secrets exposure through logs, referenced in the password-reset case study's URL-exposure finding, extends the secure-logging discipline from **Phase 15, Authentication Logging and Monitoring**.
