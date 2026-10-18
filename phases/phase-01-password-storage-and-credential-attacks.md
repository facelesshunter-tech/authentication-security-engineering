# Phase 1: Password Storage and Credential Attacks

**Source material:** Module 1 of 17, "Authentication Complete Phases Test.md" (Lessons 1.1 through 1.12, the Module 1 consolidated review, and the "Three Attack Surfaces" summary), with supplementary assessment material drawn from "Authentication Security.md" (Challenge 03 and Challenge 04).

## Learning Objectives

After completing this phase, you should be able to:

1. Explain the difference between plaintext password storage and password hashing, and why the distinction is a critical security boundary.
2. Identify why fast, general purpose hash functions such as SHA256, SHA1, and MD5 are unsuitable for password storage, and name the algorithm family that is suitable.
3. Explain what a salt does and does not protect against, and distinguish a salt from a pepper.
4. Explain how password hashing cost parameters are chosen and why both overly weak and overly aggressive configurations create risk.
5. Distinguish credential stuffing, password spraying, and brute force as three related but different attack strategies, and identify the defenses appropriate to each.
6. Identify default credentials and hardcoded credentials as separate weaknesses with separate root causes.
7. Explain why a password change endpoint is security sensitive and what evidence of authorization it should require.
8. Explain why security questions are a weak substitute for multi factor authentication.
9. Trace a password hash migration strategy and identify the specific ways a migration can fail.
10. Distinguish offline password attacks, online credential attacks, and credential lifecycle weaknesses as three separate attack surfaces requiring separate defenses.
11. Investigate a rate limiting control using the same disciplined evidence standard a senior application security engineer would apply, including recognizing when a client supplied header undermines a rate limiter's trust boundary.

## Introduction

Authentication security does not begin at the login page. It begins the moment a password is created, and it continues through every point where that password is stored, verified, changed, recovered, or retired. This phase is about that entire lifecycle of a credential, not merely the moment it is typed into a form.

An application can have a perfectly designed login page and still be critically insecure if it stores passwords in plaintext. It can have a strong password hashing algorithm and still be vulnerable if nothing prevents an attacker from testing stolen credentials against it at scale. It can resist brute force and still allow an attacker in through a hardcoded administrative account that nobody remembered to remove. Each of these is a different failure, with a different root cause and a different fix. The purpose of this phase is to teach you to tell them apart, because a vulnerability report that says only "weak authentication" is not useful to a developer, and a defense that only addresses one of these failures will leave the others open.

## Core Concepts

This phase is organized around twelve lessons that build on one another. The first five lessons (1.1 through 1.5) concern how a password is stored: plaintext versus hashing, why hash choice matters, what a salt and a pepper each contribute, and how cost parameters are tuned. The next three lessons (1.6 through 1.8, plus 1.11) concern how an attacker tries to defeat authentication from the outside: credential stuffing, password spraying, brute force, and the use of default or hardcoded credentials. The remaining lessons (1.9, 1.10, 1.12) concern the credential's lifecycle: how a password change is verified, why security questions are a weak recovery mechanism, and how an application safely migrates passwords from an old hashing scheme to a new one.

The module closes by naming the single most important distinction that threads through all twelve lessons: offline attacks, online attacks, and lifecycle weaknesses are three separate attack surfaces, and a defense built for one does not protect the others.

## Lessons

### Lesson 1.1: What Happens to a Password After You Submit It

Before examining attacks, you need to understand what a secure authentication system should do with a password.

Imagine a fictional application, `https://securebank.example`. A user registers with:

```text
Email: user@example.com
Password: BlueRiver!2026
```

The application needs a way to verify that password during future logins. There are two fundamentally different approaches.

**Approach A: Store the actual password.** The database contains:

```text
email: user@example.com
password: BlueRiver!2026
```

This is plaintext password storage, and it is a critical security failure. Suppose an attacker obtains a database backup through an unrelated vulnerability. The attacker does not need to crack passwords, because the passwords are already readable. Possible consequences include direct access to the affected account, access to other services where the user reused the same password, exposure of the user's email account and other linked services, and targeted phishing built from information obtained through the compromised account. The attacker might never need to exploit the login endpoint at all.

This illustrates a governing principle for the whole phase: authentication security does not begin at the login page. It begins when credentials are created, stored, verified, and managed.

**Approach B: Store a password hash.** A properly designed system stores a password verifier produced by a password hashing function.

```text
User's password
       |
       v
Password hashing function
       |
       v
Stored password verifier
```

During login:

```text
User submits password
       |
       v
Server retrieves stored verifier
       |
       v
Password hashing library verifies password
       |
       v
Match or no match
```

The application does not need to retrieve the original password from the database. A secure password hashing library handles the verification process. However, hashing a password is not enough on its own. The application must use a password hashing algorithm designed to resist offline guessing, which is the subject of the next lesson.

### Lesson 1.2: Password Hashing, Not All Hashes Are Suitable

A cryptographic hash function transforms input into a fixed size output. Traditional cryptographic hashes such as SHA256 are designed to calculate hashes efficiently. That efficiency is useful for many applications, but it creates a problem for password storage.

**Why fast hashing is dangerous for passwords.** Suppose an attacker obtains a database containing password hashes. The attacker can guess offline: guess a password, calculate its hash, compare the calculated hash with the stolen hash, and if they match, the guess is likely correct. Repeat. A fast hash allows the attacker to test enormous numbers of guesses.

Consider this vulnerable implementation:

```python
import hashlib

def store_password(password):
    return hashlib.sha256(password.encode()).hexdigest()
```

This code hashes a password, but it does not use a password specific hashing algorithm, and it does not include a salt. It is unsuitable for production password storage. The problem is not that SHA256 is broken. The problem is that it is too fast for this particular job.

**The correct family of algorithms.** Modern password storage options include Argon2id, generally the preferred starting point for new applications; scrypt, designed to impose significant memory and computational costs; bcrypt, an established option with limitations that must be understood, including its input length handling; and PBKDF2, a key derivation function with configurable work factors. These algorithms make password guessing more expensive through configurable computational work, and some also impose significant memory costs. No algorithm makes weak passwords impossible to guess. The goal is to make large scale guessing substantially more expensive.

A better implementation using the Argon2 library:

```python
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

password_hasher = PasswordHasher()

def hash_password(password: str) -> str:
    return password_hasher.hash(password)

def verify_password(password: str, stored_hash: str) -> bool:
    try:
        return password_hasher.verify(stored_hash, password)
    except VerifyMismatchError:
        return False
```

This illustrates the correct general approach, but production code also needs appropriate error handling, parameter selection, account protections, and dependency management. The library generates a salt and encodes the necessary verification parameters into its stored representation. You should not invent your own password hashing algorithm.

**What a security reviewer should examine.** Look for plaintext password storage, direct use of SHA256, SHA1, or MD5 for password verification, unsalted password hashes, inadequate hashing work factors, home grown hashing schemes, passwords accidentally written to logs, weak or outdated dependencies, password hashes exposed through APIs or debugging endpoints, and inconsistent password hashing across registration, password changes, imports, and account migration. Finding `sha256()` somewhere in an application does not automatically establish a password storage vulnerability, since SHA256 may be used for unrelated purposes. You must trace how the function is used. The bug hunter's lesson is to identify the data flow, not just a suspicious function name.

### Lesson 1.3: Salting, Why Identical Passwords Should Not Produce Identical Stored Hashes

A salt is a unique, randomly generated value associated with a password hash.

Consider two users, User A and User B, who both choose the password `BlueRiver!2026`. Without salts, a deterministic hashing algorithm produces the same output for both users. An attacker who obtains the database can immediately see that those accounts share a password, assuming the hashes use the same algorithm and parameters.

A salt changes the calculation:

```text
User A:
Password + Salt A -> Password verifier A

User B:
Password + Salt B -> Password verifier B
```

Even though the passwords are identical, the stored verifiers differ because the salts differ.

**What a salt accomplishes.** It helps prevent attackers from using one precomputed hash result against many accounts, and it makes precomputed rainbow table attacks much less useful against properly salted hashes. However, a salt does not make a weak password strong. If a password is `password123`, an attacker can still guess it and test the guess against the stored verifier. The salt makes each account's calculation distinct, it does not eliminate guessing.

**Does the salt need to be secret?** No. A password salt is normally stored alongside the password verifier. Its security purpose does not depend on secrecy. A typical stored record might conceptually contain:

```text
algorithm: Argon2id
parameters: [work factor settings]
salt: [unique random value]
verifier: [derived output]
```

A reputable password hashing library usually manages the salt and encoded format.

**What to flag in a security review.** Investigate whether every password hash gets a unique salt, whether salts are generated using appropriate randomness, whether the application has incorrectly implemented its own salt scheme, whether the system uses one static salt for all users, and whether a custom implementation stores the salt but fails to incorporate it into verification. A static salt shared by every user is not equivalent to a unique salt per password.

### Lesson 1.4: Peppering, an Additional Layer of Protection

A pepper is a secret value used as an additional protection for password verification. Unlike a salt, a pepper is intended to remain secret and should generally be stored separately from the password database, such as in a properly managed secrets system.

Conceptually:

```text
Password + Salt + Secret pepper
                 |
                 v
         Password verifier
```

Implementation details depend on the selected password hashing scheme and library. Do not simply concatenate a secret to a password and assume the result is secure.

**What does peppering protect against?** Imagine an attacker steals a database backup but does not obtain access to the application's secret management system. If the application has implemented peppering correctly, the attacker may have an additional obstacle when attempting offline password guesses.

**What does peppering not protect against?** Peppering does not automatically protect against an attacker who can execute code in the application environment, theft of both the database and the pepper, credential stuffing against the live login endpoint, weak passwords that are successfully guessed through online attacks, or poor account recovery procedures. Peppering also creates an operational challenge: losing the pepper can affect password verification, so key management and migration planning matter.

**Bug bounty relevance.** Peppering is usually not a standalone bug bounty requirement. You should not report an application merely because it does not use a pepper. Focus on demonstrable weaknesses such as plaintext password exposure, inappropriate password hashing, or exposed password verifiers combined with other evidence.

### Lesson 1.5: Password Hashing Cost Parameters

Password hashing algorithms allow the application to configure the amount of work required to calculate or verify a password. For Argon2id, relevant parameters include memory cost, time cost, and degree of parallelism. For bcrypt, the work factor controls the computational effort. For PBKDF2, the iteration count is an important parameter.

**Why does this matter?** Suppose a password hashing configuration is so weak that a stolen verifier can be tested very quickly. An attacker can try more guesses in a given period. Increasing the cost makes each guess more expensive, which can make offline attacks significantly harder. But the application must also be able to handle legitimate logins. If password verification is configured too aggressively, attackers may be able to consume excessive server resources by triggering many expensive verifications.

The security engineer must balance resistance to offline guessing, legitimate login latency, server capacity, the application's threat model, and the selected algorithm's recommended parameters. Use current recommendations from the algorithm's maintainers and authoritative security guidance rather than copying a fixed parameter value from an old tutorial.

**Password hash upgrades.** Password hashing parameters may become outdated as hardware improves. Many libraries support checking whether a stored hash needs rehashing. A common strategy is to verify the submitted password using the existing stored verifier, determine whether the verifier uses outdated parameters, and if necessary generate a new verifier using the current parameters, storing the upgraded verifier after successful authentication. This allows gradual upgrades without requiring every user to reset their password immediately.

### Lesson 1.6: Credential Stuffing

Credential stuffing is the automated use of previously compromised username password pairs against another service. It relies on password reuse.

Imagine a fictional shopping platform, `https://shop.example`. A user has an account there with `user@example.com` and password `RiverStone!44`. The same person uses that password on another website. The other website suffers a breach, and the credentials become available to criminals. An attacker then tries the stolen combination against the shopping platform. The attacker does not need to guess the password, because it has already been obtained elsewhere.

**Why credential stuffing succeeds.** Common contributing factors include password reuse, no effective detection of automated login attempts, weak rate limiting design, poorly protected accounts without multi factor authentication, lack of suspicious login monitoring, login systems that allow excessive attempts across many accounts, and inadequate protection against automated traffic.

Credential stuffing is different from traditional brute force.

| Attack | Main strategy |
|---|---|
| Brute force | Try many possible passwords, often against one account or a limited set of accounts |
| Password spraying | Try a small number of common passwords against many accounts |
| Credential stuffing | Try username password pairs obtained from previous compromises |

These techniques can overlap in real attacks, but their defining strategies differ.

**How a bug hunter assesses credential stuffing defenses.** Your goal is not to launch a massive credential attack. It is to evaluate whether the application's controls behave correctly using an authorized test account and the approved scope.

1. **Rate limiting.** Does the system limit repeated failed attempts? Look for controls that account for more than one dimension, such as the target account, the source IP or network, the device or session, and broader automated abuse signals. An IP only limit may be ineffective against distributed attempts. An account only limit can create a denial of service opportunity if someone can repeatedly lock another user's account. Neither dimension should be assumed sufficient by itself.

2. **Authentication failure handling.** Does the system respond safely when a login fails? A failed login should not disclose sensitive details about the password, internal account state, or authentication configuration. However, generic error messages alone do not stop credential stuffing, since attackers can still determine whether a credential works by observing successful authentication.

3. **Multi factor authentication coverage.** Is multi factor authentication consistently enforced for accounts that require it? Multi factor authentication can reduce the usefulness of a stolen password, but it is not a complete defense. Attackers may attempt phishing, authentication fatigue, recovery abuse, or theft of an authenticated session, which are covered in later phases.

4. **Detection and response.** Does the system recognize patterns such as many accounts receiving login attempts from related infrastructure, a single account receiving attempts from numerous sources, sudden unusual login activity, successful authentication following a suspicious series of failures, or repeated attempts using known compromised credentials where the organization has a suitable detection mechanism? The correct response depends on the risk and may include throttling, additional verification, risk based challenges, notifications, or temporary protective measures. Avoid assuming every unusual IP address indicates an attack.

5. **Password reuse controls.** The application may offer compromised password screening during registration and password changes. Such screening should use an appropriate privacy preserving integration or trusted service, and the application should not expose user passwords to an arbitrary third party.

**Realistic fictional example.** Suppose a login endpoint returns:

```http
POST /login HTTP/1.1
Host: shop.example
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "RiverStone!44"
}
```

The server returns:

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "authenticated": true
}
```

This response establishes that the supplied credentials were accepted in this fictional example. It does not establish a credential stuffing vulnerability on its own. To report a vulnerability, you would need evidence of a specific weakness in the application's controls and a meaningful impact within the authorized testing scope. Your report should describe the demonstrated weakness, evidence, affected accounts or functionality, realistic impact, and remediation. Do not claim a confirmed account takeover merely because a login endpoint accepts valid credentials.

### Lesson 1.7: Password Spraying

Password spraying is a different attack strategy. Instead of trying many passwords against one account, the attacker tries a small number of common passwords against many accounts.

Imagine an organization with hundreds of employee accounts. The attacker tries one weak password across many usernames, then waits before trying another.

**Why attackers use this approach.** Some applications have account specific lockout policies. Repeatedly guessing many passwords against one account may trigger a lockout quickly. Password spraying distributes attempts across multiple accounts, potentially avoiding simple per account thresholds.

**What makes a defense effective?** A mature defense considers more than the number of failures against an individual account. It can correlate failed logins across many accounts, repeated use of the same password candidate where observable through appropriate controls, source network behavior, unusual geographic or device patterns, authentication outcomes over time, and signals from identity and security monitoring systems. Do not build security monitoring that logs plaintext passwords just to detect spraying. The system should use safe event metadata and appropriate detection strategies.

**What should a security engineer look for?** During an authorized assessment, evaluate whether the system has effective per account protections, protections against distributed login attempts, detection of abnormal failure patterns, appropriate multi factor authentication enforcement, safe and useful authentication logging, and account lockout behavior that cannot be trivially abused to lock out other users.

**The account lockout trade off.** Locking an account after a small number of failures can slow some attacks, but it can also allow an attacker to deliberately lock out legitimate users. A better design may combine progressive delays, throttling, risk based verification, and monitoring instead of relying exclusively on permanent or easily triggered lockouts. The guiding security principle is to make automated guessing expensive without giving attackers an easy way to deny service to other users.

### Lesson 1.8: Default and Hardcoded Credentials

These two weaknesses are related but distinct.

**Default credentials** are supplied by a product or installation process and remain active because they were not changed. Examples might include a vendor's initial administrator account or a predictable password configured during deployment. The vulnerability arises when those credentials remain usable in an environment where they should have been changed, disabled, or securely provisioned.

Where should you look during a code review? Examine initial administrator creation, installation and first run workflows, development and staging deployments, container images and deployment templates, documentation containing example credentials, demo accounts, recovery and maintenance accounts, and third party components integrated into the application. A documented example password is not automatically a vulnerability. The important question is whether it can authenticate to the deployed system.

**Hardcoded credentials** are secrets embedded in source code, configuration, build artifacts, or other distributed application materials. For example, consider this fictional code:

```python
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "Summer2025!"
```

The application might compare submitted credentials directly against those values. This is dangerous because the secret may be recoverable from public source repositories, leaked private repositories, application packages, container images, build artifacts, backup archives, or deployed source maps and other accidentally exposed materials. The exact exposure depends on the application's architecture and deployment.

**Why environment variables are not the entire solution.** Moving a secret out of source code is a useful improvement, but merely placing it in an environment variable does not guarantee security. Secrets can still be exposed through misconfigured deployment systems, excessive process permissions, debug output, logs, deployment metadata, or compromised application hosts. Production credentials should be managed through an appropriate secret management process, with access controls, rotation, monitoring, and separation between environments.

**How to assess impact.** If you discover a hardcoded secret, determine what it actually grants access to. Ask whether it is active, whether it is production or development only, whether it authenticates a user, administrator, service, or database, what permissions the associated identity has, whether the secret can be used remotely, whether it has been rotated, and whether there is evidence that it was exposed. Do not report every string resembling a password as a confirmed credential vulnerability. Validate its purpose and exposure safely. If a production secret is confirmed to be exposed, remediation generally involves removing the exposure and rotating or revoking the affected credential. Removing it from the latest commit does not erase copies that may already exist in repository history or downloaded artifacts.

### Lesson 1.9: Weak Password Change Verification

A password change endpoint is security sensitive because it changes the credential that protects an account.

Consider this fictional endpoint:

```http
POST /account/change-password HTTP/1.1
Host: shop.example
Content-Type: application/json
Cookie: session=REDACTED

{
  "current_password": "OldPassword!44",
  "new_password": "NewPassword!88"
}
```

A sound implementation normally requires appropriate proof that the requester is authorized to change the password. Depending on the application's risk and authentication design, this may involve a valid authenticated session, verification of the current password, recent reauthentication, multi factor authentication or step up authentication for high risk circumstances, and appropriate checks on the account's current state. The exact requirements depend on the threat model and product design.

**Vulnerable pattern.** Imagine a server that receives a password change request and updates the password without verifying the current password or requiring another adequate proof of control. That can create a serious problem if an attacker gains access to a session through a limited compromise or if another weakness permits unauthorized requests to reach the endpoint. However, the failure to request the current password is not automatically a vulnerability in every design. A system might use a strong recent reauthentication mechanism or another suitable proof. The security question is whether the application has sufficient evidence that the requester is entitled to make this sensitive change.

**Another failure: verifying the wrong account.** Consider this conceptual implementation:

```python
async def change_password(session, new_password):
    user = await find_user(session.user_id)
    await update_password(user.id, new_password)
```

This code is not necessarily vulnerable solely because it is short. The security critical question is whether the surrounding flow adequately verifies the requester's authority and freshness of authentication. If a developer assumes that any valid session is sufficient for every sensitive action, that assumption may be unsafe. For example, an application might require recent authentication for password changes but fail to enforce that requirement on one alternative endpoint.

**What should be tested?** Within an authorized assessment, examine whether the current account is correctly identified, whether the request requires appropriate proof of control, whether recent authentication is enforced where necessary, whether multi factor authentication requirements are preserved, whether errors leave the account in a consistent state, whether existing sessions and persistent tokens are handled appropriately after the change, and whether notifications inform the legitimate user of sensitive changes. The last point matters because changing a password is not the end of the security operation. The application must also decide what happens to sessions and tokens that were issued before the change. Session revocation is covered in later phases.

### Lesson 1.10: Security Questions

Security questions were historically used as an alternative way to recover accounts. Examples include "What city were you born in?", "What was your first school?", and "What is your mother's maiden name?"

The problem is that these answers are often not secret. They may be publicly discoverable, available on social media, guessable, reused across multiple services, vulnerable to social engineering, and easy to infer from personal information. A system that treats a predictable answer as equivalent to a strong authentication factor may allow account takeover.

**Why security questions are not a strong substitute for multi factor authentication.** A meaningful authentication factor should provide appropriate assurance that the person attempting to authenticate controls the relevant credential or device. Security question answers often lack sufficient secrecy and uniqueness to provide that assurance. They also tend to remain unchanged for long periods, which increases the risk of exposure and reuse.

**If an application still uses them.** A security review should examine whether answers are required to be guessable personal facts, whether attempts are restricted, whether answers are stored securely, whether the answers can independently authorize a sensitive action, whether the application has stronger recovery alternatives, whether changing the recovery method requires adequate verification, and whether support staff can bypass the normal recovery controls without sufficient safeguards. Hashing answers can reduce the consequences of database exposure, but it does not make predictable answers unpredictable.

**Better account recovery design.** Prefer recovery mechanisms that provide stronger evidence of control, such as appropriately secured recovery codes, verified recovery channels, or a carefully designed identity verification process. Recovery must be designed as part of the authentication system, not as an exception that bypasses it. The critical principle is that an attacker should not be able to defeat a strong login mechanism simply by choosing a weaker recovery path.

### Lesson 1.11: Brute Force Attacks

**What is brute force?** A brute force attack attempts multiple possible passwords until one works. Suppose a fictional application has this login endpoint:

```http
POST /login HTTP/1.1
Host: accounts.example
Content-Type: application/json

{
  "username": "emmanuel",
  "password": "Guess123!"
}
```

The application responds:

```http
HTTP/1.1 401 Unauthorized
Content-Type: application/json

{
  "message": "Invalid credentials"
}
```

An attacker may repeatedly submit different passwords for the same username. Unlike credential stuffing, the attacker does not necessarily need a previously stolen password list. They may generate guesses from common passwords, likely patterns, or information about the target.

**Why brute force sometimes succeeds.** Common causes include weak passwords, excessive permitted login attempts, no meaningful throttling, poor password policies, missing multi factor authentication where stronger authentication is required, predictable temporary passwords, weak account recovery controls, and inconsistent protections across login endpoints. A long password is not automatically secure if it is predictable, reused, or exposed elsewhere. Likewise, a strong password does not compensate for an authentication system that accepts unlimited attempts without appropriate safeguards.

**Understanding the mathematics.** Assume an attacker has a search space of N equally likely passwords and can test R guesses per second. Under a simplified model, the worst case time to exhaust the search space is:

```text
T_max = N / R
```

If the correct password is equally likely to appear anywhere in the search space, the average search time is approximately:

```text
T_average = N / (2R)
```

These formulas are illustrative. Real attackers usually prioritize likely passwords rather than test every possibility uniformly. For online attacks, the actual rate is also affected by throttling, network delays, detection, and other controls. For offline attacks against stolen password hashes, the rate depends heavily on the hashing algorithm, its parameters, and the attacker's hardware. The critical distinction is that online guessing and offline password cracking are different attack scenarios and require different primary defenses.

**How to assess brute force protection.** As an authorized tester, evaluate whether repeated failures trigger appropriate throttling, whether limits apply consistently across login routes, whether an attacker can trivially evade a limit by changing a request field, whether limits account for distributed attempts, whether the application creates a denial of service risk through aggressive account lockouts, and whether suspicious successful logins are detected. Do not infer a vulnerability simply because the application allows several failed attempts. A few failures may be normal. The question is whether the controls are adequate for the system's risk and whether a meaningful weakness can be demonstrated.

**Remediation.** Use layered protections. Enforce sensible password requirements and screen against commonly compromised passwords. Apply adaptive throttling and abuse detection. Use multi factor authentication where appropriate. Detect suspicious authentication patterns. Avoid relying exclusively on account lockouts. Alert users to significant suspicious activity. Protect password verifiers against offline guessing. There is no single universal attempt limit that is appropriate for every application.

### Lesson 1.12: Password Hash Migration and Upgrade Failures

Password hash migration is the process of moving stored password verifiers from an old algorithm or configuration to a more secure one. This is important because an application may have accumulated years of password records.

Imagine a legacy application stores passwords using a fast hash:

```python
def verify_password(password, stored_hash):
    return sha256(password) == stored_hash
```

The application is redesigned to use Argon2id. What happens to existing users? The server generally cannot convert an old password hash directly into a new password hash equivalent to the user's original password, since it does not know the original password. Instead, a common migration strategy is to upgrade the stored verifier when the user successfully authenticates.

**Secure migration pattern.**

1. The user submits their password.
2. The server retrieves the existing password verifier.
3. The server verifies the password using the appropriate legacy verification mechanism.
4. If verification succeeds, the application generates a new verifier using the approved modern algorithm and parameters.
5. The application replaces the legacy verifier.
6. Subsequent logins use the new verifier.

**What can go wrong?**

*Failure A: Legacy verification remains permanently enabled.* The application continues accepting accounts using the weak legacy scheme indefinitely, even when they could have been migrated or reset. This leaves those accounts exposed to the weaknesses of the old design.

*Failure B: The migration silently changes the password.* A badly implemented migration might treat a legacy hash as if it were the original password and hash that value again without preserving a compatible verification process. The user's original password will then fail verification.

*Failure C: The application weakens the new verifier.* The migration introduces the new algorithm but uses inappropriate parameters or a broken implementation.

*Failure D: Password resets fail to migrate.* Registration uses Argon2id, but a password reset endpoint writes passwords using the old hashing function. The application is now inconsistent: one route produces secure verifiers, while another reintroduces the legacy weakness.

**Source code review.** When reviewing password storage, trace every path that creates or changes a password, including registration, password change, password reset, administrative password reset, account import, legacy account migration, account recovery, and any supported synchronization process. A secure registration endpoint does not prove that the entire application uses secure password storage. The rule is that every password writing path must follow the approved password storage design.

## Assessment

The following assessment is drawn from "Authentication Security.md" and addresses the same subject as Lessons 1.6 and 1.7, credential attack defenses and the specific trust boundary problem of rate limiting that trusts attacker controlled client identity information. In keeping with the project's rule for assessment material, the questions below are preserved from the original source, and the answers given are the instructor's corrected, authoritative answers rather than the original learner's submitted answers.

### Assessment Question 1

A fictional banking application has this login endpoint:

```http
POST /api/auth/login HTTP/1.1
Host: securebank.example.test
Content-Type: application/json

{
  "email": "alice@example.test",
  "password": "WrongPassword123!"
}
```

Response:

```http
HTTP/1.1 401 Unauthorized

{
  "message": "Invalid email or password"
}
```

You submit 100 incorrect passwords for the same account. Every request returns 401 Unauthorized. There is no CAPTCHA, temporary lockout, delay, or visible throttling.

Does the fact that all 100 requests return 401 prove that the application has no rate limiting? What additional evidence would you need before reporting this as a vulnerability?

<details markdown="1">
<summary><strong>Reveal Answer</strong></summary>

No, 100 consecutive accepted incorrect attempts does not conclusively prove that rate limiting is absent, even though it is suspicious evidence of inadequate protection. Rate limiting might activate only after 100 attempts, might apply per IP address rather than per account, might apply per account rather than per IP, might return 429 Too Many Requests only after a threshold is crossed, or might introduce delays without outright blocking requests. Before concluding that rate limiting is missing, you need to continue testing past the point you stopped at, and observe whether a threshold eventually triggers a 429 response, an account restriction, or a progressive delay.

It is also important to distinguish three related but separate concepts: brute force is trying many passwords against one account, credential stuffing is trying previously exposed username and password combinations, and rate limiting is the control that restricts how frequently authentication attempts can occur. You do not need to perform credential stuffing with a leaked wordlist to test whether rate limiting works. For an authorized assessment, a controlled, bounded series of repeated invalid attempts against your own test account is sufficient evidence.

</details>

### Assessment Question 2

Suppose you observe the following pattern during that same test:

```text
Attempts 1 through 20: 401
Attempts 21 through 50: 401
Attempts 51 through 100: 401
Attempt 101: 429 Too Many Requests
```

Would you report this as a missing rate limiting vulnerability? Explain your reasoning, considering whether the protection is effective rather than simply whether it exists.

<details markdown="1">
<summary><strong>Reveal Answer</strong></summary>

No, this would not be reported as a missing rate limiting vulnerability, because rate limiting clearly exists here: the application allows 100 attempts and then blocks the 101st. The presence of a threshold is not in question.

The more senior question is whether that threshold is secure, and that depends on the application's risk profile, the sensitivity of the protected account, the realistic attack conditions, and any additional protections in place. There is no universally correct number of permitted attempts. A banking application protecting high value accounts might need a far lower threshold than a low risk consumer application. Before drawing a conclusion about whether 100 attempts is an adequate threshold, you would need to understand the application's threat model, whether the limit is enforced per account, per source, or both, and whether other compensating controls exist, such as multi factor authentication on the account.

A related, equally important question is whether the control can be bypassed, which is addressed in the next assessment question.

</details>

### Assessment Question 3

You discover the following behavior in a fictional banking application:

```http
POST /api/auth/login HTTP/1.1
Host: securebank.example.test
X-Forwarded-For: 192.0.2.10
Content-Type: application/json

{
  "email": "alice@example.test",
  "password": "WrongPassword123!"
}
```

Response:

```http
HTTP/1.1 401 Unauthorized

{
  "message": "Invalid email or password"
}
```

After repeated attempts, the application returns:

```http
HTTP/1.1 429 Too Many Requests
Retry-After: 300

{
  "message": "Too many attempts"
}
```

However, when the forwarding header changes, the counter appears to reset. What is your primary vulnerability hypothesis, and what specific evidence would you collect to distinguish a genuine proxy trust misconfiguration from an intentionally supported proxy configuration?

<details markdown="1">
<summary><strong>Reveal Answer</strong></summary>

The primary hypothesis is that the application's rate limiter is identifying the client by trusting the client supplied `X-Forwarded-For` header rather than by using a value the server can actually verify. If so, the rate limiting state can be bypassed simply by changing that header, because the application is using attacker controlled client identity data to decide which rate limit bucket a request belongs to.

To establish this as a real finding rather than a theoretical observation, you need controlled evidence using your own test account. The sequence is: using one claimed identity, repeatedly fail login until you receive 429 Too Many Requests. Then, using the same test account but a different `X-Forwarded-For` value, observe whether the requests become 401 again rather than remaining blocked. Repeat with several controlled header values and confirm the behavior is consistent. If the counter resets every time the header changes, you have demonstrated something considerably stronger than "the X-Forwarded-For header exists." You have demonstrated that the authentication rate limiter trusts attacker controlled client identity data, which allows the rate limit state to be bypassed entirely.

One important refinement is necessary for precision. `X-Forwarded-For` can legitimately be trusted when the application sits behind a correctly configured, trusted reverse proxy or load balancer that itself controls and sanitizes the header before the request reaches the application. The actual vulnerability is specifically the application blindly trusting a client controlled forwarding header in circumstances where the client can reach the application directly, without a trusted proxy guaranteeing that the header's value is accurate. Distinguishing the two requires confirming, through the application's deployment architecture, whether an untrusted client can actually reach the authentication endpoint without passing through the trusted proxy that is supposed to set that header.

</details>

## Remediation and Secure Implementation

The following table consolidates the remediation guidance from across all twelve lessons in this phase.

| Area | What can go wrong | What a secure design should do |
|---|---|---|
| Registration | Password stored in plaintext | Use a suitable password hashing function |
| Password hashing | Fast or outdated hashing | Use a modern password specific algorithm and appropriate parameters |
| Salting | Shared or missing salt | Use a unique salt through a reputable library |
| Peppering | Secret exposed alongside database | Keep the pepper separate and manage it securely |
| Credential stuffing | Reused credentials accepted at scale | Combine throttling, multi factor authentication, monitoring, and risk appropriate protections |
| Password spraying | Distributed guessing evades simple limits | Detect patterns across accounts and sources |
| Brute force | Excessive guessing attempts | Apply layered throttling and abuse detection |
| Default credentials | Initial credentials remain active | Require secure provisioning and remove unsafe defaults |
| Hardcoded credentials | Secrets leak through source or artifacts | Use managed secrets, least privilege, and rotation |
| Password change | Insufficient proof of control | Require appropriate authentication and reauthentication |
| Security questions | Predictable answers enable recovery | Use stronger recovery mechanisms |
| Password hash migration | Weak parameters persist indefinitely | Upgrade verifiers safely after successful authentication |
| Logging | Passwords or secrets enter logs | Log security events without recording authentication secrets |

## Key Takeaways

This phase rests on one governing distinction that you should carry forward into every later phase: there are three separate attack surfaces, and a defense built for one does not protect the others.

**Offline password attacks.** The attacker has obtained password verifiers and attempts to recover passwords without interacting with the live login endpoint. Primary defenses are suitable password hashing, unique salts, appropriately configured work factors, and protecting the password database itself.

**Online credential attacks.** The attacker repeatedly submits passwords to the live application, whether through brute force, password spraying, or credential stuffing. Primary defenses are effective throttling, abuse detection, multi factor authentication, safe account lockout design, and monitoring that correlates signals across accounts and sources, not just within a single account.

**Credential lifecycle weaknesses.** The attacker exploits how credentials are created, changed, recovered, stored, or revoked, including default and hardcoded credentials, weak password change verification, weak security question recovery, and incomplete password hash migration. Primary defenses are secure provisioning, suitable verification at every state transition, robust recovery procedures, and consistent enforcement across every credential management path, not merely the main login form.

A strong password hashing algorithm does not stop an attacker from testing stolen credentials against a live login endpoint. Rate limiting does not repair plaintext password storage. A mature authentication system needs appropriate controls across all three surfaces at once.

## Review Checklist

- [ ] Can you explain why plaintext password storage is a critical failure even if the login page itself is secure?
- [ ] Can you name the password hashing algorithm family suitable for new applications, and explain why SHA256 alone is not suitable?
- [ ] Can you explain what a salt protects against, and confirm that a salt does not need to be secret?
- [ ] Can you explain what a pepper adds beyond a salt, and what a pepper does not protect against?
- [ ] Can you explain the trade off between a hashing cost parameter that is too low and one that is too aggressive?
- [ ] Can you distinguish credential stuffing, password spraying, and brute force by their defining strategy, not just by name?
- [ ] Can you distinguish default credentials from hardcoded credentials as separate root causes?
- [ ] Can you explain why a password change endpoint needs a defined proof of authorization, and why that proof is not always "the current password"?
- [ ] Can you explain why security questions are a weak recovery mechanism compared to multi factor authentication?
- [ ] Can you list the four specific ways a password hash migration can fail?
- [ ] Can you explain why 100 accepted failed login attempts does not, by itself, prove that rate limiting is absent?
- [ ] Can you explain how a client supplied forwarding header can undermine a rate limiter's trust boundary, and what controlled evidence would prove it?

## References to Related Phases

- Session handling after a password change or password reset is introduced in Lessons 1.9 and 1.12 but is covered in full in **Phase 6, Cookie and Session Security**.
- Multi factor authentication as a complementary defense against credential attacks is introduced throughout this phase but is covered in full in **Phase 3, MFA Attacks**.
- Account recovery mechanisms beyond security questions, including password reset token security, are covered in **Phase 2, Password Change and Account Recovery**.
- The trust boundary problem demonstrated in the assessment, an application trusting a client supplied header, recurs in a different context in later phases dealing with proxy trust and client controlled identity data.
