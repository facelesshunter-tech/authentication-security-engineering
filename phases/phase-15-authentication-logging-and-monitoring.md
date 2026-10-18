# Phase 15: Authentication Logging and Monitoring

**Source material:** Module 15 of 17, "Authentication Complete Phases Test.md" (27 numbered sections covering authentication logging and monitoring, and the course tracker). As with several earlier phases, "Authentication Security.md" contains no logging or monitoring content. The Assessment section in this phase is instead built from the module's own embedded material, Section 23's vulnerable logging implementation review and Section 24's safer redesign, using the module's own given findings as the answer.

## Learning Objectives

After completing this phase, you should be able to:

1. Explain why authentication enforcement and authentication monitoring are separate controls, neither replacing the other, and why a correctly authenticating system can still leave an organization unable to investigate a compromise.
2. Distinguish logging, monitoring, and alerting as three related but non-identical functions, and trace how an application event becomes an alert through the module's six-stage pipeline.
3. Identify the full set of authentication lifecycle events worth logging, beyond login success and failure, and explain why each state transition is separately security-relevant.
4. Design a structured log record with the seven important field categories: timestamp, event type and action, outcome, account reference, authentication method, correlation identifier, and source/client context.
5. List what must never appear in an authentication log, passwords, MFA codes, session identifiers, OAuth tokens, private keys, and unfiltered request bodies, and explain why post-collection redaction is insufficient.
6. Explain how logging and monitoring implementations can themselves contribute to account enumeration, and design an architecture that preserves useful internal distinctions without exposing them externally.
7. Distinguish credential stuffing, password spraying, and brute force by their detection signals, and explain why per-account failure counts alone can miss distributed attacks.
8. Explain why monitoring account recovery, MFA changes, and session lifecycle events matters as much as monitoring login itself, and design a detection rule for a suspicious sequence of high-risk changes.
9. Evaluate the three logging-failure response strategies, fail-open, fail-closed, and durable buffering, and explain why the correct choice depends on the specific operation's risk.
10. Explain log integrity protection, log injection, and safe exception handling as three distinct logging-pipeline risks, each requiring a different defense.
11. Apply the module's 8-question incident-response framework to reconstruct an authentication event from logs without relying on raw credentials.
12. Apply the Phase 1 through Phase 14 impact-validation discipline to logging findings: distinguish a logging defect from an authentication vulnerability, and establish what must be proven for each of the module's nine observation types.

## Introduction

Every earlier phase in this course studied how authentication can fail at the moment it happens: a forged assertion, a missing membership check, a session that outlives its revocation. This phase studies a different kind of failure, one that doesn't let an attacker in, but leaves the organization unable to find out that they got in at all. The module opens with a deliberately simple scenario: an attacker phishes a password, fails MFA repeatedly, eventually authenticates, creates a persistent session, and accesses sensitive data. The next morning, the only record of any of it is a single line: `LOGIN SUCCESS`. The application authenticated correctly. It just left no evidence of anything that mattered.

The governing distinction this phase draws, and returns to constantly, is that authentication enforcement prevents or limits unauthorized access, while authentication monitoring helps detect suspicious activity and investigate what happened. Neither replaces the other. Logging a failed login does not stop brute force. Blocking brute force does not guarantee the organization can investigate a successful compromise. This phase also carries forward a second discipline from every earlier phase, applied here to the logs themselves: a logging pipeline that captures real secrets to "help investigations" has not improved security, it has built a second, often less protected place for an attacker to steal credentials from. The entire module is a balance between these two failure modes, logging too little to investigate anything, and logging so much that the logs themselves become the vulnerability.

## Core Concepts

The module moves through five stages. First, sections 1 through 4 establish the fundamentals: why logging matters, how logging, monitoring, and alerting differ, what the full authentication lifecycle looks like, and how to structure a log record usefully. Second, sections 5 through 7 address the opposite risk: what must never be logged, why redaction after the fact is not enough, and how logging itself can leak account existence. Third, sections 8 through 15 build detection capability across every stage of the authentication lifecycle: credential stuffing, password spraying, brute force, MFA fatigue, account recovery and MFA changes, session lifecycle events, federated authentication, and recovery-endpoint enumeration. Fourth, sections 16 through 22 address the logging pipeline's own risks: what happens when logging infrastructure fails, log integrity and tampering, log injection, exception handling, building useful detection rules, incident response, and privacy and retention. Fifth, sections 23 through 27 bring the module together into a practical discipline: a complete vulnerable-implementation review and its redesign, a full assessment checklist, the logging-defect-versus-vulnerability distinction, and the final ten principles.

## Lessons

### 1. Why Authentication Logging Matters

Imagine an attacker obtains an employee's password through a phishing attack. The attacker attempts to sign in from an unfamiliar device, repeatedly fails MFA, eventually authenticates, creates a persistent session, and accesses sensitive information. The organization investigates the following morning. Unfortunately, the application recorded only `2026-10-17 01:42:08 LOGIN SUCCESS`. There is no account identifier, no authentication method, no MFA result, no session identifier for correlation, no source information, and no record of subsequent security-sensitive activity.

The security team cannot reliably determine which account was accessed, whether MFA was completed, whether the login was expected, whether the session was newly created or reused, whether account recovery occurred, whether the attacker created another authentication method, or whether the session was subsequently revoked. The application may have authenticated users correctly while still providing insufficient evidence to investigate attacks. This illustrates an important distinction: authentication enforcement prevents or limits unauthorized access, authentication monitoring helps detect suspicious activity and investigate what happened. Neither replaces the other. Logging a failed login does not stop brute force. Blocking brute force does not guarantee that the organization can investigate a successful compromise. A mature system needs both preventive controls and useful, protected security telemetry.

### 2. Authentication Logging Versus Monitoring Versus Alerting

These terms are related, but they are not identical.

**A. Logging** records events that have occurred, for example `{"event_type": "authentication", "event_action": "login", "outcome": "failure", "reason_category": "invalid_credentials", "timestamp": "2026-10-17T01:42:08Z"}`, recording an authentication failure without storing the submitted password.

**B. Monitoring** evaluates events and their relationships to identify meaningful patterns. A single failed login may be ordinary user error. A concentrated sequence of failures across seconds may indicate password guessing, credential stuffing, a misconfigured client, or a legitimate user struggling with an outdated password. Monitoring must consider context rather than blindly equating every failure with an attack.

**C. Alerting** notifies a responsible person or system when a monitored condition warrants investigation or action, for example an alert for 18 failed attempts across 7 distinct source addresses within 5 minutes against an account with a prior successful authentication, recommending investigation. The threshold and response are illustrative. Real thresholds should be calibrated against the application, user population, and threat model.

**How they fit together.**

```text
Application event
       |
       v
Structured log
       |
       v
Collection and normalization
       |
       v
Correlation and detection rules
       |
       v
Alert or investigation
       |
       v
Response and evidence preservation
```

If the application does not generate useful events, downstream monitoring cannot reliably reconstruct them. If the logs are never collected, a perfectly designed event schema may still be operationally useless. If alerts are generated without meaningful context, analysts may become overwhelmed by false positives.

### 3. What Should Be Logged During Authentication?

A common mistake is to record only whether a login succeeded. Authentication consists of multiple state transitions, and each transition can be security-relevant:

```text
Unauthenticated
      |
      v
Primary credentials submitted
      |
      v
Primary authentication succeeds
      |
      +------> MFA required
      |              |
      |              v
      |        MFA challenge created
      |              |
      |              v
      |        MFA succeeds or fails
      |              |
      v              v
Authentication policy evaluated
              |
              v
        Session created
              |
              v
       Protected access
              |
              v
       Logout or revocation
```

A useful logging system captures the relevant events without unnecessarily exposing secrets.

**Core authentication events.**

| Event | What it helps establish |
|---|---|
| Login attempt | Authentication was attempted |
| Login success | The applicable authentication policy was satisfied |
| Login failure | An authentication attempt failed |
| MFA challenge issued | Additional verification was required |
| MFA success | The required verification succeeded |
| MFA failure | Additional verification failed |
| MFA enrollment | An authenticator was added |
| MFA removal | An authenticator was removed |
| Password changed | A credential lifecycle event occurred |
| Password reset completed | Recovery resulted in a credential change |
| Email or phone changed | An identity or recovery channel changed |
| Passkey registered or removed | A phishing-resistant credential's lifecycle changed |
| Session created | An application session was issued |
| Session revoked | A session was invalidated |
| Federated login completed | Authentication through an external identity provider succeeded |
| Logout processed | A logout action was handled |
| Account disabled | An account's authentication eligibility changed |
| Privileged role changed | A security-sensitive account state changed |

Not every application needs to log every possible event at the same level of detail. The event set should reflect the application's risks, applicable requirements, and operational needs. A consumer social application and a high-value financial application may require different detection depth and retention policies.

### 4. Structured Logs: The Foundation of Useful Monitoring

Compare a poor log, `User logged in.`, with a better structured one:

```json
{
  "timestamp": "2026-10-17T09:15:42Z",
  "event_type": "authentication",
  "event_action": "login",
  "outcome": "success",
  "account_ref": "acct_1042",
  "authentication_method": "password",
  "mfa_required": true,
  "mfa_satisfied": true,
  "application": "employee-portal",
  "request_id": "req_demo_821"
}
```

The second record provides more useful context. It also avoids including the password, MFA code, session cookie, or bearer token.

**Important fields to consider.**

*1. Timestamp.* Use a consistent time representation, preferably UTC for centralized security telemetry. Suppose the application records a login at 09:15 while the identity provider records it at 10:15 because one system uses a different timezone, an analyst may incorrectly conclude that the events occurred in the wrong order. Time synchronization and consistent timestamps improve cross-system correlation. Also distinguish the event time from the time a logging system receives the event, delays can occur during buffering or transport.

*2. Event type and action.* Use consistent categories such as `authentication.login`, `authentication.mfa`, `authentication.password_reset`, `authentication.session_revocation`. The exact naming scheme can vary. Consistency matters more than a particular string format.

*3. Outcome.* Useful outcomes include `success`, `failure`, `denied`, `error`. Do not collapse every unsuccessful event into the same category if doing so prevents meaningful analysis. An invalid password, a disabled account, and an unavailable identity provider may require different internal investigation paths. However, internal diagnostic distinctions do not necessarily need to be disclosed to the user.

*4. Account reference.* Use a stable internal identifier where appropriate. A stable account reference helps analysts correlate events even if a user changes their email address. Avoid logging unnecessary personal information when a pseudonymous identifier is sufficient.

*5. Authentication method.* Examples include `password`, `passkey`, `federated_sso`, `mfa_totp`, `mfa_security_key`, `recovery_code`. The record should accurately reflect the authentication steps that occurred. Do not record `mfa_satisfied=true` merely because the user started an MFA challenge.

*6. Request or correlation identifier.* A request ID helps connect application logs, authentication services, and gateway records, for example `req_demo_821`. It should not be a session credential or a secret that grants access.

*7. Source and client context.* Depending on the threat model, useful fields may include source IP address, user-agent information, application or client identifier, device or session reference, and network or geographic risk signals. These fields require careful handling because they may contain personal information and can be misleading. A source IP may belong to a corporate proxy, VPN, mobile carrier, or shared network. A user-agent string can be spoofed. Neither should be treated as definitive proof of identity.

### 5. What Must Never Be Logged?

This is one of the most important sections in the module. Authentication logs must provide evidence without becoming another repository of credentials. Suppose an application logs email, password, MFA code, and session cookie together in a single plaintext entry, this is dangerous because the logs now contain material that may allow an attacker or unauthorized insider to authenticate as the user. Even if the application itself is secure, the logging pipeline may introduce a separate credential-exposure path.

**A. Passwords.** Never log submitted passwords, including login passwords, password-change submissions, password-reset forms, temporary passwords, and password-confirmation fields. Even a failed login must not record the supplied password. Attackers often target logs, observability platforms, support dashboards, and developer tools because these systems may have broader access than the production authentication database. A plaintext password in a log can expose a reusable credential across multiple services if the user reused it.

**B. MFA codes.** Do not log active TOTP codes, SMS codes, email verification codes, or other reusable authentication secrets. A code may have a short lifetime, but it can still be useful during that lifetime. Recovery codes and backup codes require similar protection.

**C. Session identifiers and cookies.** A session identifier may function as a bearer credential. If an attacker obtains a valid session ID, the attacker may be able to impersonate the user, depending on the session architecture and other controls. Avoid logging full session cookies, raw bearer tokens, refresh tokens, API keys, recovery tokens, and password-reset tokens. A carefully designed system can use a non-reversible or otherwise safely managed correlation reference for investigation instead of recording the raw credential. If pseudonymization is used, its design must account for the possibility of guessing or correlating identifiers.

**D. OAuth authorization codes and tokens.** Do not log full authorization codes, access tokens, refresh tokens, or ID tokens. These values may expose authenticated access or identity information. Log the event and a safe correlation reference instead.

**E. Private keys and authenticator secrets.** Never expose private authentication keys, TOTP shared secrets, or cryptographic key material in ordinary application logs. A secret used to generate or verify authentication proofs must remain protected according to its security requirements.

**F. Sensitive request bodies.** A generic middleware component may log every incoming HTTP request body, for example `logger.info("Request body: %s", request.body)`, unintentionally capturing login passwords and recovery codes. A safer design records selected, explicitly approved fields:

```python
def log_authentication_event(event):
    logger.info(
        "Authentication event",
        extra={
            "event_type": event.event_type,
            "outcome": event.outcome,
            "account_ref": event.account_ref,
            "request_id": event.request_id
        }
    )
```

This is illustrative pseudocode. Real logging libraries and structured logging frameworks use different interfaces. The principle is to construct an allowlisted event rather than indiscriminately logging raw request data.

### 6. Log Redaction: Why Filtering After Logging Is Not Enough

Consider an architecture that logs the complete request body, stores it, and only then attempts to redact the password. This design creates a dangerous interval during which the secret may already have been written to disk, forwarded to a central logging platform, indexed, copied to a backup, included in an alert, or read by an unauthorized person. Redaction after collection may reduce exposure in the final display but does not undo every earlier copy.

A stronger design avoids capturing secrets in the first place: HTTP request flows to an authentication handler, which constructs an approved security event, which is validated and serialized, and only then enters a protected logging pipeline.

**Defense-in-depth measures.** Use allowlisted event fields. Avoid raw authentication request and response bodies. Redact sensitive headers such as `Authorization` and `Cookie`. Exclude credentials from exception messages. Review reverse-proxy and API-gateway logging. Review tracing and observability instrumentation. Check alert payloads and exported dashboards. Restrict access to security logs. Apply retention and deletion policies. Test whether secrets appear in any downstream copies. A developer may correctly redact the application log while a reverse proxy continues recording the same `Authorization` header. The whole logging path must be examined.

### 7. Account Enumeration Through Authentication Logs and Responses

This topic connects directly to Phase 12. Suppose an application produces distinct internal events for `unknown_account` and `incorrect_password`. There is nothing inherently wrong with maintaining distinct internal failure categories, provided the logs are appropriately protected. The danger arises if the application unintentionally exposes these distinctions to unauthorized users, for example returning `404 Not Found` with "Account does not exist" for an unknown account but `401 Unauthorized` with "Incorrect password" for a known one. An attacker may be able to use the difference to discover registered accounts. This is an information-disclosure issue, not necessarily a logging vulnerability. However, logging and monitoring implementations can contribute to it if they expose internal failure reasons through debug responses, client-visible event streams, support APIs, analytics endpoints, or administrative interfaces with inadequate access controls.

**Correct architectural approach.** The application may preserve useful internal distinctions while providing appropriately generic public responses: internal reason `unknown_account` or `incorrect_password`, public response "Invalid credentials" either way. The exact response strategy depends on the application and its privacy requirements. Do not remove useful internal diagnostic information merely to prevent enumeration. Instead, control where it is exposed.

### 8. Detecting Credential Stuffing

Credential stuffing occurs when attackers try username-password combinations obtained from previous breaches against another service. The attacker is not necessarily guessing every possible password, they may be testing known credential pairs. A weak monitoring system may record each failed login but never correlate them, for example six different accounts each failing once within six seconds. A single account may have only one failure, so per-account monitoring may therefore miss the broader pattern.

**What should monitoring examine?** Many distinct accounts receiving failures in a short period, high failure-to-success ratios, repeated use of previously exposed credentials where safely and lawfully detectable, concentrated attempts against a particular application, sudden changes in login failure patterns, unusual activity across multiple network sources, and successful logins following repeated failures. No single signal proves credential stuffing. A shared NAT gateway, a misconfigured application, or a legitimate organization-wide password issue may create similar patterns.

**Example detection logic:**

```python
def detect_possible_credential_stuffing(events, window):
    recent = events.within(window)

    distinct_accounts = count_distinct(
        recent.failed_logins.account_ref
    )

    total_failures = count(
        recent.failed_logins
    )

    if (
        total_failures > FAILURE_THRESHOLD
        and distinct_accounts > ACCOUNT_THRESHOLD
    ):
        create_security_alert(
            category="possible_credential_stuffing"
        )
```

The thresholds are placeholders. A production detector should consider event quality, traffic baselines, source context, successful authentications, and operational false positives.

**Why successful logins matter.** An alert that records only failures may miss the most important part of the incident: the attacker eventually authenticated. Correlate failure patterns with subsequent successes and sensitive account changes. That is often more useful than treating every failed attempt as an isolated incident.

### 9. Detecting Password Spraying

Password spraying differs from conventional brute force, as established in Phase 1. A password-spraying attack attempts a small number of likely passwords across many accounts, rather than trying a large number of passwords against one account. This pattern can avoid simplistic per-account thresholds, since each account may remain below a threshold such as five failures while the overall pattern is still suspicious.

**Detection signals.** One source attempts authentication against many accounts. Several accounts fail with a similar timing pattern. Multiple accounts receive attempts using a common password candidate, if such information can be detected without logging plaintext passwords. Authentication failures increase across a tenant or organization. A subsequent success follows a broad failure campaign.

**Important privacy and implementation point.** Do not store attempted passwords merely to determine whether many accounts received the same password. You can detect many spraying patterns using account counts, event timing, source context, and outcomes without collecting the submitted secrets. Monitoring should not create a new credential-exposure vulnerability.

### 10. Detecting Brute Force and Distributed Attacks

Brute-force attempts may target one account or many accounts. A simple detector may count failed attempts against a single account, for example 25 failures in 5 minutes. But sophisticated or distributed activity may spread attempts across multiple sources. A robust monitoring strategy can consider several dimensions.

| Dimension | What it helps identify |
|---|---|
| Per-account failures | Targeted guessing |
| Per-source failures | A source generating unusually high failure volume |
| Distinct accounts per source | Password spraying or account discovery |
| Distinct sources per account | Distributed attacks or legitimate shared access |
| Tenant-wide failure rate | Broad attacks affecting an organization |
| Failure-to-success sequence | Potential compromise following guessing |
| Authentication method | Abuse concentrated in one flow |
| Time-of-day baseline | Unusual access patterns |
| Account privilege | Potential business impact |

Rate limiting and monitoring serve different purposes. Rate limiting attempts to constrain activity in real time. Monitoring helps identify patterns, investigate incidents, and detect activity that individual rate limits may not stop. A system should not depend exclusively on a monitoring alert to stop an active credential attack.

### 11. Detecting MFA Fatigue and MFA Abuse

An attacker who possesses a user's password may repeatedly trigger MFA challenges, hoping the user eventually approves one, often called MFA fatigue or push bombing, as established in Phase 3. The monitoring system should capture the relevant events without recording the authentication secret itself, for example a structured event with `event_action: "challenge"`, `outcome: "failure"`, `reason_category: "user_denied"`.

**Potential signals.** Repeated MFA prompts within a short period. Repeated user denials. Unusual numbers of challenges for one account. Challenges generated from multiple login attempts. Successful MFA immediately after a series of denials. A new device or authentication method following suspicious activity.

**Why event correlation matters.** Imagine a sequence: password accepted, MFA challenge issued, MFA denied, challenge issued again, denied again, challenge issued a third time, approved, new session created. This sequence deserves investigation, particularly if the user did not expect the prompts. However, a successful MFA event does not prove the user knowingly approved a legitimate login. Monitoring should correlate challenge outcomes with session creation and subsequent account activity. The application should also enforce challenge limits and other preventive controls rather than relying only on alerts.

### 12. Monitoring Account Recovery and MFA Changes

Attackers may target account recovery because it can provide a route around ordinary authentication, as established in Phase 2 and Phase 4. Security-sensitive events include password-reset requests, successful password resets, email or phone changes, MFA enrollment, MFA removal, passkey registration, recovery-code generation, recovery-code use, trusted-device enrollment, and administrative account recovery.

A single event may be legitimate. A suspicious sequence can be more informative. Consider a fictional timeline: successful login, recovery email changed two minutes later, MFA authenticator removed a minute after that, new passkey registered, password changed, existing sessions revoked, all within about nine minutes. This may represent a legitimate account-security upgrade. It could also represent an attacker consolidating control over a compromised account. The logs alone do not establish which explanation is correct.

**The investigation should examine** whether the user expected the changes, whether required reauthentication occurred, whether the changes were authorized, whether the events came from the same relevant session or authentication context, whether notifications were sent, and whether the account accessed sensitive resources afterward.

**A useful detection rule.** Generate an alert when several high-risk authentication changes occur in a short period, especially when the account recently exhibited unusual login activity. Do not automatically disable every account that changes two security settings. Use risk-based responses appropriate to the system.

### 13. Monitoring Session Creation, Revocation, and Reuse

Authentication monitoring must continue after the login event, extending the session-security discipline from Phase 6. Suppose the application records a login, a session created, a password change eighteen minutes later, the session revoked one minute after that, and then the old session being accepted again one minute later still. That final event indicates a possible inconsistency. If the old session was supposed to be invalidated, continued authenticated access may represent a session-revocation flaw.

**What should be correlated?** Session creation, session rotation, session expiration, logout, administrative revocation, password changes, MFA changes, account disablement, session validation failures, reauthentication, and sensitive actions performed by the session.

**Avoid logging the raw session ID.** For investigation, a system can use a carefully designed session reference, for example `{"event_type": "session", "event_action": "created", "session_ref": "sess_ref_7f21", "account_ref": "acct_1042"}`. The reference should not itself function as an authentication credential. Depending on the architecture, it might be a random internal identifier or a protected pseudonymous reference. A simple hash of a low-entropy or predictable identifier may not provide adequate privacy. Choose the representation based on the identifier's properties and the logging threat model.

### 14. Detecting Suspicious Federated Authentication

This section connects to Phase 14. Applications using SAML or OIDC may need to correlate events across the identity provider, the application, an API gateway, a central session service, and downstream applications. Useful events include SSO initiation, authentication response received, authentication success or failure, session creation, logout initiation, logout notification received, logout notification validation failure, session invalidation, account linking or unlinking, and external identity changes.

**Example: inconsistent logout evidence.** A fictional sequence: an IdP logout event is received and its logout token validated, session revocation is requested, session invalidation fails, and roughly two minutes later a protected request is accepted. This suggests that the application may have failed to invalidate a session after a valid logout event. The protected request is important evidence, but the investigation must still establish whether it used the affected session and whether the access violated the intended policy.

**Cross-system correlation.** Use appropriate identifiers to connect related events: an internal authentication transaction reference, a session reference, a configured client identifier, a request or trace identifier, and a safe reference to a validated federated identity. Do not use raw access tokens or ID tokens as convenient correlation keys. Do not assume every system shares the same identifier format. A reliable design explicitly defines how events from different systems can be associated.

### 15. Detecting Account Enumeration and Authentication-State Leakage

Monitoring may identify attacks against registration and account-recovery endpoints. For example, a single source may submit many different email addresses to a password-reset endpoint. Potential signals include high request volume, many distinct account identifiers, repeated requests with similar timing, repeated requests to registration or recovery endpoints, unusual response patterns, and large differences in success and failure rates.

The application should avoid exposing unnecessary account-existence information to unauthenticated users where that information is sensitive. Internally, it may still record useful reason categories, for example `{"event_type": "account_recovery", "event_action": "request", "outcome": "accepted_for_processing", "account_ref": null, "request_id": "req_demo_900"}`, while a public response says "If an eligible account exists, instructions will be sent." The internal system can record the outcome of processing without unnecessarily exposing it to the requester. However, the application must not falsely record that a message was delivered when it only queued a request. Distinguish request acceptance, processing, and delivery status where operationally necessary.

### 16. Logging Failures: What If the Logging System Goes Down?

This is a more advanced design problem. Suppose authentication continues working, but the central logging service becomes unavailable. Should the application reject all login attempts, continue authenticating users, buffer events locally, degrade some high-risk operations, or trigger an operational alert? There is no universal answer. The decision depends on the application's risk, logging architecture, legal requirements, and operational constraints.

**A. Fail-open behavior.** Authentication continues even if the logging system is unavailable. Potential benefit: users can continue accessing the service. Potential risk: security events may be lost during a critical incident.

**B. Fail-closed behavior.** Certain operations are denied if required security-event recording cannot be completed. Potential benefit: the application avoids performing high-risk operations without required audit evidence. Potential risk: an attacker or infrastructure failure may create an availability problem.

**C. Durable buffering.** The application records events in a protected local queue or durable transport layer and forwards them when the logging system recovers. This can improve resilience, but it introduces additional requirements: storage limits, queue integrity, backpressure handling, secret protection, duplicate-event handling, recovery procedures, and monitoring for delayed delivery.

**A practical approach.** Classify operations by risk. An ordinary low-risk login and a privileged administrative action may have different requirements for synchronous audit recording. If a high-risk operation must have a durable audit record before it proceeds, enforce that requirement explicitly. Do not blindly block every authentication attempt whenever a centralized dashboard is temporarily unavailable. Likewise, do not silently discard all security events without a recovery strategy.

### 17. Log Integrity and Protection Against Tampering

Logs can be valuable evidence during an investigation. But what happens if an attacker who compromises an application can also delete or modify the logs? Suppose the application records a successful privileged login, a sensitive configuration change two minutes later, and then the security log being deleted a minute after that. If all three events exist only in a writable application-local file, an attacker with sufficient access may be able to alter the evidence.

**Important protections.** Centralized collection: forward security events to a separately controlled logging system, reducing dependence on the compromised application's local storage. Access control: only authorized roles should be able to read, modify, export, or delete logs, and reading logs can itself expose sensitive information, so access should be restricted and audited. Separation of duties: where appropriate, the people who administer production authentication systems should not have unrestricted ability to alter centralized audit records. Integrity protection: depending on the environment, mechanisms may include append-oriented storage, restricted deletion permissions, tamper-evident records, cryptographic integrity controls, and protected archival storage. No single mechanism guarantees perfect log integrity, a hash chain can make certain modifications detectable, but it does not solve every problem if an attacker can rewrite the entire chain and its trusted checkpoints. Time synchronization: use consistent, monitored time synchronization across systems, since inaccurate or manipulated timestamps can undermine event correlation. Retention and deletion: define retention periods and protect records against unauthorized deletion, and do not retain authentication logs indefinitely without considering privacy, storage, and applicable requirements.

### 18. Log Injection and Untrusted Input

Authentication logs may include data derived from user input, such as email addresses, usernames, user-agent strings, request paths, client-supplied identifiers, and error messages. If an application writes untrusted input directly into a log format, an attacker may manipulate how the record is displayed or parsed. For example, a poorly implemented logger might receive a username containing newline characters, producing output that could mislead an analyst into thinking a successful administrative login occurred when it did not. This is an example of log injection or log forging.

**Safer implementation.** Use a structured logging library that serializes fields safely. Validate and normalize fields according to their expected format. Avoid constructing security logs by concatenating arbitrary user input into a plain-text message:

```python
logger.info(
    "Login attempt",
    extra={
        "account_input": normalized_account_input,
        "outcome": "failure"
    }
)
```

The exact behavior depends on the logging framework. The application must ensure the data is serialized safely and that downstream systems do not reinterpret it unsafely. Do not assume that JSON automatically solves every log-injection problem. Incorrect serialization, unsafe downstream parsing, or display-layer interpretation can still create issues.

**Bug-hunting perspective.** A suspicious log entry is not sufficient proof of a vulnerability. Establish that attacker-controlled input can alter the meaning or structure of a security record in a way that affects investigations, alerting, or other system behavior.

### 19. Exception Handling and Authentication Errors

Authentication failures may produce exceptions. Consider a handler that catches any exception and logs `"Authentication failed: %s" % exc`. This is potentially problematic if the exception contains sensitive request details, credentials, tokens, or internal state. However, exceptions should not simply be discarded, diagnostic evidence is important.

**Better approach.** Record a controlled event and a safe diagnostic reference:

```python
def login(request):
    try:
        return authenticate(request)

    except ExpectedAuthenticationFailure:
        log_auth_failure(
            reason_category="invalid_credentials"
        )
        return generic_authentication_failure()

    except Exception:
        incident_ref = create_diagnostic_reference()

        log_authentication_error(
            diagnostic_ref=incident_ref
        )

        return generic_server_error(
            reference=incident_ref
        )
```

This is illustrative pseudocode. Production implementations need proper exception classification, secure diagnostic storage, and careful handling of unexpected failures.

**The distinction.** A failed login due to invalid credentials is an expected security event. A database outage during authentication is an operational failure. A malformed identity-provider response may be a protocol-processing error. These events should not necessarily trigger identical alerts. But unexpected errors must not be logged with unredacted secrets merely because developers need debugging information.

### 20. Building a Detection Rule That Is Actually Useful

A detection rule can be technically correct and operationally poor. "Alert on every failed login" may generate thousands of alerts from ordinary user mistakes. Analysts may begin ignoring the alerts, including the ones that matter. A better detection system uses context, correlation, and severity.

**Example: suspicious authentication sequence.** Three login failures in under fifteen seconds, then a success, then an MFA method removed, then the recovery email changed, then a new persistent session created, all within about thirty seconds. The combination is more concerning than any individual event. A detection rule might look for multiple authentication failures, a subsequent successful login, a security-sensitive authentication change, creation of a persistent credential, and an unusual device or network context. The system should correlate the sequence using trustworthy account and session references. It should not assume that all events from the same IP belong to the same person or that a new IP automatically means compromise.

**Example pseudocode:**

```python
def evaluate_authentication_risk(events):
    risk = 0

    if events.has_repeated_login_failures:
        risk += 2

    if events.has_success_after_failures:
        risk += 3

    if events.has_unusual_mfa_change:
        risk += 4

    if events.has_new_persistent_credential:
        risk += 3

    return risk
```

These scores are purely illustrative and are not a validated detection model. Real implementations should calibrate rules against observed traffic, threat scenarios, and the costs of false positives and false negatives. A score should inform a defined response rather than substitute for understanding the underlying event.

### 21. Authentication Logs and Incident Response

Suppose an employee reports an unexpected login. A mature incident-response process should answer several questions.

**Question 1: was authentication successful?** Find the relevant login event and establish the outcome.

**Question 2: which authentication method was used?** Determine whether the session originated from a password, passkey, MFA-assisted login, SSO, recovery mechanism, or another supported method.

**Question 3: was MFA required and completed?** Distinguish between a challenge being issued, a challenge being approved, and the application actually accepting the completed authentication.

**Question 4: what session was created?** Correlate the session-creation event without exposing the session credential itself.

**Question 5: what happened afterward?** Look for account recovery, MFA changes, new passkeys, trusted-device enrollment, privileged operations, data exports, session revocation, and additional logins.

**Question 6: is the session still valid?** Check the current session state through authorized administrative mechanisms. Do not assume a historical log entry tells you the current validity of the session.

**Question 7: were there related events across other applications?** For federated systems, correlate the IdP, application, and relevant downstream records.

**Question 8: what response is appropriate?** Depending on the evidence, the response might include revoking relevant sessions, requiring password reset, requiring fresh authentication, removing unauthorized authenticators, suspending an account, preserving relevant evidence, and notifying the affected user. The response should be proportionate to the verified risk.

### 22. Privacy, Data Minimization, and Retention

Security logging must balance investigative usefulness with privacy. More data is not automatically better. Logging complete authentication request bodies, full IP histories, raw device fingerprints, and every piece of identity information may create unnecessary privacy and security risks. A good logging design asks: what security question must this field answer, is the field necessary, can a less sensitive identifier serve the same purpose, who can access it, how long must it be retained, how will it be protected, and how will it be deleted when retention is no longer justified?

For example, a security team may need to correlate authentication events for a limited period without retaining full request bodies. A pseudonymous account reference may be sufficient for many investigations. The exact approach depends on the threat model, organizational requirements, and applicable law. Security logs are sensitive data. Treat them as a protected system, not as harmless debugging output.

### 23. Realistic AppSec Review: A Vulnerable Authentication Logging Implementation

Imagine reviewing this fictional handler:

```python
def login(email, password, request):
    logger.info(
        "Login attempt: email=%s password=%s headers=%s",
        email,
        password,
        request.headers
    )

    user = find_user(email)

    if user is None:
        logger.warning(
            "Unknown user: %s",
            email
        )
        return generic_failure()

    if not verify_password(password, user.password_hash):
        logger.warning(
            "Invalid password for: %s",
            email
        )
        return generic_failure()

    logger.info(
        "Login successful: %s",
        email
    )

    return create_session(user)
```

**Finding 1: password disclosure in logs.** The handler writes the submitted password to the logs. If the logs are accessible to unauthorized users or are exported to a less protected system, the credential may be exposed. This is a real security concern if the code path is active.

**Finding 2: potential exposure through headers.** The handler logs all request headers. Headers may include cookies, authorization values, and other sensitive material. Whether a particular secret is exposed depends on the headers and the logging configuration, but indiscriminate logging creates unnecessary risk.

**Finding 3: account enumeration through logs?** The handler records distinct internal reasons for unknown users and incorrect passwords. That is not automatically a vulnerability. If the records are appropriately protected, the distinctions may help defenders. The problem arises if the information becomes accessible to unauthorized users or influences public responses in a way that exposes account existence.

**Finding 4: insufficient event context.** The success event does not clearly record the authentication method, MFA state, session-creation result, or a correlation identifier. The handler may log those details elsewhere, so inspect the complete system before concluding they are missing.

**Finding 5: monitoring is not demonstrated.** The code records events but does not show collection, correlation, alerting, retention, access control, or integrity protection. That does not mean the overall application lacks those capabilities, they may exist in the infrastructure. A code review should trace the complete logging pipeline.

### 24. A Safer Conceptual Implementation

```python
def login(email, password, request):
    request_id = request.correlation_id

    user = find_user(email)

    if user is None:
        log_authentication_event(
            request_id=request_id,
            account_ref=None,
            outcome="failure",
            reason_category="invalid_credentials"
        )

        return generic_failure()

    if not verify_password(password, user.password_hash):
        log_authentication_event(
            request_id=request_id,
            account_ref=user.internal_id,
            outcome="failure",
            reason_category="invalid_credentials"
        )

        return generic_failure()

    if user.is_disabled:
        log_authentication_event(
            request_id=request_id,
            account_ref=user.internal_id,
            outcome="denied",
            reason_category="account_not_eligible"
        )

        return generic_failure()

    result = apply_authentication_policy(user)

    log_authentication_event(
        request_id=request_id,
        account_ref=user.internal_id,
        outcome=result.outcome,
        authentication_method="password",
        mfa_required=result.mfa_required
    )

    return result.response
```

This illustrates several improvements: passwords are not logged, internal failure categories are controlled, a correlation reference is available, account eligibility is checked, and the current authentication policy determines the result. However, this is not production-ready code. A complete implementation must also handle unknown-account timing and enumeration considerations, rate limiting and attack detection, MFA challenge state, session issuance and invalidation, concurrent account-state changes, exception handling, durable logging, secret redaction in other layers, and consistent authentication behavior across endpoints. The important lesson is to design logs around the security events you need to understand, not around the raw data available in an HTTP request.

### 25. Practical Checklist for an Authentication Logging Assessment

**Event coverage:** login successes and failures are recorded appropriately; MFA challenge outcomes are distinguishable; password changes and recovery events are recorded; MFA and passkey enrollment or removal are recorded; session creation, revocation, and logout are recorded; account disablement and reactivation are recorded; federated authentication and logout events are covered; privileged authentication-related changes are recorded.

**Data safety:** passwords are never logged; MFA codes and recovery codes are not logged; raw session credentials are not logged; authorization headers and cookies are appropriately redacted; request bodies are not logged indiscriminately; exception messages do not expose authentication secrets; alert payloads do not contain reusable credentials.

**Detection:** credential stuffing patterns can be identified; password-spraying patterns can be identified; repeated MFA failures and unusual approvals can be correlated; suspicious authentication changes can be detected; session-revocation failures can be investigated; federated authentication events can be correlated; detection thresholds are calibrated to reduce false positives.

**Protection and resilience:** logs have appropriate access controls; security events are collected reliably; time synchronization is monitored; logs have appropriate retention policies; sensitive records are protected against unauthorized modification or deletion; logging outages have a defined operational response; log injection is considered; access to sensitive logs is itself monitored.

**Investigation:** events can be correlated across relevant services; session references do not function as credentials; analysts can determine which authentication method was used; analysts can distinguish a failed login from a failed authentication service; analysts can establish whether a session was actually revoked; security logs support incident investigation without unnecessary personal data.

### 26. The Difference Between a Logging Defect and an Authentication Vulnerability

This distinction matters when reporting findings.

| Observation | Possible classification | What you must prove |
|---|---|---|
| Passwords are written to logs | Sensitive information exposure | Active code path records real submitted credentials and the resulting exposure risk |
| MFA codes appear in logs | Authentication-secret exposure | The codes are actually captured and accessible through the logging path |
| Failed logins are not logged | Detection or audit weakness | The absence violates a relevant requirement or materially impairs a defined security capability |
| No alert triggers on repeated failures | Monitoring weakness | The relevant attack pattern is not detected as required or expected |
| Session revocation is not logged | Auditability weakness | The missing event impairs required investigation or security operations |
| A valid session survives required revocation | Session-management vulnerability | The session continues to provide access contrary to the intended policy |
| Different internal failure reasons exist | Not necessarily a vulnerability | Establish whether unauthorized parties can access the distinction |
| Logs can be modified | Log-integrity weakness | Demonstrate inadequate protections and the relevant impact |
| User-controlled input alters log records | Potential log injection | Show that the input changes the meaning or structure of records in a security-relevant way |

A monitoring weakness does not automatically prove that authentication can be bypassed. Likewise, a password disclosure in logs can be a serious vulnerability even if the authentication handler correctly verifies passwords. Report the actual issue and impact.

### 27. Final Senior-Level Principles

**1. Record authentication state transitions, not merely login outcomes.** A login attempt, MFA challenge, successful authentication, and session creation are different events.

**2. Never log reusable authentication secrets.** Passwords, session cookies, bearer tokens, recovery tokens, and private authentication material do not belong in ordinary logs.

**3. Structured logging improves correlation.** Consistent fields and event names help defenders reconstruct what happened.

**4. Logging and prevention are separate controls.** An alert does not replace rate limiting, and rate limiting does not replace investigation capability.

**5. Detect patterns across accounts and sessions.** Per-account failure counts alone may miss distributed credential attacks.

**6. Monitor sensitive authentication changes.** Password recovery, MFA removal, passkey enrollment, and session revocation can be crucial incident indicators.

**7. Protect the logs themselves.** Logs can expose credentials and personal information, and compromised logs can mislead incident responders.

**8. Correlate federated events carefully.** An IdP login, application session, and logout notification must be connected through trustworthy identifiers.

**9. Distinguish evidence from inference.** A suspicious event sequence deserves investigation, but it does not automatically prove account compromise.

**10. Test the complete logging pipeline.** Review the application, reverse proxy, observability tools, central log store, alert system, and exported reports.

## Assessment

Unlike most of the prior phases, this phase has no separate instructor-graded challenge transcript to draw an assessment from. The two exercises below are instead drawn directly from the module's own embedded material, Section 23's vulnerable logging implementation and Section 24's safer redesign, using the module's own given findings as the answer.

### Assessment Question 1

Review this fictional authentication handler as a senior AppSec engineer:

```python
def login(email, password, request):
    logger.info(
        "Login attempt: email=%s password=%s headers=%s",
        email,
        password,
        request.headers
    )

    user = find_user(email)

    if user is None:
        logger.warning(
            "Unknown user: %s",
            email
        )
        return generic_failure()

    if not verify_password(password, user.password_hash):
        logger.warning(
            "Invalid password for: %s",
            email
        )
        return generic_failure()

    logger.info(
        "Login successful: %s",
        email
    )

    return create_session(user)
```

Identify every logging-related concern in this implementation, and explain specifically why the distinct `"Unknown user"` and `"Invalid password for"` log messages are not automatically a vulnerability by themselves, even though they record different failure reasons.

<details markdown="1">
<summary><strong>Reveal Answer</strong></summary>

Five findings. First, password disclosure in logs: the handler writes the submitted password directly into the log entry on every attempt. If the logs are accessible to unauthorized users or are exported to a less protected system, the credential may be exposed, and this is a real security concern as long as this code path is active, regardless of whether the password was correct. Second, potential exposure through headers: the handler logs the entire `request.headers` object, which may include cookies, authorization values, and other sensitive material. Whether a specific secret is actually exposed depends on which headers are present and how the logging pipeline is configured, but indiscriminately logging all headers creates unnecessary risk regardless. Third, account enumeration through logs: the handler records distinct internal reasons for an unknown user versus an incorrect password. Fourth, insufficient event context: the success log is just `"Login successful: %s"`, it does not clearly record the authentication method used, whether MFA was required or satisfied, the session-creation result, or a correlation identifier, though the full system might record those details elsewhere and would need to be checked before concluding they are missing. Fifth, monitoring is not demonstrated: the code only writes log lines, it does not show collection, correlation, alerting, retention, access control, or integrity protection, though those capabilities may well exist elsewhere in the infrastructure.

The distinct internal failure reasons, finding three, are not automatically a vulnerability on their own. There is nothing inherently wrong with an application maintaining separate internal categories for "account does not exist" versus "password was wrong," provided those log records themselves are appropriately protected, that distinction can genuinely help defenders investigate later. The problem only materializes if that internal information becomes accessible to unauthorized users, or if it influences a public-facing response in a way that exposes account existence to an attacker, for example if these exact log messages, or a response derived from them, leaked outside the protected logging system. The question to answer is never "does an internal distinction exist," it is "who can actually see it."

</details>

### Assessment Question 2

A safer conceptual redesign of the same handler replaces the raw `logger.info`/`logger.warning` calls with a `log_authentication_event()` helper, checks `user.is_disabled` before evaluating authentication, and derives the final outcome from `apply_authentication_policy(user)`. List the specific improvements this redesign makes, and then explain why it is still described as "not production-ready code," naming at least four concerns a complete implementation would still need to address.

<details markdown="1">
<summary><strong>Reveal Answer</strong></summary>

The redesign demonstrates several concrete improvements over the original. Passwords are no longer logged at all, every call site passes only `email`, `request_id`, `account_ref`, `outcome`, and similar structured fields, never the submitted password itself. Internal failure categories are controlled rather than freeform, every failure path uses the same `reason_category="invalid_credentials"` value for both the unknown-user and wrong-password cases, which is a deliberate architectural choice: the internal event can still distinguish them for defenders if needed, but the pattern shown here collapses them to the same category, reducing the risk that an inconsistent public response derived from these logs would leak the distinction. A correlation reference, `request_id`, is available on every logged event, enabling cross-system investigation without needing a raw credential. Account eligibility is explicitly checked, the `user.is_disabled` branch logs a distinct `"denied"` outcome with `reason_category="account_not_eligible"`, something the original handler never considered at all. And the final outcome is derived from `apply_authentication_policy(user)` rather than being hardcoded to always create a session, meaning the logged outcome actually reflects the real authentication decision, including whatever MFA requirement that policy imposes.

Despite these improvements, this is still explicitly not production-ready code, and a complete implementation would still need to address at least the following: unknown-account timing and enumeration considerations, since nothing here addresses whether the unknown-user and wrong-password code paths take comparably long to execute, the timing-based enumeration risk examined in Phase 12; rate limiting and attack detection, since this function only records events, it does not throttle or block repeated attempts itself; MFA challenge state, since the snippet shows `mfa_required` being logged but not how an actual MFA challenge is issued, tracked, or verified; session issuance and invalidation, since `result.response` is treated as a black box without showing how a session is actually created or how prior sessions might need to be revoked; concurrent account-state changes, exception handling for unexpected failures, durable logging so events survive a logging-system outage, secret redaction at other layers such as the reverse proxy, and consistent authentication behavior enforced the same way across every other endpoint that performs login, not just this one handler. The overarching lesson is that logs should be designed around the specific security events you need to understand, not simply assembled from whatever raw data happens to be available in the HTTP request.

</details>

## Remediation and Secure Implementation

The following consolidates the remediation guidance across all twenty-seven sections of this phase.

1. Log every security-relevant authentication state transition, not just final login outcome, including MFA challenges, session creation, account recovery, and credential lifecycle events, using consistent structured fields: timestamp, event type, outcome, account reference, authentication method, and correlation identifier.
2. Never write passwords, MFA codes, session identifiers, OAuth tokens, refresh tokens, recovery tokens, or private key material into logs under any circumstances, including failed-attempt paths, and construct an allowlisted event from approved fields rather than logging raw request bodies or headers.
3. Avoid relying on post-collection redaction as a primary control, since a secret can already be written to disk, forwarded, indexed, or backed up before redaction runs, and instead prevent secrets from being captured at the point of construction.
4. Preserve useful internal failure-reason distinctions for defenders while returning generic, non-distinguishing responses externally, and audit every downstream path, debug endpoints, support tools, analytics, admin interfaces, that could leak the internal distinction to an unauthorized party.
5. Build detection logic that correlates events across accounts and sources, not just per-account failure counts, to catch credential stuffing and password spraying, and correlate failure sequences with subsequent successes and sensitive account changes rather than treating failures in isolation.
6. Monitor account recovery, MFA enrollment and removal, passkey registration, and session lifecycle events with the same rigor as login itself, and alert on clusters of high-risk changes occurring close together, particularly following unusual login activity.
7. Define an explicit, risk-calibrated policy for what happens when the logging pipeline itself becomes unavailable, fail-open, fail-closed, or durable buffering, chosen per operation based on its risk rather than applied uniformly.
8. Protect logs with centralized collection separate from the systems that generate them, strict access control, separation of duties, and integrity protections, and synchronize time consistently across every system that contributes events.
9. Serialize all user-derived input, email addresses, usernames, user agents, into logs through a structured logging library rather than string concatenation, to prevent log injection from altering how records are displayed or parsed.
10. Classify exceptions during authentication into expected security events versus unexpected operational failures, logging each appropriately with a safe diagnostic reference, and never let debugging convenience justify logging unredacted secrets.

## Key Takeaways

This phase's governing tension, stated in its own introduction, is that authentication enforcement prevents or limits unauthorized access while authentication monitoring helps detect suspicious activity and investigate what happened, and neither one substitutes for the other. A system that authenticates flawlessly but logs only `LOGIN SUCCESS` has not failed at authentication, it has failed at being investigable, and the module's opening scenario shows exactly how expensive that gap becomes the moment an incident actually happens.

The second tension running through every section is the mirror image of the first: logging exists to help investigate compromises, but a logging pipeline that captures real passwords, MFA codes, or session tokens to make that investigation easier has not strengthened security, it has built a second, frequently less-protected place for an attacker to steal exactly the same credentials from. The assessment in this phase demonstrates both failure modes in a single piece of code: a handler that logs the password on every attempt has failed the second discipline outright, while its redesign, which finally gets the secret-handling right, is still explicitly incomplete, because getting logging right also means correlating across the full pipeline, from proxy to alert to export, not just fixing one function. Carrying that same two-sided discipline, log enough to investigate, never enough to become a target, forward is the core skill this phase teaches.

## Review Checklist

- [ ] Can you state, in one sentence, why authentication enforcement and authentication monitoring are separate controls that don't substitute for each other?
- [ ] Can you distinguish logging, monitoring, and alerting, and trace the six-stage pipeline connecting an application event to a response?
- [ ] Can you name at least eight distinct authentication lifecycle events worth logging beyond login success and failure?
- [ ] Can you list everything that must never appear in an authentication log, and explain why post-collection redaction is insufficient on its own?
- [ ] Can you explain how a logging or monitoring system could itself contribute to account enumeration, and the architecture that avoids it?
- [ ] Can you distinguish the detection signals for credential stuffing, password spraying, and brute force?
- [ ] Can you design a detection rule for a suspicious sequence combining login failures, a subsequent success, and a high-risk account change?
- [ ] Can you evaluate fail-open, fail-closed, and durable buffering as responses to a logging-system outage, and explain when each is appropriate?
- [ ] Can you explain log injection and why structured serialization, not just using JSON, is the actual defense?
- [ ] Can you walk through the module's 8-question incident-response framework for an unexpected login report?
- [ ] Can you distinguish a logging defect from an authentication vulnerability for each of the nine observation types in the module's classification table?
- [ ] Can you identify, from the assessment's source code, which specific concerns remain even after passwords are removed from the logs?

## References to Related Phases

- Account enumeration through differing responses, referenced in section 7 as connecting directly to this module, was covered in full in **Phase 12, Authentication Information Leakage**.
- Credential stuffing, password spraying, and brute force detection in sections 8 through 10 extend the attack-pattern definitions established in **Phase 1, Password Storage and Credential Attacks**.
- MFA fatigue detection in section 11 and account recovery monitoring in section 12 build directly on **Phase 3, Multifactor Authentication (MFA) Attacks** and **Phase 4, MFA Enrollment and Recovery Vulnerabilities**.
- Session lifecycle correlation in section 13 extends the session-revocation discipline from **Phase 6, Cookie and Session Security**.
- Federated authentication correlation in section 14, including the inconsistent-logout-evidence example, connects directly to **Phase 14, Federated Logout and Identity Persistence**.
