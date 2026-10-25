# Authentication Security Engineering

A practitioner's course on authentication security, written from the perspective of a senior application security engineer and bug bounty hunter. Each phase walks through a specific area of authentication, the ways it fails in practice, how to test for those failures safely and with evidence, and how to fix them, with real HTTP requests, real code, and a worked assessment at the end of every phase.

This site is a companion to the [GitHub repository](https://github.com/facelesshunter-tech/authentication-security-engineering), which remains the canonical source. Every page on this site is generated directly from the Markdown files in that repository.

## How to use this course

Work through the phases in order. Later phases build on vocabulary and principles established earlier, particularly the recurring distinction between offline attacks, online attacks, and credential lifecycle weaknesses introduced in Phase 1, and the principle that a weaker recovery or fallback path can defeat an otherwise strong primary authentication mechanism, which reappears in a different form in nearly every phase after it.

Every phase ends with an **Assessment** section. Each question is followed by a collapsed **Reveal Answer** block, work through the question yourself first, then click to check your reasoning against the answer.

Every page also includes an optional read-aloud control, the speaker icon in the bottom right corner. It narrates the page using your browser's own text to speech and highlights each word as it is spoken, which can make dense technical material easier to follow. It is off by default, nothing is sent to a server, and you can adjust the speed and voice or click any paragraph to start reading from that point.

## Course progress

| Phase | Title | Status |
|---|---|---|
| 1 | [Password Storage and Credential Attacks](phases/phase-01-password-storage-and-credential-attacks.md) | Complete |
| 2 | [Password Change and Account Recovery](phases/phase-02-password-change-and-account-recovery.md) | Complete |
| 3 | [Multifactor Authentication (MFA) Attacks](phases/phase-03-multifactor-authentication-mfa-attacks.md) | Complete |
| 4 | [MFA Enrollment and Recovery Vulnerabilities](phases/phase-04-mfa-enrollment-and-recovery-vulnerabilities.md) | Complete |
| 5 | [Passkeys, WebAuthn, and FIDO2](phases/phase-05-passkeys-webauthn-and-fido2.md) | Complete |
| 6 | [Cookie and Session Security](phases/phase-06-cookie-and-session-security.md) | Complete |
| 7 | [OAuth 2.0 and OpenID Connect Security](phases/phase-07-oauth-2-0-and-openid-connect-security.md) | Complete |
| 8 | [Account Lifecycle and Identity Proofing](phases/phase-08-account-lifecycle-and-identity-proofing.md) | Complete |
| 9 | [Reauthentication and Step-Up Authentication](phases/phase-09-reauthentication-and-step-up-authentication.md) | Complete |
| 10 | [SAML Security](phases/phase-10-saml-security.md) | Complete |
| 11 | [Multi-Tenant Identity Isolation](phases/phase-11-multi-tenant-identity-isolation.md) | Complete |
| 12 | [Authentication Information Leakage](phases/phase-12-authentication-information-leakage.md) | Complete |
| 13 | [Legacy Authentication Security](phases/phase-13-legacy-authentication-security.md) | Complete |
| 14 | [Federated Logout and Identity Persistence](phases/phase-14-federated-logout-and-identity-persistence.md) | Complete |
| 15 | [Authentication Logging and Monitoring](phases/phase-15-authentication-logging-and-monitoring.md) | Complete |
| 16 | [Authentication Cryptographic Failures](phases/phase-16-authentication-cryptographic-failures.md) | Complete |
| 17 | [Authentication-Adjacent Authorization Flaws](phases/phase-17-authentication-adjacent-authorization-flaws.md) | Complete |

All seventeen phases are complete. This table, and the navigation on the left, will be replaced by the full curriculum index.
