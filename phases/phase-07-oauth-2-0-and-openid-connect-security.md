# Phase 7: OAuth 2.0 and OpenID Connect Security

**Source material:** Module 7 of 17, "Authentication Complete Phases Test.md" (16 numbered sections covering OAuth 2.0 and OpenID Connect, and the course progress tracker), with supplementary assessment material drawn from "Authentication Security.md" (Challenge 17, the ID-token trust follow-up, Challenge 18, Challenge 19, Challenge 20, and Challenge 21).

## Learning Objectives

After completing this phase, you should be able to:

1. Explain what OAuth 2.0 actually does as a delegated authorization framework, and why it is not by itself a universal user-authentication protocol.
2. Distinguish OAuth 2.0 from OpenID Connect, and distinguish the access token, ID token, and refresh token by purpose and audience.
3. Walk through the full six-step authorization-code flow and identify the security purpose of each parameter: `response_type`, `client_id`, `redirect_uri`, `scope`, `state`, `nonce`, and `code_challenge`.
4. Explain why redirect URI validation must use exact or narrowly defined matching, and identify a substring-matching implementation as unsafe.
5. Explain what the `state` parameter actually protects, and distinguish the four specific ways its validation can fail.
6. Explain how PKCE protects the authorization-code exchange, and recognize an implementation that accepts a challenge without ever enforcing the verifier.
7. Explain why account linking based solely on a matching email address is unsafe, and design a safer linking flow built on proof of control and provider-plus-subject identity.
8. Explain why decoding an ID token is not the same as validating it, and list the essential checks a client must perform before trusting its claims.
9. Distinguish the ID token from the access token by audience and purpose, and identify the specific failure of treating them as interchangeable.
10. Distinguish confidential clients from public clients, and explain why embedding a secret in a frontend application does not make it confidential.
11. Explain OAuth login CSRF and transaction confusion as a distinct failure from a simple missing-parameter bug, and design a safe two-account test for it.
12. Apply the Phase 1 through Phase 6 impact-validation discipline to an OAuth/OIDC finding: trace a flaw through the complete trust chain from client registration to protected application access, and avoid overstating severity.

## Introduction

Every phase up to this point studied authentication an application performs directly: its own passwords, its own sessions, its own second factors. This phase studies what happens when an application delegates part of that responsibility to someone else, an external identity provider, through OAuth 2.0 and OpenID Connect. This module matters because OAuth implementations can look perfectly functional while allowing attackers to log in as another user, link the wrong account, bypass identity verification, or obtain access they were never supposed to receive.

The governing idea of this phase is stated plainly in its own final section: OAuth and OIDC security is a chain of trust decisions, client registration, authorization request, transaction binding, identity-provider authentication, authorization response, code exchange, token validation, external identity mapping, local session creation, and protected application access, and a flaw at any single stage can undermine the result. A correctly signed token does not compensate for an unsafe account-linking process. PKCE does not compensate for accepting the wrong identity. A valid identity-provider session does not automatically prove that a client application correctly established its own session. The core skill this phase teaches is tracing identity and authorization context across the entire flow, not inspecting any single step in isolation.

## Core Concepts

The module moves through four stages. First, sections 1 through 3 establish the protocol fundamentals: what OAuth actually authorizes, how it differs from OpenID Connect, the three token types, and the complete six-step authorization-code flow with its distinct parameters. Second, sections 4 through 11 examine eight specific vulnerability categories in turn: weak redirect URI validation, missing or incorrect `state` validation, PKCE implementation failures, account-linking flaws, incorrect ID-token validation, token-type confusion, unsafe client configuration, and login CSRF. Third, section 12 addresses token and authorization-code leakage as a cross-cutting concern. Fourth, sections 13 through 16 bring the module together into a practical discipline: a complete source-code review exercise, an assessment checklist, severity guidance, and the final chain-of-trust mental model.

## Lessons

### 1. First, Understand What OAuth Actually Does

OAuth 2.0 is an authorization framework. It allows an application to obtain limited access to a resource through an authorization server without requiring the application to collect the user's password for that resource.

Imagine three parties: you, the resource owner; Photo Manager, an application you want to use; and Google, the authorization server and identity provider in this example. You want Photo Manager to access certain photos from your Google account. You should not need to give Photo Manager your Google password. Instead, Google can authorize the application to obtain a token that grants specified access.

The general flow is:

```text
You
 |
 | 1. Request to connect Google account
 v
Photo Manager
 |
 | 2. Redirect to authorization server
 v
Google
 |
 | 3. You authenticate and grant permission
 v
Google
 |
 | 4. Redirect back with authorization code
 v
Photo Manager
 |
 | 5. Exchange code for tokens
 v
 Google
 |
 | 6. Return token response
 v
Photo Manager
 |
 | 7. Access permitted resources
 v
Google resource server
```

This is a simplified authorization-code flow. Notice that the application does not need your Google password to obtain the authorization it requested. However, OAuth alone is not a universal user-authentication protocol. That distinction is essential.

### 2. OAuth Versus OpenID Connect

This is the first concept you must get right.

**OAuth 2.0** answers a question such as: is this application authorized to access a particular resource on behalf of a user? For example, Photo Manager might be granted permission to read selected photos. OAuth is concerned with delegated authorization.

**OpenID Connect** adds an identity layer on top of OAuth 2.0. It allows a client application to verify an end user's identity through a defined protocol. OIDC introduces the ID token, which communicates authentication-related claims to the client. An access token and an ID token serve different purposes.

| Token | Purpose |
|---|---|
| Access token | Allows access to a resource according to its permissions and the resource server's validation rules. |
| ID token | Communicates authentication-related claims to the OIDC client. |
| Refresh token | Can be used to obtain new access tokens when the authorization server permits it. |

A refresh token is not automatically issued in every flow.

**Critical security distinction.** An application should not treat any arbitrary access token as proof of the user's identity. An access token might be intended for a particular API, not for the application that received it. Similarly, an ID token must be validated according to the OIDC requirements before its claims are trusted. The security rule: use the correct token for the correct purpose, audience, and protocol.

### 3. The Authorization-Code Flow

The authorization-code flow is central to understanding modern OAuth security. Consider a fictional application with client `https://shop.example.test`, authorization server `https://identity.example.test`, and redirect URI `https://shop.example.test/oauth/callback`. The application wants the user to sign in through the identity provider.

**Step 1: the client redirects the browser.**

```http
GET /authorize?
 response_type=code&
 client_id=shop-client&
 redirect_uri=https%3A%2F%2Fshop.example.test%2Foauth%2Fcallback&
 scope=openid%20profile%20email&
 state=RANDOM_STATE&
 nonce=RANDOM_NONCE&
 code_challenge=PKCE_CHALLENGE&
 code_challenge_method=S256
HTTP/1.1
Host: identity.example.test
```

This example includes OIDC and PKCE parameters. The parameters have distinct purposes: `response_type=code` requests an authorization code, `client_id` identifies the registered client, `redirect_uri` specifies where the authorization response should be sent, `scope` requests particular permissions and, with `openid`, invokes OIDC, `state` associates the response with the initiating client transaction, `nonce` binds an ID token to the authentication request, and `code_challenge` supports PKCE, which protects the authorization-code exchange. These parameters are not interchangeable.

**Step 2: the user authenticates.** The identity provider handles authentication. Depending on its policy, it might require a password, MFA, a passkey, an existing authenticated session, or additional verification for a sensitive operation. The client should not assume that redirecting to the identity provider guarantees that the user has been authenticated to the required assurance level.

**Step 3: the identity provider returns an authorization code.**

```http
GET /oauth/callback?code=AUTHORIZATION_CODE&state=RANDOM_STATE
HTTP/1.1
Host: shop.example.test
```

The code is not the same as an access token. The client must process the response according to the flow it initiated.

**Step 4: the client validates the response.** Before proceeding, the client should verify that the returned `state` matches the state associated with the pending transaction. For OIDC, the client must also validate the ID token and relevant authentication response properties. The application must not simply accept any incoming authorization code and assume it represents the intended user.

**Step 5: the client exchanges the code.**

```http
POST /token HTTP/1.1
Host: identity.example.test
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&
code=AUTHORIZATION_CODE&
redirect_uri=https%3A%2F%2Fshop.example.test%2Foauth%2Fcallback&
client_id=shop-client&
code_verifier=ORIGINAL_PKCE_VERIFIER
```

Depending on the client type and registration, the request may require client authentication. A confidential server-side client can authenticate itself. A public client, such as a native application, cannot safely rely on a static embedded secret to prove its identity. The authorization server validates the code and other required parameters before issuing tokens.

**Step 6: the client establishes its own session.** If the authentication succeeds, the application may establish its own session:

```http
HTTP/1.1 302 Found
Location: /dashboard
Set-Cookie: __Host-session=NEW_RANDOM_SESSION; Path=/; Secure; HttpOnly; SameSite=Lax
```

This cookie represents the application's own session. It is distinct from the identity provider's session and from the OAuth tokens.

**Why this distinction matters.** A user can have an authenticated session with the identity provider, an OAuth authorization transaction in progress, an authenticated session with the client application, and one or more tokens associated with particular resources. These states must not be confused.

### 4. Vulnerability One: Weak Redirect URI Validation

This is one of the most important OAuth security issues. The `redirect_uri` tells the authorization server where to send the authorization response. If the authorization server allows untrusted destinations, an authorization response may be sent somewhere the legitimate client does not control.

**Secure behavior.** Suppose the registered redirect URI is `https://shop.example.test/oauth/callback`. The authorization server should validate the requested URI against the client's registered redirect URI according to the applicable OAuth requirements. For the standard authorization-code flow, exact matching against a registered redirect URI is generally the correct approach, with narrowly defined protocol exceptions such as native-app redirect URI handling. Do not invent broad matching rules that accept arbitrary destinations.

**Vulnerable example.** Imagine an application validates the redirect URI using this logic:

```python
def is_allowed_redirect(uri):
    return "shop.example.test" in uri
```

This is unsafe because an attacker-controlled URI can contain the trusted text without actually being controlled by the trusted application, for example a string might contain the trusted hostname as part of a different hostname or URL path. The code is illustrative, whether a real authorization server is vulnerable depends on its complete parsing and validation behavior.

**What should a tester investigate?** In an authorized test environment: identify the registered redirect URI, observe how the authorization server validates it, test controlled variations that change the host, path, scheme, or URL structure, determine whether an unregistered destination is accepted, establish whether an authorization code or other sensitive response reaches that destination, and determine whether the response is usable and what account or resource is affected. Do not claim account takeover merely because an unexpected redirect occurs. The impact depends on what is returned, whether it leaks sensitive information, and whether the attacker can use the leaked material.

**Common false positives.** A redirect to an untrusted page is not necessarily an OAuth vulnerability if the authorization response contains no sensitive information and the protocol transaction is safely rejected. Likewise, a URL that visually resembles the legitimate domain is not proof that the authorization server accepts it. You must establish actual behavior.

### 5. Vulnerability Two: Missing or Incorrectly Validated `state`

The `state` parameter is used to correlate an authorization response with the authorization request initiated by the client. It helps prevent an attacker from injecting an unsolicited or mismatched authorization response into the client's login flow.

**How it should work.** The client creates a fresh, unpredictable value, `state = RANDOM_TRANSACTION_VALUE`, and stores it in a way that associates it with the initiating browser and pending transaction. The client sends it to the authorization server. When the browser returns to the callback, the client checks that the returned value matches the pending transaction:

```python
def handle_oauth_callback(request):
    returned_state = request.query.get("state")
    expected_state = get_state_for_pending_transaction()

    if not expected_state:
        return reject_request()

    if not constant_time_compare(returned_state, expected_state):
        return reject_request()

    return continue_oauth_flow()
```

This is simplified pseudocode. The actual implementation must handle transaction storage, expiration, concurrency, and the correct association with the initiating browser.

**What can go wrong?**

*Case A: the client does not check `state`.* The callback accepts the authorization response without verifying the transaction. This can permit login CSRF or authorization-response injection scenarios, depending on the application's design and other protections.

*Case B: the client checks only that `state` exists.* For example, `if request.query.get("state"): continue_login()`. This is insufficient. An attacker can supply an arbitrary nonempty value. The client needs to verify the response against the expected state associated with the pending transaction.

*Case C: the client uses a fixed state value.* For example, `state=123456`. A predictable, reusable state value does not provide the intended transaction-binding protection.

*Case D: state is not bound to the initiating browser.* A server might generate a random state value but store it in a way that does not bind it to the browser or transaction that initiated authentication. Randomness alone does not solve this problem.

**Testing approach.** Observe the normal authorization request and callback. In an authorized test account, assess whether a state value is generated, whether it is sufficiently unpredictable, whether the client stores the expected value, whether the callback rejects a missing value where one is required, whether a mismatched value is rejected, whether state values cannot be reused to bypass transaction binding, and whether concurrent login attempts are handled correctly. The objective is to test the validation logic, not simply to look for the presence of a parameter.

### 6. Vulnerability Three: PKCE Implementation Failures

PKCE stands for Proof Key for Code Exchange. It protects the authorization-code flow by binding the code exchange to a secret verifier held by the client that initiated the transaction. It is particularly important for public clients that cannot safely keep a client secret.

**How PKCE works.** The client generates a random verifier, `code_verifier = HIGH_ENTROPY_RANDOM_VALUE`, and derives a challenge using SHA-256, `code_challenge = BASE64URL(SHA256(code_verifier))`. The client sends the challenge with the authorization request. Later, when exchanging the authorization code, it sends the original verifier. The authorization server checks that the verifier corresponds to the challenge associated with the authorization transaction. This helps prevent someone who intercepts an authorization code from redeeming it without the verifier.

The two relevant parameters are `code_challenge_method=S256`, indicating the SHA-256-based method, and `code_verifier=ORIGINAL_RANDOM_VERIFIER`, sent during the token exchange. For modern implementations, `S256` is the preferred method.

**What does a vulnerable implementation look like?** Consider this fictional behavior: the client sends a challenge, the authorization server issues a code, and the token endpoint accepts the code without checking the corresponding verifier. The server appears to support PKCE, but it does not enforce the protection. A parameter appearing in an HTTP request is not evidence that the server validates it.

**How to test.** In a controlled environment: complete a normal authorization-code flow using PKCE, confirm the expected challenge and verifier behavior, test whether the token endpoint rejects an incorrect verifier, test whether it rejects a missing verifier when the transaction requires PKCE, confirm that the authorization code is bound to the relevant client and transaction, and verify that the code cannot be redeemed more than once. The exact test depends on the client's type and the authorization server's documented behavior.

**Important nuance.** PKCE is not a replacement for all OAuth protections. It does not eliminate the need for redirect URI validation, transaction correlation, client-appropriate configuration, and proper token validation. A secure authorization-code flow uses the appropriate protections together.

### 7. Vulnerability Four: OAuth Account-Linking Flaws

This is a particularly important real-world category because it can lead to account takeover.

Imagine a shopping application that allows users to sign in with an external identity provider. An existing local account contains `email = customer@example.test`, `user_id = 1042`. The application also supports Google sign-in. A developer implements account linking using this logic:

```python
def oauth_callback(identity):
    user = find_user_by_email(identity.email)

    if user:
        link_external_identity(user.id, identity.subject)
        return login(user)

    return create_new_account(identity)
```

This example is intentionally simplified. The dangerous assumption is that an email address returned by an external provider automatically authorizes the application to link that identity to an existing local account. That assumption may be unsafe.

**Why can this fail?** Possible causes include the provider's email verification status being ignored, the application trusting an identity claim without validating the ID token, the external identity not being correctly bound to the provider that issued it, the application automatically linking accounts based solely on matching email addresses, the user being logged into the wrong local account during the linking operation, the application not requiring adequate proof of control over the existing account, or a linking callback accepting an identity response from the wrong transaction. The exact risk depends on the identity provider, its claims, the application, and the linking policy.

**A safer design.** Account linking should require trustworthy evidence that the user controls both the existing local account and the external identity. A safer conceptual flow is: the user signs in to the existing account using an appropriate authentication method, the application initiates the external identity flow, the callback is validated against the correct transaction, the external identity token and claims are validated, the application identifies the external account using the appropriate stable identifier and issuer, the application explicitly links the identity to the currently authenticated local account, and the operation is logged and the user is notified when appropriate. The account-linking process should not rely on email matching alone.

**The stable identity question.** For OIDC, the combination of issuer (`iss`) and subject (`sub`) is central to identifying an end-user at an issuer. A subject identifier should not be treated as globally unique without considering its issuer and the applicable protocol context. A database might store `local_user_id: 1042`, `issuer: https://identity.example.test`, `subject: 00u123456789`. The precise schema depends on the provider and application.

**Testing account linking.** Using controlled accounts: create an existing local account, create a separate external identity, test normal linking, test whether the application requires authentication to the existing local account, test whether an unverified or mismatched identity can be linked, confirm that the provider issuer and subject are validated correctly, verify that one external identity cannot be improperly attached to multiple local accounts, and confirm that unlinking and relinking follow a deliberate security policy. Do not test this by attempting to take over another person's real account.

**Impact.** A confirmed account-linking flaw can allow an attacker to associate an identity they control with a victim's local account. Depending on the login flow, the attacker may subsequently gain access to that victim's account. This can be a high-impact finding, but only when the attack path is demonstrated.

### 8. Vulnerability Five: Incorrect OIDC ID-Token Validation

This section covers validation principles, not deep JWT cryptographic attacks. An ID token contains claims that the client uses to establish the identity associated with an authentication transaction. The client must not simply decode the token and trust its contents. Decoding is not validation.

**Essential validation checks.** A proper OIDC implementation must validate the ID token according to the protocol and the client's configuration.

| Check | Security purpose |
|---|---|
| Signature and permitted algorithm | Establishes that the token is validly signed under the expected trust configuration. |
| Issuer (`iss`) | Confirms the token came from the expected identity provider. |
| Audience (`aud`) | Confirms the token is intended for the client. |
| Expiration (`exp`) | Rejects expired tokens. |
| Issued-at and related time claims | Supports applicable temporal validation and policy. |
| Nonce, when sent | Binds the token to the initiating authentication request. |
| Authentication transaction | Ensures the token belongs to the flow the client initiated. |
| Key selection and trust configuration | Ensures verification uses trusted keys from the expected issuer. |

Additional protocol requirements may apply depending on the flow and token claims.

**Example of a dangerous implementation.**

```python
def login_from_id_token(token):
    claims = decode_without_verification(token)
    user = find_user(claims["email"])
    return login(user)
```

This is not a secure authentication implementation. It trusts decoded claims without demonstrating cryptographic verification or the other required checks. A secure implementation uses a maintained OIDC library configured for the expected issuer and client, and validates the ID token according to the protocol.

**What should a tester look for?** In source code or a controlled environment, determine whether the client verifies the signature against trusted keys, rejects unexpected issuers, validates the audience, rejects expired tokens, validates the nonce when applicable, associates the response with the correct authentication transaction, handles key rotation and discovery metadata safely, and avoids trusting claims from unvalidated tokens. Do not infer a token-validation flaw merely because the source code calls a function named `decode()`. Some libraries separate decoding from verification, while others provide a combined validation method. Inspect the actual implementation and configuration.

### 9. Vulnerability Six: Confusing the ID Token with the Access Token

Suppose an application receives an ID token with audience `shop-client` and an access token with audience `orders-api`. These audiences are illustrative. The ID token is intended for the OIDC client. The access token is intended for the relevant resource server. If the application sends the ID token to an API and the API accepts it as an access token, the API may be using the wrong credential type. Conversely, a client should not assume an access token is a trustworthy identity assertion simply because it came from a token endpoint.

**What goes wrong?** An implementation might use an ID token to authorize API operations without an appropriate design, accept an access token intended for a different resource, treat the existence of any token as proof of a fully authenticated user, skip the validation required for the token's actual purpose, or confuse the client session with the identity provider's session.

**Testing principle.** Identify the token's intended recipient and purpose. Then establish whether the component receiving it validates and uses it appropriately. Do not assume all tokens issued by the same identity provider are interchangeable.

### 10. Vulnerability Seven: Unsafe Client Configuration

OAuth clients have different security requirements depending on their type. A server-side web application can often protect a client secret in a server-controlled environment. A native mobile application or browser-based application generally cannot keep an embedded static secret confidential from users who control the device or runtime.

**Confidential clients.** A confidential client can authenticate itself to the authorization server using a suitable method. Examples include server-side web applications with protected credentials. A client secret should not be placed in public source repositories, frontend JavaScript bundles, public mobile application packages, client-visible configuration files, or browser storage accessible to the user.

**Public clients.** A public client cannot reliably maintain a secret that is confidential from the user. Such clients should use an appropriate authorization-code flow with PKCE and follow the security requirements for their application type.

**Common misconception.** Adding a client secret to a frontend application does not make it a confidential client. If users can retrieve the secret from the distributed application, it cannot serve as a reliable proof of client confidentiality.

**Testing approach.** Inspect the application's architecture and configuration. Determine whether the client is correctly classified, whether secrets are exposed to the user, whether PKCE is used where required, whether the redirect URI and client registration match the application type, and whether token storage and session management follow the relevant security requirements. A visible client ID is generally not itself a vulnerability, client IDs are ordinarily identifiers, not secrets.

### 11. Vulnerability Eight: OAuth Login CSRF and Transaction Confusion

This topic overlaps conceptually with transaction binding, but it deserves separate attention because it can affect account identity.

Imagine a browser is redirected through an authorization flow, but the client does not reliably associate the callback with the login transaction initiated by that browser. The application might accept an authorization response that belongs to a different transaction. Depending on the flow and implementation, this can cause the browser to become authenticated as the wrong account. The user may believe they are using their own account while the application has actually established a session associated with another identity. This can create downstream consequences, such as the user submitting private information to an account controlled by someone else.

**What should be bound together?** A secure implementation should correctly associate the initiating browser or client transaction, the generated `state`, the relevant authorization request, the expected redirect URI, the authorization response, the PKCE verifier when applicable, the OIDC nonce when applicable, the validated identity, and the local session established after successful completion. These controls serve different purposes, none should be treated as a universal substitute for all the others.

**How to test safely.** Use two accounts you control and separate browser sessions. Establish the normal login behavior first. Then examine whether the client rejects missing or mismatched transaction information and whether it ever establishes a session for an identity unrelated to the initiating transaction. Record the resulting session identity, not just the redirect behavior. Evidence of the wrong account being authenticated is much stronger than evidence of an unusual callback URL.

### 12. OAuth Tokens and Authorization-Code Leakage

Authorization codes and tokens are sensitive, but their security properties differ. An authorization code is intended to be exchanged at the token endpoint. It should not be treated as a long-lived session credential. An access token may permit access to a resource until it expires or is otherwise rejected. A refresh token can have longer-lasting implications because it may permit the client to obtain new access tokens.

**Potential leakage locations.** Sensitive OAuth material can be exposed through application logs, reverse-proxy logs, error reporting, browser history or URL handling, analytics systems, debugging tools, public repositories or configuration, and improperly protected client storage. The actual exposure depends on the flow, token type, browser behavior, and implementation.

**Defensive principles.** Keep tokens out of ordinary logs. Avoid placing access or refresh tokens in URLs. Protect refresh tokens with appropriate storage and lifecycle controls. Use short-lived authorization codes and enforce one-time redemption. Validate redirect URIs. Use PKCE for applicable authorization-code flows. Ensure authorization codes are bound to the relevant client and transaction. Apply suitable token revocation and expiration policies. Never treat a leaked token as harmless simply because the user has a password. A token's practical impact depends on its audience, privileges, lifetime, and whether the receiving service accepts it.

### 13. Source-Code Review: A Complete Fictional Case

You are reviewing a fictional application's OIDC callback.

```python
def oauth_callback(request):
    code = request.query.get("code")

    tokens = exchange_code(code)

    claims = decode_without_verification(tokens["id_token"])

    user = find_user_by_email(claims["email"])

    if not user:
        user = create_user(claims["email"])

    session["user_id"] = user.id

    return redirect("/dashboard")
```

This code raises several review concerns.

**Concern 1: no visible state validation.** The code does not demonstrate that the callback matches the initiating authorization transaction. Required investigation: inspect the transaction-handling layer and determine whether mismatched or unsolicited callbacks are rejected.

**Concern 2: no visible PKCE handling.** The code does not show a PKCE verifier. Required investigation: determine whether PKCE is required for the client type and whether the verifier is correctly associated with the pending authorization request.

**Concern 3: no visible ID-token validation.** The function explicitly calls a function named `decode_without_verification()`. If the returned claims are used for authentication without subsequent validation, that is a serious flaw. Required investigation: determine whether a separate validation step exists. If no such step exists, verify the precise acceptance behavior in a controlled environment.

**Concern 4: automatic account creation and email matching.** The application creates or selects an account using the email claim. Required investigation: determine whether the email is verified, whether the issuer and subject are validated, and whether the application improperly links external identities to existing accounts based solely on email matching.

**Concern 5: no visible session rotation.** The code writes `user_id` into the current session. Required investigation: determine whether the session ID is rotated after successful authentication and whether any prior session can access the authenticated state.

**Concern 6: no visible authentication-state policy.** The code does not show how the application handles authentication assurance or whether a recent authentication requirement applies. Required investigation: inspect the policy for the protected resources and the identity provider's authentication context.

**How a senior AppSec engineer approaches this.** Do not assume every omitted control is absent from the whole application. Trace the implementation through client registration, authorization request generation, transaction storage, callback handling, code exchange, ID-token validation, external identity mapping, local session creation, protected-resource authorization, and logging, expiration, and revocation. A vulnerability is established by the behavior of the complete system, not by a single function name in isolation.

### 14. Practical OAuth/OIDC Assessment Checklist

Use this checklist during authorized security assessments.

| Area | What to verify |
|---|---|
| Client registration | Correct client type and registered redirect URIs. |
| Redirect URI | Strict validation against registered destinations. |
| Authorization code | Correct client and redirect binding; one-time redemption. |
| `state` | Fresh, unpredictable, transaction-bound value; mismatches rejected. |
| PKCE | Correct challenge/verifier association and enforcement. |
| OIDC nonce | Proper validation when required by the initiated flow. |
| Issuer | The expected identity provider is validated. |
| Audience | The ID token is intended for the correct client. |
| Signature | The token is cryptographically verified under trusted configuration. |
| Expiration | Expired tokens are rejected. |
| Account linking | External identity linking requires appropriate proof and correct identity binding. |
| Email claims | Verification and trust semantics are respected. |
| Token purpose | ID tokens and access tokens are not treated as interchangeable. |
| Client secret | No false assumption that frontend secrets are confidential. |
| Session creation | Authentication produces an appropriately protected local session. |
| Token leakage | Codes and tokens are protected from logs, URLs, and unintended disclosure. |
| Error handling | Errors do not expose sensitive credentials or bypass transaction validation. |

Not every item applies identically to every OAuth/OIDC flow. Test against the flow actually implemented and its relevant protocol requirements.

### 15. Severity: How to Avoid Overstating Findings

OAuth findings can range from low impact to account takeover.

**Example A: weak redirect validation with no demonstrated sensitive response leakage.** Potentially a configuration weakness, but impact must be established.

**Example B: missing `state` validation.** Potentially serious if it allows an attacker to inject or confuse authentication transactions. Severity depends on the demonstrated attack path and other protections.

**Example C: PKCE parameter appears in the request but the verifier is not enforced.** Potentially serious if an attacker can exploit authorization-code interception or injection in the relevant client context.

**Example D: ID token accepted without required validation.** Potentially critical to the authentication boundary if an attacker can supply an untrusted token and obtain an authenticated session. Confirm the actual acceptance behavior and prerequisites.

**Example E: account linking based solely on a matching email.** Potentially high impact if it permits an attacker-controlled identity to become linked to a victim's account. Establish the provider's identity semantics and demonstrate the resulting account access using controlled accounts.

**Report-writing rule.** Your report should answer: what trust assumption failed, what did you actually test, what response or application behavior proves the issue, what can an attacker achieve, what prerequisites are necessary, and what remediation addresses the root cause. Never inflate severity to make a report sound more impressive.

### 16. Final Mental Model

When reviewing OAuth/OIDC, think of it as a chain of trust decisions:

```text
Client registration
       |
       v
Authorization request
       |
       v
Transaction binding
       |
       v
Identity-provider authentication
       |
       v
Authorization response
       |
       v
Authorization-code exchange
       |
       v
Token validation
       |
       v
External identity mapping
       |
       v
Local session creation
       |
       v
Protected application access
```

A flaw at any stage can undermine the result. A correctly signed token does not compensate for an unsafe account-linking process. PKCE does not compensate for accepting the wrong identity. A valid identity-provider session does not automatically prove that a client application correctly established its own session. A successful redirect does not prove that the OAuth transaction was secure. The core skill is tracing the identity and authorization context across the entire flow.

## Assessment

The following assessment is drawn from "Authentication Security.md" and addresses account-linking proof of control, ID-token trust validation, the purpose of the `state` parameter, the precise mechanics of OAuth login CSRF, and why provider-plus-subject is the correct identity key instead of email alone. As with the prior phases, the questions are preserved from the original source, and the answers given are the instructor's corrected, authoritative answers rather than the original learner's submitted answers.

### Assessment Question 1

A fictional application allows users to connect a Google account:

```http
POST /api/account/link-google
Cookie: session_id=alice_session

{
  "googleEmail": "alice@gmail.com"
}
```

```http
HTTP/1.1 200 OK

{
  "message": "Google account linked"
}
```

The endpoint accepts `googleEmail` directly from the request body. There is no Google OAuth authorization code, ID token, or proof that the requester actually controls that Google account. As a security tester, what is the first security property you would test here?

<details markdown="1">
<summary><strong>Reveal Answer</strong></summary>

Changing the `googleEmail` field to an email you control and observing whether it links successfully is a reasonable starting point, but it only proves that the application accepts a client-controlled identity claim, it does not yet prove the most dangerous impact. Before linking an external identity, the application must establish that the authenticated user actually controls that external identity, and normally that proof comes from an OAuth/OIDC flow, not simply from an email string supplied by the client.

The stronger test follows the identity through the authentication flow rather than stopping at the settings page: with your own attacker-controlled account, for example `attacker@gmail.com`, link it to Alice's account using this unverified endpoint, then attempt to sign in with Google using that same attacker-controlled Google identity, and determine whether doing so authenticates you as Alice. If linking `attacker@gmail.com` to Alice's account followed by "Sign in with Google" as `attacker@gmail.com` results in an authenticated session for Alice, you have demonstrated a serious account-linking and authentication-boundary flaw, potentially leading to account takeover. The senior-level step beyond the initial instinct to swap the email is to follow the linked identity all the way through the authentication flow and prove what authority it actually grants, not merely that the email field was accepted.

</details>

### Assessment Question 2

Suppose the application does use Google OAuth properly this time: Alice clicks "Link Google account," completes Google authorization, and Google returns an ID token from which the application extracts `{"email": "attacker@gmail.com"}`. What security property would you verify before trusting that email and linking the account? For example, if an attacker crafts a fake token claiming `{"email": "alice@gmail.com"}` and sends it to the website asserting "this is my Google identity," should the website (A) trust it because the email looks valid, (B) verify that the token is genuine and was issued by Google for this application, or (C) check only whether the email contains `@gmail.com`?

<details markdown="1">
<summary><strong>Reveal Answer</strong></summary>

The correct choice is B. The application must not trust a claimed email merely because the value looks legitimate. It must establish that the identity assertion is authentic, intended for this application, currently valid, and associated with the correct external identity, by validating the token's signature and relevant claims, including the issuer (`iss`), audience (`aud`), and expiry (`exp`). Checking only the shape of the email address, option C, or trusting it outright, option A, both skip the step that actually establishes the token is genuine.

The senior-level mental model for any OIDC identity token is a sequence of questions, in order: is the issuer trusted, is the signature valid, was the token issued for our application specifically, is it still valid and not expired, and only after all of that, who does the verified identity actually belong to. Only once every step in that sequence passes should the application link or authenticate based on the token's claims. Decoding a token and reading its fields is not the same as validating it.

</details>

### Assessment Question 3

Alice is already logged into `shop.test`. She clicks "Link Google Account," the application sends her to Google, and Google redirects back with `GET /oauth/callback?code=AUTH_CODE_123&state=xyz789`. The application exchanges the code with Google and gets a verified identity for `alice@gmail.com`, but you notice the application does not verify the `state` parameter. What security purpose does the OAuth `state` parameter serve, and what could go wrong if the application doesn't validate it?

<details markdown="1">
<summary><strong>Reveal Answer</strong></summary>

`state` is not the user's identity, and testing it does not mean changing it to represent "another user." Think of `state` as a transaction or session correlation value. Before sending Alice to Google, the application generates a value such as `state = RANDOM_ABC123` and associates it with Alice's specific browser and pending transaction. When Google eventually redirects back with `code=AUTH_CODE_123&state=RANDOM_ABC123`, the application must check that the returned state matches the state it originally generated for that specific browser or session. If it matches, continue. If it does not, reject.

Without that validation, an attacker may be able to start an OAuth transaction using their own Google account, obtain a valid authorization response for that transaction, and then cause another user's browser to complete that same transaction, that is the classic OAuth login and account-linking CSRF problem. The precise question `state` answers is not "this is Alice," it is "this OAuth response belongs to the OAuth transaction that this specific browser or application session started." If an attacker can cause a victim's browser to consume an authorization result that the attacker generated, and the application accepts it, that is a potentially severe account-linking and login CSRF vulnerability, worth proving through the full chain: attacker identity, injected into, victim's account, attacker can then authenticate as that account.

</details>

### Assessment Question 4

You discover that `GET /oauth/start` begins Google authentication, generating `state=ATTACKER_STATE`, but the application does not validate `state` when the callback arrives. You, the attacker, authenticate to Google as `attacker@gmail.com` and obtain a complete callback URL, `GET /oauth/callback?code=ATTACKER_CODE&state=ATTACKER_STATE`. Your goal is to get a victim who is already logged into `shop.test` to end up with `attacker@gmail.com` linked to their account. What would you try to do with your attacker-generated callback URL, and what outcome would prove that the missing state validation is exploitable?

<details markdown="1">
<summary><strong>Reveal Answer</strong></summary>

The test is not to change the victim's state value to match the attacker's state, since that framing misunderstands what's being tested. The actual test is whether you can make the victim's browser consume the OAuth callback URL you, the attacker, already generated using your own Google account. Concretely: you complete OAuth with your own Google account and obtain `GET /oauth/callback?code=ATTACKER_CODE&state=ATTACKER_STATE`, which belongs entirely to you. You then cause the victim's browser, while it is authenticated to `shop.test` as the victim, to visit that exact callback URL.

Secure behavior is that the application recognizes this OAuth transaction was never initiated by the victim's session and rejects it, for example with `400 Bad Request` and an error such as "Invalid OAuth state." Vulnerable behavior is that the application accepts the callback, returns something like `302 Found` to `/account`, and the victim's account now shows `attacker@gmail.com` as a linked Google account. If that happens, you have demonstrated that an OAuth identity controlled by the attacker became associated with an account controlled by someone else without that person's intentional authorization, which is the actual proof of impact. The critical distinction to hold onto is that the test is not "can I modify the victim's state," it is "can I inject my OAuth result into another user's authenticated session." Whether you received a 200 response is not the question that matters, whether an attacker-controlled identity became linked to a victim-controlled account is.

</details>

### Assessment Question 5

A fictional application supports Google, GitHub, and Microsoft sign-in. Alice originally linked her Google account. Later she clicks "Link GitHub," and the application receives a verified identity `{"provider": "github", "subject": "github-user-48291"}`. You inspect the backend and discover it identifies accounts using `find account WHERE external_email = returned_email`, instead of using `provider + subject`. What is the fundamental security problem with using the email address as the primary identity binding instead of provider plus subject, and what would you test to determine whether the application incorrectly treats two different providers' identities as the same external account?

<details markdown="1">
<summary><strong>Reveal Answer</strong></summary>

Noting that email addresses can change is a real but secondary weakness, it is not the core problem. The deeper issue is that email is an attribute of an identity, not the strongest unique identifier of the external identity itself. The application is trying to answer "which external identity is this," and the only correct way to answer that question is with the combination of issuer, or provider, and subject, for example `Google + 109283746501`, not with an attribute like an email address that can be shared or reused across completely different, unrelated providers.

Consider two genuinely different external identities that happen to share an email address: a Google identity with `sub = GOOGLE_123` and `email = alice@gmail.com`, and a Microsoft identity with `sub = MICROSOFT_789` and the same `email = alice@gmail.com`. These are two different external identities, `Google + GOOGLE_123` does not equal `Microsoft + MICROSOFT_789`, even though an email-only lookup like `findUserByEmail("alice@gmail.com")` would incorrectly conclude "I've seen this email before, so this must be the same identity." Email answers "what email address does this identity currently claim," while issuer plus subject answers "which exact external identity is this."

The correct test does not involve faking or literally swapping one provider's identity into another, since the provider is determined by the actual authorization flow and token issuer, not by a value you can simply substitute. Instead, authenticate through Google and record which application account becomes associated with that identity, then authenticate through a second, different provider, for example GitHub or Microsoft, using an account that shares the same email address. Check whether the application incorrectly treats the second provider's identity as already linked to the account from the first provider, without Alice ever explicitly linking that second identity herself. If the application automatically recognizes the second provider's identity as the same user purely because the email matches, that demonstrates an external-identity binding flaw, and the security boundary the application has failed to enforce is binding each external identity to its correct, specific provider and subject rather than trusting a shared, mutable attribute like email as if it were a unique identifier.

</details>

## Remediation and Secure Implementation

The following consolidates the remediation guidance across all sixteen sections of this phase.

1. Validate `redirect_uri` against an exact, pre-registered destination, or a narrowly defined and protocol-sanctioned exception, never a substring or pattern match that could accept an attacker-controlled host.
2. Generate a fresh, unpredictable `state` value per transaction, bind it to the initiating browser and session, and reject the callback whenever the returned value is missing, mismatched, or merely present without matching.
3. Enforce PKCE for public clients and verify the submitted `code_verifier` against the original `code_challenge` at the token endpoint, don't just accept that the parameters appeared somewhere in the request.
4. Require proof of control of both identities before linking an external account to a local one: authenticate to the existing local account first, validate the external identity's token fully, and never link based on an unverified or client-supplied email alone.
5. Identify and bind external identities using issuer plus subject, never email address alone, since email is a mutable attribute, not a stable identifier, and the same email can legitimately belong to different identities across different providers.
6. Fully validate every ID token before trusting its claims: verify the signature against trusted keys, check the issuer, audience, expiration, and nonce, and confirm the token belongs to the authentication transaction the client actually initiated. Decoding is not validation.
7. Keep ID tokens and access tokens scoped to their intended purpose and audience, and never treat either one as a universal, interchangeable proof of identity or access.
8. Classify clients correctly as confidential or public, never place a client secret anywhere a user or attacker can retrieve it from a distributed frontend or mobile package, and use PKCE for every public client.
9. Bind the complete OAuth transaction, state, PKCE verifier, nonce, authorization response, and the resulting local session, to the specific browser and session that initiated it, so that an attacker's own valid OAuth result can never be injected into a victim's authenticated session.
10. Keep authorization codes short-lived and single-use, keep tokens out of logs and URLs, and apply appropriate storage and revocation policies to refresh tokens given their longer-lasting implications.

## Key Takeaways

OAuth and OpenID Connect security cannot be assessed by checking whether a particular parameter or token is present. This phase's governing mental model, a chain of trust decisions running from client registration through to protected application access, means a flaw at any single stage undermines the whole system regardless of how correctly every other stage is implemented. A correctly signed ID token does not compensate for an account-linking process that trusts a bare email claim. PKCE does not compensate for a `state` parameter that is never actually checked. A valid identity-provider session does not prove the client application correctly validated the response and established its own session properly.

The assessment challenges in this phase sharpen that discipline on the two failure categories responsible for the most serious real-world OAuth vulnerabilities: account-linking flaws that trust an identity claim without proof of control, and identity binding that uses a mutable attribute like email instead of the stable issuer-plus-subject pair. Both failures share the same underlying lesson carried forward from every earlier phase, a claim is not evidence, and evidence is not proof of impact until you have traced it all the way through to a demonstrated, concrete security consequence using controlled test accounts.

## Review Checklist

- [ ] Can you explain, in one sentence, why OAuth alone is not a user-authentication protocol?
- [ ] Can you name the three OAuth/OIDC token types and state what each one is actually for?
- [ ] Can you walk through all six steps of the authorization-code flow and name the parameter each step depends on?
- [ ] Can you identify an unsafe redirect URI validation pattern in source code, and explain why substring matching fails?
- [ ] Can you explain what the `state` parameter actually protects, and distinguish all four of its specific failure modes?
- [ ] Can you explain how PKCE protects the code exchange, and recognize when it is present but not enforced?
- [ ] Can you explain why account linking must require proof of control, not just a matching email address?
- [ ] Can you list the essential ID-token validation checks, and explain why decoding is not validation?
- [ ] Can you explain why an ID token and an access token must not be treated as interchangeable?
- [ ] Can you explain why a client secret embedded in a frontend application does not make that client confidential?
- [ ] Can you design a safe, two-account test for OAuth login CSRF that proves the wrong identity became authenticated?
- [ ] Can you explain why issuer-plus-subject, not email, is the correct way to bind an external identity?

## References to Related Phases

- The recurring principle that a weaker secondary path can defeat a strong primary mechanism, demonstrated here through account linking and login CSRF, was first introduced with security questions in **Phase 1** and extended through recovery flows in **Phase 2** and MFA fallbacks in **Phase 4**.
- Session creation after successful OAuth authentication, referenced in section 3's step 6 and the source-code review's concern 5, connects directly to session rotation and fixation as covered in **Phase 6, Cookie and Session Security**.
- Phishing-resistant authentication through WebAuthn, which changes several of the trust assumptions relevant to identity-provider authentication in section 3's step 2, is covered in **Phase 5, Passkeys, WebAuthn, and FIDO2**.
- The authentication-assurance and recent-authentication requirements referenced in the source-code review's concern 6 are covered in full in a later phase, **Reauthentication and Step-Up Authentication**.
- SAML as an alternative federated identity protocol with its own distinct trust and validation requirements is covered in a later phase, **SAML Security**.
