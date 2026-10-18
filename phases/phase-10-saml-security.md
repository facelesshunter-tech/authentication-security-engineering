# Phase 10: SAML Security

**Source material:** Module 10 of 17, "Authentication Complete Phases Test.md" (20 numbered sections covering SAML security, and the course progress tracker). As with Phases 5 and 9, "Authentication Security.md" contains no SAML-specific content. The Assessment section in this phase is instead built from the module's own embedded material, Section 18's complete simulated bug-hunting case, using the module's own given reasoning as the answer.

## Learning Objectives

After completing this phase, you should be able to:

1. Name the three components of a SAML deployment, the user, the identity provider, and the service provider, and explain why the central security question is why the service provider should trust a given assertion.
2. Walk through the full six-step SAML authentication flow and identify the distinction between a valid assertion and an authenticated application session.
3. Identify the security-relevant fields of a SAML assertion, `ID`, `Issuer`, `NameID`, `NotBefore`, `NotOnOrAfter`, and `Audience`, and explain why their presence in XML does not establish authenticity.
4. Explain why accepting an unsigned or unverified assertion is a fundamental SAML failure, and recognize a vulnerable identity-extraction pattern in source code.
5. Explain XML Signature Wrapping as a mismatch between the content a signature validator verified and the content the application actually consumed, not merely the absence of a signature.
6. Explain why audience, recipient, and destination validation are three distinct checks, and why a genuine, correctly signed assertion can still be invalid for a particular service provider.
7. Distinguish assertion expiration from assertion replay as two separate controls, and explain why a short validity window does not by itself prevent replay.
8. Explain why a claimed `Issuer` value is not proof of trust, and distinguish identifying a claimed issuer from cryptographically verifying it against configured trust.
9. Explain `NameID`-based account mapping as an identity-binding problem distinct from signature validity, and identify the specific failure scenarios that can cause account confusion.
10. Explain how an application can achieve a technically successful SAML authentication while still suffering an authentication downgrade, and why unverified attributes such as a role claim must not be trusted without a defined policy.
11. Distinguish SAML authentication from application session management, and explain why logging out of one application does not necessarily terminate an identity-provider session.
12. Apply the Phase 1 through Phase 9 impact-validation discipline to a SAML implementation: trace the full sequence from receiving a response to session creation, and identify at which specific stage a given finding actually breaks down.

## Introduction

Every earlier phase in this course examined authentication an application performs largely on its own terms, its own passwords, its own sessions, its own second factors, and in Phase 7, a delegated authorization framework built on JSON and HTTP. This phase studies a different, older federated identity protocol built on signed XML: SAML, Security Assertion Markup Language. SAML is one of the most important authentication technologies to understand when testing enterprise applications, because a single validation mistake can allow an attacker to impersonate another user, potentially including an administrator.

The central security question this phase asks about every SAML deployment is stated plainly in its first section: why should the service provider trust this particular assertion? The answer must rest on cryptographic verification, correct validation, and an established trust configuration, never merely on the presence of XML that claims the user is authenticated. An attacker can construct XML containing every field a legitimate assertion would have, a subject, an issuer, validity conditions, an audience. The security boundary was never the presence of those fields. It is the complete validation process that checks them against a trusted configuration before any of them are believed.

## Core Concepts

The module moves through four stages. First, sections 1 through 3 establish the fundamentals: what SAML is, the complete six-step authentication flow, and the anatomy of an assertion. Second, sections 4 through 13 examine ten specific vulnerability categories in turn: unsigned or unverified assertions, XML Signature Wrapping, missing audience validation, incorrect recipient and destination validation, unenforced expiration, assertion replay, incorrect issuer trust, `NameID` account-mapping confusion, authentication downgrade through configuration, and trusting unverified attributes. Third, sections 14 through 17 cover the surrounding protocol mechanics: HTTP bindings and what the browser does and does not secure, SAML logout and session boundaries, XML parser security, and a complete review checklist. Fourth, sections 18 through 20 bring the module together into a practical discipline: a full simulated bug-hunting case, severity and reporting guidance, and the final receive-to-session-creation mental model.

## Lessons

### 1. What Is SAML?

SAML stands for Security Assertion Markup Language. It is an XML-based standard commonly used for exchanging authentication and authorization information between an identity provider and a service provider. Consider an organization that uses one corporate account to access several applications. Instead of creating separate passwords for every application, the organization uses Single Sign-On.

Three components matter:

| Component | Responsibility |
|---|---|
| User | Person attempting to access an application |
| Identity Provider (IdP) | Authenticates the user and issues a SAML response |
| Service Provider (SP) | Application that validates the response and grants access |

For example, a company might use a corporate identity platform to authenticate employees before allowing access to an internal HR application. The HR application trusts the identity provider, but only when the incoming SAML response satisfies the application's validation requirements.

The central security question is: why should the service provider trust this particular assertion? The answer must be based on cryptographic verification, correct validation, and an established trust configuration, not merely on the presence of XML that claims the user is authenticated.

### 2. Understand the SAML Authentication Flow

Consider this example: identity provider `idp.example.test`, service provider `hr.example.test`, and a user, an employee trying to access the HR application. These domains are fictional.

**Step 1: the user requests the application.**

```http
GET /dashboard HTTP/1.1
Host: hr.example.test
```

The application determines that the user does not have an authenticated session.

**Step 2: the application initiates SAML authentication.** The service provider creates a SAML authentication request and directs the browser to the identity provider. The request identifies the service provider and may contain information such as a request ID and a return location.

**Step 3: the identity provider authenticates the user.** The identity provider applies its authentication policy, which might involve a password, MFA, a passkey, or an existing identity-provider session. The exact method depends on the identity provider's configuration and the requested assurance.

**Step 4: the identity provider issues a SAML response.** After successful authentication, the identity provider generates a response containing a SAML assertion. An assertion may contain the identity of the subject, the issuing identity provider, the intended audience, validity conditions, authentication information, and attributes about the user. Depending on the binding, the response is delivered to the service provider through the browser.

**Step 5: the service provider validates the response.** This is the most security-sensitive step. The service provider must validate the response and assertion according to the SAML protocol, its trust configuration, and the application's security requirements. It must not simply extract an email address from the XML and log the user in.

**Step 6: the application creates a session.** Only after successful validation should the service provider establish an authenticated application session.

Important distinction: a valid SAML assertion and an authenticated application session are different things. The assertion is an input to the authentication process, the application session is the application's resulting authentication state.

### 3. What Does a SAML Assertion Look Like?

Below is a simplified, fictional SAML assertion for educational purposes. It omits important protocol details and must not be used as a production template.

```xml
<saml:Assertion
    ID="_assertion123"
    Version="2.0"
    IssueInstant="2026-10-17T09:00:00Z">

  <saml:Issuer>
    https://idp.example.test
  </saml:Issuer>

  <saml:Subject>
    <saml:NameID>
      employee@example.test
    </saml:NameID>
  </saml:Subject>

  <saml:Conditions
      NotBefore="2026-10-17T08:59:00Z"
      NotOnOrAfter="2026-10-17T09:05:00Z">

    <saml:AudienceRestriction>
      <saml:Audience>
        https://hr.example.test
      </saml:Audience>
    </saml:AudienceRestriction>

  </saml:Conditions>

</saml:Assertion>
```

| Element | Purpose | Security concern |
|---|---|---|
| `ID` | Identifies the assertion | Duplicate IDs and replay handling |
| `Issuer` | Identifies the assertion's issuer | Must match a trusted identity provider |
| `NameID` | Identifies the subject | Must be mapped to the correct account |
| `NotBefore` | Earliest permitted validity time | Must be checked |
| `NotOnOrAfter` | End of validity period | Must be checked |
| `Audience` | Identifies the intended recipient application | Must match the expected service provider |

These fields are not all sufficient on their own. Their presence in XML does not establish that the assertion is authentic. An attacker can create XML containing all these fields. The security boundary is the complete validation process.

### 4. Vulnerability One: Accepting an Unsigned or Unverified Assertion

This is a fundamental SAML security failure. Imagine that a service provider receives an assertion containing `<saml:Subject><saml:NameID>admin@example.test</saml:NameID></saml:Subject>`. The application extracts the `NameID` and creates a session for the corresponding account. If the application does not verify the assertion's authenticity, the identity information may be forgeable. An attacker could potentially construct an assertion claiming to represent another user.

**Vulnerable conceptual code:**

```python
def saml_login(request):
    assertion = parse_xml(request.form["SAMLResponse"])

    email = assertion.find_subject_name()

    user = find_user_by_email(email)

    return create_authenticated_session(user)
```

The code parses the response, extracts an identity, and creates a session. But it does not demonstrate any cryptographic or protocol validation.

**Safer conceptual flow:**

```python
def saml_login(request):
    response = parse_saml_response(request)

    result = validate_saml_response(
        response=response,
        trusted_idp_configuration=TRUSTED_IDP,
        expected_sp_configuration=EXPECTED_SP,
        expected_transaction=get_pending_saml_transaction(request)
    )

    if not result.valid:
        return authentication_failure()

    user = map_validated_identity_to_account(
        issuer=result.issuer,
        subject=result.subject
    )

    return create_authenticated_session(user)
```

The function names are illustrative. A production implementation should use a reputable SAML library and correctly configure its validation behavior rather than reimplementing the protocol from scratch.

**Testing considerations.** In an authorized environment, establish whether the application verifies the required signature, the signature chains to a configured trusted key, the application rejects modified signed content, the application rejects unsigned assertions when its trust policy requires signatures, and the validated identity comes from the content actually covered by the verified signature. A library may legitimately support different signature-placement and signing policies. Do not assume every valid deployment must sign exactly the same XML element in exactly the same way.

Finding: authentication may be forgeable if the application accepts identity claims without the cryptographic verification required by its trust configuration.

### 5. XML Signature Wrapping: A Critical SAML Testing Concept

XML Signature Wrapping, often abbreviated XSW, is a family of attacks involving discrepancies between the XML content that is cryptographically verified and the XML content the application actually uses. This is more subtle than simply removing a signature.

**The underlying problem.** Imagine a SAML response containing multiple XML elements that describe assertions. The signature-validation component verifies one assertion. However, the application extracts the subject identity from a different assertion that was not covered by the verified signature. The cryptographic operation may have succeeded, yet the application may still authenticate the wrong identity. The failure is caused by a mismatch between what the signature validator authenticated and what the application used to make its authentication decision.

**Conceptual example.** Suppose the validator confirms the authenticity of:

```xml
<saml:Assertion ID="_trusted">
  <saml:Subject>
    <saml:NameID>employee@example.test</saml:NameID>
  </saml:Subject>
</saml:Assertion>
```

But another part of the application selects an assertion based on a broad XML search and encounters:

```xml
<saml:Assertion ID="_other">
  <saml:Subject>
    <saml:NameID>admin@example.test</saml:NameID>
  </saml:Subject>
</saml:Assertion>
```

This illustrates the validation-versus-consumption mismatch. It is not a complete, working exploit payload. If the application trusts the first assertion but consumes the second, the result could be authentication as the wrong user.

**Why naive XML parsing is dangerous.** Code such as `subject = xml_document.find(".//NameID")` does not establish which assertion was validated. It merely finds an element matching a search expression. A secure implementation must ensure that the identity and conditions used for login come from the exact validated assertion or response, according to the protocol and configured validation policy.

**How to assess the risk.** Review whether the XML signature is correctly validated, the reference URI resolves to the intended element, duplicate or ambiguous IDs are rejected, the application uses the validated object rather than performing a separate broad search, and unexpected additional assertions or response structures are rejected where required by the implementation's security policy. Do not report XSW merely because an application contains multiple XML elements. Demonstrate a discrepancy between verified content and consumed identity data.

### 6. Vulnerability Three: Missing Audience Validation

An assertion may be authentic but intended for a different application. This is where the `Audience` condition matters. Imagine that an organization has two service providers, `https://hr.example.test` and `https://finance.example.test`. The identity provider issues an assertion intended for the HR application. The finance application receives the assertion. Should the finance application accept it merely because it was signed by the trusted identity provider? No. Authenticity does not establish that the assertion is intended for this particular application.

**The vulnerability.** Suppose the finance application trusts the identity provider's signature, extracts the subject, and ignores the audience restriction. It may accept an assertion intended for another service provider. The precise impact depends on the identity mapping, application policies, assertion contents, and trust relationships.

**Correct validation principle.** The service provider should validate the audience against its expected identifier:

```python
if validated_assertion.audience != EXPECTED_SP_ENTITY_ID:
    reject_authentication()
```

Real implementations may support multiple configured audiences or other protocol-defined arrangements, so the exact comparison must follow the intended configuration. Do not use an overly broad substring comparison such as `if "finance.example.test" in audience: accept()`. A broad string check may accept unintended values. Testing goal: determine whether the application rejects a genuine but incorrectly addressed assertion.

### 7. Vulnerability Four: Incorrect Recipient and Destination Validation

SAML messages can contain fields identifying where a response or assertion is intended to be delivered. Two relevant concepts: destination, a location associated with the SAML response, and recipient, a location associated with the subject confirmation method. Their precise roles depend on the message structure and binding. A service provider must validate applicable fields according to the protocol and its configuration.

**Why this matters.** Suppose an assertion was intended for one service provider's assertion consumer service, but the application accepts it in a different context without enforcing the relevant recipient requirements. This can create an unintended trust path.

**What to examine.** Is the expected assertion consumer service correctly configured? Are applicable `Destination` values checked? Are subject-confirmation recipient constraints checked? Does the application accept unexpected response locations? Are the values compared against trusted configuration rather than derived unsafely from untrusted request headers? Do not confuse `Destination` with `Audience`. The audience answers which relying application the assertion is intended for. Destination and recipient checks concern the relevant response or subject-confirmation delivery context. Depending on the exact SAML profile and library, the applicable checks differ. Assess them against the protocol requirements and deployment configuration rather than applying a simplistic universal rule to every XML element.

### 8. Vulnerability Five: Assertion Expiration Is Not Enforced

SAML assertions can contain validity conditions, for example `<saml:Conditions NotBefore="2026-10-17T09:00:00Z" NotOnOrAfter="2026-10-17T09:05:00Z">`. The assertion is not valid before the permitted start time and is not valid at or after the specified end time, subject to the applicable protocol rules. If the service provider ignores these conditions, an assertion may remain usable beyond its intended validity period.

**Vulnerable conceptual code:**

```python
def accept_assertion(assertion):
    if verify_signature(assertion):
        return True

    return False
```

This illustrates an incomplete validation routine: it checks only a signature and ignores other required conditions.

**Safer conceptual approach:**

```python
def accept_assertion(assertion, now, configuration):
    if not verify_required_signatures(assertion, configuration):
        return False

    if not validate_issuer(assertion, configuration):
        return False

    if not validate_audience(assertion, configuration):
        return False

    if not validate_time_conditions(assertion, now, configuration):
        return False

    if not validate_response_context(assertion, configuration):
        return False

    return True
```

This is illustrative pseudocode, not a complete SAML validator. Real validation involves additional protocol requirements, including applicable subject-confirmation conditions and transaction correlation.

**Clock skew.** Distributed systems may have small differences between their clocks. Implementations sometimes allow a limited clock-skew tolerance. That does not automatically constitute a vulnerability. Assess whether the tolerance is appropriate and whether the application still rejects assertions that are clearly outside the allowed validity period.

### 9. Vulnerability Six: Assertion Replay

An assertion may be valid when first received but dangerous if it can be reused inappropriately. Consider this sequence: a user successfully authenticates through the identity provider, the service provider accepts the assertion, the assertion is captured or otherwise obtained by an attacker, and the attacker attempts to submit it again. Whether replay succeeds depends on the assertion's validity, subject-confirmation rules, transaction handling, session state, and replay protections.

**Important distinction.** Expiration and replay prevention are not the same control. A short-lived assertion can still be replayed during its validity window if the implementation permits it.

**Common protections.** Depending on the SAML flow and implementation, relevant protections include short, appropriate assertion validity, correct request/response correlation, validation of `InResponseTo` where required, validation of applicable subject-confirmation data, rejection of previously consumed identifiers where required by the design, appropriate cache or state handling, and secure session creation and transaction completion.

**What about `InResponseTo`?** In a service-provider-initiated flow, the response may refer to the authentication request it answers. The service provider should verify the correlation according to the flow's requirements. It should not simply accept any value that happens to be present. Unsolicited or identity-provider-initiated SSO has different transaction properties, so the tester must distinguish the configured flow rather than assuming every response must contain the same correlation field.

**Testing the behavior.** In a controlled test environment, assess whether a previously accepted response can be reused, a response to an unrelated authentication request is accepted, a response with an invalid request correlation is rejected where correlation is required, and the application handles repeated assertion identifiers appropriately. A repeated request returning an error is not sufficient proof of replay prevention. Confirm whether the application would create a new authenticated session or accept the assertion again.

### 10. Vulnerability Seven: Incorrect Issuer Trust

The `Issuer` identifies the entity that issued the assertion. But a string that claims to be a trusted identity provider is not proof that the message came from that provider. Imagine the application receives `<saml:Issuer>https://idp.example.test</saml:Issuer>`. If the application trusts this value without validating the required signature against the configured identity provider's trusted key, the issuer field can become a false claim of identity.

**A common implementation mistake.** Developers sometimes confuse identifying the claimed issuer, establishing that the issuer is trusted, and verifying that the message was cryptographically signed by the expected trusted party. These are different operations.

**Correct approach.** The service provider should use trusted configuration to establish the expected identity provider and its signing keys. It should then validate the required signature and issuer information according to that trust configuration. Do not fetch an arbitrary key from an untrusted URL contained in the incoming assertion and immediately trust it to verify that same assertion.

**Additional considerations.** Review how identity-provider metadata is obtained and updated, whether signing certificates are pinned or otherwise securely trusted through configured metadata, how certificate rotation is handled, whether unexpected issuers are rejected, and whether development and production identity providers are accidentally mixed. An expired signing certificate does not automatically mean every signature should be rejected in all circumstances, certificate validity, metadata trust, signing time, rotation, and library behavior must be evaluated according to the deployment's policy. Do not make simplistic assumptions from certificate dates alone.

### 11. Vulnerability Eight: Account Confusion Through `NameID` Mapping

A valid assertion can still be mapped to the wrong local account. This is an identity-binding problem. Imagine that an application uses email addresses as its account lookup key: `user = find_user_by_email(assertion.email)`. That may be appropriate in a carefully designed environment, but the security of the mapping depends on the identity provider, the attribute's meaning, verification policy, and account-linking rules.

**Potential failure scenarios.** The application accepts an email attribute that is not guaranteed to be verified. Two identity providers can issue the same email address. An email address changes, but the application treats it as a permanent identifier. An account-linking process trusts an unverified matching email. A developer mistakes a display name for a stable identity identifier.

**Better identity-binding principles.** A robust design should establish which identity provider authenticated the user, which stable subject identifier the provider assigned, which local account that identity maps to, whether account linking requires additional proof, and how identifier changes and provider migrations are handled. For OIDC, the combination of issuer and subject is commonly used to identify an identity, as covered in Phase 7. SAML has different identifier and subject semantics. The correct mapping depends on the identity provider's contract and the application's design. Do not mechanically treat every `NameID` as a globally unique, immutable identifier. SAML supports different NameID formats and policies. Testing goal: determine whether a valid assertion can be mapped to an unintended local account.

### 12. Vulnerability Nine: Authentication Downgrade Through SAML Configuration

An identity provider may support several authentication methods or assurance levels. For example, an organization might require MFA for privileged access. But the service provider may incorrectly accept an assertion produced under a weaker authentication context. SAML assertions can contain authentication statements and context information describing the authentication event. The service provider must interpret that information in the context of its actual security requirements.

**Example.** Suppose an administrator's application requires MFA. A user authenticates to the identity provider with only a password. The identity provider issues an assertion, and the service provider accepts it without checking whether the required authentication context was satisfied. The application may have authenticated the user successfully while failing to enforce its stronger policy.

**What to examine.** Does the application require a specific authentication context? Does the identity provider enforce the intended authentication policy? Does the service provider validate the returned context? Does the application distinguish ordinary users from privileged operations? Can a weaker login route reach a privileged application? A context value is not necessarily proof that every underlying factor was independently verified. Its meaning depends on the identity provider's implementation and configuration. The service provider must understand the trust relationship and ensure the returned context meets the intended requirement.

### 13. Vulnerability Ten: Trusting Unverified User Attributes

SAML assertions may include attributes such as email address, display name, department, group membership, role, and organizational identifier. These attributes can influence application behavior. For example:

```xml
<saml:Attribute Name="role">
  <saml:AttributeValue>administrator</saml:AttributeValue>
</saml:Attribute>
```

The existence of this attribute does not establish that the user is legitimately an administrator. The service provider must validate the assertion and determine whether the attribute is trusted for the intended purpose.

**Common mistakes.** Accepting attributes from an untrusted issuer. Trusting an assertion without the required signature verification. Mapping a user-controlled profile field directly to an administrative role. Accepting unexpected attribute formats or ambiguous mappings. Failing to distinguish authentication attributes from application authorization policy.

**The correct mental model.** A SAML assertion may provide information used by the application, but the application must define which trusted sources are allowed to supply which attributes and what those attributes are permitted to control. If a role claim is correctly issued by a trusted identity provider and the organization intentionally uses that claim for role assignment, it may be entirely legitimate. The issue is not the mere presence of a role attribute. The issue is whether the application trusts it in a way that violates its security policy. Authorization flaws are examined in greater depth in a later phase, Authentication-Adjacent Authorization Flaws.

### 14. HTTP Bindings and the Browser

Understanding how SAML messages travel helps you interpret traffic captures. Two common bindings:

**HTTP Redirect Binding.** A SAML message is transported through an HTTP redirect, often using URL parameters. This is commonly used for authentication requests.

**HTTP POST Binding.** A SAML response is submitted to an assertion consumer endpoint, commonly using an HTML form:

```http
POST /saml/acs HTTP/1.1
Host: hr.example.test
Content-Type: application/x-www-form-urlencoded

SAMLResponse=<base64-encoded-SAML-response>
```

The `SAMLResponse` parameter commonly contains a Base64-encoded XML response. Base64 is encoding, not encryption. It does not make the message confidential. The response may contain identity information, so avoid logging or sharing real production assertions unnecessarily. A SAML response's transport through the browser does not eliminate the need for signature verification, condition validation, and correct identity binding.

**What you should know as a tester.** When examining authorized traffic, identify the assertion consumer endpoint, determine which binding is being used, understand where the application receives the response, identify how the application handles invalid responses, and check whether the resulting application session is created only after successful validation. Do not assume the browser itself is a trusted security component.

### 15. SAML Logout and Session Boundaries

SAML authentication and application-session management are separate concerns. A user may have an active identity-provider session, an active service-provider session, and sessions in multiple other applications. Logging out of one application does not necessarily terminate all the others. SAML defines Single Logout mechanisms, but deployment support and behavior vary.

**Questions to investigate.** Does local logout invalidate the application's own session? Does the application initiate or participate in Single Logout? What happens if the identity-provider session remains active? Can a user return to the application without fresh authentication because the IdP session is still valid? Does the application's logout message accurately represent what has been terminated?

This is not automatically a vulnerability. A service provider may legitimately terminate only its own local session. The security issue arises when actual behavior contradicts the application's stated security policy or leaves an unintended access path. For example, a user may click "Log out" and then be silently signed back in because the identity provider still has an active session. That behavior may be expected in some SSO deployments, but it can be misleading or inappropriate in environments requiring stronger logout semantics.

### 16. XML Parser Security

SAML messages use XML, so the implementation must handle XML safely. A dangerous parser configuration can expose an application to XML-related attacks, including external entity processing or unsafe external resource resolution. The details depend on the parser, configuration, and how the XML is processed.

**What to review.** Is the XML parser securely configured? Are unnecessary external entity features disabled? Can untrusted XML trigger external resource access? Are document size and processing complexity appropriately bounded? Does the implementation use a maintained SAML library? Are malformed or unexpectedly structured documents rejected safely? Do not assume that every XML parser enables dangerous behavior by default. Likewise, do not assume that using a SAML library automatically guarantees secure parsing. Review its configuration and relevant security advisories. The right goal is to establish how the actual application parses and validates incoming XML.

### 17. Complete SAML Security Review Checklist

Use this checklist when reviewing a SAML implementation.

| Area | What to verify |
|---|---|
| Signature validation | Required signatures are verified against trusted keys |
| Signature coverage | The consumed identity data is covered by the verified signature |
| Issuer | The issuer matches the expected trusted identity provider |
| Audience | The assertion is intended for the service provider |
| Destination | Applicable response destination requirements are enforced |
| Recipient | Applicable subject-confirmation recipient requirements are enforced |
| Time conditions | Validity periods are checked correctly |
| Subject confirmation | Required subject-confirmation conditions are enforced |
| Request correlation | `InResponseTo` and request state are validated when required |
| Replay | Reuse is prevented where required by the flow and security policy |
| XML parsing | Parser configuration is safe |
| Identity mapping | The assertion maps to the correct local account |
| Attributes | Only trusted attributes control sensitive application behavior |
| Authentication context | Required authentication strength is enforced |
| Session creation | A session is created only after successful validation |
| Logout | Session termination matches the intended policy |
| Metadata and keys | Trust configuration and key rotation are handled securely |
| Error handling | Invalid assertions are rejected without unnecessary information leakage |
| Monitoring | Relevant authentication failures and suspicious activity are logged |

Important: not every row maps to an independent vulnerability in every deployment. Validate the applicable protocol requirements, profile, library behavior, and application policy before reporting a finding.

### 18. Simulated Bug-Hunting Case

A fictional enterprise application uses SAML SSO. A tester discovers this simplified backend code:

```python
def saml_acs(request):
    xml = decode_base64(request.form["SAMLResponse"])
    document = parse_xml(xml)

    if verify_signature(document):
        email = document.find(".//NameID").text
        user = find_user_by_email(email)

        return create_session(user)

    return authentication_failure()
```

The tester should not immediately conclude that the application is exploitable. Instead, examine the following.

**Issue A: what exactly does `verify_signature()` verify?** Does it validate the correct signature, the trusted signing key, the expected signed element, and the relationship between the verified element and the identity being consumed? The function name alone does not answer these questions.

**Issue B: what does `find(".//NameID")` select?** Does it select the subject from the validated assertion, or could it select an element elsewhere in the document? If the application consumes identity data outside the verified content, an XML Signature Wrapping problem may exist.

**Issue C: where are the protocol conditions checked?** The code does not visibly demonstrate audience validation, applicable recipient and destination validation, time-condition validation, request correlation, subject-confirmation validation, or replay handling. These omissions are review leads, not definitive proof. A library or wrapper might perform some of these checks elsewhere.

**Issue D: how is the user mapped?** Is email the intended stable identifier? Is it guaranteed to come from the trusted identity provider? Can two issuers produce the same email? Is account linking safe?

**Issue E: when is the session created?** Does the application establish a session only after all required validation succeeds? Could any exception or partial-validation path create an authenticated session?

**Senior-level conclusion.** A good tester traces the full path from incoming response to validated assertion, identity mapping, and session creation. The key question is not whether a particular function appears in the code. It is whether the application correctly enforces the complete security requirements before trusting the identity.

### 19. Severity and Reporting

SAML issues can have serious consequences, but severity must be based on demonstrated impact.

| Finding | Potential impact |
|---|---|
| Forged assertion accepted | Potential authentication bypass |
| Signature wrapping changes consumed identity | Potential impersonation |
| Audience validation missing | Cross-service assertion acceptance |
| Expired assertions accepted | Extended opportunity for misuse |
| Assertion replay accepted | Potential reuse of an authentication response |
| Weak identity mapping | Potential account confusion or takeover |
| Authentication context not enforced | Potential authentication downgrade |
| Untrusted role attribute accepted | Potential privilege escalation |
| Unsafe XML parsing | Potential XML-processing attack impact |
| Incomplete logout behavior | Persistent or unexpected authentication |

These are potential impacts, not automatic severity ratings. For example, accepting an assertion with an incorrect audience may be serious if it allows cross-application impersonation. In another configuration, additional controls may prevent any meaningful impact.

**Strong evidence includes** the exact authentication flow and configuration, a description of the expected validation requirement, the controlled test input or relevant code path, the actual validation failure, evidence of the resulting account or session state, the affected trust boundary and realistic impact, and any limitations or compensating controls. Never include real users' authentication assertions, session cookies, or private identity data in a public report.

### 20. Module 10 Final Mental Model

When assessing SAML, remember this sequence: receive, parse safely, validate cryptographic trust, validate protocol conditions, bind the correct identity, apply authentication policy, create the session. Every step has a different responsibility. Safe parsing does not prove authenticity. A valid signature does not prove the assertion is intended for this application. A trusted issuer does not automatically prove that the subject maps to the correct local account. A valid assertion does not automatically satisfy every authentication-strength requirement. Successful authentication does not replace application authorization.

The most dangerous implementation mistakes often occur when one component assumes another component has already performed a security check. Your job is to verify that the checks actually happen, and that the application uses the result of those checks correctly.

## Assessment

Unlike most of the prior phases, this phase has no separate instructor-graded challenge transcript to draw an assessment from. The two exercises below are instead drawn directly from the module's own embedded material, Section 18's complete simulated bug-hunting case, using the module's own given reasoning as the answer.

### Assessment Question 1

A fictional enterprise application uses SAML SSO. You discover this simplified backend code:

```python
def saml_acs(request):
    xml = decode_base64(request.form["SAMLResponse"])
    document = parse_xml(xml)

    if verify_signature(document):
        email = document.find(".//NameID").text
        user = find_user_by_email(email)

        return create_session(user)

    return authentication_failure()
```

Should you immediately conclude that this application is exploitable? Walk through what `verify_signature()` and `find(".//NameID")` each actually need to establish before you could reach that conclusion, and explain the specific risk if they do not.

<details markdown="1">
<summary><strong>Reveal Answer</strong></summary>

No, you should not immediately conclude the application is exploitable. The function name `verify_signature()` alone does not answer the questions that actually matter: does it validate the correct signature, does it chain to the trusted signing key, does it check the expected signed element specifically, and critically, does it establish the relationship between the element it verified and the identity the application goes on to consume? A function can genuinely verify a real, valid signature on part of a document while the application still uses identity data from a different, unverified part of that same document.

That second question is exactly what `find(".//NameID")` raises. This is a broad XML search expression, it does not inherently select the subject specifically from the assertion that was just validated, it could just as easily select a `NameID` element located elsewhere in the document. If the application consumes identity data that falls outside the content actually covered by the verified signature, that is precisely the XML Signature Wrapping problem: the cryptographic operation may have genuinely succeeded on one assertion, while the application's authentication decision is actually driven by a different, unverified assertion elsewhere in the response. The specific risk, if that mismatch exists, is that an attacker could include a legitimately signed assertion for their own low-privilege identity alongside a second, unsigned, forged assertion claiming to be an administrator, and if the broad search picks up the forged one, the attacker authenticates as the administrator despite the signature check having technically passed.

</details>

### Assessment Question 2

Continuing the same code review, the function also does not visibly demonstrate audience validation, recipient or destination validation, time-condition validation, request correlation, subject-confirmation validation, or replay handling, and it is unclear whether `email` is a safe, stable identifier to map to a local account. Are these omissions proof of vulnerabilities on their own? What is the correct way to reach a conclusion about this code, and what should you check about exactly when the session gets created?

<details markdown="1">
<summary><strong>Reveal Answer</strong></summary>

No, these omissions are review leads, not definitive proof of vulnerabilities. A surrounding library or wrapper that this snippet doesn't show might perform some or all of these checks elsewhere in the request-handling path before this function is ever reached. The correct way to reach a conclusion is to trace the complete path, from the incoming response, through validated-assertion extraction, through identity mapping, all the way to session creation, rather than judging the vulnerability status of the application from this one function name in isolation.

On the identity-mapping question specifically: whether email is a safe identifier to map to a local account depends on whether it is actually the intended stable identifier for this deployment, whether it is guaranteed to originate from the trusted identity provider rather than being attacker-influenced, whether two different issuers could plausibly produce the same email value, and whether whatever account-linking process exists around this lookup is itself safe. None of that can be determined from `find_user_by_email(email)` alone.

Finally, and just as importantly, check precisely when the session gets created: does the application establish a session only after every required piece of validation has actually succeeded, and could any exception path, partial-validation branch, or error-handling shortcut in the surrounding code still result in an authenticated session being created despite incomplete validation? The key question throughout this entire exercise is never whether a particular function appears in the code. It is whether the application, as a complete system, actually enforces every required security check before it trusts the identity the response claims to represent.

</details>

## Remediation and Secure Implementation

The following consolidates the remediation guidance across all twenty sections of this phase.

1. Use a reputable, maintained SAML library rather than reimplementing signature verification or XML parsing from scratch, and configure it according to the deployment's actual trust requirements.
2. Verify that the identity data consumed for authentication comes from the exact XML content covered by the verified signature, never from a separate, broad search of the document, to prevent XML Signature Wrapping.
3. Validate the `Audience` restriction against the service provider's own expected entity identifier using exact, configuration-driven comparison, never a substring or pattern match.
4. Enforce applicable `Destination` and subject-confirmation `Recipient` requirements as checks distinct from audience validation, comparing against trusted configuration rather than unsafely derived request data.
5. Enforce `NotBefore` and `NotOnOrAfter` time conditions on every assertion, with only a deliberately bounded, appropriate clock-skew tolerance, and separately implement replay protection, since a short validity window alone does not prevent reuse within that window.
6. Establish identity provider trust through securely managed, pinned metadata and signing keys, never by trusting a key or endpoint referenced inside the incoming assertion itself.
7. Bind the validated subject to a local account using a stable, intended identifier and a defined account-linking policy, rather than mechanically trusting an email or display-name attribute as a permanent, unique identity key.
8. Validate the returned authentication context against the actual assurance level a given operation requires, and do not let a weaker authentication route reach a privileged application or action.
9. Define explicitly which trusted sources may supply which attributes and what those attributes are permitted to control, and never map a user-influenced or unverified attribute directly to an administrative role.
10. Create the application session only after every required validation step has succeeded, and audit every exception path and error branch to confirm none of them can result in a session despite incomplete validation.

## Key Takeaways

SAML security rests on a single discipline repeated in a dozen different forms throughout this phase: a component earlier in the pipeline successfully completing its job is not proof that a later component correctly used the result. A valid signature does not prove the signed content is what the application consumed. A trusted issuer does not prove the subject maps to the right account. A technically successful authentication does not prove the required assurance level was met. The module's own final mental model states this as a sequence, receive, parse safely, validate cryptographic trust, validate protocol conditions, bind the correct identity, apply authentication policy, create the session, and insists that every step has a different responsibility that the next step must not simply assume was already handled.

The assessment case in this phase distills that discipline into its sharpest form: a function literally named `verify_signature()` can be entirely honest about what it verifies while the application still authenticates the wrong person, because the vulnerability lives in the gap between what was verified and what was consumed, not in the verification itself failing. That gap, between a check succeeding and its result being used correctly, is the pattern to carry forward from this phase into every remaining one.

## Review Checklist

- [ ] Can you name SAML's three components and state the central security question the module poses about trust?
- [ ] Can you walk through all six steps of the SAML authentication flow and distinguish a valid assertion from an authenticated session?
- [ ] Can you identify, from a source code snippet, whether identity extraction actually derives from the content a signature verified, or from a separate, unverified search?
- [ ] Can you explain XML Signature Wrapping in your own words, including why it is not simply "the signature is missing"?
- [ ] Can you distinguish audience validation from destination and recipient validation as three separate checks?
- [ ] Can you explain why expiration and replay prevention are separate controls, and why a short-lived assertion can still be replayed?
- [ ] Can you distinguish identifying a claimed issuer from cryptographically verifying it against trusted configuration?
- [ ] Can you list at least three specific scenarios where `NameID`-based account mapping can cause identity confusion?
- [ ] Can you explain how an authentication downgrade can occur even when the SAML response is technically valid and correctly signed?
- [ ] Can you explain why a role or privilege attribute in an assertion is not inherently trustworthy, even from a legitimate identity provider?
- [ ] Can you explain why logging out of a service provider does not necessarily terminate the identity-provider session?
- [ ] Can you trace the assessment's `saml_acs` function end to end and identify at which specific stage, verification, extraction, condition checking, identity mapping, or session creation, a given finding actually breaks down?

## References to Related Phases

- The `auth_time` concept introduced for federated authentication in **Phase 9, Reauthentication and Step-Up Authentication**, and the authentication-downgrade pattern examined there, both reappear in this phase's treatment of SAML authentication context.
- The stable issuer-plus-subject identity-binding principle, introduced for OIDC account linking in **Phase 7, OAuth 2.0 and OpenID Connect Security**, is the same underlying concern this phase addresses for SAML's distinct `NameID` semantics.
- Session creation and management after successful federated authentication connects directly to **Phase 6, Cookie and Session Security**.
- Authorization flaws arising from trusting unverified attributes such as role claims, flagged in section 13 as reserved for deeper treatment, are examined in full in a later phase, **Authentication-Adjacent Authorization Flaws**.
- Multi-tenant identity isolation, relevant wherever a single identity provider serves multiple service providers or tenants, is covered in the next phase, **Multi-Tenant Identity Isolation**.
