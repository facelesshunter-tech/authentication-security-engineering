# Phase 11: Multi-Tenant Identity Isolation

**Source material:** Module 11 of 17, "Authentication Complete Phases Test.md" (23 numbered sections covering multi-tenant identity isolation, the Module 11 Completion Tracker, and the overall course progress table). As with Phases 5, 9, and 10, "Authentication Security.md" contains no multi-tenant content at all. The Assessment section in this phase is instead built from the module's own embedded material, Section 19's intensive source-code review exercise, using the module's own given findings as the answer.

## Learning Objectives

After completing this phase, you should be able to:

1. Distinguish authentication, identity binding, tenant membership, role evaluation, and tenant isolation as five separate security questions, and explain why a valid login does not establish membership in every tenant an application serves.
2. Describe the identity, membership, and tenant data model, and explain why a role is meaningful only within the scope in which it was granted.
3. Identify a handler that trusts a client-supplied tenant ID without independently verifying the authenticated user's membership in that tenant.
4. Explain why a tenant switcher must revalidate membership and re-derive the role for the new tenant, and identify the specific failure of carrying an old role into a new tenant context.
5. Distinguish a global platform role from a tenant-scoped role, and identify source code that checks the former where the latter is required.
6. Explain how SSO identity confusion between tenants can occur, particularly through unverified email-only account matching, and design a safer issuer-plus-subject binding.
7. Explain why identity-provider discovery answers where authentication happens but must not independently determine what tenant privileges the resulting identity receives.
8. Identify the specific ways a cross-tenant invitation can be abused, including role elevation, tenant substitution, and recipient mismatch.
9. Explain why membership revocation and role downgrades must take effect against active sessions and trusted authorization state, not merely the underlying membership table.
10. Trace tenant isolation beyond the initial HTTP request into database queries, background jobs, caches, host-based routing, SAML configuration, JIT provisioning, and account recovery, and identify the specific failure pattern in each.
11. Apply the module's unified attack-surface map and 7-phase testing methodology to a multi-tenant application, and avoid the seven specific false positives this module identifies.
12. Apply the Phase 1 through Phase 10 impact-validation discipline to multi-tenant findings: distinguish a client-supplied tenant identifier appearing in a request from a demonstrated cross-tenant authorization failure.

## Introduction

Every phase in this course up to now examined authentication within a single organizational boundary: one application, one set of users, one identity domain. This phase studies what happens when a single application serves many organizations at once, a SaaS platform used by competing banks, hospitals, and logistics companies, all sharing one backend, one database, and often one identity service. A system can correctly authenticate a user and still incorrectly authorize them inside someone else's organization. That distinction, between authenticating who someone is and authorizing what organization they may act within, is the single idea this entire module is built around.

The module's own central security requirement states it precisely: one user's identity and privileges must not allow them to act within another organization's boundary unless an explicitly authorized cross-tenant relationship exists. This sounds obvious stated plainly. The fifteen named vulnerabilities in this phase exist because multi-tenant applications introduce dozens of places, login, tenant switching, invitations, background jobs, caches, custom domains, SAML configuration, account recovery, where that rule can quietly fail without anyone noticing, because every individual request still looks like it succeeded.

## Core Concepts

The module moves through four stages. First, sections 1 and 2 establish the architecture: the fundamental problem of shared infrastructure serving separate organizations, and the identity, membership, and tenant data model that correctly separates a person from any single organization's role. Second, sections 3 through 17 examine fifteen specific, named vulnerability categories in turn, moving from the most direct, trusting a client-supplied tenant ID, through tenant switching, role scoping, federated identity confusion, invitations, lifecycle staleness, database scoping, and into the less obvious territory of background jobs, caches, custom domains, tenant-specific SAML configuration, JIT provisioning, and account recovery. Third, section 18 unifies all fifteen into a single attack-surface map. Fourth, sections 19 through 23 bring the module together into a practical discipline: a complete source-code review exercise, a 7-phase testing methodology, seven false positives, a full vulnerability report template, and the final five-question mastery model.

## Lessons

### 1. Understand the Fundamental Problem

Imagine a SaaS application used by three organizations: Tenant A, Acme Bank; Tenant B, Zenith Logistics; and Tenant C, Orion Healthcare. Each organization has its own users, administrators, documents, and business data. The application may use a single backend, database, and identity service for all three organizations. The system authenticates users and then determines which organization they belong to. For example, `alice@acme.example` might have internal user ID `usr_104`, tenant ID `tenant_A`, and role administrator, while `bob@zenith.example` has internal user ID `usr_205`, tenant ID `tenant_B`, and also role administrator. Both users are administrators, but they are administrators of different organizations.

The central security requirement is that Alice's identity and privileges must not allow her to act within Bob's organization unless an explicitly authorized cross-tenant relationship exists. This sounds obvious. However, multi-tenant applications introduce several places where that rule can fail. A system can correctly authenticate Alice and still incorrectly authorize her within Tenant B. That distinction is critical.

**Authentication versus tenant isolation.**

| Security question | What it establishes |
|---|---|
| Authentication | Who is the user? |
| Identity binding | Which internal account corresponds to that identity? |
| Tenant membership | Which organization or organizations may the account access? |
| Role evaluation | What may the user do within that organization? |
| Tenant isolation | Can the user access another organization's resources without authorization? |

These controls are related, but they are not interchangeable. A valid login does not establish membership in every tenant the application serves.

### 2. The Most Important Architecture: Identity, Membership, and Tenant

A weak implementation often treats the user and the tenant as if they were one inseparable record. A more flexible design separates them:

```text
User
----
user_id
identity_provider
external_subject
email
status

Tenant
------
tenant_id
tenant_name
status

Membership
----------
membership_id
user_id
tenant_id
role
status
```

This allows one user to belong to multiple organizations without duplicating their identity. For example, user `usr_104` might have membership as administrator in `tenant_A` and viewer in `tenant_C`. The same person must not automatically become an administrator of Tenant C merely because they administer Tenant A.

**Why this model matters.** Suppose the application stores `{"user_id": "usr_104", "tenant_id": "tenant_A", "role": "administrator"}` to represent the user's active context. The application must still determine whether the user is authorized for the requested operation within that tenant. If the user changes the active tenant to `tenant_B`, the server must not blindly retain the administrator role from Tenant A. The role belongs to a particular membership relationship, not universally to the human being.

Senior-level rule: a role is meaningful only within the scope in which it was granted. An application that fails to preserve that scope may convert a legitimate role into an unintended privilege escalation.

### 3. Vulnerability One: Trusting a Client-Supplied Tenant ID

This is one of the most important patterns to recognize. Consider a fictional application endpoint:

```http
GET /api/tenant/tenant_A/documents HTTP/1.1
Host: saas.example.test
Cookie: session=VALID_SESSION
```

The application returns documents belonging to Tenant A. The user then sends `GET /api/tenant/tenant_B/documents` with the same session, and the response contains Tenant B's documents. Is this automatically a vulnerability? Not necessarily. Some users legitimately belong to multiple tenants. The actual security question is: does the authenticated user have permission to access Tenant B, and did the server verify that permission?

**Vulnerable implementation:**

```python
@app.get("/api/tenant/{tenant_id}/documents")
def get_documents(tenant_id: str):
    return database.get_documents(tenant_id)
```

The handler accepts a tenant ID and retrieves the corresponding records. It does not show authentication, membership verification, or authorization. If those controls are genuinely absent from the full request path, the application may expose data across tenants. But do not judge a handler in isolation if authentication and authorization are enforced by middleware or dependencies elsewhere.

**Safer implementation:**

```python
@app.get("/api/tenant/{tenant_id}/documents")
def get_documents(
    tenant_id: str,
    current_user=Depends(get_authenticated_user),
):
    membership = get_active_membership(
        user_id=current_user.id,
        tenant_id=tenant_id,
    )

    if membership is None:
        raise HTTPException(
            status_code=403,
            detail="Access denied",
        )

    return database.get_documents(
        tenant_id=tenant_id,
    )
```

This is illustrative pseudocode. A production implementation must also handle tenant status, document-level permissions where applicable, and consistent enforcement across the application's access paths. The key difference is that the server checks the authenticated user's membership before retrieving tenant data.

**What a bug hunter should establish.** Authenticate as a controlled user in Tenant A, identify a resource belonging to Tenant A, determine whether the account has any legitimate membership in Tenant B, attempt to access a controlled Tenant B resource only if authorized by the testing scope, observe whether the server independently enforces membership and permissions, and verify the actual data returned or action performed. A tenant ID supplied by the client identifies the requested tenant. It does not prove that the user belongs to that tenant.

### 4. Vulnerability Two: Tenant Switching Without Revalidating Membership

Many SaaS applications provide a tenant switcher. When the user selects a different organization, the application may issue a request:

```http
POST /api/session/switch-tenant HTTP/1.1
Host: saas.example.test
Cookie: session=VALID_SESSION
Content-Type: application/json

{
  "tenant_id": "tenant_C"
}
```

This is a legitimate design pattern. The problem occurs when the server accepts any tenant ID without verifying that the user has an active membership.

**Vulnerable conceptual code:**

```python
def switch_tenant(request, session):
    tenant_id = request.json["tenant_id"]

    session.tenant_id = tenant_id

    save_session(session)

    return {"active_tenant": tenant_id}
```

The handler changes the active tenant without demonstrating any membership check.

**Safer conceptual code:**

```python
def switch_tenant(request, session):
    tenant_id = request.json["tenant_id"]

    membership = get_active_membership(
        user_id=session.user_id,
        tenant_id=tenant_id,
    )

    if membership is None:
        raise AccessDenied()

    session.tenant_id = tenant_id
    session.role = membership.role

    save_session(session)

    return {"active_tenant": tenant_id}
```

The important operations: validate the authenticated identity, check active membership in the requested tenant, derive the role from that membership, update the tenant context, and ensure later operations enforce the context and permissions.

**A subtle failure.** Suppose the server validates membership when switching tenants but retains the old role: `session.tenant_id = tenant_C` while `session.role` remains `"administrator"` from tenant_A. The application has validated tenant membership but failed to update the authorization context. This can create a cross-tenant privilege escalation. Changing the tenant context must not carry unrelated privileges into the new context.

### 5. Vulnerability Three: Global Roles Mistaken for Tenant Roles

This is a classic design mistake. Imagine the database stores `{"user_id": "usr_104", "role": "administrator"}`, and the application uses that role to authorize administrative actions in every tenant. But the user is only an administrator of Tenant A. Their role should not automatically authorize administrative actions in Tenant B.

**Vulnerable code:**

```python
def delete_tenant_document(user, tenant_id, document_id):
    if user.role != "administrator":
        raise AccessDenied()

    delete_document(tenant_id, document_id)
```

The handler checks whether the user is an administrator, but it does not establish whether the user's administrative role applies to the requested tenant.

**Better model:**

```python
def delete_tenant_document(
    user,
    tenant_id,
    document_id,
):
    membership = get_active_membership(
        user_id=user.id,
        tenant_id=tenant_id,
    )

    if membership is None:
        raise AccessDenied()

    if membership.role not in {
        "administrator",
        "document_manager",
    }:
        raise AccessDenied()

    delete_document(
        tenant_id=tenant_id,
        document_id=document_id,
    )
```

This demonstrates tenant-scoped authorization. However, the document's own ownership and access policy must also be respected. Membership alone does not necessarily authorize every action on every resource within a tenant.

**How to identify the weakness in source code.** Look for authorization conditions such as `if user.is_admin:` or `if user.role == "admin":`. Then ask: is this a global platform role, is it an organization-specific role, is the role derived from the correct membership, does the requested tenant match the scope of that membership, and is the action permitted for that role? A global administrator role can be legitimate for platform operations. The vulnerability arises when a role with limited scope is mistakenly treated as universal authority.

### 6. Vulnerability Four: SSO Identity Confusion Between Tenants

Now we move into the intersection of multi-tenant isolation and federated authentication. Imagine a SaaS platform that allows different companies to configure their own SAML identity providers: Tenant A uses IdP A, Tenant B uses IdP B, Tenant C uses IdP C. A user signs in through Tenant A's identity provider. The service provider must establish which identity provider authenticated the user, which external identity was asserted, which SaaS account corresponds to that identity, which tenant membership the account has, and which tenant context the application should establish. A failure in any of these relationships can result in identity confusion.

**Example: matching only by email.** Suppose the application receives issuer `https://idp-a.example.test`, subject `employee-104`, and email `alex@example.test`, and looks up the local account using only `user = find_user_by_email(assertion.email)`. This is not always inherently unsafe, but it can be dangerous if email is not a sufficiently trusted and unique account-binding key in the deployment. Different identity providers may assert the same email address under different trust arrangements. If the application incorrectly treats those identities as interchangeable, one tenant's identity provider could potentially authenticate an account associated with another tenant.

**Better identity binding:**

```python
identity = find_federated_identity(
    issuer=validated_assertion.issuer,
    subject=validated_assertion.subject,
)

if identity is None:
    reject_or_require_account_linking()

user = get_user(identity.user_id)
```

The mapping must be based on a well-defined identity contract. For SAML, the appropriate subject identifier depends on the configured NameID format, identity-provider behavior, and account-linking policy, as covered in Phase 10. Issuer plus subject is a useful conceptual model, but not a universal substitute for correctly configured SAML identity semantics.

**Testing questions.** Can an identity from one tenant resolve to another tenant's local account? Does the application trust the expected identity provider for the selected tenant? Is account linking based solely on an email match? Can a tenant administrator attach an external identity that is already bound elsewhere? Does changing the active tenant change which identity provider or account mapping is trusted? Are deactivated or unlinked external identities still accepted? A successful federated login proves only what the configured identity relationship establishes. It does not automatically establish membership in every organization using the platform.

### 7. Vulnerability Five: Incorrect Identity-Provider Discovery

Some applications use an email address or organization identifier to determine which identity provider should handle a login. The user enters `alice@acme.example`, and the application discovers Tenant A's identity provider and redirects the browser to it. This can be convenient, but the discovery process must not let an untrusted user arbitrarily select a different organization's authentication configuration.

**Potential design failure.** The application accepts a request such as:

```http
POST /login/discover HTTP/1.1
Host: saas.example.test
Content-Type: application/json

{
  "tenant_id": "tenant_B",
  "email": "alice@acme.example"
}
```

The application then uses Tenant B's SSO configuration without establishing that the login identity and intended tenant context are consistent with the application's policy. This is not automatically exploitable. A user may legitimately be allowed to authenticate through a particular provider or belong to several organizations. The security failure occurs when the application uses an untrusted discovery choice to bypass its intended identity-to-tenant binding.

**What to inspect.** How the tenant is discovered, whether the discovery identifier is authoritative, whether the chosen identity provider is configured and trusted for that tenant, whether the callback is correlated with the correct login transaction, whether the resulting identity is bound to the intended account and membership, and whether the application silently falls back to another identity provider when validation fails.

Senior-level lesson: identity-provider discovery determines where authentication happens. It must not independently determine what tenant privileges the resulting identity receives.

### 8. Vulnerability Six: Cross-Tenant Invitation Abuse

Invitations are a frequent source of identity and membership errors. Imagine an administrator of Tenant A invites `new.employee@example.test`. The application creates a pending invitation. A safe design should associate the invitation with the intended tenant, the invited identity or email according to policy, the permitted role, the inviter, an expiration policy, a unique invitation token, and a clear acceptance state.

**Vulnerable conceptual model:**

```python
def accept_invitation(request, user):
    invitation_id = request.json["invitation_id"]

    invitation = get_invitation(invitation_id)

    add_membership(
        user_id=user.id,
        tenant_id=request.json["tenant_id"],
        role=request.json["role"],
    )

    mark_invitation_accepted(invitation)

    return {"message": "Invitation accepted"}
```

The request controls the tenant and role independently of the invitation. If the implementation does not enforce the invitation's original tenant, permitted role, intended recipient, expiry, and acceptance state, the invitation process may grant unintended membership or privileges.

**Safer conceptual approach:**

```python
def accept_invitation(request, user):
    invitation = get_invitation_by_secure_token(
        request.json["invitation_token"]
    )

    if invitation is None:
        raise InvalidInvitation()

    if invitation.is_expired or invitation.is_accepted:
        raise InvalidInvitation()

    if not invited_identity_matches(
        user,
        invitation,
    ):
        raise AccessDenied()

    create_membership(
        user_id=user.id,
        tenant_id=invitation.tenant_id,
        role=invitation.permitted_role,
    )

    mark_invitation_accepted(invitation)

    return {"message": "Invitation accepted"}
```

This is illustrative pseudocode. Production systems need appropriate token protection, atomic state transitions, concurrency handling, and a clear identity-matching policy.

**Important testing distinctions.** An invitation is not automatically unsafe because the invited user can join a tenant without already belonging to it, that is the purpose of an invitation. The security question is whether the application enforces the invitation's intended scope and permissions: can a viewer invitation be turned into an administrator invitation, can an invitation for Tenant A create membership in Tenant B, can an invitation intended for one identity be accepted by an unauthorized identity, and can an accepted or expired invitation be reused? Each finding requires evidence of an actual policy violation.

### 9. Vulnerability Seven: Tenant Context Persists After Membership Revocation

Consider an employee who belongs to Tenant A. The employee's session contains `{"user_id": "usr_104", "active_tenant": "tenant_A", "role": "administrator"}`. An administrator then removes that employee's membership. The application updates the membership table, but the employee's session remains active. What happens when the employee makes another request? If the server relies exclusively on stale session data, the former member may retain access.

**The dangerous implementation:**

```python
def access_tenant_resource(request):
    session = request.session

    if session.is_authenticated:
        return load_resource(
            tenant_id=session.active_tenant,
            role=session.role,
        )
```

This code demonstrates a risk if the stored role and tenant membership are not revalidated or reliably invalidated when membership changes.

**Better design.** The application should ensure that membership revocation takes effect according to its security policy. Possible approaches include rechecking active membership on sensitive requests, using versioned authorization state, invalidating relevant sessions when membership or privileges change, using short-lived authorization data with reliable refresh and revocation, or combining approaches according to the application's risk model. The exact implementation depends on the architecture.

**Testing workflow.** Using two controlled accounts: establish a legitimate session for a tenant member, revoke that account's membership using an authorized administrator, attempt an ordinary request and a sensitive request using the existing session, determine whether access continues, check whether a fresh login changes the result, and examine whether the application invalidates sessions or refreshes membership state. Do not confuse an application displaying cached data with the server continuing to authorize requests. Verify whether protected data can still be retrieved or a protected action can still be performed.

### 10. Vulnerability Eight: Stale Roles After Privilege Changes

Membership revocation is only one lifecycle problem. Consider this sequence: a user is an administrator in Tenant A, the administrator is downgraded to a viewer, the user retains an active session containing the old administrator role, and the server continues accepting the stale role. The application may now allow actions that the user's current membership no longer permits.

For example, the current database state is `role: viewer`, but the existing session still contains `{"user_id": "usr_104", "tenant_id": "tenant_A", "role": "administrator"}`. If the backend authorizes sensitive actions using only the session's old role, the role downgrade may not take effect.

**What to review.** Where are roles stored? How are role changes propagated to active sessions? Are authorization decisions based on current trusted state? Are stale sessions invalidated or refreshed? Does the application treat global and tenant-scoped roles differently? Are privileged operations checked independently at the server? The presence of a role claim in a signed token is not inherently a vulnerability. The problem is failing to handle role changes and revocation according to the application's security requirements.

### 11. Vulnerability Nine: Cross-Tenant Data Leaks Through Incorrect Database Scoping

This is where authentication, authorization, and data isolation meet. Suppose the application stores documents with `document_id`, `tenant_id`, `title`, `content`. The intended query is:

```sql
SELECT document_id, title, content
FROM documents
WHERE tenant_id = :authorized_tenant_id
  AND document_id = :document_id;
```

But a vulnerable query might be:

```sql
SELECT document_id, title, content
FROM documents
WHERE document_id = :document_id;
```

If document identifiers are not globally protected by another authorization check, the second query may return a document belonging to another tenant.

**Important distinction.** This is often described as a cross-tenant authorization or data-isolation vulnerability, rather than purely an authentication flaw. It belongs in this course because incorrect identity-to-tenant binding often causes it.

**Safer design principle.** The application should derive the authorized tenant context from trusted server-side state and enforce the appropriate tenant and resource permissions in the data-access path:

```python
def get_document(user, tenant_id, document_id):
    membership = require_active_membership(
        user.id,
        tenant_id,
    )

    require_document_read_permission(membership)

    return database.get_document(
        tenant_id=tenant_id,
        document_id=document_id,
    )
```

The data query must use the authorized tenant context. A correct query alone does not solve every issue. The application must also establish that the user is allowed to access that tenant and document.

**Deeper architectural defenses.** Depending on the system, defenses can include tenant-scoped repository methods, database row-level security, composite uniqueness constraints, tenant-aware foreign keys or integrity rules, centralized authorization policies, negative cross-tenant tests, and monitoring for denied cross-tenant access. Database row-level security can provide valuable defense in depth, but it must be configured correctly and cannot compensate for every flaw in identity binding or application authorization.

### 12. Vulnerability Ten: Background Jobs and Asynchronous Processing

This is an easy area to overlook during manual testing. Suppose a user requests an export of tenant data:

```http
POST /api/exports HTTP/1.1
Host: saas.example.test
Cookie: session=VALID_SESSION
Content-Type: application/json

{
  "tenant_id": "tenant_A",
  "format": "csv"
}
```

The application queues a background job. The job later processes the request and generates a downloadable file. The initial endpoint might correctly check membership, but the background worker could still use untrusted or stale tenant information.

**Potential failure:**

```python
def process_export_job(job):
    tenant_id = job["tenant_id"]

    export_all_documents(tenant_id)
```

This illustrates a risky design if the job's tenant context and authorization are not properly validated when the job is created and processed.

**What should happen?** The system should establish which authenticated user requested the job, which tenant the job is authorized to access, whether the user was authorized at the relevant decision point, which permissions the job is intended to exercise, whether the job's stored parameters can be modified or confused, and whether generated files are accessible only to authorized users. The right revocation behavior depends on the system's policy. Some systems authorize the operation at job creation, others revalidate at execution or download. Sensitive operations may need both.

**Testing opportunities.** Review export jobs, report generation, scheduled jobs, document conversions, email-delivery jobs, webhook processing, bulk imports, and long-running administrative tasks. The key lesson is that tenant isolation must survive asynchronous boundaries, not just the initial HTTP request.

### 13. Vulnerability Eleven: Cross-Tenant Cache Contamination

Caches can introduce a different class of isolation failure. Imagine that a backend caches a document using the key `cache_key = f"document:{document_id}"`. Two tenants somehow request the same logical identifier, or the cached result is not adequately scoped to the tenant. A response generated for Tenant A could be returned to a request from Tenant B if the cache lookup and authorization model are incorrect.

**Risky design:**

```python
def get_document(tenant_id, document_id):
    key = f"document:{document_id}"

    cached = cache.get(key)

    if cached is not None:
        return cached

    return fetch_and_cache_document(
        key,
        tenant_id,
        document_id,
    )
```

The key does not include the tenant, and the example does not show authorization before returning a cached result. This is a review lead, not proof that a real application is exploitable.

**What to verify.** Are cache keys scoped appropriately? Does authorization occur before cached protected data is returned? Can a cache entry created under one tenant be served under another? Are authorization decisions cached, and how are they invalidated? Does the cache distinguish users, tenants, roles, and resource permissions where necessary?

A tenant-aware cache key might look like `cache_key = f"tenant:{authorized_tenant_id}:document:{document_id}"`. However, adding the tenant to the cache key does not eliminate the need for authorization. The tenant identifier must itself come from a trusted authorization decision.

### 14. Vulnerability Twelve: Tenant-Specific Domain and Host Confusion

Some SaaS platforms use custom domains, such as `acme.example.test` and `zenith.example.test`. Others allow customer-owned domains, such as `portal.acme.example`. The incoming host may help identify the tenant, but it should not be treated as sufficient proof of membership or authorization.

**Dangerous assumption:**

```python
tenant = find_tenant_by_host(request.headers["Host"])
user = get_authenticated_user(request)

return load_tenant_dashboard(tenant, user)
```

This code is incomplete if it does not also check whether the user may access the tenant. Resolving a tenant from a hostname answers a routing question. It does not necessarily answer the authorization question.

**What to examine.** Is the hostname mapped to a verified tenant configuration? Are unrecognized hosts rejected? Can tenant routing be confused by untrusted host information? Does the application independently validate user membership? Are SAML callback URLs and tenant-specific identity-provider settings correctly bound? Can one tenant's login configuration influence another tenant's login flow? A well-designed application may legitimately use the host to select a tenant. The security failure occurs when that selection bypasses or corrupts identity, membership, or trust validation.

### 15. Vulnerability Thirteen: Tenant-Specific SAML Configuration Errors

Let's combine this module with the SAML material from Phase 10. Suppose each tenant configures its own SAML identity provider: `tenant_A → IdP A → signing configuration A`, `tenant_B → IdP B → signing configuration B`. A response arrives at the SAML assertion consumer endpoint. The application must determine which configuration applies and validate the response against the correct trust relationship.

**Dangerous implementation pattern.** The application selects the signing configuration using a tenant ID supplied by the incoming response, then treats that same response as trustworthy after validation. The risk is a circular trust decision: untrusted input influences which identity provider or key is trusted to validate that input. This does not mean an incoming tenant identifier can never be used to look up configuration. It means the lookup and transaction must be securely bound to an expected tenant and authentication flow.

**Safer approach.** Start an authentication transaction for a known tenant, record the expected tenant and identity-provider configuration in trusted server-side transaction state, initiate the SAML flow using that configuration, validate the response against the expected trust configuration, validate applicable issuer, audience, recipient, time, and correlation conditions, map the validated external identity to a local account, confirm the account has the required active tenant membership, and create the application session with the correct tenant context.

**Critical distinction.** A response signed by Tenant A's legitimate identity provider may be perfectly authentic. It can still be invalid for a login transaction initiated for Tenant B. Cryptographic authenticity and tenant-context correctness are separate checks.

### 16. Vulnerability Fourteen: Just-in-Time Provisioning Creates Excessive Membership

Some enterprise applications create a local user or tenant membership automatically the first time a user authenticates through SSO, commonly called just-in-time provisioning. It can be legitimate and useful, but its rules must be explicit.

**Example.** A user authenticates through a corporate identity provider. The application receives a valid identity and creates a local account. That behavior is not automatically dangerous. The risk arises if the application creates membership in the wrong tenant, trusts an unverified organization attribute, grants excessive privileges by default, allows an unexpected identity provider to provision users, recreates membership after an administrator revoked it, or fails to enforce the tenant's provisioning policy.

**Example of a risky default:**

```python
def provision_user(assertion):
    user = create_or_find_user(assertion.subject)

    create_membership(
        user_id=user.id,
        tenant_id=assertion.attributes["tenant_id"],
        role="administrator",
    )

    return user
```

This illustrates multiple potential issues: the tenant comes from an attribute whose trust has not been established in the example, the role is automatically elevated, the code does not show whether provisioning is enabled for that tenant, and it does not show how existing membership and revocation are handled.

**What a safer policy considers.** Is just-in-time provisioning enabled for this tenant? Which identity provider is trusted to provision users? Which verified attribute or configuration establishes the organization? What is the default role? Does the organization require administrator approval? Can provisioning reactivate a previously disabled membership? Are changes audited? Successful SSO authentication should not silently grant privileges that the tenant's provisioning policy does not authorize.

### 17. Vulnerability Fifteen: Tenant Isolation Failures in Account Recovery

Account recovery can also cross tenant boundaries. Imagine a user belongs to two organizations and has a local account associated with both. The application uses a password-reset token to identify the account. A dangerous implementation might accept both a valid reset token and a separate client-supplied tenant or account identifier, then use the client-supplied identifier to determine which account or membership should be modified. The token may prove control of one account, while the untrusted parameter redirects the operation toward another account context.

**The rule.** The account being recovered must be determined by the validated recovery transaction, not by an unrelated client-controlled tenant identifier. If the recovery operation affects tenant-specific identity state, the server must independently verify the relevant account and tenant relationship.

**Review these scenarios.** A user requests a reset while a particular tenant is selected. The user has memberships in multiple tenants. The email address is shared or mapped across identity providers. The account's tenant membership has been revoked. The user is invited to a new tenant while a recovery flow is pending. The account has both local credentials and federated identities. The intended behavior depends on the architecture, but recovery must not become an alternative route around tenant-bound identity checks.

### 18. A Unified Attack-Surface Map

At this point, you should understand that multi-tenant identity isolation is not one endpoint check. It is a property that must survive across the entire application lifecycle.

| Component | Failure to investigate |
|---|---|
| Login | Wrong identity provider or tenant context |
| SAML/OIDC callback | Incorrect identity-to-tenant binding |
| Account linking | Identity confusion between organizations |
| Tenant switcher | Membership not revalidated |
| Invitation acceptance | Wrong tenant or excessive role |
| Session creation | Stale or incorrectly scoped authorization state |
| Membership changes | Revoked access remains active |
| API handlers | Client-supplied tenant trusted without authorization |
| Database queries | Records retrieved without correct tenant scope |
| Background jobs | Tenant context lost or misapplied |
| Caches | Data or authorization state leaks across tenants |
| Custom domains | Host-based tenant selection bypasses authorization |
| Provisioning | Unauthorized or excessive membership created |
| Recovery | Account or tenant binding becomes confused |
| Logout | Old tenant context remains usable |
| Audit logs | Events attributed to the wrong tenant or identity |

This table is a map of where to investigate, not a list of confirmed vulnerabilities.

### 19. Intensive Source-Code Review Exercise

Now apply the concepts as a senior reviewer. Consider this fictional FastAPI-style handler:

```python
@app.post("/api/tenant/{tenant_id}/users/{user_id}/role")
def update_role(
    tenant_id: str,
    user_id: str,
    request: RoleUpdate,
    current_user=Depends(get_authenticated_user),
):
    if current_user.role != "administrator":
        raise HTTPException(status_code=403)

    user = database.get_user(user_id)

    if user is None:
        raise HTTPException(status_code=404)

    user.role = request.role
    database.save(user)

    return {"message": "Role updated"}
```

The endpoint changes a user's role. Let's review it.

**Finding A: role scope is unclear.** The code checks `current_user.role != "administrator"`, but it does not establish whether the caller is an administrator of the requested tenant. A user who is an administrator of Tenant A should not automatically be allowed to manage roles in Tenant B.

**Finding B: target-user membership is not checked.** The code fetches a user by `user_id` without showing whether the target belongs to the requested tenant. If the database operation can retrieve a user from another tenant, the endpoint may permit cross-tenant role changes.

**Finding C: the requested tenant is not enforced in the update.** Although `tenant_id` is part of the URL, the database lookup uses only `user_id`. The requested tenant therefore does not visibly constrain the target record.

**Finding D: role assignment policy is missing.** The code accepts `request.role`. A robust implementation must enforce which roles the caller is permitted to assign, including whether the caller may create another administrator or assign a platform-level role.

**Finding E: membership and session consistency are unclear.** If a role changes, the system must ensure that existing sessions and authorization decisions respect the change according to policy.

**A safer conceptual design:**

```python
@app.post("/api/tenant/{tenant_id}/users/{user_id}/role")
def update_role(
    tenant_id: str,
    user_id: str,
    request: RoleUpdate,
    current_user=Depends(get_authenticated_user),
):
    actor_membership = get_active_membership(
        user_id=current_user.id,
        tenant_id=tenant_id,
    )

    if actor_membership is None:
        raise HTTPException(status_code=403)

    if not can_manage_roles(actor_membership):
        raise HTTPException(status_code=403)

    target_membership = get_active_membership_for_user(
        user_id=user_id,
        tenant_id=tenant_id,
    )

    if target_membership is None:
        raise HTTPException(status_code=404)

    if not can_assign_role(
        actor_membership,
        request.role,
    ):
        raise HTTPException(status_code=403)

    update_membership_role(
        target_membership,
        request.role,
    )

    invalidate_stale_authorization_state(
        user_id=user_id,
        tenant_id=tenant_id,
    )

    return {"message": "Role updated"}
```

This example is still conceptual. Production systems must define role hierarchy, prevent unauthorized privilege escalation, protect platform-level administration, handle concurrent updates, and enforce consistent authorization throughout the application.

**The senior-level conclusion.** The improved implementation establishes three separate relationships: the caller belongs to the tenant, the caller is authorized to manage roles within that tenant, and the target user's membership is also within that tenant. It also constrains which role assignments are permitted. That is the difference between checking whether a person is an administrator and determining whether that person is authorized to perform this specific operation within this specific organization.

### 20. How to Test Multi-Tenant Isolation Properly

Use this workflow in an authorized staging environment or an explicitly scoped security assessment.

**Phase 1: establish a tenant matrix.** Create or identify controlled accounts:

| Account | Tenant A | Tenant B |
|---|---|---|
| User A | Administrator | No membership |
| User B | Viewer | Administrator |
| User C | No membership | Viewer |

Record the actual membership and role relationships. Do not assume that an email domain or global role proves membership.

**Phase 2: map identity flows.** Document local login, SAML or OIDC login, account linking, tenant selection, tenant switching, invitations, provisioning, recovery, and logout. For federated login, identify how the application selects and trusts the identity provider.

**Phase 3: map sensitive operations.** Identify operations that read tenant data, modify tenant data, manage memberships, change roles, configure SSO, export information, create credentials, or delete tenant resources. Prioritize operations with high impact.

**Phase 4: verify membership enforcement.** For each operation, determine which identity is authenticated, which tenant is being accessed, whether active membership is required, which role or permission is required, whether the target resource belongs to that tenant, and whether the server independently enforces those conditions.

**Phase 5: test lifecycle changes.** Using controlled accounts, examine what happens after membership revocation, role downgrade, tenant deactivation, identity-provider unlinking, invitation expiration, and session termination. Check whether existing sessions and background operations respect the intended policy.

**Phase 6: inspect indirect data paths.** Review exports, caches, reports, background jobs, webhooks, file downloads, notifications, and audit logs. Tenant isolation must remain correct beyond the initial request handler.

**Phase 7: verify impact.** Determine whether the behavior actually permits unauthorized tenant access, cross-tenant data disclosure, unauthorized role changes, account impersonation, privilege escalation, or persistence after revocation. A parameter changing successfully is not enough. Confirm the security consequence.

### 21. False Positives That Experienced Testers Avoid

**False positive 1: a user belongs to several tenants.** This is a legitimate SaaS feature. Cross-tenant access is not a vulnerability when the user has an authorized membership and the requested action is permitted.

**False positive 2: the same person is an administrator in two organizations.** That can also be legitimate. The important question is whether each role was independently granted and correctly scoped.

**False positive 3: a tenant ID appears in the URL.** Client-supplied tenant identifiers are not inherently insecure. The vulnerability exists when the server fails to enforce authorization for the selected tenant.

**False positive 4: an application uses email to locate an account.** Email-based mapping is not automatically vulnerable. Assess the trust guarantees, uniqueness assumptions, verification policy, account-linking rules, and behavior across identity providers.

**False positive 5: a revoked user's browser still displays information.** The browser may be displaying cached data. Verify whether the server still permits protected requests or sensitive operations.

**False positive 6: a SAML assertion is accepted by more than one application.** That can be legitimate when trust and audience configuration intentionally allow it. Investigate whether the assertion is accepted outside its intended audience or trust relationship.

**False positive 7: a background job completes after the user loses membership.** The system may have intentionally authorized the job at creation time. Determine the application's policy, operation sensitivity, and whether subsequent download or access is still authorized.

### 22. How to Write a Strong Multi-Tenant Vulnerability Report

Let's use a hypothetical confirmed finding.

**Title:** Cross-Tenant Role Update Due to Missing Tenant-Scoped Authorization.

**Summary:** An authenticated user with administrative privileges in Tenant A can modify a user's role in Tenant B because the role-management endpoint does not enforce tenant-scoped authorization for the caller and target user.

**Preconditions:** the attacker has an ordinary account with administrative privileges in Tenant A; the target user belongs to Tenant B; the attacker does not have authorized membership or administrative privileges in Tenant B.

**Evidence:** the attacker's legitimate tenant membership and role; the target user's membership in the other tenant; the relevant request and response from the authorized test; evidence that the role change actually occurred; the target user's resulting permissions, if safely verified; and the affected code path or missing authorization check.

**Impact:** an attacker may gain unauthorized control over users or privileges belonging to another organization. Depending on the assigned role and application capabilities, this may lead to cross-tenant privilege escalation or further data exposure.

**Remediation:** enforce active tenant membership for the caller; enforce tenant-scoped permissions for the requested operation; resolve the target membership within the same authorized tenant context; restrict which roles can be assigned; ensure stale sessions and authorization caches respect membership changes; and add regression tests for unauthorized cross-tenant access.

**Severity considerations:** severity depends on the attacker's initial privileges, whether another tenant's data or users are affected, the role that can be assigned, whether the attack requires victim interaction, whether the attacker can gain administrative control, and any effective compensating controls. A confirmed cross-tenant administrative takeover can be very serious. A harmless tenant identifier appearing in a request is not.

### 23. Final Mastery Model: Five Questions for Every Tenant-Sensitive Operation

Whenever you assess a multi-tenant application, ask these five questions.

**1. Who is authenticated?** Identify the actual authenticated principal, not merely an email address or username found in a request.

**2. Which identity provider or credential established that identity?** For federated login, confirm that the trust relationship is correct and that the identity is bound to the intended account.

**3. Which tenant membership authorizes the operation?** Determine whether the user has an active membership in the specific tenant and whether the required role applies there.

**4. Does the requested resource belong to the authorized tenant?** The tenant context must be enforced when retrieving or modifying the resource, not merely displayed in the interface.

**5. Will the authorization remain correct after lifecycle changes?** Membership revocation, role changes, tenant deactivation, logout, and identity-provider changes must be handled according to the security policy.

If any answer is missing, you have a concrete area to investigate. The ultimate principle: identity must be established correctly, membership must be verified independently, and authorization must remain scoped to the intended tenant throughout the operation.

## Assessment

Unlike most of the prior phases, this phase has no separate instructor-graded challenge transcript to draw an assessment from. The two exercises below are instead drawn directly from the module's own embedded material, Section 19's intensive source-code review exercise, using the module's own given findings as the answer.

### Assessment Question 1

Review this fictional FastAPI-style handler as a senior reviewer:

```python
@app.post("/api/tenant/{tenant_id}/users/{user_id}/role")
def update_role(
    tenant_id: str,
    user_id: str,
    request: RoleUpdate,
    current_user=Depends(get_authenticated_user),
):
    if current_user.role != "administrator":
        raise HTTPException(status_code=403)

    user = database.get_user(user_id)

    if user is None:
        raise HTTPException(status_code=404)

    user.role = request.role
    database.save(user)

    return {"message": "Role updated"}
```

Identify every security concern with this implementation, and explain specifically why checking `current_user.role != "administrator"` is not, by itself, sufficient authorization for this operation.

<details markdown="1">
<summary><strong>Reveal Answer</strong></summary>

Five findings. First, role scope is unclear: the code checks whether `current_user.role` equals `"administrator"`, but it never establishes whether the caller is an administrator specifically of the tenant named in the URL. A user who is an administrator of Tenant A should not automatically be allowed to manage roles in Tenant B, and this check alone cannot distinguish those two cases if `role` is a global, un-scoped attribute on the user record. Second, target-user membership is not checked: the code fetches the target user by `user_id` alone, without verifying that the target actually belongs to the requested tenant, so if the database lookup can retrieve a user from a different tenant entirely, the endpoint may permit cross-tenant role changes. Third, the requested tenant is not enforced in the update itself: although `tenant_id` appears in the URL, the actual database lookup and save operate purely on `user_id`, so the tenant parameter does not visibly constrain which record gets modified at all. Fourth, role assignment policy is missing: the code accepts `request.role` directly with no constraint on which roles the caller is actually permitted to assign, meaning nothing here prevents a tenant administrator from assigning a platform-level role or creating another administrator beyond what their own authority should allow. Fifth, membership and session consistency are unclear: if a role does change, nothing in this code shows whether existing sessions or cached authorization decisions for that user get updated or invalidated to reflect it.

The deeper reason `current_user.role != "administrator"` is insufficient on its own is that it answers the wrong question. It confirms the caller holds some administrator role somewhere, but the operation here is scoped to a specific tenant, and the code never establishes that this particular administrator role applies to this particular tenant. That is precisely the difference between checking whether a person is an administrator and determining whether that person is authorized to perform this specific operation within this specific organization, the central distinction this entire module is built around.

</details>

### Assessment Question 2

Design a safer conceptual version of the same `update_role` handler that addresses all five findings, and explain the three separate relationships the improved version establishes before it allows the role change to proceed.

<details markdown="1">
<summary><strong>Reveal Answer</strong></summary>

A safer conceptual design replaces the single global role check with explicit, tenant-scoped membership lookups for both the caller and the target, plus an explicit role-assignment policy check:

```python
@app.post("/api/tenant/{tenant_id}/users/{user_id}/role")
def update_role(
    tenant_id: str,
    user_id: str,
    request: RoleUpdate,
    current_user=Depends(get_authenticated_user),
):
    actor_membership = get_active_membership(
        user_id=current_user.id,
        tenant_id=tenant_id,
    )

    if actor_membership is None:
        raise HTTPException(status_code=403)

    if not can_manage_roles(actor_membership):
        raise HTTPException(status_code=403)

    target_membership = get_active_membership_for_user(
        user_id=user_id,
        tenant_id=tenant_id,
    )

    if target_membership is None:
        raise HTTPException(status_code=404)

    if not can_assign_role(
        actor_membership,
        request.role,
    ):
        raise HTTPException(status_code=403)

    update_membership_role(
        target_membership,
        request.role,
    )

    invalidate_stale_authorization_state(
        user_id=user_id,
        tenant_id=tenant_id,
    )

    return {"message": "Role updated"}
```

This still a conceptual design, a real production system must additionally define a full role hierarchy, prevent unauthorized privilege escalation paths, protect platform-level administration separately, handle concurrent updates safely, and enforce consistent authorization throughout the rest of the application, not just this one endpoint.

The improved implementation establishes three separate relationships before permitting the change, where the original established none of them explicitly. First, that the caller belongs to the tenant named in the URL at all, via `actor_membership`. Second, that the caller is specifically authorized to manage roles within that tenant, via `can_manage_roles`, rather than merely holding an administrator role somewhere in the system. Third, that the target user's membership is also within that same tenant, via `target_membership`, so the operation cannot silently reach across into a different organization's user. It also adds a fourth constraint beyond those three relationships, that the specific role being assigned is one the caller is actually permitted to grant, via `can_assign_role`, which closes the privilege-escalation gap where a scoped administrator could otherwise hand out platform-level authority they do not themselves possess.

</details>

## Remediation and Secure Implementation

The following consolidates the remediation guidance across all twenty-three sections of this phase.

1. Treat identity, tenant membership, and role as three separate, explicitly modeled relationships, never collapse them into a single global attribute on the user record, since a role is only meaningful within the specific tenant scope it was granted in.
2. Verify active tenant membership independently on every tenant-sensitive operation, regardless of whether the tenant identifier comes from the URL, a request body, a session, or a hostname, a client-supplied tenant identifier identifies a request, it does not prove authorization.
3. Revalidate membership and re-derive the role fresh whenever the active tenant context changes, such as during tenant switching, and never carry a role forward from a previous tenant context into a new one.
4. Bind federated identities using a stable, well-defined contract such as issuer plus subject, not an unverified or potentially non-unique attribute like email, and ensure the application trusts only the identity provider actually configured for the relevant tenant.
5. Enforce an invitation's original tenant, permitted role, intended recipient, expiration, and single-use acceptance state server-side, never let the acceptance request independently control which tenant or role is granted.
6. Ensure membership revocation and role downgrades actually take effect against active sessions and cached authorization state, through mechanisms such as active revalidation, versioned authorization state, or session invalidation, according to the application's risk model.
7. Scope every database query, cache key, and background job to the authorized tenant context derived from trusted server-side state, never from an identifier alone that lacks an accompanying authorization check, and extend that same scoping to exports, reports, webhooks, and file downloads.
8. Treat hostname-based or custom-domain tenant resolution strictly as a routing decision, and always pair it with an independent, server-side membership check before granting access.
9. Bind tenant-specific SAML or OIDC configuration to a transaction initiated for a known, expected tenant, never let an incoming response's own claimed tenant identifier determine which trust configuration is used to validate that same response.
10. Make just-in-time provisioning rules explicit per tenant, including which identity provider may provision users, which attribute establishes the organization, what the default role is, and whether reactivating a previously revoked membership requires separate authorization.

## Key Takeaways

This phase's central lesson is that multi-tenant identity isolation is not a single endpoint check, it is a property that must survive the entire application lifecycle: login, tenant switching, invitations, database queries, background jobs, caches, custom domains, tenant-specific SAML configuration, JIT provisioning, and account recovery. A system can authenticate a user correctly and still authorize them incorrectly inside another organization's boundary, and every one of the fifteen named vulnerabilities in this module is a different place where that gap between correct authentication and correct tenant-scoped authorization can open up.

The recurring pattern underneath nearly every vulnerability in this phase is the same one the assessment case demonstrates directly: a check that looks like it enforces tenant boundaries, `if current_user.role != "administrator"`, actually enforces something weaker, that the caller holds some administrator role somewhere, without ever confirming that role applies to the specific tenant and specific target resource the request concerns. The module's own final five questions, who is authenticated, which credential established that identity, which tenant membership authorizes the operation, does the resource belong to that tenant, and will authorization remain correct after lifecycle changes, exist precisely because any one of them going unasked is where a legitimate login quietly becomes unauthorized access to someone else's organization.

## Review Checklist

- [ ] Can you distinguish authentication, identity binding, tenant membership, role evaluation, and tenant isolation as five separate questions?
- [ ] Can you explain why a role is meaningful only within the scope it was granted in, using the identity/membership/tenant data model?
- [ ] Can you identify, from source code, whether a tenant-sensitive operation independently verifies the caller's active membership in the specific requested tenant?
- [ ] Can you explain the specific failure of a tenant switcher that validates membership but forgets to update the session's role?
- [ ] Can you distinguish a global platform role from a tenant-scoped role in source code, and explain when each is appropriate?
- [ ] Can you explain why email-only account matching in SSO can cause identity confusion between tenants, and what issuer-plus-subject binding fixes?
- [ ] Can you list at least four of the fifteen named vulnerabilities in this module from memory?
- [ ] Can you explain why tenant isolation must be enforced in background jobs and caches, not just the initial HTTP request handler?
- [ ] Can you explain the circular-trust risk in tenant-specific SAML configuration, where an incoming response's own claims influence which key validates it?
- [ ] Can you list at least five of the seven false positives this module identifies, and explain why each one is not automatically a vulnerability?
- [ ] Can you apply the module's 7-phase testing methodology to design a tenant matrix and a lifecycle-change test plan?
- [ ] Can you answer all five of the module's final mastery-model questions for a tenant-sensitive operation of your choosing?

## References to Related Phases

- Session rotation, revocation, and stale authorization state, central to the tenant-switching and membership-revocation vulnerabilities in sections 4, 9, and 10, extend the session-security discipline from **Phase 6, Cookie and Session Security**.
- SSO identity confusion and tenant-specific SAML configuration, covered in sections 6 and 15, build directly on the assertion validation, issuer trust, and NameID binding principles from **Phase 10, SAML Security**.
- The issuer-plus-subject identity-binding model referenced throughout this phase was first introduced for OAuth and OIDC account linking in **Phase 7, OAuth 2.0 and OpenID Connect Security**.
- Just-in-time provisioning and invitation-based membership creation connect directly to the registration and identity-proofing principles in **Phase 8, Account Lifecycle and Identity Proofing**.
- Trusting unverified attributes such as role claims, flagged in section 13 as reserved for deeper treatment, is examined in full in a later phase, **Authentication-Adjacent Authorization Flaws**.
