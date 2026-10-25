# Phase 17: Authentication-Adjacent Authorization Flaws

**Source material:** Module 17 of 17, "Authentication Complete Phases Test.md" (28 parts covering authentication-adjacent authorization flaws, the module's final summary table, and the course tracker), the final module in the course. "Authentication Security.md" contains one short, partially relevant exchange (Challenge 22) about JWT `sub` claims and authorization, but it is entangled with JWT signature-integrity content already covered in Phase 16. The Assessment section in this phase is instead built from the module's own Part 25 comprehensive case study, using the module's own given classifications and reasoning as the answer.

## Learning Objectives

After completing this phase, you should be able to:

1. Distinguish authentication from authorization precisely, and explain why a correctly authenticated request can still constitute a severe security failure.
2. Explain the four-question authorization framework, identity, action, resource, permission, and apply it to any authenticated request.
3. Distinguish RBAC, ABAC, and ReBAC as three authorization models, and explain why a well-designed system may combine them.
4. Define IDOR and BOLA, explain how they overlap, and identify why changing an identifier and receiving a `200 OK` is not, by itself, proof of either.
5. Distinguish horizontal privilege escalation from vertical privilege escalation, and from broken function-level authorization, using the specific question each one answers.
6. Identify mass assignment and property-level authorization as related but distinct failures, and name the specific fields in an application most likely to require protection.
7. Explain why multi-tenant authorization requires validated server-side tenant membership rather than a trusted tenant identifier from the URL, body, header, or subdomain.
8. Identify authorization bypass through alternate routes, inconsistent HTTP-method enforcement, and unprotected background jobs, exports, and file storage as instances of the same underlying failure: incomplete enforcement across every path to a resource.
9. Distinguish an authorization failure from a business-logic or integrity failure, and from a workflow-state failure, using the refund and checkout examples as a model.
10. Explain authorization caching, stale privileges, and account-lifecycle revocation as a single class of problem: correct authorization becoming incorrect when state changes without the system noticing.
11. Apply the module's systematic 8-step authorization testing workflow and its controlled-account permission-matrix method to a real application.
12. Apply the Phase 1 through Phase 16 impact-validation discipline to authorization findings specifically: avoid the module's ten advanced mistakes, and classify a demonstrated root cause accurately rather than labeling everything "IDOR."

## Introduction

This is the seventeenth and final phase of this course, and it closes the course by returning to the distinction every earlier phase assumed but never fully examined: authentication establishes who you are, authorization determines what you are allowed to do. Every phase before this one studied authentication, passwords, MFA, passkeys, sessions, federation, logging, cryptography, as if correctly proving identity were the whole problem. This phase proves that it is not. A user can have a valid session, complete MFA, and use a perfectly secure password, and still access another person's data, because the application never actually asked whether that specific identity was permitted to perform that specific action on that specific resource.

The module's own fundamental distinction, stated in its first scenario, is the thread running through all 28 parts: Alice authenticates correctly, and the server still returns Bob's private bank account, because authentication succeeded while authorization failed. Every vulnerability category that follows, IDOR, BOLA, horizontal and vertical privilege escalation, broken function-level authorization, mass assignment, property-level authorization, broken tenant isolation, business-logic failures, stale authorization, is a different specific way that same gap can open: the server correctly knows who is asking, and still fails to correctly decide whether they should get what they asked for.

## Core Concepts

The module moves through six stages. First, Parts 1 and 2 establish the fundamental distinction and the authorization model itself, the four questions and the three common access-control approaches. Second, Parts 3 through 9 define the core object- and function-level vulnerability categories: IDOR, BOLA, horizontal and vertical privilege escalation, broken function-level authorization, mass assignment, and property-level authorization. Third, Parts 10 through 14 extend the analysis across boundaries a single endpoint check often misses: multi-tenant authorization, alternate routes, HTTP methods, business logic, and price and payment manipulation. Fourth, Parts 15 through 20 examine authorization as something that can become wrong over time or across architecture: workflow state, caching and stale privileges, account lifecycle, authentication-state changes, background jobs, and file storage. Fifth, Parts 21 through 24 build the testing and review discipline: controlled-account testing, a systematic workflow, advanced source-code review, and severity assessment. Sixth, Parts 25 through 28 close the module and the course with a comprehensive case study, a professional report template, ten advanced mistakes to avoid, and the final master checklist.

## Lessons

### Part 1: The Fundamental Distinction

**1. Authentication versus authorization.** Imagine a banking application with three users: Alice and Bob, ordinary customers, and Carol, a bank administrator. Alice logs in with her correct password and MFA code, and the application establishes a valid session for Alice. Now Alice sends `GET /api/accounts/2002`, an account that belongs to Bob. The server responds `200 OK` with Bob's account ID, owner, and balance. Assume Alice has no legitimate permission to view Bob's account. What failed? Authentication did not necessarily fail. Authorization failed. The server accepted Alice's identity but did not correctly enforce her permissions over Bob's account. This distinction matters because a report titled "Authentication Bypass" would misclassify the demonstrated problem. A more accurate title would be "Broken object-level authorization exposes another customer's bank account." The exact severity would depend on the actual data exposed, the application's context, and the realistic impact.

**The four fundamental questions.** For every authenticated request, ask: identity, who is making the request; action, what are they attempting to do; resource, which object or function are they targeting; and permission, why should this identity be allowed to perform this action on this resource. If you cannot establish the permission decision, you have not completed the authorization analysis.

### Part 2: Understanding the Authorization Model

**2. Authorization is more than checking whether someone is logged in.** Consider this simplistic middleware:

```python
def require_login(request):
    if not request.session.get("user_id"):
        return unauthorized()

    return continue_request()
```

This checks whether the request has an authenticated user. It does not establish that the user can view a particular invoice, edit another user's profile, delete a different customer's order, access an administrative function, change another user's role, read another tenant's records, refund a transaction, or export sensitive organizational data. The middleware answers "does this request have an authenticated identity?" It does not answer "is this identity authorized to perform this specific operation?" That missing distinction is the foundation of many authorization vulnerabilities.

**2.1 The authorization decision.** A useful conceptual model is `Allow = f(identity, action, resource, context, policy)`. For example: identity Alice, action read, resource Invoice 2002, context active customer account, policy customers can read their own invoices. If invoice 2002 belongs to Bob, the request should be denied. For an administrator, the policy might allow access to invoices within an assigned administrative scope. For a support employee, the policy might permit limited access only after an authorized support workflow. Authorization is therefore a policy decision, not simply a comparison of usernames.

**2.2 Three common authorization models.**

*A. Role-Based Access Control (RBAC).* Permissions are assigned to roles.

| Role | Read products | Create products | Delete products |
|---|---:|---:|---:|
| Customer | Yes | No | No |
| Seller | Yes | Yes | Only their own, if policy permits |
| Administrator | Yes | Yes | Yes, within administrative scope |

A user's role determines which permissions are available. However, role-based access alone may be insufficient. Suppose Alice and Bob are both sellers. Both have permission to edit products, but Alice should only edit products she owns. A check such as `if user.role == "seller": allow()` is insufficient for an object that requires ownership enforcement.

*B. Attribute-Based Access Control (ABAC).* Authorization depends on attributes of the user, resource, action, and context, for example `User.department == Resource.department AND User.clearance >= Resource.classification AND Action == "read"`. ABAC can represent policies that depend on attributes beyond a user's role. However, attribute-based systems can still fail if attributes are incorrect, stale, client-controlled, or evaluated inconsistently.

*C. Relationship-Based Access Control (ReBAC).* Authorization depends on relationships between identities and resources. Examples: Alice owns order 1001, Alice belongs to Organization A, Bob is an administrator of Organization B, Carol is a support agent assigned to a specific case. A relationship may grant permission to read, edit, or administer a resource. ReBAC is particularly useful in collaborative applications, organizations, document-sharing systems, and multi-tenant SaaS products.

The senior-engineer lesson: do not assume an application needs one specific authorization model. A well-designed system may combine roles, attributes, and relationships. Your job as a reviewer is to understand the intended policy and determine whether the implementation enforces it consistently.

### Part 3: IDOR, Insecure Direct Object References

**3. What is IDOR?** IDOR stands for Insecure Direct Object Reference. It occurs when an application exposes a reference to an object and fails to enforce the authorization required to access or modify that object. The reference might be a database ID, a UUID, an invoice number, an order number, a filename, a document identifier, a username, a payment reference, or an account identifier. The reference can appear in a URL, request body, query parameter, header, or another part of a request.

Example: Alice legitimately owns order 1001 and requests `GET /api/orders/1001`, receiving her order. Now consider `GET /api/orders/1002`. If order 1002 belongs to Bob and the server returns Bob's private order details without a legitimate authorization basis, the application has an object-level authorization vulnerability.

Critical principle: the identifier does not need to be secret for authorization to be required. An application that relies on unpredictable identifiers as its only protection is vulnerable to the underlying design problem. An attacker who discovers a valid identifier through another route may still be able to access the object.

**3.1 Why changing an ID is not, by itself, proof of IDOR.** Suppose you change `/api/orders/1001` to `/api/orders/1002` and the second request returns `200`. Is that automatically a vulnerability? No. You must determine whether the second object belongs to another user or a different authorization scope, whether the requesting user lacks permission to access it, whether the response actually discloses data or permits an unauthorized action, whether access is intentionally granted by a legitimate sharing or administrative policy, and whether the response merely indicates that the object exists or actually exposes protected content. An administrator may legitimately access both orders. A customer may also legitimately access an order shared with their account. IDOR is an authorization failure, not merely an identifier manipulation technique.

### Part 4: BOLA, Broken Object-Level Authorization

**4. How BOLA relates to IDOR.** BOLA stands for Broken Object Level Authorization. It is a widely used API security term for situations in which an application does not properly enforce authorization on the particular object a user is attempting to access. IDOR and BOLA overlap substantially. A useful practical distinction: IDOR commonly describes an insecure object reference combined with missing or incorrect authorization enforcement, while BOLA emphasizes the failure to enforce object-level authorization in an API. They are not mutually exclusive vulnerability classes. A single defect may reasonably be described using either term, depending on the context and reporting convention.

**4.1 The common vulnerable pattern.** Consider a fictional FastAPI endpoint:

```python
@app.get("/api/orders/{order_id}")
def get_order(order_id: int, user=Depends(require_login)):
    order = db.get_order(order_id)

    if order is None:
        raise HTTPException(status_code=404)

    return order
```

What does the code check? The user is authenticated, and the order exists. What does it fail to demonstrate? That the user owns the order, that the user belongs to a tenant authorized to access it, that an approved sharing relationship exists, or that an administrative permission grants access. The defect is not that the application uses an integer ID. The defect is that the code retrieves and returns an object without demonstrating the required authorization check.

A safer design scopes the lookup:

```python
@app.get("/api/orders/{order_id}")
def get_order(order_id: int, user=Depends(require_login)):
    order = db.get_order_for_user(
        order_id=order_id,
        user_id=user.id
    )

    if order is None:
        raise HTTPException(status_code=404)

    return order
```

This is safer for an application whose policy is that users may access only their own orders. However, this example is not a universal authorization solution. It would be insufficient if the application supports shared orders, delegated access, organizational administrators, support workflows, or multiple resource-specific permission levels. A production system must implement its actual authorization policy. A scoped lookup can reduce the risk of accidentally returning a resource before authorization is evaluated, and it encourages developers to make ownership or tenancy part of the retrieval operation. But a function named `get_order_for_user` is not proof of security. Its actual database query and surrounding policy must be reviewed.

### Part 5: Horizontal Privilege Escalation

**5. What is horizontal privilege escalation?** Horizontal privilege escalation occurs when a user gains access to resources or actions belonging to another user with a comparable level of privilege. For example: customer Alice accesses Bob's orders, employee Alice reads Bob's private employment record, seller Alice edits seller Bob's product, patient Alice views another patient's medical record, student Alice downloads another student's private submission. Both users may have the same role. The problem is that the application fails to enforce the boundary between their individual resources.

Simulated evidence: Alice, authenticated as an ordinary customer, requests `GET /api/invoices/INV-5002` and receives `200 OK` with invoice details, customer ID 742, an amount, and a status. Suppose controlled test data establishes that invoice `INV-5002` belongs to Bob, and Alice has no permission to view it. That is meaningful evidence of a horizontal authorization failure.

Impact depends on the object. Reading another user's display name is different from reading medical records, financial transactions, private messages, identity documents, authentication recovery information, or confidential employment records. The vulnerability class may be the same, but the impact and severity can differ significantly.

### Part 6: Vertical Privilege Escalation

**6. What is vertical privilege escalation?** Vertical privilege escalation occurs when a user gains access to functionality or permissions intended for a higher privilege level. For example: a customer invokes an administrator-only endpoint, a seller changes the price of another seller's product, an ordinary employee grants themselves an administrator role, a user accesses a privileged export function, a normal account disables security controls reserved for administrators.

Simulated example: the application exposes `GET /api/admin/users`, and Alice, requesting with only the customer role, receives `200 OK` with a list of users and their roles. If the endpoint is intended exclusively for administrators and the server returns the administrative data without enforcing the role or an equivalent permission, that is a broken function-level authorization issue. If the data contains another user's private information, the endpoint may also have object-level authorization implications. One request can reveal more than one defect, but the report should explain each distinct security failure clearly.

### Part 7: Broken Function-Level Authorization

**7. What is broken function-level authorization?** Broken Function Level Authorization (BFLA) occurs when a user can invoke a function or operation they are not permitted to perform. The issue concerns access to a function, rather than only access to a particular object. Examples include accessing an administrator-only endpoint, creating privileged accounts without authorization, changing global application settings, performing refunds without the required role, accessing support tools reserved for staff, invoking a privileged export operation, and deleting users through a function meant only for administrators.

**Example: frontend-only restriction.** A frontend might hide an administrator button, `if (user.role === "admin") { showAdminButton(); }`. This is useful for the user interface, but it is not a server-side security control. An attacker may call an endpoint directly without using the button. If the backend does not enforce the relevant permission, the UI restriction does not protect the function.

**Vulnerable backend example:**

```python
@app.delete("/api/admin/users/{user_id}")
def delete_user(user_id: int, user=Depends(require_login)):
    db.delete_user(user_id)
    return {"status": "deleted"}
```

The endpoint requires login but does not demonstrate an administrator check.

**A safer design:**

```python
@app.delete("/api/admin/users/{user_id}")
def delete_user(
    user_id: int,
    user=Depends(require_admin)
):
    target = db.get_user(user_id)

    if target is None:
        raise HTTPException(status_code=404)

    authorize_user_deletion(actor=user, target=target)

    db.delete_user(target.id)

    return {"status": "deleted"}
```

The function `require_admin` must itself be correct, and `authorize_user_deletion` must enforce any additional restrictions, such as whether the actor can delete that particular account. For high-impact operations, the system may also need recent authentication, approval workflows, audit logging, and protection against accidental or concurrent changes.

Important distinction: an administrator role is not a universal permission to perform every possible action. A support administrator may be permitted to view account status but not to reveal passwords, change payout details, or disable MFA without an approved workflow. Authorization must reflect the actual policy.

### Part 8: Mass Assignment and Property-Level Authorization

**8. Mass assignment.** Mass assignment is a vulnerability pattern in which an application automatically copies request fields into an internal object without restricting which fields the client is allowed to change. It can become an authorization vulnerability when the client can modify protected properties.

Suppose a registration endpoint accepts `{"email": "alice@example.test", "password": "fictional-password"}`, intended to create a normal customer account. But imagine the backend binds arbitrary request fields directly to the user model, `user = User(**request.json()); db.save(user)`. If the model includes fields such as `role`, `is_admin`, or `account_status`, the application may unintentionally allow clients to control privileged state.

Simulated attack request: the client submits `{"email": "alice@example.test", "password": "fictional-password", "role": "admin"}`. Suppose the server creates an account with administrative privileges. This demonstrates a serious authorization failure in the account-creation workflow. The exact impact depends on whether the submitted property is accepted, persisted, and actually used by authorization decisions. A response that merely echoes `"role": "admin"` is not enough to prove privilege escalation.

**Safer implementation.** Define an explicit set of client-editable fields:

```python
payload = request.json()

user = User(
    email=payload["email"],
    password_hash=hash_password(payload["password"]),
    role="customer"
)

db.save(user)
```

Here, the server determines the initial role instead of trusting the client. In larger systems, use explicit input schemas or DTOs that exclude server-managed properties.

**What else should be protected?** Do not focus only on `role`. Potentially sensitive fields include `is_admin`, `is_verified`, `account_status`, `tenant_id`, `owner_id`, `approved`, `balance`, `discount_percentage`, `price`, `payment_status`, `mfa_enabled`, `email_verified_at`, and `security_level`. These fields are not all equally sensitive in every application. Their significance depends on how they affect permissions, money, identity, and workflow state.

### Part 9: Property-Level Authorization

**9. A user may be allowed to edit an object but not every field.** Suppose Alice owns a product listing, and the application correctly verifies that Alice owns the product. She is allowed to edit the product name, description, images, and stock quantity, subject to business rules. She is not allowed to edit the seller ownership, administrative approval status, another seller's commission, or platform-wide discount settings. Even if the application enforces object ownership, it can still fail to enforce which properties Alice is allowed to modify. This is a property-level authorization problem.

Example:

```http
PATCH /api/products/101 HTTP/1.1
Host: shop.example.test
Cookie: session=alice_session
Content-Type: application/json

{
  "name": "Gold Pendant",
  "approved": true
}
```

Suppose Alice owns product 101 but is not authorized to approve products. If the backend accepts `approved: true` and changes the moderation state, the application has failed to enforce property-level permissions.

The correct review question is not only "can Alice edit product 101?" but also "which fields can Alice edit, and which fields must remain under server control?" This distinction is particularly important in REST APIs, GraphQL mutations, administrative dashboards, and applications that serialize database models directly into request schemas.

### Part 10: Multi-Tenant Authorization

**10. What is a tenant?** A tenant is a logical customer, organization, or isolated group within a shared application, as established in Phase 11. A user may be correctly authenticated and authorized within Company A but have no permission to access Company B. Tenant isolation is a separate security boundary.

Vulnerable example:

```python
@app.get("/api/tenants/{tenant_id}/documents")
def get_documents(
    tenant_id: int,
    user=Depends(require_login)
):
    return db.get_documents(tenant_id=tenant_id)
```

The code uses the tenant ID supplied in the URL but does not demonstrate that the user belongs to that tenant. A safer conceptual design:

```python
@app.get("/api/tenants/{tenant_id}/documents")
def get_documents(
    tenant_id: int,
    user=Depends(require_login)
):
    require_tenant_membership(
        user_id=user.id,
        tenant_id=tenant_id
    )

    return db.get_documents(tenant_id=tenant_id)
```

The membership check must reflect the application's actual policy. Some users may belong to several tenants, while others may have cross-tenant administrative access under tightly controlled conditions.

**10.1 Why checking only the URL is insufficient.** An application may include a tenant identifier in a path, a query parameter, a JSON body, a request header, a subdomain, or a session claim. None of these locations automatically makes the tenant identity trustworthy. The server must establish the effective tenant context from authenticated identity and trusted policy, then enforce it consistently.

**10.2 The subtle database-query failure.** Suppose a document table contains `id`, `tenant_id`, `owner_id`, `title`, `content`. A vulnerable query selects by ID alone: `SELECT * FROM documents WHERE id = :document_id;`. A more appropriate query for a simple tenant-membership policy joins against tenant membership:

```sql
SELECT d.*
FROM documents AS d
JOIN tenant_memberships AS m
  ON m.tenant_id = d.tenant_id
WHERE d.id = :document_id
  AND m.user_id = :user_id;
```

Even this is only a starting point. A real application may require additional checks for resource-level sharing, user suspension, tenant suspension, document classification, read versus write permissions, delegated access, and role-specific restrictions.

Senior-engineer insight: tenant checks must exist at every relevant access path, not just the main document endpoint. Review search, bulk operations, exports, file downloads, background jobs, administrative tools, webhooks, support workflows, scheduled reports, and data analytics endpoints. A system can protect the ordinary read endpoint but leak the same data through a CSV export or background job.

### Part 11: Authorization Bypass Through Alternate Routes

**11. Different endpoints must enforce equivalent security policies.** Imagine an application has `GET /api/orders/{id}`, `GET /api/v1/orders/{id}`, `GET /api/mobile/orders/{id}`, `GET /internal/orders/{id}`, and `GET /api/orders/export`. The primary endpoint may enforce ownership correctly while an older route, mobile endpoint, internal endpoint, or export function does not. This is an example of inconsistent authorization enforcement.

Simulated example: the ordinary endpoint `GET /api/orders/1002` returns `403 Forbidden` for Alice, but an alternate endpoint `GET /api/v1/orders/1002` returns Bob's order. If the two endpoints are intended to enforce the same access policy and Alice has no permission to access Bob's order, the older route may expose a BOLA vulnerability.

Common causes: new authorization middleware was added only to the latest route, an old handler remains deployed, the mobile API has different policy enforcement, a reverse proxy exposes an internal route, an export handler performs its own database query, a refactor removed a permission check, or a background job trusts a request-supplied owner ID.

How to review safely, in an authorized test environment: establish the expected permission policy, identify relevant routes from documentation, source code, or the approved test scope, use controlled accounts with different permissions, compare the same intended operation across routes, confirm whether the alternate route actually returns protected data or permits an unauthorized change, and record the precise request, response, and account relationships. Do not assume every `/internal` route is exposed or vulnerable. Verify actual reachability and authorization behavior.

### Part 12: HTTP Methods and Authorization Consistency

**12. Protecting GET does not protect every operation.** Suppose an application protects `GET /api/products/101` but fails to protect `PUT /api/products/101` or `DELETE /api/products/101`. The application may correctly restrict reading but allow unauthorized modification or deletion. Authorization must be appropriate to the action. For a product resource, a policy might allow:

| Action | Seller owning product | Other seller | Administrator |
|---|---|---|---|
| Read public details | Yes | Yes | Yes |
| Read private analytics | Yes | No | Yes, if permitted |
| Edit description | Yes | No | Yes |
| Change ownership | No, unless explicitly authorized | No | Restricted workflow |
| Approve listing | No | No | Yes |
| Delete product | Subject to policy | No | Yes, subject to policy |

The exact permissions depend on the business model. The security principle is that each method and operation must enforce the corresponding policy.

Important caveat: an HTTP method is not itself a permission. For example, an application might legitimately permit public `GET` requests for product details. It does not follow that all `GET` routes should be public or that all `POST` requests should require administrator privileges. Authorization follows the intended action and resource, not simplistic method-based assumptions.

### Part 13: Business-Logic Authorization

**13. Technically valid requests can still violate business rules.** Business-logic vulnerabilities occur when an application allows a user to manipulate a workflow or sequence of operations in ways the system's rules do not permit. Some are authorization failures, others are integrity, workflow, or concurrency problems. The important task is to identify which security invariant is violated.

**Example: unauthorized refund.** A customer should be able to request a refund for their own eligible order. The intended rules: the order belongs to the customer, the order has been paid, the order meets the refund policy, the refund has not already been completed, the refund amount does not exceed the eligible amount, and the customer is permitted to initiate the operation. Now suppose the backend accepts `POST /api/refunds` with `{"order_id": 1002, "amount": 240000}`. If order 1002 belongs to Bob and Alice can cause the refund to be issued, the application has an object-level authorization failure. If Alice can request a refund for her own order but change the amount beyond the eligible balance, that is a different business-logic or integrity failure. If the endpoint permits refunds that should be restricted to finance staff, that may be broken function-level authorization. These defects can coexist, but they should be described separately when doing so improves the clarity of the report.

**13.1 Trusting client-supplied ownership.** Consider:

```python
def create_order(request, user):
    order = Order(
        user_id=request.json["user_id"],
        items=request.json["items"]
    )

    db.save(order)
```

The client supplies the account that owns the order. If ordinary users are supposed to create orders only for themselves, this is unsafe. The server should derive the owner from the authenticated identity:

```python
def create_order(request, user):
    order = Order(
        user_id=user.id,
        items=validate_items(request.json["items"])
    )

    db.save(order)
```

If the system legitimately supports delegated purchasing, the implementation must authorize that relationship rather than blindly accepting any user ID. Never assume that a request-body field is trustworthy merely because the client is authenticated.

### Part 14: Price and Payment Manipulation

**14. A common e-commerce authorization and integrity boundary.** Consider an online store where the frontend sends `{"product_id": 101, "quantity": 2, "unit_price": 100, "total": 200}`. Suppose the actual product price is much higher per item. If the backend trusts the submitted price and charges only the client-supplied total, the application has a serious price-integrity failure. It may also involve business-logic flaws, depending on the design. This is not necessarily an IDOR or a privilege-escalation vulnerability. Accurate classification matters.

**Safer approach.** The server should authenticate the user, retrieve the authoritative product and current price, validate the requested quantity, check inventory and purchase restrictions, calculate the total server-side, create an order using the server-calculated amount, send the appropriate amount to the payment provider, verify the provider's payment result through a trusted mechanism, and record the payment outcome consistently. For financial systems, payment status must not be accepted solely because a client sends `{"payment_status": "paid"}`. The application needs trusted payment confirmation and appropriate reconciliation.

**Where authorization enters the problem.** Consider these distinct scenarios: a user changes a price, an integrity/business-logic defect; a user changes the order ID and refunds another customer's order, an object-level authorization defect; a customer invokes a staff-only refund operation, a function-level authorization defect; a seller changes another seller's product, an object-level authorization defect; a customer marks an account as administrator through a registration field, a property-level authorization defect. These classifications help you describe the actual root cause rather than reporting every problem as "IDOR."

### Part 15: Workflow State and Authorization

**15. Authorization can depend on the current state of a resource.** Some actions are permitted only when an object is in a particular state. For example, an order might follow created, paid, processing, shipped, delivered. A refund may be allowed only for certain states. An employee may be allowed to approve an expense only if it has not already been approved and the employee has the appropriate authority. A workflow can fail if the application checks the user's role but ignores the resource's current state.

**Vulnerable conceptual logic:**

```python
def approve_expense(expense_id, user):
    require_manager(user)

    expense = db.get_expense(expense_id)
    expense.status = "approved"

    db.save(expense)
```

This code does not demonstrate whether the manager is authorized for the expense's department, whether the expense belongs to the manager's organizational scope, whether the expense is in an approvable state, whether the manager is prohibited from approving their own expense, or whether the expense has already been approved or cancelled.

**A safer design combines authorization with workflow validation:**

```python
def approve_expense(expense_id, user):
    expense = db.get_expense(expense_id)

    if expense is None:
        raise NotFound()

    authorize_expense_approval(user, expense)

    if expense.status != "pending_approval":
        raise InvalidState()

    perform_approval_transition(expense, user)
```

For concurrent operations, the state transition may also require database locking, optimistic concurrency control, or another mechanism to ensure that two requests cannot both complete an operation that should happen only once.

This leads to an important distinction: authorization answers whether the actor is allowed to perform the action, workflow validation answers whether the action is permitted in the current state. Both may be necessary.

### Part 16: Authorization Caching and Stale Privileges

**16. Correct authorization can become incorrect when state changes.** Suppose Alice is an administrator. At 10:00, the application grants her a session. At 10:15, another administrator revokes Alice's administrative privileges. At 10:16, Alice attempts an administrator-only action. If the application relies on stale authorization data and does not account for the privilege change, Alice may retain permissions longer than intended. The defect depends on the application's documented revocation policy and the freshness of its authorization state.

Common causes: roles embedded in long-lived session state, stale cached permission results, delayed propagation of role changes, background workers using outdated identity data, inconsistent authorization services, and long-lived access tokens that are not checked against current policy where required.

What should be reviewed? Where the authoritative role or permission is stored, whether the application caches authorization decisions, how role changes invalidate or refresh cached state, whether high-risk operations recheck current permissions, whether disabled users and revoked roles are consistently enforced, and whether background jobs and secondary services observe the same changes. Not every cache is a vulnerability. Caching is often necessary for performance. The question is whether the system's freshness and invalidation rules meet its security requirements.

### Part 17: Authorization and Account Lifecycle

**17. Deactivated accounts and revoked membership.** Authorization decisions must account for changes in account state. Imagine Alice belongs to Company A, leaves the company, and an administrator removes her membership. If her old session still grants access to Company A's resources indefinitely, the system may have an authorization or session-revocation defect, extending the account-lifecycle principles from Phase 8. Similarly, a disabled user should not automatically retain access just because a previously issued session remains technically valid.

Review whether the application's policy requires immediate access revocation, revocation on the next request, session expiration within a defined interval, token revocation or introspection, revalidation of tenant membership, and termination of background jobs or long-running exports. The correct behavior depends on the system's requirements and architecture.

**A subtle distinction.** A user may still be authenticated but no longer authorized, for example a valid session with an active account but revoked tenant membership and denied resource permission. The server must evaluate the relevant authorization state rather than assume that a valid session grants indefinite access to every previously accessible resource.

### Part 18: Authorization and Password or MFA Changes

**18. Changes to authentication state do not automatically fix authorization.** Suppose an administrator revokes a user's privileged role. The system may correctly require the user to log in again but still fail to update the role mapping used by a background service. Alternatively, a user's MFA state may change while an old session retains a privilege that should require stronger authentication. These are related but different issues. A robust design distinguishes authentication identity, authentication assurance, session validity, current account state, and current authorization permissions. A session may be valid but insufficiently authenticated for a sensitive action. Likewise, a user may be fully authenticated but lack permission for the action.

For example: Alice, valid session, MFA verified, role customer, attempting to delete another customer's account, decision deny. Successful MFA does not grant an otherwise unauthorized permission. Likewise: Carol, valid session, role administrator, recent authentication too old for policy, attempting to change a sensitive security setting, decision require step-up authentication. An administrator's role does not necessarily eliminate the requirement for fresh authentication, as established in Phase 9. This is why authentication and authorization must be evaluated as separate but cooperating controls.

### Part 19: Authorization in Background Jobs and Exports

**19. The request may be authorized, but the later job may not be.** Consider a report-export function. A user requests an export of their own transactions. The API verifies ownership and queues a background job:

```python
def request_export(user, account_id):
    authorize_account_access(user, account_id)

    queue_export(
        account_id=account_id
    )
```

The background worker later performs:

```python
def export_worker(account_id):
    records = db.get_all_transactions(account_id)
    create_export_file(records)
```

The worker receives an account ID but does not demonstrate whether it has preserved the original authorization decision. If an attacker can influence the job parameters or reuse the worker through another entry point, the system may expose data outside the permitted scope. A secure architecture needs to define how authorization is preserved across asynchronous work.

Possible controls include passing a trusted, validated job context, restricting who can enqueue or modify jobs, revalidating the actor's permissions at execution time when required, ensuring that the export is scoped to the intended account or tenant, protecting generated files with access controls, expiring download links appropriately, and preventing one user's job result from being served to another user. A signed job message or trusted queue does not automatically solve every authorization problem. The worker must still operate within the intended policy.

### Part 20: Authorization and File Storage

**20. Protect the actual file, not just the page that links to it.** Suppose an application displays documents through an authenticated page. The page checks whether the user is authorized, but the file is stored at a directly accessible location, such as `/uploads/customer-742/invoice.pdf`. If the file server or object-storage configuration permits unauthorized access, the page's authorization check does not protect the underlying file. The same issue can occur with cloud object-storage buckets, CDN-hosted private files, generated reports, profile documents, medical records, password-reset exports, and identity-verification uploads.

Questions to investigate: is the file actually private, does the storage service enforce access control, does the application generate signed download URLs, if signed URLs are used what is their scope and expiry, can one user's download link be used to access another user's file, are file identifiers bound to the intended user or tenant, can a deleted or revoked resource still be downloaded, and are public cache settings compatible with the sensitivity of the file? A signed URL is a bearer capability, possession may grant access, therefore its expiry, scope, handling, and revocation limitations matter. Do not conclude that a file is protected simply because the page that links to it requires login.

### Part 21: Authorization Testing with Controlled Accounts

**21. The most reliable test design.** Authorization testing is strongest when you can compare the behavior of controlled accounts with different permissions. Suppose you have Account A, an ordinary customer; Account B, an ordinary customer with a separate set of records; and Account C, an administrator. Create or identify test records whose ownership and expected permissions are known. Then build a permission matrix.

| Test | Expected result |
|---|---|
| A reads A's private order | Allow |
| A reads B's private order | Deny, unless explicitly shared |
| B reads B's private order | Allow |
| A edits B's private order | Deny |
| A deletes B's private order | Deny |
| A invokes an administrator-only function | Deny |
| C invokes a function covered by the administrator policy | Allow, subject to any additional restrictions |
| A changes their own role through a normal profile update | Deny |
| A accesses a tenant they do not belong to | Deny |

This matrix helps identify both missing checks and legitimate access patterns.

**21.1 Why positive controls matter.** A negative test alone is not always enough. Suppose Account A receives `403` when requesting Account B's order. That is consistent with correct authorization, but the test becomes stronger if you also verify that Account A can successfully access its own order. This helps rule out unrelated failures such as an invalid session, a malformed request, a missing object, an application outage, or a globally broken endpoint. A good authorization test includes both permitted and forbidden cases.

**21.2 What if the response is HTTP 404?** A `404` response does not automatically prove that authorization is correct. Some applications intentionally return `404` for inaccessible resources to avoid revealing whether they exist. Others return `404` because the object truly does not exist. Check the behavior with controlled records and known account relationships. Similarly, `403` is not the only acceptable denial response. The correct response depends on the application's design.

### Part 22: Authorization Testing, a Systematic Workflow

Use this workflow in authorized environments.

**Step 1: understand the intended policy.** Identify user roles, resource owners, tenant memberships, sharing relationships, administrative boundaries, sensitive operations, and workflow states. Do not invent a policy after observing a response. Establish the intended behavior first where possible.

**Step 2: identify relevant entry points.** Review the approved application scope, using API documentation, route definitions, frontend code, application logs, existing test cases, role and permission definitions, database relationships, and background-job handlers.

**Step 3: map identity to resource.** For every resource, determine how the application establishes its owner, its tenant, its permitted readers, its permitted editors, its administrators, and its current state.

**Step 4: test the intended permission boundaries.** Use controlled accounts and records. Compare owner versus non-owner, ordinary user versus administrator, tenant member versus non-member, authorized versus revoked membership, and allowed versus disallowed workflow state.

**Step 5: test different actions.** For the same resource, review read, create, update, delete, approve, export, share, transfer ownership, refund, and change security settings. Do not assume a permission check on one operation protects another.

**Step 6: verify the server-side effect.** For a write operation, determine whether the protected state actually changed. A response that says `"success": true` may not prove that a change occurred. Conversely, a failed-looking response does not prove that the database was left unchanged. Use the application's authorized test records or available audit evidence to confirm the result.

**Step 7: record minimal evidence.** Capture the test account's relevant role or ownership, the exact request, the response, the expected policy, the actual unauthorized data or state change, and any relevant audit evidence. Avoid accessing more private data than necessary.

**Step 8: assess impact accurately.** Describe what the demonstrated authorization failure permits. Do not automatically claim complete account takeover, unrestricted database access, or arbitrary administrative control from a single object-level finding.

### Part 23: Advanced Source-Code Review

**23.1 Look for direct object retrieval without a visible authorization decision.** Examples worth reviewing include `db.get_order(order_id)`, `db.get_document(document_id)`, `db.get_user(user_id)`, and `db.get_invoice(invoice_id)`. These functions are not automatically vulnerable. They become concerning when their callers return or modify the resource without enforcing the required permissions. Trace the complete path: HTTP route, authentication middleware, request handler, service layer, resource lookup, authorization decision, database operation, response or side effect. The authorization check may exist in a service layer, policy engine, database query, or middleware. Do not report a missing check merely because it is not immediately adjacent to the route.

**23.2 Review both read and write paths.** A read endpoint may be correctly scoped while an update endpoint is not, for example `read_order` using `get_order_for_user` while `update_order` fetches the order with `db.get_order(order_id)` unscoped and applies changes directly. The update handler requires independent review. The same principle applies to delete operations, bulk updates, imports, administrative actions, ownership transfer, file generation, export processing, and scheduled jobs.

**23.3 Review database constraints and relationships.** Application checks can be undermined by incorrect data relationships. For example, an order may contain a user ID and a tenant ID. If the application checks the tenant ID from one table but retrieves the order from another table without ensuring the relationship is consistent, the resulting authorization decision may be wrong. Review foreign-key relationships, tenant-scoped uniqueness, ownership changes, deleted or orphaned memberships, duplicate identity mappings, data imported from external systems, and consistency between application and database policy. Database constraints are valuable, but they do not automatically enforce every authorization rule.

**23.4 Review error handling and partial operations.** An authorization failure should not leave behind an unauthorized side effect. For example, an endpoint may update a record, generate an export, perform an authorization check, and then return an error, the check occurs too late. Similarly, an application may authorize a parent object but then update a child object without validating that the child belongs to that parent. The order of operations matters. Authorization must be enforced before the protected action takes effect, with transaction boundaries appropriate to the operation.

### Part 24: Severity and Impact

**24. Not all authorization flaws have the same severity.** A vulnerability's severity depends on more than its category.

| Finding | Potential impact | Context to establish |
|---|---|---|
| User reads another user's public profile | Possibly limited | Is the information intended to be public? |
| User reads another user's private order | Privacy breach | What information is exposed? |
| User changes another user's email address | Account integrity risk | Can the change be completed, and what verification is required? |
| User modifies another seller's product | Business integrity impact | What fields can be changed, and what effects follow? |
| Customer invokes a staff-only refund operation | Financial impact | Can a real refund be issued, and what controls remain? |
| User grants themselves an administrator role | Potentially critical | Does the role take effect, and what privileged actions become available? |
| Tenant member accesses another tenant's private documents | Cross-tenant data exposure | How broad is the exposure, and what data is accessible? |
| User triggers an unauthorized account deletion | Availability and integrity impact | Can the deletion be reversed, and whose account is affected? |

The actual severity depends on exploitability, scope, data sensitivity, required privileges, and the consequences of successful exploitation.

**Avoid these reporting mistakes.** Do not claim account takeover when only a profile field was read, administrator access when an administrative label was returned but no privilege was granted, full database exposure from one accessible record, financial loss when no financial operation was demonstrated, or cross-tenant compromise when both accounts belong to the same tenant and the policy permits sharing. Report the strongest impact supported by evidence, not the strongest impact you can imagine.

### Part 25: Comprehensive Case Study

**25.1 Scenario: a fictional multi-tenant commerce platform.** The platform has customers, sellers, support agents, administrators, and multiple tenant organizations. Its endpoints include `GET /api/orders/{order_id}`, `PATCH /api/orders/{order_id}`, `POST /api/refunds`, `GET /api/admin/users`, `PATCH /api/users/{user_id}`, `POST /api/products`, `PATCH /api/products/{product_id}`, and `GET /api/tenants/{tenant_id}/reports`. We will analyze several hypothetical defects.

**Finding A: an order can be read without checking ownership.**

```python
def get_order(order_id, user):
    require_login(user)
    return db.get_order(order_id)
```

Classification: potential IDOR/BOLA. Evidence required: a controlled account can access a private order belonging to another user without an authorized sharing or administrative relationship. Remediation: enforce object-level authorization in the relevant retrieval path.

**Finding B: a customer can invoke an administrator-only function.**

```python
def list_all_users(user):
    require_login(user)
    return db.get_all_users()
```

Classification: broken function-level authorization. Evidence required: an ordinary customer can invoke the endpoint and obtain data that the policy reserves for administrators. Remediation: enforce the required administrative permission server-side and scope the returned data appropriately.

**Finding C: a seller can modify the `approved` field.**

```python
def update_product(product_id, request, user):
    product = db.get_product(product_id)
    authorize_product_edit(user, product)

    for key, value in request.json().items():
        setattr(product, key, value)

    db.save(product)
```

Classification: potential property-level authorization or mass-assignment vulnerability. Evidence required: the seller is permitted to edit the product but can also modify a protected field that should be controlled by the moderation process. Remediation: use explicit writable-field schemas and enforce the separate permission for product approval.

**Finding D: a user can read reports from another tenant.**

```python
def get_tenant_reports(tenant_id, user):
    require_login(user)
    return db.get_reports(tenant_id)
```

Classification: potential broken tenant isolation and BOLA. Evidence required: the user is not a member of, or otherwise authorized for, the target tenant, yet receives its private reports. Remediation: derive or validate tenant access through trusted membership and policy checks.

**Finding E: a customer changes the refund amount.**

```python
def refund_order(request, user):
    require_login(user)

    return payment_provider.refund(
        order_id=request.json["order_id"],
        amount=request.json["amount"]
    )
```

Classification: potential business-logic and integrity failure, potentially BOLA as well if the order's ownership is not checked. Evidence required: demonstrate that the server does not independently validate the order, eligible refund amount, actor permissions, and payment state. Remediation: recompute eligibility and the refundable amount from authoritative server-side data, verify ownership and permissions, and enforce valid state transitions.

**Finding F: a user's old session retains revoked permissions.** The application caches a user's administrator role when creating the session. Later, the role is revoked, but the session continues to grant access to administrative functions. Classification: potential stale-authorization or privilege-revocation failure. Evidence required: establish the intended revocation policy and show that the old session continues to perform a privileged action after the revocation should have taken effect. Remediation: ensure role and permission changes propagate according to the security policy, with appropriate cache invalidation, revalidation, or session/token revocation.

### Part 26: How to Write a Professional Bug Bounty Report

A good report explains the root cause and proves the impact.

**Example report.** Title: Broken object-level authorization exposes private orders belonging to other customers. Summary: the order retrieval endpoint does not adequately enforce object-level authorization. An authenticated customer can retrieve an order belonging to another customer by requesting an order identifier outside their authorized scope. Affected component: `GET /api/orders/{order_id}`. Preconditions: two authorized test accounts with separate, privately owned orders. Steps to reproduce: authenticate as test customer Alice, request Alice's own order and confirm that the endpoint returns it, request a separate order belonging to test customer Bob, observe that the server returns Bob's private order data despite Alice having no permission to access it. Expected result: the application should deny access to an order outside the requesting user's permitted scope. Actual result: the application returns the other customer's order data. Security impact: an attacker with a valid customer account may be able to access private order information belonging to other customers, depending on the range of accessible records and the application's authorization policy. Root cause: the endpoint retrieves the requested order without adequately enforcing the required object-level authorization. Remediation: enforce the applicable ownership, tenant, sharing, and administrative policies before returning the order, and apply consistent authorization checks across related read, update, delete, and export operations.

Why this report works: it establishes the affected endpoint, the relevant identity, the expected permission boundary, the observed unauthorized result, the impact supported by the evidence, the likely root cause, and the appropriate remediation. It does not claim arbitrary account takeover or full database access without evidence.

### Part 27: Advanced Mistakes to Avoid

These are the mistakes that distinguish shallow vulnerability hunting from strong authorization analysis.

**Mistake 1: treating authentication as authorization.** A valid session does not grant unrestricted access to every resource.

**Mistake 2: assuming UUIDs solve IDOR.** Unpredictable IDs may reduce discoverability, but they do not replace authorization checks.

**Mistake 3: testing only GET requests.** Write, delete, approval, export, and administrative operations may have different authorization defects.

**Mistake 4: trusting the frontend.** Hidden buttons, disabled controls, and client-side role checks do not enforce backend permissions.

**Mistake 5: trusting client-supplied roles or ownership.** The server must establish these values from trusted state or explicitly authorized workflows.

**Mistake 6: assuming every 200 response proves unauthorized access.** The returned data or side effect must violate an actual permission boundary.

**Mistake 7: assuming every 403 proves the application is secure.** Other endpoints or methods may still lack the necessary checks.

**Mistake 8: ignoring background jobs and exports.** A protected page can coexist with an unprotected generated file or asynchronous worker.

**Mistake 9: reporting multiple symptoms as unrelated vulnerabilities without finding the root cause.** One missing object-level authorization check may affect several endpoints. Explain the common root cause and demonstrate the affected paths.

**Mistake 10: overstating severity.** Severity should reflect demonstrated access and realistic impact, not hypothetical worst-case consequences unsupported by evidence.

### Part 28: Your Authorization Testing Master Checklist

**Identity and policy:** identify the authenticated actor; understand the intended roles and permissions; identify object ownership and sharing relationships; understand tenant membership and administrative scope; identify any authentication-assurance requirements for sensitive actions.

**Object-level authorization:** test permitted and forbidden object access with controlled accounts; check read, update, delete, export, and sharing operations; confirm the server enforces ownership or the applicable relationship; verify that child resources belong to the authorized parent; check for cross-tenant access where applicable.

**Function-level authorization:** identify administrative and staff-only functions; verify backend enforcement independently of the frontend; test sensitive operations with accounts lacking the required role; check alternate routes and older API versions; confirm that role revocation takes effect according to policy.

**Property-level authorization:** identify server-managed fields; review request schemas and mass-assignment behavior; verify that clients cannot grant themselves privileged roles; protect approval, payment, ownership, verification, and security-state fields; confirm that allowed edits do not unintentionally alter protected fields.

**Business logic:** validate ownership and eligibility before financial actions; recompute sensitive values on the server; enforce valid workflow transitions; check that one-time operations cannot be repeated improperly; review transaction boundaries and concurrent state changes where relevant.

**Evidence and reporting:** use controlled accounts and records; include positive controls; confirm the actual response or state change; capture minimal evidence; explain the root cause; report realistic impact without exaggeration; recommend a remediation that addresses the underlying policy failure.

### Module 17 Final Summary

The most important lesson is that authorization must be enforced at the level where the protected action occurs. A user can have a valid session, complete MFA, and use a perfectly secure password, and still be able to access another person's data if the application fails to enforce authorization.

| Vulnerability | Central question |
|---|---|
| IDOR | Does an object reference allow access outside the intended permission boundary? |
| BOLA | Does the API correctly enforce authorization for the specific object? |
| Horizontal privilege escalation | Can one user access another user's resources or permissions? |
| Vertical privilege escalation | Can a user obtain privileges intended for a higher privilege level? |
| Broken function-level authorization | Can the user invoke a function they are not permitted to use? |
| Mass assignment | Can the client modify protected model properties? |
| Property-level authorization failure | Can the user modify or read fields they should not be allowed to access? |
| Broken tenant isolation | Can a user cross an organizational or tenant boundary without permission? |
| Business-logic failure | Can the user violate an intended workflow or business rule? |
| Stale authorization | Does revoked or outdated permission state continue to grant access? |

These categories overlap. Classify the demonstrated root cause accurately. Senior AppSec principle: never stop at discovering an identifier, a hidden endpoint, or a suspicious request. Establish the intended policy, prove that the server violates it, demonstrate the actual impact, and recommend a fix that enforces the policy consistently.

## Assessment

The following assessment is drawn directly from Module 17's own Part 25 comprehensive case study, since the one marginally relevant exchange in the supplementary file overlaps with JWT signature-integrity content already covered in Phase 16. The two exercises below select four of the six findings, using the module's own given classifications and reasoning as the answer.

### Assessment Question 1

A fictional multi-tenant commerce platform has this order-retrieval handler:

```python
def get_order(order_id, user):
    require_login(user)
    return db.get_order(order_id)
```

and this tenant-reports handler:

```python
def get_tenant_reports(tenant_id, user):
    require_login(user)
    return db.get_reports(tenant_id)
```

Classify each of these two findings precisely, and state exactly what evidence would be required to confirm each one as a real vulnerability rather than a theoretical concern.

<details markdown="1">
<summary><strong>Reveal Answer</strong></summary>

The order-retrieval handler is a potential IDOR/BOLA finding. It checks only that the user is logged in and then retrieves the order purely by `order_id`, with no visible check that the order belongs to this user, that the user's tenant is authorized for it, or that any sharing or administrative relationship applies. The evidence required to confirm it is a real vulnerability: a controlled account can access a private order belonging to another user without an authorized sharing or administrative relationship actually existing. The remediation is to enforce object-level authorization in the relevant retrieval path, for example scoping the database lookup to the authenticated user's permitted orders rather than fetching by ID alone.

The tenant-reports handler is a potential broken tenant isolation finding, and also potentially BOLA, since a tenant's reports are themselves objects the user may lack authorization for. It checks only that the user is logged in and then returns reports purely by the `tenant_id` supplied in the request, with no visible check that the authenticated user is actually a member of, or otherwise authorized for, that specific tenant. The evidence required to confirm it: the user is not a member of, or otherwise authorized for, the target tenant, yet receives its private reports when queried. The remediation is to derive or validate tenant access through trusted membership and policy checks, for example requiring an explicit, server-verified tenant-membership check before the report query runs, rather than trusting the tenant identifier supplied in the request.

In both cases, merely observing that the function exists and omits a visible check is not itself proof of a vulnerability, since the check could exist elsewhere in the call path. The finding is only confirmed once a controlled test account, with a known, different ownership or tenant relationship, is shown to actually receive the other party's protected data.

</details>

### Assessment Question 2

The same platform has this product-update handler:

```python
def update_product(product_id, request, user):
    product = db.get_product(product_id)
    authorize_product_edit(user, product)

    for key, value in request.json().items():
        setattr(product, key, value)

    db.save(product)
```

and this refund handler:

```python
def refund_order(request, user):
    require_login(user)

    return payment_provider.refund(
        order_id=request.json["order_id"],
        amount=request.json["amount"]
    )
```

Classify each of these two findings precisely, explain why the product-update handler is dangerous even though it correctly calls `authorize_product_edit`, and explain why the refund handler could actually represent two separate problems rather than one.

<details markdown="1">
<summary><strong>Reveal Answer</strong></summary>

The product-update handler is a potential property-level authorization or mass-assignment vulnerability. It is dangerous despite correctly calling `authorize_product_edit(user, product)` because that call only establishes that the seller is permitted to edit the product as an object, it says nothing about which specific fields they are permitted to change. The handler then loops over every key and value in the raw request body and applies all of them directly to the product with `setattr`, with no restriction on which properties are writable. The evidence required: the seller is permitted to edit the product but can also modify a protected field, such as `approved`, that should be controlled by the moderation process rather than by the product's owner. The remediation is to use explicit writable-field schemas, an allowlist of the specific fields a seller may change, and to enforce the separate, distinct permission required for product approval, rather than trusting the full shape of the incoming request body.

The refund handler is classified as a potential business-logic and integrity failure, potentially BOLA as well if the order's ownership is not checked. It could represent two separate problems because it checks only that the user is logged in before calling the payment provider directly with a client-supplied `order_id` and a client-supplied `amount`. First, there is no visible check that the order identified by `order_id` actually belongs to the requesting user at all, which is the object-level authorization half, a customer could potentially refund someone else's order. Second, even for a user's own order, there is no visible recomputation of what the actual eligible refund amount is, the `amount` is taken directly from client input, which is the business-logic and integrity half, a customer could potentially refund an amount exceeding what is actually owed. The evidence required to confirm this is to demonstrate that the server does not independently validate the order, the eligible refund amount, the actor's permissions, and the payment state, each as a separate check. The remediation is to recompute eligibility and the refundable amount from authoritative server-side data, verify ownership and permissions independently, and enforce valid state transitions, rather than acting on any of those values as supplied by the client.

</details>

## Remediation and Secure Implementation

The following consolidates the remediation guidance across all twenty-eight parts of this phase.

1. Treat every authenticated request as requiring a separate, explicit authorization decision, identity, action, resource, and permission, and never let "the session is valid" substitute for "this identity may perform this action on this resource."
2. Scope every object lookup to the authenticated identity's actual ownership, tenant membership, or sharing relationship at the database-query level, rather than retrieving an object by its identifier alone and checking permissions afterward or not at all.
3. Enforce authorization independently for every HTTP method and every route that can reach a given resource, read, write, delete, export, alternate API versions, mobile endpoints, and internal routes alike, since protecting one path does not protect the others.
4. Define an explicit, server-controlled set of client-editable fields for every writable object, and never bind raw request bodies directly to internal models, to prevent both mass assignment and property-level authorization failures.
5. Derive tenant context from authenticated identity and validated server-side membership, never from a tenant identifier supplied in a URL, body, header, subdomain, or session claim without independent verification.
6. Separate authorization from workflow-state validation as two distinct checks, confirming both that the actor is permitted to perform the action and that the resource's current state actually permits that action.
7. Invalidate or revalidate cached authorization state whenever a role, membership, or permission changes, and define explicitly how quickly that revocation must take effect for high-risk operations.
8. Preserve the original authorization decision across asynchronous boundaries, background jobs, exports, and generated files, by passing a trusted, validated job context and revalidating permissions at execution time where required, rather than trusting a bare identifier.
9. Protect the actual storage location of sensitive files, not merely the authenticated page that links to them, and treat any signed download URL as a bearer credential requiring appropriate scope, expiry, and revocation handling.
10. Recompute every financially or security-sensitive value, prices, refund amounts, payment status, server-side from authoritative data, and never trust a client-supplied value for anything that determines money moved or privilege granted.

## Key Takeaways

This phase, and the course, close on the same distinction they opened with: authentication establishes who you are, authorization determines what you are allowed to do, and an application can get the first one completely right while failing catastrophically at the second. Every vulnerability category in this module, IDOR, BOLA, horizontal and vertical privilege escalation, broken function-level authorization, mass assignment, property-level authorization, broken tenant isolation, business-logic failure, and stale authorization, is a different specific shape of the same underlying gap: a server that correctly knows who is asking, and still fails to correctly decide whether they should get what they asked for.

The case study in this phase's assessment demonstrates why precise classification matters as much as detection throughout this entire course: an unscoped `db.get_order(order_id)` call, a `setattr` loop that trusts the full request body, and a refund handler that never recomputes its own numbers are three structurally different failures that happen to share a surface symptom, an authenticated user reaching data or actions they should not reach. The discipline this course has built across all seventeen phases, trace the complete lifecycle, distinguish what the evidence proves from what it merely suggests, and name the specific root cause rather than the most alarming label available, applies here exactly as it applied to a forged SAML assertion, a predictable reset token, or a legacy endpoint that skips MFA. Authorization is the boundary every other control in this course ultimately exists to protect, and it is the boundary most easily forgotten precisely because authentication so often works correctly right up until the moment it doesn't matter anymore.

## Review Checklist

- [ ] Can you state the four fundamental authorization questions, identity, action, resource, permission, and apply them to a request of your choosing?
- [ ] Can you distinguish RBAC, ABAC, and ReBAC, and explain why a real system might combine all three?
- [ ] Can you explain why changing an object identifier and receiving a `200 OK` is not, by itself, proof of IDOR or BOLA?
- [ ] Can you distinguish horizontal privilege escalation, vertical privilege escalation, and broken function-level authorization by the specific question each one answers?
- [ ] Can you explain the difference between mass assignment and property-level authorization, and name at least five fields an application should typically protect?
- [ ] Can you explain why a tenant identifier from a URL, header, or subdomain is never sufficient on its own to establish tenant access?
- [ ] Can you identify at least four distinct places, beyond the primary endpoint, where the same authorization check can be silently missing: alternate routes, HTTP methods, background jobs, and file storage?
- [ ] Can you distinguish an authorization failure from a business-logic failure and from a workflow-state failure, using the refund and price-manipulation examples?
- [ ] Can you explain why correct authorization can become stale, and what must be reviewed to catch it?
- [ ] Can you build a controlled-account permission matrix for an authorization test, including positive controls?
- [ ] Can you list at least six of the ten advanced mistakes this module identifies, and explain why each one weakens a finding?
- [ ] Can you classify each of the six findings in the module's comprehensive case study correctly, using the module's own terminology?

## References to Related Phases

- Multi-tenant authorization in Part 10 directly extends the tenant-membership, role-scoping, and database-query principles established in **Phase 11, Multi-Tenant Identity Isolation**.
- Stale authorization and account-lifecycle revocation in Parts 16 and 17 extend the session-revocation discipline from **Phase 6, Cookie and Session Security** and the account-lifecycle principles from **Phase 8, Account Lifecycle and Identity Proofing**.
- Authorization and authentication-state changes in Part 18, including the step-up authentication example, builds directly on **Phase 9, Reauthentication and Step-Up Authentication**.
- Authorization caching, background jobs, and stale privileges throughout this phase extend the authorization-adjacent concerns first flagged for SAML role attributes in **Phase 10, SAML Security**, and for information disclosure in **Phase 12, Authentication Information Leakage**.
- The impact-validation discipline applied throughout this phase's assessment and severity guidance is the same discipline carried forward from **Phase 1, Password Storage and Credential Attacks**, through every phase of this course.

This is the final phase of the Authentication Security Engineering course. All seventeen phases are now complete.
