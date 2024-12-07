# Broken Access Control

## Overview

Broken Access Control is currently ranked #1 in the OWASP Top 10 2021. This vulnerability occurs when users can act outside of their intended permissions, leading to unauthorized information disclosure, modification, or destruction of data.

Common issues include:
- Bypassing access control checks by modifying the URL or HTML page
- Allowing primary key to be changed to another user's records
- Elevation of privilege by acting as a user without being logged in
- Metadata manipulation like tampering with JWT tokens or cookies
- CORS misconfiguration allowing unauthorized API access
- Force browsing to authenticated pages as an unauthenticated user

## Technical Details

### Common Attack Vectors

1. **Vertical Access Control Failures**
   - Accessing functionality not authorized for your user role
   - Example: Regular user accessing admin endpoints

2. **Horizontal Access Control Failures**
   - Accessing resources belonging to other users
   - Example: Modifying URL parameters to view other users' documents

3. **Context-Dependent Access Control Failures**
   - Accessing resources in wrong order or incorrect state
   - Example: Accessing order details before payment completion

### Vulnerable Patterns in Our Domain

Using our solution's models, here are examples of vulnerable patterns:

```csharp
// Vulnerable endpoint allowing document access without proper checks
public async Task<Document> GetDocument(int id)
{
    return await _context.Documents.FindAsync(id);
}

// Vulnerable order access
public async Task<Order> GetOrder(int orderId)
{
    return await _context.Orders.FindAsync(orderId);
}
```

## OWASP Mitigation Details

1. **Deny by Default**
   - Implement proper access control mechanisms
   - Deny all access by default, requiring explicit grants

2. **Role-Based Access Control (RBAC)**
   - Implement and enforce role-based access control
   - Define clear roles and permissions

3. **Record Ownership**
   - Enforce record ownership
   - Implement proper user authentication and session management

4. **Business Logic**
   - Enforce proper business logic for step-by-step processes
   - Implement proper state checks

## ASP.NET Core Mitigation Details

### 1. Authorization Attributes

```csharp
[Authorize(Roles = "Admin")]
public class DocumentController : Controller
{
    private readonly IUserManagementService _userService;
    
    [HttpGet("{id}")]
    public async Task<ActionResult<Document>> GetDocument(int id)
    {
        var currentUserId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        var document = await _context.Documents
            .FirstOrDefaultAsync(d => d.Id == id);
            
        if (document == null)
            return NotFound();
            
        // Check if user owns document or has admin rights
        if (document.OwnerId != currentUserId && 
            !User.IsInRole("Admin"))
            return Forbid();
            
        return document;
    }
}
```

### 2. Policy-Based Authorization

```csharp
public class DocumentAuthorizationHandler : 
    AuthorizationHandler<OperationAuthorizationRequirement, Document>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        OperationAuthorizationRequirement requirement,
        Document document)
    {
        var user = context.User;
        
        if (document.OwnerId == user.FindFirst(ClaimTypes.NameIdentifier)?.Value ||
            user.IsInRole("Admin"))
        {
            context.Succeed(requirement);
        }
        
        return Task.CompletedTask;
    }
}
```

### 3. Resource-Based Authorization

```csharp
public class OrderController : Controller
{
    private readonly IAuthorizationService _authorizationService;
    
    [HttpGet("{id}")]
    public async Task<ActionResult<Order>> GetOrder(int id)
    {
        var order = await _context.Orders.FindAsync(id);
        
        if (order == null)
            return NotFound();
            
        var authorizationResult = await _authorizationService
            .AuthorizeAsync(User, order, "OrderPolicy");
            
        if (!authorizationResult.Succeeded)
            return Forbid();
            
        return order;
    }
}
```

### 4. Custom Middleware for Global Checks

```csharp
public class AccessControlMiddleware
{
    private readonly RequestDelegate _next;
    
    public async Task InvokeAsync(HttpContext context)
    {
        // Implement global access control checks
        if (!await ValidateAccess(context))
        {
            context.Response.StatusCode = 403;
            return;
        }
        
        await _next(context);
    }
}
```

## Sample Test Payloads

### 1. Horizontal Privilege Escalation Tests

```http
# Attempt to access another user's document
GET /api/documents/123 HTTP/1.1
Authorization: Bearer [valid_token_for_different_user]

# Expected: 403 Forbidden
```

### 2. Vertical Privilege Escalation Tests

```http
# Attempt to access admin endpoint as regular user
GET /api/admin/users HTTP/1.1
Authorization: Bearer [regular_user_token]

# Expected: 403 Forbidden
```

### 3. Missing Authentication Tests

```http
# Attempt to access protected resource without authentication
GET /api/documents/123 HTTP/1.1

# Expected: 401 Unauthorized
```

### 4. Parameter Tampering Tests

```http
# Attempt to modify order belonging to another user
PUT /api/orders/123 HTTP/1.1
Authorization: Bearer [valid_token_for_different_user]
Content-Type: application/json

{
    "orderId": 123,
    "userId": "different_user_id",
    "status": "Completed"
}

# Expected: 403 Forbidden
```

### 5. CORS Exploitation Tests

```http
# Attempt cross-origin request from unauthorized domain
Origin: https://malicious-site.com
GET /api/documents/123 HTTP/1.1
Authorization: Bearer [valid_token]

# Expected: CORS error
```
