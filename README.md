# IDOR Patterns

Insecure Direct Object Reference: the app exposes a reference to an internal object and doesn't verify the requesting user is authorised to access it. The reference can be anything that maps to a backend object — numeric ID, UUID, filename, hash, encoded value.

---

## Reference Types

### Numeric IDs
The obvious case. Sequential integers in URLs, request bodies, or headers.
```
GET /api/invoices/1042
GET /api/users/8831/profile
POST /api/messages {"recipient_id": 5521}
```
Increment, decrement, enumerate. Often sequential even when they look random.

### UUIDs
Not sequential but not unpredictable from the attacker's perspective if they can observe any UUIDs (their own objects, shared links, email confirmations). Version 1 UUIDs contain a timestamp and MAC address — guessable. Version 4 are random but may appear in:
- Shared URLs
- Email links
- API responses that include other users' object IDs
- Leaked via Referer headers

### Hashed / encoded references
```
GET /files/download?id=aGVsbG8=          # base64
GET /report/5d41402abc4b2a76b9719d911017c592  # MD5 of something predictable
```
Decode first. If it's base64 of a numeric ID, or MD5/SHA1 of something predictable (email, username, sequential ID), it's enumerable.

### Filenames
```
GET /uploads/invoice_march_2026_john_smith.pdf
GET /exports/user_8831_export.csv
```
Filename reveals structure. Predictable naming = enumerable.

### Indirect references (harder to find)
Object not referenced directly in the request — derived from session state, but server-side mapping can be bypassed.
```
GET /api/account/settings
# Internally maps session -> user_id -> settings
# Test: what if you change a secondary parameter that affects which account loads?
```

---

## Where References Appear

Don't just check URL parameters. References appear in:

- URL path: `/api/users/1234/orders`
- Query params: `?account=1234&report=5678`
- Request body (JSON/form): `{"user_id": 1234, "file_id": 9876}`
- HTTP headers: `X-User-ID: 1234`, `X-Account: enterprise_001`
- Cookies: `account_id=1234` (separate from session cookie)
- GraphQL variables: `{"query": "user(id: 1234) { ... }"}`
- WebSocket messages: `{"action": "subscribe", "channel": "user_1234"}`
- Multipart form fields: file upload with `owner_id` field

---

## IDOR Patterns Beyond Basic Object Access

### Mass Assignment IDOR
API accepts more fields than it should. Attacker adds fields the app wasn't expecting from user input.

```json
PUT /api/profile
{"name": "Jack", "email": "jack@x.com"}

# Try adding:
{"name": "Jack", "email": "jack@x.com", "role": "admin", "user_id": 1, "verified": true}
```

App may silently accept and apply fields it shouldn't expose to user control. Common in frameworks that auto-bind request body to model objects (Rails, Spring, Django REST Framework with bad serializer config).

### State-Based IDOR
Access depends on object state, not just ownership. Object is accessible in one state but should be restricted in another.

```
Order #5521 belongs to user A, status: "pending"
Order #5521 gets cancelled -> status: "cancelled"
App checks ownership on active orders but not archived ones

GET /api/orders/5521  # Returns 403 for user B when active
GET /api/orders/5521/invoice  # Returns 200 for user B after cancellation
```

Test access to objects at different states: draft/published, active/archived, pending/completed, deleted/restored.

### Method-Based IDOR
Access control enforced on one HTTP method but not others.

```
GET /api/documents/8831     # 403 - access denied
POST /api/documents/8831    # 200 - allowed (create endpoint ignores ID auth check)
PUT /api/documents/8831     # 200 - updates someone else's document
DELETE /api/documents/8831  # 403
```

Try GET, POST, PUT, PATCH, DELETE on the same resource. Also try HEAD (sometimes returns headers that leak data even when body is blocked).

### Parameter Pollution IDOR
Send the ID parameter multiple times.

```
GET /api/profile?user_id=attacker_id&user_id=victim_id
POST /api/transfer  body: user_id=attacker_id&user_id=victim_id
```

Some parsers take the first value, some take the last, some take both. If the auth check uses a different value than the action execution, you have IDOR.

Also try:
```
GET /api/profile?user_id[]=attacker_id&user_id[]=victim_id
GET /api/profile?user_id=attacker_id,victim_id
```

### Chained/Indirect IDOR
No direct reference to the victim object, but a reference to an intermediate object that links to it.

```
# Direct: GET /api/users/1234/documents  (blocked)
# Indirect: 
GET /api/teams/56/members           # returns member user IDs including 1234
GET /api/teams/56/shared-documents  # returns documents belonging to member 1234
```

The team endpoint is accessible, and through it you reach data you shouldn't.

Another pattern: object A references object B. You have access to A but not B. App doesn't check auth on B when accessed through A.

```
GET /api/comments/9921       # your comment
# response includes: {"id": 9921, "post_id": 3310, "author_id": 1234}
GET /api/posts/3310          # 403 - private post
GET /api/comments/9921/post  # 200 - returns the private post (auth not checked)
```

### IDOR via Response Manipulation
App returns 403 but includes object data in the response body anyway. Or returns a redirect to an access denied page but the redirect response contains the data.

```
HTTP/1.1 403 Forbidden
Content-Type: application/json

{"error": "access denied", "resource": {"id": 1234, "name": "Confidential Report", "content": "..."}}
```

Always read 403/401 response bodies.

Also: change `403` to `200` in the response using an intercepting proxy. Sometimes the frontend code that renders the page is what checks auth, not the backend — if you bypass the 403 the data renders fine.

### Export/Report IDOR
Async export jobs are a common blind spot. Job creation checks auth, but job retrieval doesn't.

```
POST /api/export {"type": "account_data", "user_id": 1234}
-> {"job_id": "exp_8831"}

GET /api/export/exp_8831/download  # no auth check on the download endpoint
```

Enumerate job IDs. Also: trigger your own export, note the job ID format, try adjacent IDs.

### Blind IDOR
Response doesn't return the object data but a side effect confirms access.

```
DELETE /api/messages/5521  # returns 200 (your message)
DELETE /api/messages/5522  # returns 200 (not your message, but it got deleted)
DELETE /api/messages/5523  # returns 404 (doesn't exist)
```

200 vs 404 vs 403 tells you whether the object exists and whether you acted on it. Timing differences can also indicate processing.

---

## Enumeration Techniques

### Burp Intruder
Capture request with ID parameter, send to Intruder, set payload position, use number list payload. Filter responses by length or status code.

```
GET /api/invoices/§1000§
Payload: numbers 1000-2000
Filter: responses != 403
```

### Comparing response sizes
Objects you own return full data. Objects you don't return 403 or empty. Sort by response length in Intruder results — outliers are accessible objects.

### Observed ID ranges
Create multiple accounts, note what IDs you get. If you're user 10431 and your colleague is user 10438, the range is clear. Enumerate between them and beyond.

### API responses leaking IDs
Your own API responses often include IDs of related objects you shouldn't necessarily access directly:
- List of team members includes their user IDs
- Notification includes sender ID
- Audit log includes referenced object IDs
- Search results include object IDs even for restricted results

Collect all IDs you observe across the app, then try direct access to each.

---

## Access Control Patterns That Look Safe But Aren't

**GUID/UUID as security control:** "We use UUIDs so it's not enumerable." UUIDs in v1 are time-based. V4 are random but appear in URLs that get shared, emailed, logged, cached by CDNs. UUID != authorization check.

**Signed references:** Object ID is signed (e.g., HMAC). Signature prevents tampering but doesn't prove the requester owns the object. Signature verification != authorization.

**Short-lived tokens:** Download link with expiring token. If the token encodes the object ID and the server doesn't check who the token was issued to, any user with a valid token for any object can access it.

**Rate limiting as security:** "We'll detect enumeration." Rate limiting slows you down, doesn't prevent access. Slow enumeration over time or from multiple IPs bypasses it.

---

## Testing Checklist

```
[ ] Identify all ID parameters across the app (URL, body, headers, cookies)
[ ] Create two accounts, A and B
[ ] With account B, try accessing all objects belonging to A
[ ] Try all HTTP methods on each endpoint (GET/POST/PUT/PATCH/DELETE)
[ ] Try IDs in unexpected places: headers, cookies, hidden form fields
[ ] Decode any encoded references (base64, hex, hash)
[ ] Test state-based access: access objects after status changes
[ ] Try mass assignment: add unexpected fields to PUT/POST requests
[ ] Try parameter pollution: duplicate ID params with different values
[ ] Check 403/401 response bodies for leaked data
[ ] Test async job/export endpoints for ID enumeration
[ ] Look for indirect access: reach restricted objects via related accessible ones
[ ] Test API versions: v1 endpoint fixed, v2 not, or vice versa
[ ] Test mobile API endpoints separately from web endpoints
[ ] Check GraphQL: introspection, then test each query/mutation with other users' IDs
```

---

## Reporting Impact

Basic IDOR is a medium at best in isolation. To push it higher:

- Show data accessed (PII, financial data, credentials, private communications)
- Chain it: IDOR to read API key -> use API key to take over account
- Demonstrate write/delete (not just read): IDOR on DELETE endpoint = data destruction
- Show scale: enumerate 10,000 records to demonstrate mass data exposure
- Show auth bypass: IDOR on admin endpoint accessed by regular user
