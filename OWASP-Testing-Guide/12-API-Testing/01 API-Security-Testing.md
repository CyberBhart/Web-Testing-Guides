# **Comprehensive API Security Testing Guide**

## **Overview**

API security testing evaluates the security of Application Programming Interfaces (APIs), including GraphQL, REST, and SOAP, which are critical for modern web applications. APIs are vulnerable to attacks due to their exposure and access to sensitive data. The OWASP Web Security Testing Guide (WSTG) v4.2 includes **WSTG-APIT-01: Testing GraphQL**, which focuses on GraphQL-specific vulnerabilities like introspection abuse, broken access control, deep query abuse, and injection attacks. This guide extends beyond GraphQL to cover all API testing scenarios, incorporating the OWASP API Security Top 10 2023 and additional vulnerabilities (e.g., SSRF, misconfigurations) to ensure comprehensive testing.

**Impact**: API vulnerabilities can lead to:
- Unauthorized data access or manipulation.
- Server compromise via injections or malicious queries.
- Denial of Service (DoS) through resource exhaustion.
- Financial or operational damage due to exploited logic flaws.

This guide provides a practical, hands-on methodology for API security testing, including detailed steps for GraphQL testing (WSTG-APIT-01), REST/SOAP testing, and generic API vulnerabilities. It includes tool setups with at least two specific commands per tool, detailed real-world test cases with step-by-step commands and executable code, remediation strategies, and ethical considerations.

## **Scope**

This guide covers:
- **GraphQL Testing (WSTG-APIT-01)**: Introspection queries, broken access control, deep queries, batch query abuse, injections, and alias overloading.
- **REST and SOAP Testing**: Authentication, authorization, input validation, rate-limiting, and OWASP API Security Top 10 2023 (e.g., Broken Object Level Authorization, Excessive Data Exposure).
- **Generic API Vulnerabilities**: SSRF, error handling, session management, and misconfigurations.
- **All Possible Tests**: Ensures no test is missed by combining OWASP guidelines, real-world scenarios, and advanced techniques like fuzzing.

## **Testing Tools**

The following tools are recommended, with at least two specific commands or configurations per tool for real security testing:

- **Burp Suite Community Edition**: Intercepts and manipulates API requests.
- **Postman**: Tests API endpoints with crafted queries.
- **GraphQL Playground**: Interacts with GraphQL APIs for query testing.
- **cURL**: Sends custom API requests.
- **OWASP ZAP**: Automated scanner for API vulnerabilities.
- **Python Requests Library**: Scripts automated API tests.

### **Tool Setup Instructions**

1. **Burp Suite Community Edition**:
   - Download: [PortSwigger](https://portswigger.net/burp/communitydownload).
   - Configure proxy: 127.0.0.1:8080 (Firefox).
   - Enable “Intercept” in Proxy tab.
   - Verify: `curl -x http://127.0.0.1:8080 http://example.com`.
2. **Postman**:
   - Download: [postman.com](https://www.postman.com/downloads/).
   - Install and create a free account.
   - Verify: Open Postman and check version.
3. **GraphQL Playground**:
   - Download: [GitHub](https://github.com/graphql/graphql-playground).
   - Configure endpoint (e.g., `http://example.com/graphql`).
   - Verify: Run a sample query.
4. **cURL**:
   - Install: `sudo apt install curl` (Linux) or download from [curl.se](https://curl.se/).
   - Verify: `curl --version`.
5. **OWASP ZAP**:
   - Download: [zaproxy.org](https://www.zaproxy.org/download/).
   - Run: `zap.sh` (Linux) or `zap.bat` (Windows).
   - Verify: Check ZAP GUI.
6. **Python Requests Library**:
   - Install: `sudo apt install python3; pip install requests`.
   - Verify: `python3 -c "import requests; print(requests.__version__)"`.

## **Testing Methodology**

This methodology combines WSTG-APIT-01 for GraphQL with comprehensive REST/SOAP and generic API testing, ensuring all vulnerabilities are tested.

### **1. Discover API Endpoints with Burp Suite**

Map all API endpoints to understand the attack surface.

**Steps**:
1. Configure Burp Suite proxy (127.0.0.1:8080).
2. Browse the application or use API documentation to capture requests in “HTTP History”.
3. Identify endpoints (e.g., `/graphql`, `/api/v1/users`, `/soap/service`).
4. Save endpoints in “Site Map”.

**Burp Suite Commands**:
- **Command 1**: Crawl for endpoints:
  ```
  Target tab -> Site Map -> Right-click example.com -> Engagement Tools -> Crawl -> Include /graphql, /api/* -> Start Crawl
  ```
- **Command 2**: Export endpoints for analysis:
  ```
  Target tab -> Site Map -> Right-click example.com -> Copy URLs in Scope -> Paste to file
  ```

**Remediation**:
- Restrict endpoint exposure:
  ```nginx
  location ~ ^/(graphql|api) {
      allow 127.0.0.1;
      deny all;
  }
  ```

### **2. Test GraphQL Introspection with GraphQL Playground**

Test if introspection queries expose the schema (WSTG-APIT-01).

**Steps**:
1. Open GraphQL Playground, set endpoint to `http://example.com/graphql`.
2. Add headers (e.g., `Authorization: Bearer abc123`).
3. Run introspection query to retrieve schema.
4. Test without authentication to check public exposure.
5. Save query and response.

**GraphQL Playground Commands**:
- **Command 1**: Run introspection query:
  ```
  Schema tab -> Endpoint: http://example.com/graphql -> Headers: {"Authorization": "Bearer abc123"} -> Query: {__schema {types {name fields {name}}}} -> Run
  ```
- **Command 2**: Test unauthorized introspection:
  ```
  Schema tab -> Remove Authorization header -> Query: {__schema {types {name}}} -> Run
  ```

**Remediation**:
- Disable introspection:
  ```javascript
  const { ApolloServer } = require('apollo-server');
  const server = new ApolloServer({ schema, introspection: false });
  ```

### **3. Test Access Controls with Postman**

Test for broken object-level or function-level authorization (WSTG-APIT-01, API Top 10 A01:2023).

**Steps**:
1. Import GraphQL/REST endpoints into Postman.
2. Send queries/requests with unauthorized IDs or roles.
3. Check for data exposure or HTTP 403.
4. Save results.

**Postman Commands**:
- **Command 1**: Test GraphQL unauthorized access:
  ```
  New Request -> POST http://example.com/graphql -> GraphQL -> Query: query { user(id: 999) { email } } -> Headers: Authorization: Bearer user_token -> Send
  ```
- **Command 2**: Test REST unauthorized access:
  ```
  New Request -> GET http://example.com/api/users/999 -> Headers: Authorization: Bearer user_token -> Send
  ```

**Remediation**:
- Enforce authorization:
  ```javascript
  const resolvers = {
    Query: {
      user: (parent, { id }, { user }) => {
        if (user.id !== id && !user.isAdmin) throw new Error('Unauthorized');
        return db.getUser(id);
      }
    }
  };
  ```

### **4. Test Deep Queries and DoS with cURL**

Test GraphQL for resource exhaustion via deep queries (WSTG-APIT-01).

**Steps**:
1. Craft a nested GraphQL query.
2. Use cURL to send it repeatedly.
3. Monitor response time and server behavior.
4. Save commands and responses.

**cURL Commands**:
- **Command 1**: Send deep query:
  ```bash
  curl -X POST -H "Content-Type: application/json" -H "Authorization: Bearer abc123" --data '{"query": "query { users { posts { comments { author { posts { comments { id } } } } } } }"}' http://example.com/graphql
  ```
- **Command 2**: Flood with queries:
  ```bash
  for i in {1..10}; do curl -X POST -H "Content-Type: application/json" --data '{"query": "query { users { posts { comments { author { posts { id } } } } } }"}' http://example.com/graphql; done
  ```

**Remediation**:
- Limit query depth:
  ```javascript
  const depthLimit = require('graphql-depth-limit');
  const server = new ApolloServer({ schema, validationRules: [depthLimit(5)] });
  ```

### **5. Test Injections with OWASP ZAP**

Test for SQL, NoSQL, and command injections (WSTG-APIT-01, API Top 10 A03:2023).

**Steps**:
1. Configure OWASP ZAP proxy (127.0.0.1:8080).
2. Import API endpoints.
3. Run active scan with injection payloads.
4. Save scan reports.

**OWASP ZAP Commands**:
- **Command 1**: Scan GraphQL for injections:
  ```
  Sites tab -> Right-click http://example.com/graphql -> Attack -> Active Scan -> Select SQL Injection -> Start Scan
  ```
- **Command 2**: Fuzz REST parameters:
  ```
  Sites tab -> Right-click GET http://example.com/api/users?name=test -> Attack -> Fuzzer -> Add Payloads: SQL Injection (e.g., ' OR 1=1 --) -> Start Fuzzer
  ```

**Remediation**:
- Sanitize inputs:
  ```python
  from graphql import GraphQLError
  def resolve_user(parent, info, name):
      if not re.match(r'^[a-zA-Z0-9]+$', name):
          raise GraphQLError('Invalid input')
      return db.query(f"SELECT * FROM users WHERE name = '{name}'")
  ```

### **6. Automate Testing with Python Requests**

Script automated tests for multiple vulnerabilities.

**Steps**:
1. Write a Python script for GraphQL/REST testing.
2. Run the script and analyze results.
3. Save output.

**Python Code**:
```python
import requests
import json

url = 'http://example.com/graphql'
headers = {'Authorization': 'Bearer abc123', 'Content-Type': 'application/json'}
payloads = [
    {'query': '{__schema {types {name fields {name}}}}'},  # Introspection
    {'query': 'query { user(id: 999) { email } }'},       # Access control
    {'query': 'query { users(name: "admin\' OR 1=1 --") { id } }'},  # Injection
    {'query': 'query { users { posts { comments { author { posts { id } } } } } }'}  # Deep query
]

for payload in payloads:
    response = requests.post(url, headers=headers, json=payload)
    print(f"Payload: {payload['query']}")
    print(f"Status: {response.status_code}")
    print(f"Response: {response.text[:100]}\n")

# Test REST SSRF
rest_url = 'http://example.com/api/fetch'
rest_payload = {'url': 'http://internal.example.com/secret'}
response = requests.post(rest_url, json=rest_payload, headers=headers)
print(f"REST SSRF Status: {response.status_code}")
print(f"REST SSRF Response: {response.text[:100]}")
```

**Python Commands**:
- **Command 1**: Run GraphQL tests:
  ```bash
  python3 test_api.py
  ```
- **Command 2**: Test REST SSRF separately:
  ```bash
  python3 -c "import requests; url='http://example.com/api/fetch'; payload={'url': 'http://internal.example.com/secret'}; headers={'Authorization': 'Bearer abc123'}; r=requests.post(url, json=payload, headers=headers); print(r.status_code, r.text[:100])"
  ```

**Remediation**:
- Validate URLs:
  ```javascript
  const isValidUrl = (url) => /^https?:\/\/example\.com/.test(url);
  if (!isValidUrl(req.body.url)) res.status(400).send('Invalid URL');
  ```

## **Real-World Test Cases**

Below are detailed, step-by-step test cases covering GraphQL (WSTG-APIT-01), REST, and OWASP API Security Top 10 vulnerabilities, with specific commands and code for execution.

### **Test 1: GraphQL Introspection Exposure**

**Objective**: Check if introspection queries expose the schema.

**Steps**:
1. **Set Up GraphQL Playground**:
   - Open GraphQL Playground, set endpoint to `http://example.com/graphql`.
   - Add header: `Authorization: Bearer abc123`.
2. **Run Introspection Query**:
   - Execute:
     ```graphql
     query {
       __schema {
         types {
           name
           fields {
             name
             type {
               name
             }
           }
         }
       }
     }
     ```
   - Command: In GraphQL Playground, paste query and click “Run”.
3. **Test Unauthorized Access**:
   - Remove `Authorization` header and rerun query.
4. **Analyze Response**:
   - Check for schema details (e.g., `User`, `Admin` types).
   - Expected secure response: HTTP 403 or empty schema.
5. **Save Results**:
   - Export query and response as JSON.

**Command**:
```bash
curl -X POST -H "Content-Type: application/json" -H "Authorization: Bearer abc123" --data '{"query": "{__schema {types {name fields {name}}}}"}' http://example.com/graphql > introspection.json
```

**Example Vulnerable Response**:
```json
{
  "data": {
    "__schema": {
      "types": [
        {"name": "User", "fields": [{"name": "email"}]},
        {"name": "Admin", "fields": [{"name": "role"}]}
      ]
    }
  }
}
```

**Remediation**:
```javascript
const { ApolloServer } = require('apollo-server');
const server = new ApolloServer({ schema, introspection: false });
```

### **Test 2: GraphQL Broken Object-Level Authorization**

**Objective**: Test if users can access unauthorized objects.

**Steps**:
1. **Obtain User Token**:
   - Log in as a regular user to get a JWT (`user_token`).
2. **Set Up Postman**:
   - Create request: `POST http://example.com/graphql`.
   - Add header: `Authorization: Bearer user_token`.
3. **Send Query**:
   - Query:
     ```graphql
     query {
       user(id: 999) {
         email
       }
     }
     ```
   - Command: In Postman, set GraphQL query and send.
4. **Analyze Response**:
   - Check for HTTP 403 or data exposure.
   - Expected secure response: `Unauthorized`.
5. **Save Results**:
   - Export request and response.

**Command**:
```bash
curl -X POST -H "Content-Type: application/json" -H "Authorization: Bearer user_token" --data '{"query": "query { user(id: 999) { email } }"}' http://example.com/graphql
```

**Example Vulnerable Response**:
```json
{
  "data": {
    "user": {
      "email": "admin@example.com"
    }
  }
}
```

**Remediation**:
```javascript
const resolvers = {
  Query: {
    user: (parent, { id }, { user }) => {
      if (user.id !== id) throw new Error('Unauthorized');
      return db.getUser(id);
    }
  }
};
```

### **Test 3: GraphQL Deep Query DoS**

**Objective**: Test for resource exhaustion via nested queries.

**Steps**:
1. **Craft Deep Query**:
   - Create:
     ```graphql
     query {
       users {
         posts {
           comments {
             author {
               posts {
                 comments {
                   id
                 }
               }
             }
           }
         }
       }
     }
     ```
2. **Send Query with cURL**:
   - Command:
     ```bash
     curl -X POST -H "Content-Type: application/json" -H "Authorization: Bearer abc123" --data '{"query": "query { users { posts { comments { author { posts { comments { id } } } } } } }"}' http://example.com/graphql
     ```
3. **Flood Server**:
   - Command:
     ```bash
     for i in {1..10}; do curl -X POST -H "Content-Type: application/json" --data '{"query": "query { users { posts { comments { author { posts { id } } } } } }"}' http://example.com/graphql; done
     ```
4. **Analyze Response**:
   - Check for timeouts, HTTP 429, or server errors.
   - Expected secure response: Query rejected.
5. **Save Results**:
   - Save responses to file.

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
[Large JSON response]
```

**Remediation**:
```javascript
const depthLimit = require('graphql-depth-limit');
const server = new ApolloServer({ schema, validationRules: [depthLimit(5)] });
```

### **Test 4: REST SQL Injection**

**Objective**: Test REST endpoints for SQL injection.

**Steps**:
1. **Identify Endpoint**:
   - Use Burp Suite to find `GET /api/users?name=test`.
2. **Set Up OWASP ZAP**:
   - Configure proxy (127.0.0.1:8080).
   - Import endpoint.
3. **Fuzz Parameters**:
   - Command:
     ```
     Sites tab -> Right-click GET http://example.com/api/users?name=test -> Attack -> Fuzzer -> Add Payloads: ' OR 1=1 -- -> Start Fuzzer
     ```
4. **Manual Test with cURL**:
   - Command:
     ```bash
     curl -X GET "http://example.com/api/users?name=admin%27%20OR%201=1--"
     ```
5. **Analyze Response**:
   - Check for SQL errors or data exposure.
   - Expected secure response: HTTP 400.
6. **Save Results**:
   - Save ZAP alerts and cURL output.

**Example Vulnerable Response**:
```
HTTP/1.1 500 Internal Server Error
Error: SQL syntax error near 'OR 1=1'
```

**Remediation**:
```python
from flask import Flask, request
app = Flask(__name__)
@app.route('/api/users')
def users():
    name = request.args.get('name')
    if not re.match(r'^[a-zA-Z0-9]+$', name):
        return jsonify({'error': 'Invalid input'}), 400
    return jsonify(db.query('SELECT * FROM users WHERE name = %s', (name,)))
```

### **Test 5: REST Excessive Data Exposure**

**Objective**: Check if REST endpoints expose sensitive data.

**Steps**:
1. **Set Up Postman**:
   - Create request: `GET http://example.com/api/users`.
   - Add header: `Authorization: Bearer user_token`.
2. **Send Request**:
   - Command: In Postman, send request.
3. **Analyze Response**:
   - Check for sensitive fields (e.g., `password`, `ssn`).
   - Expected secure response: Minimal data.
4. **Save Results**:
   - Export response.

**Command**:
```bash
curl -X GET -H "Authorization: Bearer user_token" http://example.com/api/users
```

**Example Vulnerable Response**:
```json
[
  {"id": 1, "email": "user@example.com", "password": "hashed_password"}
]
```

**Remediation**:
```javascript
const resolvers = {
  User: {
    password: () => null
  }
};
```

### **Test 6: API Broken Authentication**

**Objective**: Test if endpoints are accessible without authentication.

**Steps**:
1. **Set Up Burp Suite**:
   - Capture request to `POST /api/secure`.
2. **Test Without Token**:
   - Command:
     ```
     Intruder -> Select POST /api/secure -> Clear § -> Select Authorization header -> Payloads: None -> Start Attack
     ```
3. **Manual Test with cURL**:
   - Command:
     ```bash
     curl -X POST http://example.com/api/secure
     ```
4. **Analyze Response**:
   - Check for HTTP 401.
   - Expected secure response: `Unauthorized`.
5. **Save Results**:
   - Save Burp Intruder results.

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
{"data": "sensitive"}
```

**Remediation**:
```javascript
const jwt = require('jsonwebtoken');
app.use((req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  jwt.verify(token, 'secret', (err) => {
    if (err) res.status(401).send('Invalid token');
    else next();
  });
});
```

### **Test 7: GraphQL Batch Query Abuse**

**Objective**: Test for resource exhaustion via batched queries (WSTG-APIT-01).

**Steps**:
1. **Craft Batch Query**:
   - Create:
     ```graphql
     [
       {"query": "query { users { id } }"},
       {"query": "query { posts { id } }"},
       {"query": "query { comments { id } }"}
     ]
     ```
2. **Send with cURL**:
   - Command:
     ```bash
     curl -X POST -H "Content-Type: application/json" -H "Authorization: Bearer abc123" --data '[{"query": "query { users { id } }"}, {"query": "query { posts { id } }"}, {"query": "query { comments { id } }"}]' http://example.com/graphql
     ```
3. **Analyze Response**:
   - Check for HTTP 429 or delays.
   - Expected secure response: Batch limit enforced.
4. **Save Results**:
   - Save response.

**Remediation**:
```javascript
const { ApolloServer } = require('apollo-server');
const server = new ApolloServer({
  schema,
  validationRules: [batchLimit(10)]
});
```

### **Test 8: API SSRF**

**Objective**: Test for Server-Side Request Forgery.

**Steps**:
1. **Identify Endpoint**:
   - Find `POST /api/fetch` in Burp Suite.
2. **Test SSRF**:
   - Command:
     ```bash
     curl -X POST -H "Content-Type: application/json" -H "Authorization: Bearer abc123" --data '{"url": "http://internal.example.com/secret"}' http://example.com/api/fetch
     ```
3. **Analyze Response**:
   - Check for internal data exposure.
   - Expected secure response: HTTP 400.
4. **Save Results**:
   - Save response.

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
{"data": "Internal secret"}
```

**Remediation**:
```php
$allowed = ['example.com'];
if (!in_array(parse_url($url, PHP_URL_HOST), $allowed)) {
  die('Invalid URL');
}
```

## **Additional Tips**

- **Cover All Endpoints**: Test GraphQL, REST, and SOAP endpoints comprehensively.
- **Automate Repetitive Tests**: Use Python scripts for fuzzing and access control tests.
- **Gray-Box Testing**: Use API documentation to identify hidden endpoints.
- **Ethical Testing**: Obtain permission for active testing to avoid disruptions.
- **References**: [OWASP API Security Top 10](https://owasp.org/www-project-api-security/), [GraphQL Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html).