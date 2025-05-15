# **Test Role Definitions**

## **Overview**

Testing for Role Definitions (WSTG-IDNT-01) involves assessing a web application’s role-based access control (RBAC) system to ensure that user roles are clearly defined, appropriately assigned, and strictly enforced to prevent unauthorized access or actions. According to OWASP, poorly defined or misconfigured roles can allow users to access sensitive data or functionalities beyond their privileges, violating the principle of least privilege and segregation of duties. This test focuses on identifying all roles, mapping their permissions, verifying access controls, and testing for misconfigurations or vulnerabilities that could lead to privilege escalation or unauthorized access.

**Impact**: Weak role definitions can lead to:
- Unauthorized access to sensitive data or administrative functions (e.g., a User accessing Admin features).
- Privilege escalation by exploiting overlapping or excessive permissions.
- Non-compliance with regulatory standards (e.g., GDPR, HIPAA) due to inadequate access controls.
- Operational risks from lack of segregation of duties (e.g., a user approving their own actions).

This guide provides a practical, hands-on methodology for testing role definitions, adhering to OWASP’s WSTG-IDNT-01, with detailed tool setups, at least two specific commands or configurations per tool, real-world test cases, remediation strategies, and ethical considerations for professional penetration testing.

## **Testing Tools**

The following tools are recommended for testing role definitions, with at least two specific commands or configurations per tool for real security testing:

- **Burp Suite Community Edition**: Intercepts and manipulates HTTP requests to test role-based access controls.
- **Postman**: Tests API endpoints for role enforcement and permission leaks.
- **cURL**: Sends requests with modified role parameters to test access controls.
- **Browser Developer Tools**: Inspects client-side interfaces for role information or permission indicators.
- **OWASP ZAP**: Automates detection of access control issues through scanning and fuzzing.

### **Tool Setup Instructions**

1. **Burp Suite Community Edition**:
   - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
   - Configure browser proxy: 127.0.0.1:8080 (Firefox recommended).
   - Enable “Intercept” in Proxy tab.
   - Verify: `curl -x http://127.0.0.1:8080 http://example.com`.
2. **Postman**:
   - Download from [postman.com](https://www.postman.com/downloads/).
   - Install and create a free account.
   - Verify: Open Postman and check version.
3. **cURL**:
   - Install on Linux: `sudo apt install curl`.
   - Install on Windows/Mac: Pre-installed or download from [curl.se](https://curl.se/).
   - Verify: `curl --version`.
4. **Browser Developer Tools**:
   - Access in Chrome/Firefox: Press `F12` or right-click and select “Inspect”.
   - No setup required.
5. **OWASP ZAP**:
   - Download from [zaproxy.org](https://www.zaproxy.org/download/).
   - Run: `zap.sh` (Linux) or `zap.bat` (Windows).
   - Verify: Check ZAP GUI.

## **Testing Methodology**

This methodology follows OWASP’s black-box approach for WSTG-IDNT-01, focusing on identifying roles, mapping permissions, and testing access controls to detect misconfigurations or vulnerabilities.

### **1. Identify Roles with Burp Suite**

Enumerate all roles in the application by analyzing user interfaces, API responses, and documentation.

**Steps**:
1. **Configure Burp Suite**:
   - Set up browser proxy (127.0.0.1:8080).
   - Add `example.com` to the target scope in the “Target” tab.
2. **Capture Traffic**:
   - Browse the application as different users (e.g., Admin, User) or create test accounts.
   - Check “HTTP History” for role indicators in cookies (e.g., `role=user`), parameters (e.g., `?role_id=1`), or API responses (e.g., `{"role": "admin"}`).
3. **Analyze Responses**:
   - Identify role names, IDs, or permission levels (e.g., Admin, User, Guest).
   - Note endpoints revealing role information (e.g., `/api/user/profile`).
4. **Document Findings**:
   - Save requests and responses in Burp Suite’s “Logger”.

**Burp Suite Commands**:
- **Command 1**: Capture role in API response:
  ```
  HTTP History -> Select GET /api/user/profile -> Check response for {"role": "user"} -> Save to Logger
  ```
- **Command 2**: Test role parameter:
  ```
  HTTP History -> Select GET /dashboard?role_id=1 -> Send to Repeater -> Change role_id=2 -> Click Send -> Check response
  ```

**Example Vulnerable Response**:
```json
{
  "user_id": 123,
  "role": "admin"
}
```

**Remediation**:
- Avoid exposing role details in responses:
  ```javascript
  app.get('/api/user/profile', (req, res) => {
      res.json({ user_id: req.user.id }); // Exclude role
  });
  ```

### **2. Test Role Permissions with Postman**

Map and test permissions assigned to each role by accessing restricted endpoints.

**Steps**:
1. **Identify Endpoints**:
   - Use Burp Suite to find endpoints (e.g., `/admin`, `/api/users`).
   - Import into Postman.
2. **Test Access**:
   - Authenticate as a low-privilege user (e.g., User) and attempt to access high-privilege endpoints (e.g., `/admin`).
   - Use different role credentials or tokens.
3. **Analyze Responses**:
   - Check for HTTP 200 (success) instead of 403 (forbidden) or 401 (unauthorized).
   - Look for sensitive data or functionality accessible to unauthorized roles.
4. **Document Findings**:
   - Save Postman requests and responses.

**Postman Commands**:
- **Command 1**: Test admin endpoint as a user:
  ```
  New Request -> GET http://example.com/admin -> Headers: Authorization: Bearer user_token -> Send
  ```
- **Command 2**: Test role manipulation in API:
  ```
  New Request -> POST http://example.com/api/user -> Body -> JSON: {"role": "admin"} -> Headers: Authorization: Bearer user_token -> Send
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
{"users": [{"id": 1, "name": "Admin"}]}
```

**Remediation**:
- Enforce server-side role checks:
  ```python
  from flask import Flask, request
  app = Flask(__name__)
  @app.route('/admin')
  def admin():
      if request.user.role != 'admin':
          return jsonify({'error': 'Unauthorized'}), 403
      return jsonify({'data': 'Admin content'})
  ```

### **3. Test Role Manipulation with cURL**

Attempt to manipulate role parameters or identifiers to bypass access controls.

**Steps**:
1. **Identify Role Parameters**:
   - Use Burp Suite to find role-related parameters (e.g., `role_id=1`, `role=user`).
2. **Send Modified Requests**:
   - Use cURL to alter role parameters (e.g., change `user` to `admin`).
   - Test cookies, URL parameters, or POST data.
3. **Analyze Responses**:
   - Check for successful access (HTTP 200) or sensitive data exposure.
   - Expected secure response: HTTP 403 or 401.
4. **Document Findings**:
   - Save cURL commands and responses.

**cURL Commands**:
- **Command 1**: Test role parameter manipulation:
  ```bash
  curl -i -b "session=abc123; role=user" http://example.com/admin
  ```
- **Command 2**: Modify role in POST request:
  ```bash
  curl -i -X POST -d "role=admin" http://example.com/api/user
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: text/html
Admin Dashboard
```

**Remediation**:
- Validate role assignments server-side:
  ```javascript
  app.post('/api/user', (req, res) => {
      if (req.body.role && req.user.role !== 'admin') {
          return res.status(403).json({ error: 'Cannot modify role' });
      }
      // Process request
  });
  ```

### **4. Inspect Role Indicators with Browser Developer Tools**

Analyze client-side interfaces for role information or permission leaks.

**Steps**:
1. **Open Browser Developer Tools**:
   - Load `https://example.com` and press `F12` in Chrome/Firefox.
2. **Inspect Elements**:
   - Check DOM for role indicators (e.g., `<div class="admin-panel">`).
   - Search JavaScript for role checks (e.g., `if (user.role === 'admin')`).
3. **Test Manipulation**:
   - Modify DOM or scripts to access hidden features (e.g., enable admin buttons).
   - Verify if client-side changes grant access.
4. **Analyze Findings**:
   - Client-side role enforcement indicates weak controls.
   - Expected secure response: Server-side enforcement.
5. **Document Findings**:
   - Save screenshots and script excerpts.

**Browser Developer Tools Commands**:
- **Command 1**: Search for role indicators:
  ```
  Elements tab -> Ctrl+F -> Search "role" or "admin" -> Inspect classes or attributes
  ```
- **Command 2**: Modify DOM to test access:
  ```
  Elements tab -> Find <button class="admin-only" disabled> -> Edit as HTML -> Remove disabled -> Click button
  ```

**Example Vulnerable Script**:
```javascript
if (document.cookie.includes('role=user')) {
    document.getElementById('adminPanel').style.display = 'none';
}
```

**Remediation**:
- Enforce access controls server-side:
  ```html
  <button class="admin-only" onclick="checkAccess()">Admin Action</button>
  <script>
      async function checkAccess() {
          const res = await fetch('/api/check-access');
          if (res.status !== 200) alert('Unauthorized');
      }
  </script>
  ```

### **5. Test Segregation of Duties with OWASP ZAP**

Automate testing for segregation of duties and access control issues.

**Steps**:
1. **Configure OWASP ZAP**:
   - Set proxy to 127.0.0.1:8080.
   - Import target URL (e.g., `https://example.com`).
2. **Run Active Scan**:
   - Fuzz role parameters or test endpoints with different user credentials.
   - Check for access control bypasses (e.g., User accessing Admin features).
3. **Analyze Results**:
   - Review Alerts tab for unauthorized access or privilege escalation issues.
   - Verify findings manually with Burp Suite.
4. **Document Findings**:
   - Save ZAP scan reports.

**OWASP ZAP Commands**:
- **Command 1**: Fuzz role parameter:
  ```
  Sites tab -> Right-click GET http://example.com/dashboard?role_id=1 -> Attack -> Fuzzer -> Add Payloads: admin, 2 -> Start Fuzzer -> Check Responses
  ```
- **Command 2**: Run access control scan:
  ```
  Sites tab -> Right-click https://example.com -> Attack -> Active Scan -> Enable Access Control Testing -> Start Scan
  ```

**Example Vulnerable Finding**:
- Alert: `Access Control - Unauthorized Access to /admin`.

**Remediation**:
- Implement segregation of duties:
  ```python
  @app.route('/approve')
  def approve():
      if request.user.role == 'submitter':
          return jsonify({'error': 'Cannot approve own submission'}), 403
      return jsonify({'status': 'Approved'})
  ```

## **Real-World Test Cases**

These test cases extend OWASP’s WSTG-IDNT-01 with practical scenarios based on common role definition vulnerabilities observed in penetration testing.

### **Test 1: Unauthorized Access to Admin Endpoint**

**Objective**: Verify if a low-privilege user can access admin functionality.

**Steps**:
1. **Authenticate as User**:
   - Log in as a regular user and capture session token in Burp Suite.
   - Command:
     ```
     HTTP History -> Select POST /login -> Copy Cookie: session=abc123
     ```
2. **Test Admin Endpoint**:
   - Command:
     ```bash
     curl -i -b "session=abc123" http://example.com/admin
     ```
3. **Analyze Response**:
   - Check for HTTP 200 or admin content.
   - Expected secure response: HTTP 403 or 401.
4. **Save Results**:
   - Save cURL and Burp Suite outputs.

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: text/html
Admin Dashboard
```

**Remediation**:
```javascript
app.get('/admin', (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Unauthorized' });
    }
    res.send('Admin Dashboard');
});
```

### **Test 2: Role Parameter Manipulation**

**Objective**: Test if modifying a role parameter grants unauthorized access.

**Steps**:
1. **Capture Request**:
   - Use Burp Suite to find `GET /dashboard?role_id=1`.
   - Command:
     ```
     HTTP History -> Select GET /dashboard?role_id=1 -> Send to Repeater
     ```
2. **Modify Role**:
   - Command:
     ```
     Repeater -> Change role_id=1 to role_id=2 -> Click Send
     ```
3. **Analyze Response**:
   - Check for access to restricted content.
   - Expected secure response: HTTP 403.
4. **Save Results**:
   - Save Burp Suite outputs.

**Example Vulnerable Response**:
```json
{
  "data": "Admin Dashboard"
}
```

**Remediation**:
```python
@app.route('/dashboard')
def dashboard():
    role_id = request.args.get('role_id')
    if role_id and role_id != session['role_id']:
        return jsonify({'error': 'Invalid role'}), 403
    return jsonify({'data': 'Dashboard'})
```

### **Test 3: Segregation of Duties Violation**

**Objective**: Verify if a user can perform conflicting actions (e.g., submit and approve).

**Steps**:
1. **Authenticate as User**:
   - Log in as a submitter and capture session token.
   - Command:
     ```
     HTTP History -> Select POST /login -> Copy Cookie: session=abc123
     ```
2. **Test Approval Endpoint**:
   - Command:
     ```bash
     curl -i -b "session=abc123" -X POST http://example.com/approve
     ```
3. **Analyze Response**:
   - Check for successful approval (HTTP 200).
   - Expected secure response: HTTP 403.
4. **Save Results**:
   - Save cURL and Burp Suite outputs.

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
{"status": "Approved"}
```

**Remediation**:
```javascript
app.post('/approve', (req, res) => {
    if (req.user.role === 'submitter') {
        return res.status(403).json({ error: 'Cannot approve own submission' });
    }
    // Approve action
});
```

### **Test 4: Client-Side Role Enforcement**

**Objective**: Detect client-side role checks that can be bypassed.

**Steps**:
1. **Inspect Interface**:
   - Use Browser Developer Tools to check for role-based UI elements.
   - Command:
     ```
     Elements tab -> Find <div class="admin-only" style="display:none"> -> Edit as HTML -> Change to display:block
     ```
2. **Test Access**:
   - Click modified elements or call restricted functions.
   - Command:
     ```
     Console tab -> Run: document.getElementById('adminPanel').style.display = 'block'
     ```
3. **Analyze Response**:
   - Check if client-side changes grant access.
   - Expected secure response: Server-side denial.
4. **Save Results**:
   - Save screenshots.

**Example Vulnerable Script**:
```javascript
if (user.role !== 'admin') {
    document.getElementById('adminButton').disabled = true;
}
```

**Remediation**:
```html
<button onclick="serverCheck()">Admin Action</button>
<script>
    async function serverCheck() {
        const res = await fetch('/api/admin-action', { credentials: 'include' });
        if (res.status !== 200) alert('Unauthorized');
    }
</script>
```

## **Additional Tips**

- **Map All Roles**: Test with multiple accounts (e.g., Admin, User, Guest) to understand permission boundaries.
- **Combine Tools**: Use Burp Suite for manual testing, Postman for APIs, and OWASP ZAP for automation.
- **Gray-Box Testing**: If documentation is available, review role definitions and access control policies.
- **Document Thoroughly**: Save all commands, responses, and screenshots in a report.
- **Ethical Considerations**: Obtain explicit permission for testing, as accessing restricted endpoints or manipulating roles may disrupt live systems or violate policies.
- **References**: [OWASP Access Control Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html), [OWASP RBAC Guidelines](https://owasp.org/www-community/Role_Based_Access_Control).