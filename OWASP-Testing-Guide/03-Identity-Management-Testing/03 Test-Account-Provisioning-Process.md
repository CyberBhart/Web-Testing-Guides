# **Test Account Provisioning Process**

## **Overview**

Testing the Account Provisioning Process (WSTG-IDNT-03) involves assessing a web application’s mechanisms for creating, modifying, suspending, and deleting user accounts to ensure they are secure, restricted to authorized roles, and properly audited. According to OWASP, weaknesses in account provisioning can allow attackers to create unauthorized accounts, escalate privileges, or maintain access to deactivated accounts, compromising system security and integrity. This test focuses on validating access controls, input handling, role assignments, account deactivation, and logging during the account lifecycle to identify vulnerabilities that could lead to unauthorized access or privilege escalation.

**Impact**: Weaknesses in the account provisioning process can lead to:
- Unauthorized account creation or modification with elevated privileges (e.g., admin access).
- Continued access by deactivated or deleted accounts due to incomplete suspension.
- Privilege escalation through parameter tampering or lack of access controls.
- Data integrity issues or regulatory non-compliance from unaudited provisioning actions.

This guide provides a practical, hands-on methodology for testing the account provisioning process, adhering to OWASP’s WSTG-IDNT-03, with detailed tool setups, at least two specific commands or configurations per tool, real-world test cases, remediation strategies, and ethical considerations for professional penetration testing.

## **Testing Tools**

The following tools are recommended for testing the account provisioning process, with at least two specific commands or configurations per tool for real security testing:

- **Burp Suite Community Edition**: Intercepts and manipulates provisioning requests to test access controls and parameter tampering.
- **Postman**: Tests API endpoints for provisioning vulnerabilities, such as unauthorized account creation or modification.
- **cURL**: Sends crafted requests to verify provisioning restrictions and error handling.
- **Browser Developer Tools**: Inspects client-side interfaces for provisioning controls or exposed parameters.
- **Python Requests Library**: Automates tests for provisioning endpoints, rate limiting, and session validation.

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
5. **Python Requests Library**:
   - Install Python: `sudo apt install python3`.
   - Install Requests: `pip install requests`.
   - Verify: `python3 -c "import requests; print(requests.__version__)"`.

## **Testing Methodology**

This methodology follows OWASP’s black-box approach for WSTG-IDNT-03, focusing on testing account creation, modification, deletion, input validation, access controls, and auditing in the provisioning process.

### **1. Test Unauthorized Account Creation with Burp Suite**

Verify that only authorized roles can create accounts and that new accounts have appropriate privileges.

**Steps**:
1. **Configure Burp Suite**:
   - Set up browser proxy (127.0.0.1:8080).
   - Add `example.com` to the target scope in the “Target” tab.
2. **Capture Creation Request**:
   - Log in as a low-privilege user (e.g., User) or unauthenticated user.
   - Attempt to access account creation endpoints (e.g., `/admin/users/create`).
   - Check “HTTP History” for POST requests.
3. **Manipulate Parameters**:
   - Modify role or privilege parameters (e.g., `role=admin`, `is_admin=true`).
   - Submit the request with valid user data.
4. **Analyze Responses**:
   - Check for HTTP 200 (success) or account creation with elevated privileges.
   - Expected secure response: HTTP 403 (forbidden) or 401 (unauthorized).
5. **Document Findings**:
   - Save requests and responses in Burp Suite’s “Logger”.

**Burp Suite Commands**:
- **Command 1**: Test unauthorized account creation:
  ```
  HTTP History -> Select POST /admin/users/create -> Send to Repeater -> Set Cookie: session=user_token -> Click Send -> Check response
  ```
- **Command 2**: Manipulate role parameter:
  ```
  HTTP History -> Select POST /admin/users/create -> Send to Repeater -> Change JSON: {"email": "test@example.com", "password": "Secure123"} to {"email": "test@example.com", "password": "Secure123", "role": "admin"} -> Click Send
  ```

**Example Vulnerable Response**:
```json
{
  "status": "success",
  "role": "admin"
}
```

**Remediation**:
- Restrict account creation to admins:
  ```javascript
  app.post('/admin/users/create', (req, res) => {
      if (req.user.role !== 'admin') {
          return res.status(403).json({ error: 'Unauthorized' });
      }
      // Create user with default role: user
      res.json({ status: 'success', role: 'user' });
  });
  ```

### **2. Test Account Modification with Postman**

Check if users can modify their own or others’ account attributes (e.g., role, email) without authorization.

**Steps**:
1. **Identify Modification Endpoint**:
   - Use Burp Suite to find endpoints (e.g., `POST /api/users/update`).
   - Import into Postman.
2. **Test Unauthorized Modifications**:
   - Authenticate as a low-privilege user and attempt to change role or sensitive fields (e.g., `role=admin`, `email=admin@example.com`).
   - Try modifying another user’s account by changing `user_id`.
3. **Analyze Responses**:
   - Check for HTTP 200 or successful modification.
   - Expected secure response: HTTP 403 or 401.
4. **Document Findings**:
   - Save Postman requests and responses.

**Postman Commands**:
- **Command 1**: Test role modification:
  ```
  New Request -> POST http://example.com/api/users/update -> Body -> JSON: {"user_id": 123, "role": "admin"} -> Headers: Authorization: Bearer user_token -> Send
  ```
- **Command 2**: Test another user’s account:
  ```
  New Request -> POST http://example.com/api/users/update -> Body -> JSON: {"user_id": 456, "email": "hacked@example.com"} -> Headers: Authorization: Bearer user_token -> Send
  ```

**Example Vulnerable Response**:
```json
{
  "status": "success",
  "role": "admin"
}
```

**Remediation**:
- Validate user permissions and IDs:
  ```python
  @app.post('/api/users/update')
  def update_user():
      user_id = request.json['user_id']
      if request.user.role != 'admin' or user_id != request.user.id:
          return jsonify({'error': 'Unauthorized'}), 403
      return jsonify({'status': 'success'})
  ```

### **3. Test Account Deletion with cURL**

Verify that deleted or suspended accounts cannot access the system.

**Steps**:
1. **Identify Deletion Endpoint**:
   - Use Burp Suite to find `POST /api/users/delete` or similar.
2. **Test Deletion**:
   - Authenticate as a user and attempt to delete own or another user’s account.
   - Log in with the deleted account’s credentials to check access.
3. **Analyze Responses**:
   - Check if deletion succeeds (HTTP 200) and if the account is fully deactivated.
   - Expected secure response: HTTP 403 for unauthorized deletion; no access post-deletion.
4. **Document Findings**:
   - Save cURL commands and responses.

**cURL Commands**:
- **Command 1**: Test unauthorized deletion:
  ```bash
  curl -i -X POST -b "session=user_token" -d "user_id=456" http://example.com/api/users/delete
  ```
- **Command 2**: Test login post-deletion:
  ```bash
  curl -i -X POST -d "email=test@example.com&password=Secure123" http://example.com/login
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
{"status": "Account deleted"}

[Post-deletion login]
HTTP/1.1 200 OK
{"status": "Logged in"}
```

**Remediation**:
- Invalidate sessions on deletion:
  ```javascript
  app.post('/api/users/delete', (req, res) => {
      if (req.user.role !== 'admin') {
          return res.status(403).json({ error: 'Unauthorized' });
      }
      // Delete user and invalidate sessions
      req.session.destroy();
      res.json({ status: 'success' });
  });
  ```

### **4. Inspect Provisioning Interface with Browser Developer Tools**

Analyze client-side interfaces for exposed provisioning controls or parameters.

**Steps**:
1. **Open Browser Developer Tools**:
   - Load `https://example.com/admin/users` and press `F12` in Chrome/Firefox.
2. **Inspect Forms and Scripts**:
   - Check for hidden fields (e.g., `<input type="hidden" name="role">`) or JavaScript handling provisioning.
   - Search for client-side validation of roles or permissions.
3. **Test Manipulation**:
   - Modify hidden fields (e.g., change `role=user` to `role=admin`) or enable disabled buttons.
   - Submit the form to check server-side enforcement.
4. **Analyze Responses**:
   - Check if client-side changes grant unauthorized access.
   - Expected secure response: Server-side denial.
5. **Document Findings**:
   - Save screenshots and network logs.

**Browser Developer Tools Commands**:
- **Command 1**: Inspect hidden role field:
  ```
  Elements tab -> Find <input type="hidden" name="role" value="user"> -> Edit as HTML -> Change value="admin" -> Submit form
  ```
- **Command 2**: Enable disabled button:
  ```
  Elements tab -> Find <button class="create-user" disabled> -> Edit as HTML -> Remove disabled -> Click button
  ```

**Example Vulnerable Form**:
```html
<form action="/admin/users/create">
    <input type="hidden" name="role" value="admin">
    <input type="email" name="email">
    <button type="submit">Create</button>
</form>
```

**Remediation**:
- Validate inputs server-side:
  ```php
  if ($_POST['role'] && $_SESSION['user_role'] !== 'admin') {
      die(json_encode(['error' => 'Unauthorized']));
  }
  ```

### **5. Test Rate Limiting with Python Requests**

Attempt automated provisioning actions to verify rate limiting or anti-automation controls.

**Steps**:
1. **Write Python Script**:
   - Create a script to send multiple account creation requests:
     ```python
     import requests
     import time

     url = 'http://example.com/api/users/create'
     headers = {'Authorization': 'Bearer user_token'}
     for i in range(5):
         data = {
             'email': f'test{i}@example.com',
             'password': 'Secure123',
             'role': 'user'
         }
         response = requests.post(url, json=data, headers=headers)
         print(f"Attempt {i+1}: Status={response.status_code}, Response={response.text[:100]}")
         if response.status_code == 429:
             print("Rate limiting detected")
             break
         time.sleep(1)
     ```
2. **Run Script**:
   - Execute: `python3 test_provisioning.py`.
   - Analyze responses for rate limits (HTTP 429) or errors.
3. **Verify Findings**:
   - Check if accounts are created without restrictions.
   - Expected secure response: Rate limiting enforced.
4. **Document Results**:
   - Save script output.

**Python Commands**:
- **Command 1**: Run provisioning test:
  ```bash
  python3 test_provisioning.py
  ```
- **Command 2**: Test single creation:
  ```bash
  python3 -c "import requests; r=requests.post('http://example.com/api/users/create', json={'email': 'test@example.com', 'password': 'Secure123'}, headers={'Authorization': 'Bearer user_token'}); print(r.status_code, r.text[:100])"
  ```

**Example Vulnerable Output**:
```
Attempt 1: Status=200, Response={"status": "success"}
Attempt 5: Status=200, Response={"status": "success"}
```

**Remediation**:
- Implement rate limiting:
  ```python
  from flask_limiter import Limiter
  limiter = Limiter(app, key_func=lambda: request.remote_addr)
  @app.route('/api/users/create', methods=['POST'])
  @limiter.limit('5 per hour')
  def create_user():
      return jsonify({'status': 'success'})
  ```

## **Real-World Test Cases**

These test cases extend OWASP’s WSTG-IDNT-03 with practical scenarios based on common account provisioning vulnerabilities observed in penetration testing.

### **Test 1: Unauthorized Account Creation**

**Objective**: Verify if a low-privilege user can create accounts.

**Steps**:
1. **Authenticate as User**:
   - Log in as a regular user and capture session token in Burp Suite.
   - Command:
     ```
     HTTP History -> Select POST /login -> Copy Cookie: session=user_token
     ```
2. **Test Creation Endpoint**:
   - Command:
     ```bash
     curl -i -b "session=user_token" -X POST -d "email=test@example.com&password=Secure123&role=admin" http://example.com/api/users/create
     ```
3. **Analyze Response**:
   - Check for HTTP 200 or admin account creation.
   - Expected secure response: HTTP 403.
4. **Save Results**:
   - Save cURL and Burp Suite outputs.

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
{"status": "success", "role": "admin"}
```

**Remediation**:
```javascript
app.post('/api/users/create', (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Unauthorized' });
    }
    // Create user
});
```

### **Test 2: Unauthorized Role Modification**

**Objective**: Test if a user can modify their role or others’ accounts.

**Steps**:
1. **Capture Request**:
   - Use Burp Suite to intercept `POST /api/users/update`.
   - Command:
     ```
     HTTP History -> Select POST /api/users/update -> Send to Repeater
     ```
2. **Modify Role**:
   - Command:
     ```
     Repeater -> Change JSON: {"user_id": 123, "email": "test@example.com"} to {"user_id": 123, "role": "admin"} -> Click Send
     ```
3. **Analyze Response**:
   - Check for successful modification.
   - Expected secure response: HTTP 403.
4. **Save Results**:
   - Save Burp Suite outputs.

**Example Vulnerable Response**:
```json
{
  "status": "success",
  "role": "admin"
}
```

**Remediation**:
```python
@app.post('/api/users/update')
def update_user():
    if request.json['role'] or request.json['user_id'] != request.user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    return jsonify({'status': 'success'})
```

### **Test 3: Incomplete Account Deletion**

**Objective**: Verify that deleted accounts cannot access the system.

**Steps**:
1. **Delete Account**:
   - Use Postman to send a deletion request.
   - Command:
     ```
     New Request -> POST http://example.com/api/users/delete -> Body -> JSON: {"user_id": 123} -> Headers: Authorization: Bearer user_token -> Send
     ```
2. **Test Login**:
   - Command:
     ```bash
     curl -i -X POST -d "email=test@example.com&password=Secure123" http://example.com/login
     ```
3. **Analyze Response**:
   - Check if login succeeds post-deletion.
   - Expected secure response: HTTP 401.
4. **Save Results**:
   - Save Postman and cURL outputs.

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
{"status": "Logged in"}
```

**Remediation**:
```javascript
app.post('/api/users/delete', (req, res) => {
    // Delete user from database
    // Invalidate all sessions
    req.session.destroy();
    res.json({ status: 'success' });
});
```

### **Test 4: Client-Side Provisioning Controls**

**Objective**: Detect client-side provisioning controls that can be bypassed.

**Steps**:
1. **Inspect Interface**:
   - Use Browser Developer Tools to check for provisioning forms.
   - Command:
     ```
     Elements tab -> Find <input type="hidden" name="role" value="user"> -> Edit as HTML -> Change value="admin" -> Submit form
     ```
2. **Test Submission**:
   - Submit the modified form and check response.
   - Command:
     ```
     Network tab -> Select POST /admin/users/create -> Check response
     ```
3. **Analyze Response**:
   - Check if admin account is created.
   - Expected secure response: Server-side denial.
4. **Save Results**:
   - Save screenshots.

**Example Vulnerable Form**:
```html
<input type="hidden" name="role" value="admin">
```

**Remediation**:
```php
if ($_POST['role'] && $_SESSION['user_role'] !== 'admin') {
    die(json_encode(['error' => 'Unauthorized']));
}
```

## **Additional Tips**

- **Test All Endpoints**: Check creation, update, and deletion endpoints for all user types.
- **Combine Tools**: Use Burp Suite for manual testing, Postman for APIs, and Python for automation.
- **Gray-Box Testing**: If logs are accessible, verify auditing of provisioning actions.
- **Document Thoroughly**: Save all commands, responses, and screenshots in a report.
- **Ethical Considerations**: Obtain explicit permission for testing, as provisioning tests may create or delete accounts, potentially disrupting live systems.
- **References**: [OWASP Access Control Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html), [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html).