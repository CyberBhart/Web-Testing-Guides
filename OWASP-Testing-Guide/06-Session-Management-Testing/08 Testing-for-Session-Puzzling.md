# **Testing for Session Puzzling**

## **Overview**

Testing for Session Puzzling (WSTG-SESS-08), also known as session variable overloading, involves assessing a web application to ensure that session variables are securely managed and cannot be manipulated to bypass authentication or authorization controls. According to OWASP, session puzzling vulnerabilities allow attackers to confuse the application’s session management logic, potentially escalating privileges or accessing unauthorized resources. This test focuses on verifying proper session variable handling, input validation, and access control to mitigate session manipulation risks.

**Impact**: Session puzzling vulnerabilities can lead to:
- Unauthorized access by impersonating other users or roles (e.g., escalating to admin).
- Authentication or authorization bypass through manipulated session variables.
- Application logic errors causing privilege escalation or data exposure.
- Compromise of sensitive functionality controlled by session variables.

This guide provides a practical, hands-on methodology for testing session puzzling, adhering to OWASP’s WSTG-SESS-08, with detailed tool setups, at least two specific commands or configurations per tool, real-world test cases, remediation strategies, and ethical considerations for professional penetration testing.

## **Testing Tools**

The following tools are recommended for testing session puzzling, with at least two specific commands or configurations per tool for real security testing:

- **Burp Suite Community Edition**: Intercepts and manipulates session variables in requests.
- **Postman**: Tests API endpoints for session variable tampering.
- **cURL**: Sends crafted requests to test session variable behavior.
- **Browser Developer Tools**: Inspects client-side session variables in cookies, forms, or JavaScript.
- **Python Requests Library**: Automates session variable manipulation and testing.

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

This methodology follows OWASP’s black-box approach for WSTG-SESS-08, focusing on identifying session variables, testing variable overloading, authentication/authorization bypass, variable scope, and input validation.

### **1. Identify and Manipulate Session Variables with Burp Suite**

Map session variables and test for manipulation to alter user roles or states.

**Steps**:
1. **Configure Burp Suite**:
   - Set up browser proxy (127.0.0.1:8080).
   - Add `example.com` to the target scope in the “Target” tab.
2. **Identify Session Variables**:
   - Navigate the application (e.g., login, dashboard) and check “HTTP History” for session variables in cookies (e.g., `role=guest`), headers, or parameters.
3. **Manipulate Variables**:
   - Intercept a request to a protected resource (e.g., `GET /admin`) and modify session variables (e.g., change `role=guest` to `role=admin`).
   - Send the modified request and check if access is granted.
4. **Analyze Findings**:
   - Vulnerable: Modified variable grants unauthorized access.
   - Expected secure response: HTTP 403 or redirect to login.
5. **Document Findings**:
   - Save requests and responses in Burp Suite’s “Logger”.

**Burp Suite Commands**:
- **Command 1**: Identify session variables:
  ```
  HTTP History -> Select GET /dashboard -> Request tab -> Look for Cookie: role=guest or user_id=123
  ```
- **Command 2**: Manipulate session variable:
  ```
  HTTP History -> Select GET /admin -> Send to Repeater -> Change Cookie: role=guest to role=admin -> Click Send -> Check response
  ```

**Example Vulnerable Response**:
```
[Modified Cookie: role=admin]
HTTP/1.1 200 OK
Content-Type: text/html
Admin Dashboard
```

**Remediation**:
- Validate session variables server-side:
  ```javascript
  app.get('/admin', (req, res) => {
      if (req.session.role !== 'admin') {
          return res.status(403).json({ error: 'Unauthorized' });
      }
      res.send('Admin Dashboard');
  });
  ```

### **2. Test Authentication Bypass with Postman**

Check if session variables can bypass authentication workflows.

**Steps**:
1. **Identify Authentication Endpoint**:
   - Use Burp Suite to find `POST /login` and import into Postman.
2. **Manipulate Session Variables**:
   - Send a request to a protected resource (e.g., `/dashboard`) with a forged session variable (e.g., `isAuthenticated=true`).
   - Omit the login step to simulate bypass.
3. **Analyze Responses**:
   - Check if the request succeeds without authentication.
   - Vulnerable: Access granted with forged variable.
   - Expected secure response: HTTP 401 or 403.
4. **Document Findings**:
   - Save Postman requests and responses.

**Postman Commands**:
- **Command 1**: Test with forged variable:
  ```
  New Request -> GET http://example.com/dashboard -> Headers: Cookie: isAuthenticated=true -> Send
  ```
- **Command 2**: Check login response for variables:
  ```
  New Request -> POST http://example.com/login -> Body -> JSON: {"username": "test", "password": "Secure123"} -> Send -> Check Set-Cookie
  ```

**Example Vulnerable Response**:
```
[Cookie: isAuthenticated=true]
HTTP/1.1 200 OK
{"data": "Dashboard"}
```

**Remediation**:
- Avoid client-controlled authentication states:
  ```python
  from flask import Flask, session
  app = Flask(__name__)
  @app.get('/dashboard')
  def dashboard():
      if not session.get('user_id'):
          return jsonify({'error': 'Unauthorized'}), 401
      return jsonify({'data': 'Dashboard'})
  ```

### **3. Test Authorization Bypass with cURL**

Verify if session variables can grant access to restricted resources.

**Steps**:
1. **Identify Restricted Endpoint**:
   - Use Burp Suite to find endpoints like `/admin-panel`.
2. **Manipulate Session Variables**:
   - Send a request with a modified session variable (e.g., `user_role=admin`) to the restricted endpoint.
   - Check if access is granted.
3. **Analyze Responses**:
   - Vulnerable: HTTP 200 with restricted content.
   - Expected secure response: HTTP 403 or redirect.
4. **Document Findings**:
   - Save cURL commands and responses.

**cURL Commands**:
- **Command 1**: Test with default role:
  ```bash
  curl -i -b "user_role=guest" http://example.com/admin-panel
  ```
- **Command 2**: Test with manipulated role:
  ```bash
  curl -i -b "user_role=admin" http://example.com/admin-panel
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: text/html
Admin Panel
```

**Remediation**:
- Enforce server-side authorization:
  ```javascript
  app.get('/admin-panel', (req, res) => {
      if (!req.session.user || req.session.user.role !== 'admin') {
          return res.status(403).json({ error: 'Forbidden' });
      }
      res.send('Admin Panel');
  });
  ```

### **4. Inspect Client-Side Session Variables with Browser Developer Tools**

Analyze client-side code for exposed session variables that can be manipulated.

**Steps**:
1. **Open Browser Developer Tools**:
   - Load `https://example.com` and press `F12` in Chrome/Firefox.
2. **Inspect Forms and JavaScript**:
   - Go to “Elements” tab and search for hidden fields (e.g., `<input name="user_id" value="123">`).
   - Go to “Sources” tab and search for session variables in JavaScript (e.g., `var role = "guest";`).
3. **Manipulate Variables**:
   - Edit hidden fields or JavaScript variables (e.g., change `user_id=123` to `user_id=456`) and submit a request.
   - Check if the manipulated value is accepted.
4. **Analyze Findings**:
   - Vulnerable: Manipulated variable grants unauthorized access.
   - Expected secure response: Server rejects tampered values.
5. **Document Findings**:
   - Save screenshots and code snippets.

**Browser Developer Tools Commands**:
- **Command 1**: Search for session variables:
  ```
  Elements tab -> Ctrl+F -> Search for "user_id" or "role" -> Check hidden fields
  ```
- **Command 2**: Manipulate hidden field:
  ```
  Elements tab -> Edit <input name="user_id" value="123"> to value="456" -> Submit form -> Check Network tab response
  ```

**Example Vulnerable Form**:
```html
<form action="/update-profile" method="POST">
    <input type="hidden" name="user_id" value="123">
    <input type="text" name="name" value="test">
    <input type="submit">
</form>
```

**Remediation**:
- Avoid client-side session variables:
  ```python
  @app.post('/update-profile')
  def update_profile():
      user_id = session.get('user_id')
      if not user_id or user_id != request.form.get('user_id'):
          return jsonify({'error': 'Invalid user'}), 403
      return jsonify({'status': 'success'})
  ```

### **5. Automate Session Puzzling Testing with Python Requests**

Automate testing to detect session variable manipulation vulnerabilities.

**Steps**:
1. **Write Python Script**:
   - Create a script to manipulate session variables:
     ```python
     import requests

     base_url = 'http://example.com'
     login_url = f'{base_url}/login'
     admin_url = f'{base_url}/admin-panel'

     # Log in as regular user
     session = requests.Session()
     login_data = {'username': 'test', 'password': 'Secure123'}
     response = session.post(login_url, data=login_data)
     session_cookie = session.cookies.get_dict()
     print(f"Session cookies: {session_cookie}")

     # Test role manipulation
     manipulated_cookies = session_cookie.copy()
     manipulated_cookies['role'] = 'admin'
     response = session.get(admin_url, cookies=manipulated_cookies)
     print(f"Role manipulation: Status={response.status_code}, Response={response.text[:100]}")
     if response.status_code == 200 and 'admin' in response.text.lower():
         print("Vulnerable: Role manipulation granted admin access")

     # Test authentication bypass
     bypass_cookies = session_cookie.copy()
     bypass_cookies['isAuthenticated'] = 'true'
     response = session.get(admin_url, cookies=bypass_cookies)
     print(f"Auth bypass: Status={response.status_code}, Response={response.text[:100]}")
     if response.status_code == 200 and 'admin' in response.text.lower():
         print("Vulnerable: Authentication bypass succeeded")
     ```
2. **Run Script**:
   - Execute: `python3 test_session_puzzling.py`.
   - Analyze output for successful manipulation.
3. **Verify Findings**:
   - Vulnerable: Manipulated variables grant access.
   - Expected secure response: HTTP 403 or 401 for invalid variables.
4. **Document Results**:
   - Save script output.

**Python Commands**:
- **Command 1**: Run puzzling test:
  ```bash
  python3 test_session_puzzling.py
  ```
- **Command 2**: Test single manipulation:
  ```bash
  python3 -c "import requests; s=requests.Session(); s.post('http://example.com/login', data={'username': 'test', 'password': 'Secure123'}); r=s.get('http://example.com/admin-panel', cookies={'role': 'admin'}); print(r.status_code, r.text[:100])"
  ```

**Example Vulnerable Output**:
```
Session cookies: {'session': 'abc123', 'role': 'guest'}
Role manipulation: Status=200, Response=Admin Panel
Vulnerable: Role manipulation granted admin access
```

**Remediation**:
- Secure session management:
  ```python
  from flask import Flask, session
  app = Flask(__name__)
  @app.get('/admin-panel')
  def admin_panel():
      if session.get('role') != 'admin' or not validate_session(session):
          return jsonify({'error': 'Unauthorized'}), 403
      return jsonify({'data': 'Admin Panel'})
  ```

## **Real-World Test Cases**

These test cases extend OWASP’s WSTG-SESS-08 with practical scenarios based on common session puzzling vulnerabilities observed in penetration testing.

### **Test 1: Role Manipulation**

**Objective**: Verify that session variables cannot escalate privileges.

**Steps**:
1. **Capture Session**:
   - Use Burp Suite to intercept login.
   - Command:
     ```
     HTTP History -> Select POST /login -> Request tab -> Note Cookie: role=guest
     ```
2. **Manipulate Role**:
   - Command:
     ```
     HTTP History -> Select GET /admin -> Send to Repeater -> Change Cookie: role=guest to role=admin -> Click Send
     ```
3. **Analyze Response**:
   - Check if admin access is granted.
   - Expected secure response: HTTP 403.
4. **Save Results**:
   - Save Burp Suite outputs.

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Admin Dashboard
```

**Remediation**:
```javascript
if (req.session.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden' });
}
```

### **Test 2: Authentication Bypass**

**Objective**: Ensure session variables cannot bypass authentication.

**Steps**:
1. **Test Forged Variable**:
   - Use Postman to send request.
   - Command:
     ```
     New Request -> GET http://example.com/dashboard -> Headers: Cookie: isAuthenticated=true -> Send
     ```
2. **Analyze Response**:
   - Check if dashboard is accessible.
   - Expected secure response: HTTP 401.
3. **Save Results**:
   - Save Postman outputs.

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
{"data": "Dashboard"}
```

**Remediation**:
```python
if not session.get('user_id'):
    return jsonify({'error': 'Unauthorized'}), 401
```

### **Test 3: Hidden Field Manipulation**

**Objective**: Verify that hidden form fields cannot be tampered with.

**Steps**:
1. **Inspect Form**:
   - Use Browser Developer Tools:
     ```
     Elements tab -> Ctrl+F -> Search for "user_id" -> Check hidden fields
     ```
2. **Manipulate Field**:
   - Command:
     ```
     Elements tab -> Edit <input name="user_id" value="123"> to value="456" -> Submit form
     ```
3. **Analyze Response**:
   - Check if another user’s data is accessed.
   - Expected secure response: HTTP 403.
4. **Save Results**:
   - Save screenshots.

**Example Vulnerable Form**:
```html
<input type="hidden" name="user_id" value="123">
```

**Remediation**:
```python
if session['user_id'] != request.form['user_id']:
    return jsonify({'error': 'Invalid user'}), 403
```

### **Test 4: Shared Session Variables**

**Objective**: Ensure session variables are unique per user.

**Steps**:
1. **Test Multiple Users**:
   - Use cURL to log in as two users.
   - Command:
     ```
     curl -i -c user1.txt -X POST -d "username=user1&password=Secure123" http://example.com/login
     curl -i -c user2.txt -X POST -d "username=user2&password=Secure123" http://example.com/login
     ```
2. **Manipulate Shared Variable**:
   - Command:
     ```
     curl -i -b user1.txt -b "user_id=456" http://example.com/dashboard
     ```
3. **Analyze Response**:
   - Check if user2’s data is accessed.
   - Expected secure response: HTTP 403.
4. **Save Results**:
   - Save cURL outputs.

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
User2 Dashboard
```

**Remediation**:
```javascript
if (req.session.userId !== req.cookies.user_id) {
    return res.status(403).json({ error: 'Invalid session' });
}
```

## **Additional Tips**

- **Test All Workflows**: Check session variables in authentication, authorization, and state-changing actions.
- **Combine Tools**: Use Burp Suite for manipulation, Postman for APIs, and Python for automation.
- **Gray-Box Testing**: If source code is available, review session variable handling logic.
- **Document Thoroughly**: Save all commands, responses, and screenshots in a report.
- **Ethical Considerations**: Obtain explicit permission for testing, as session manipulation may disrupt user sessions or trigger security alerts.
- **References**: [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html), [OWASP Authorization Testing](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/05-Authorization_Testing/).