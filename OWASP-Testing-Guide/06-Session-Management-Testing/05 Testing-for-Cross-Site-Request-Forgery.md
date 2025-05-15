# **Testing for Cross Site Request Forgery (CSRF)**

## **Overview**

Testing for Cross Site Request Forgery (WSTG-SESS-05) involves assessing a web application to ensure that state-changing operations are protected against CSRF attacks, where attackers trick a user’s browser into performing unauthorized actions using their authenticated session. According to OWASP, CSRF vulnerabilities allow attackers to execute actions like updating profiles or transferring funds without user consent. This test focuses on verifying the presence and effectiveness of anti-CSRF mechanisms (e.g., tokens, `SameSite` cookies) to prevent forged requests.

**Impact**: CSRF vulnerabilities can lead to:
- Unauthorized actions performed on behalf of users (e.g., account changes, transactions).
- Financial loss or data compromise in sensitive applications.
- Account takeover or privilege escalation through state-changing exploits.
- Reputational damage from session exploitation.

This guide provides a practical, hands-on methodology for testing CSRF vulnerabilities, adhering to OWASP’s WSTG-SESS-05, with detailed tool setups, at least two specific commands or configurations per tool, real-world test cases, remediation strategies, and ethical considerations for professional penetration testing.

## **Testing Tools**

The following tools are recommended for testing CSRF vulnerabilities, with at least two specific commands or configurations per tool for real security testing:

- **Burp Suite Community Edition**: Intercepts and manipulates requests to test CSRF protections.
- **Postman**: Tests API endpoints for CSRF token validation.
- **cURL**: Sends crafted requests to simulate CSRF attacks.
- **Browser Developer Tools**: Inspects forms and cookies for anti-CSRF tokens and `SameSite` attributes.
- **Python Requests Library**: Automates CSRF testing and token bypass attempts.

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

This methodology follows OWASP’s black-box approach for WSTG-SESS-05, focusing on testing state-changing endpoints, anti-CSRF tokens, `SameSite` cookies, request validation, and bypass attempts.

### **1. Identify and Test State-Changing Endpoints with Burp Suite**

Analyze state-changing operations and test for CSRF protections.

**Steps**:
1. **Configure Burp Suite**:
   - Set up browser proxy (127.0.0.1:8080).
   - Add `example.com` to the target scope in the “Target” tab.
2. **Identify State-Changing Requests**:
   - Navigate the application (e.g., update profile, transfer funds) and check “HTTP History” for `POST` or `PUT` requests to endpoints like `/update-profile`.
   - Note parameters, headers, and any CSRF tokens (e.g., `_csrf=xyz789`).
3. **Test Without CSRF Token**:
   - Replay the request in Repeater, removing the CSRF token (e.g., delete `_csrf` parameter).
   - Check if the request succeeds (HTTP 200).
4. **Analyze Findings**:
   - Vulnerable: Request succeeds without a token.
   - Expected secure response: HTTP 403 or error indicating missing/invalid token.
5. **Document Findings**:
   - Save requests and responses in Burp Suite’s “Logger”.

**Burp Suite Commands**:
- **Command 1**: Capture state-changing request:
  ```
  HTTP History -> Select POST /update-profile -> Request tab -> Note _csrf=xyz789
  ```
- **Command 2**: Test without CSRF token:
  ```
  HTTP History -> Select POST /update-profile -> Send to Repeater -> Remove _csrf parameter -> Click Send -> Check response
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
{"status": "Profile updated"}
```

**Remediation**:
- Implement CSRF tokens:
  ```javascript
  app.post('/update-profile', (req, res) => {
      if (!req.body._csrf || !validateCsrfToken(req.body._csrf)) {
          return res.status(403).json({ error: 'Invalid CSRF token' });
      }
      // Update profile
      res.json({ status: 'success' });
  });
  ```

### **2. Test SameSite Cookie Protection with Postman**

Verify that `SameSite` attributes prevent cross-site requests.

**Steps**:
1. **Identify State-Changing Endpoint**:
   - Use Burp Suite to find `POST /update-profile`.
   - Import into Postman.
2. **Simulate Cross-Site Request**:
   - Send a `POST` request with the session cookie but from a different origin (e.g., `evil.com`).
   - Include the session cookie (e.g., `session=abc123`) but omit the CSRF token.
3. **Analyze Responses**:
   - Check if the request succeeds.
   - Vulnerable: Request succeeds with `SameSite=None` or missing attribute.
   - Expected secure response: Cookie not sent if `SameSite=Strict`; HTTP 401 or 403.
4. **Document Findings**:
   - Save Postman requests and responses.

**Postman Commands**:
- **Command 1**: Test cross-site POST:
  ```
  New Request -> POST http://example.com/update-profile -> Body -> JSON: {"name": "test"} -> Headers: Cookie: session=abc123 -> Send
  ```
- **Command 2**: Check SameSite attribute:
  ```
  New Request -> GET http://example.com/login -> Send -> Response Headers -> Check Set-Cookie for SameSite
  ```

**Example Vulnerable Response**:
```
[Cross-site POST]
HTTP/1.1 200 OK
{"status": "Profile updated"}
```

**Remediation**:
- Set `SameSite=Strict`:
  ```python
  from flask import Flask, make_response
  app = Flask(__name__)
  @app.post('/login')
  def login():
      response = make_response({'status': 'success'})
      response.set_cookie('session', 'abc123', httponly=True, secure=True, samesite='Strict')
      return response
  ```

### **3. Test GET-Based State Changes with cURL**

Check if state-changing actions can be triggered via GET requests.

**Steps**:
1. **Identify State-Changing Endpoints**:
   - Use Burp Suite to find endpoints like `/transfer` or `/update-profile`.
2. **Test GET Request**:
   - Send a GET request to the endpoint with parameters (e.g., `GET /transfer?amount=1000`).
   - Check if the action is performed.
3. **Analyze Responses**:
   - Vulnerable: GET request succeeds and changes state.
   - Expected secure response: HTTP 405 or error indicating method not allowed.
4. **Document Findings**:
   - Save cURL commands and responses.

**cURL Commands**:
- **Command 1**: Test GET-based state change:
  ```bash
  curl -i "http://example.com/transfer?amount=1000&to=attacker"
  ```
- **Command 2**: Compare POST request:
  ```bash
  curl -i -X POST -d "amount=1000&to=attacker" http://example.com/transfer
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
{"status": "Transfer completed"}
```

**Remediation**:
- Restrict state changes to POST:
  ```javascript
  app.get('/transfer', (req, res) => {
      res.status(405).json({ error: 'Method not allowed' });
  });
  app.post('/transfer', (req, res) => {
      // Validate CSRF token and process transfer
      res.json({ status: 'success' });
  });
  ```

### **4. Inspect CSRF Tokens with Browser Developer Tools**

Analyze forms and API requests for anti-CSRF tokens.

**Steps**:
1. **Open Browser Developer Tools**:
   - Load `https://example.com/profile` and press `F12` in Chrome/Firefox.
2. **Inspect Forms**:
   - Go to “Elements” tab and search for `<form>` tags.
   - Check for hidden input fields like `<input name="_csrf" value="xyz789">`.
3. **Test Token Absence**:
   - Submit the form after removing the CSRF token (edit HTML or use Burp Suite).
   - Check if the request succeeds.
4. **Analyze Findings**:
   - Vulnerable: Form submission succeeds without a token.
   - Expected secure response: Server rejects request without valid token.
5. **Document Findings**:
   - Save screenshots and network logs.

**Browser Developer Tools Commands**:
- **Command 1**: Check for CSRF token:
  ```
  Elements tab -> Ctrl+F -> Search for "_csrf" or "token" -> Verify <input name="_csrf">
  ```
- **Command 2**: Remove CSRF token:
  ```
  Elements tab -> Edit <form> -> Remove <input name="_csrf"> -> Submit form -> Check Network tab response
  ```

**Example Vulnerable Form**:
```html
<form action="/update-profile" method="POST">
    <input type="text" name="name" value="test">
    <!-- No CSRF token -->
    <input type="submit">
</form>
```

**Remediation**:
- Add CSRF token to forms:
  ```html
  <form action="/update-profile" method="POST">
      <input type="hidden" name="_csrf" value="<%= generateCsrfToken() %>">
      <input type="text" name="name" value="test">
      <input type="submit">
  </form>
  ```

### **5. Automate CSRF Testing with Python Requests**

Automate testing to detect missing or weak CSRF protections.

**Steps**:
1. **Write Python Script**:
   - Create a script to simulate CSRF attacks:
     ```python
     import requests

     base_url = 'http://example.com'
     login_url = f'{base_url}/login'
     profile_url = f'{base_url}/update-profile'

     # Log in to get session
     session = requests.Session()
     login_data = {'username': 'test', 'password': 'Secure123'}
     session.post(login_url, data=login_data)
     session_cookie = session.cookies.get('session')
     print(f"Session cookie: {session_cookie}")

     # Test state-changing request without CSRF token
     profile_data = {'name': 'attacker'}
     response = session.post(profile_url, data=profile_data)
     print(f"No CSRF token: Status={response.status_code}, Response={response.text[:100]}")
     if response.status_code == 200 and 'success' in response.text.lower():
         print("Vulnerable: Request succeeded without CSRF token")

     # Test GET-based state change
     response = session.get(f'{profile_url}?name=attacker')
     print(f"GET request: Status={response.status_code}, Response={response.text[:100]}")
     if response.status_code == 200 and 'success' in response.text.lower():
         print("Vulnerable: GET-based state change allowed")
     ```
2. **Run Script**:
   - Execute: `python3 test_csrf.py`.
   - Analyze output for successful state changes without tokens or via GET.
3. **Verify Findings**:
   - Vulnerable: Requests succeed without tokens or via GET.
   - Expected secure response: HTTP 403 or errors for invalid requests.
4. **Document Results**:
   - Save script output.

**Python Commands**:
- **Command 1**: Run CSRF test:
  ```bash
  python3 test_csrf.py
  ```
- **Command 2**: Test single CSRF request:
  ```bash
  python3 -c "import requests; s=requests.Session(); s.post('http://example.com/login', data={'username': 'test', 'password': 'Secure123'}); r=s.post('http://example.com/update-profile', data={'name': 'attacker'}); print(r.status_code, r.text[:100])"
  ```

**Example Vulnerable Output**:
```
Session cookie: abc123
No CSRF token: Status=200, Response={"status": "Profile updated"}
Vulnerable: Request succeeded without CSRF token
```

**Remediation**:
- Validate CSRF tokens:
  ```python
  from flask import Flask, request, session
  app = Flask(__name__)
  @app.post('/update-profile')
  def update_profile():
      if not request.form.get('_csrf') or not validate_csrf_token(request.form['_csrf'], session['user']):
          return jsonify({'error': 'Invalid CSRF token'}), 403
      return jsonify({'status': 'success'})
  ```

## **Real-World Test Cases**

These test cases extend OWASP’s WSTG-SESS-05 with practical scenarios based on common CSRF vulnerabilities observed in penetration testing.

### **Test 1: Missing CSRF Token**

**Objective**: Verify that state-changing requests require a CSRF token.

**Steps**:
1. **Capture Request**:
   - Use Burp Suite to intercept `POST /update-profile`.
   - Command:
     ```
     HTTP History -> Select POST /update-profile -> Request tab -> Note _csrf=xyz789
     ```
2. **Remove Token**:
   - Command:
     ```
     HTTP History -> Select POST /update-profile -> Send to Repeater -> Remove _csrf -> Click Send
     ```
3. **Analyze Response**:
   - Check if profile is updated.
   - Expected secure response: HTTP 403.
4. **Save Results**:
   - Save Burp Suite outputs.

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
{"status": "Profile updated"}
```

**Remediation**:
```javascript
app.post('/update-profile', (req, res) => {
    if (!req.body._csrf) {
        return res.status(403).json({ error: 'CSRF token required' });
    }
    res.json({ status: 'success' });
});
```

### **Test 2: Weak SameSite Configuration**

**Objective**: Test if `SameSite` prevents cross-site requests.

**Steps**:
1. **Capture Cookie**:
   - Use Postman to log in.
   - Command:
     ```
     New Request -> POST http://example.com/login -> Body -> JSON: {"username": "test", "password": "Secure123"} -> Send
     ```
2. **Simulate Cross-Site Request**:
   - Command:
     ```
     New Request -> POST http://example.com/update-profile -> Body -> JSON: {"name": "attacker"} -> Headers: Cookie: session=abc123 -> Send
     ```
3. **Analyze Response**:
   - Check if request succeeds.
   - Expected secure response: HTTP 401 if `SameSite=Strict`.
4. **Save Results**:
   - Save Postman outputs.

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
{"status": "Profile updated"}
```

**Remediation**:
```javascript
res.cookie('session', 'abc123', { sameSite: 'strict' });
```

### **Test 3: GET-Based State Change**

**Objective**: Ensure state-changing actions cannot be triggered via GET.

**Steps**:
1. **Test GET Request**:
   - Use cURL:
     ```bash
     curl -i "http://example.com/transfer?amount=1000&to=attacker"
     ```
2. **Analyze Response**:
   - Check if transfer is processed.
   - Expected secure response: HTTP 405.
3. **Save Results**:
   - Save cURL output.

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
{"status": "Transfer completed"}
```

**Remediation**:
```python
@app.get('/transfer')
def transfer_get():
    return jsonify({'error': 'Method not allowed'}), 405
```

### **Test 4: CSRF Token in Form**

**Objective**: Verify that forms include and require CSRF tokens.

**Steps**:
1. **Inspect Form**:
   - Use Browser Developer Tools:
     ```
     Elements tab -> Ctrl+F -> Search for "_csrf"
     ```
2. **Remove Token**:
   - Command:
     ```
     Elements tab -> Edit <form> -> Remove <input name="_csrf"> -> Submit form
     ```
3. **Analyze Response**:
   - Check if submission succeeds.
   - Expected secure response: Server rejects request.
4. **Save Results**:
   - Save screenshots.

**Example Vulnerable Form**:
```html
<form action="/update-profile" method="POST">
    <input type="text" name="name" value="test">
    <input type="submit">
</form>
```

**Remediation**:
```html
<form action="/update-profile" method="POST">
    <input type="hidden" name="_csrf" value="xyz789">
    <input type="text" name="name" value="test">
    <input type="submit">
</form>
```

## **Additional Tips**

- **Test All State-Changing Actions**: Check forms, APIs, and workflows for CSRF protections.
- **Combine Tools**: Use Burp Suite for interception, Postman for APIs, and Python for automation.
- **Gray-Box Testing**: If source code is available, verify CSRF token implementation.
- **Document Thoroughly**: Save all commands, responses, and screenshots in a report.
- **Ethical Considerations**: Obtain explicit permission for testing, as CSRF testing involves submitting unauthorized requests that may trigger security alerts or affect live data.
- **References**: [OWASP CSRF Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html), [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html).