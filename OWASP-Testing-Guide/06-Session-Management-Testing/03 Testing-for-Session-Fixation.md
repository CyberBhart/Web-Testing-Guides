# **Testing for Session Fixation**

## **Overview**

Testing for Session Fixation (WSTG-SESS-03) involves assessing a web application to ensure it regenerates session identifiers upon authentication or privilege changes, preventing attackers from forcing users to use a known session ID to hijack their sessions. According to OWASP, session fixation vulnerabilities allow attackers to gain unauthorized access by pre-setting a session ID that remains valid after a user logs in. This test focuses on verifying session ID regeneration, invalidation of old session IDs, and secure handling of session IDs to mitigate session fixation risks.

**Impact**: Session fixation vulnerabilities can lead to:
- Unauthorized access to user accounts by attackers using pre-set session IDs.
- Session hijacking if fixed session IDs remain valid post-authentication.
- Compromise of sensitive accounts (e.g., admin) through targeted fixation attacks.

This guide provides a practical, hands-on methodology for testing session fixation, adhering to OWASP’s WSTG-SESS-03, with detailed tool setups, at least two specific commands or configurations per tool, real-world test cases, remediation strategies, and ethical considerations for professional penetration testing.

## **Testing Tools**

The following tools are recommended for testing session fixation, with at least two specific commands or configurations per tool for real security testing:

- **Burp Suite Community Edition**: Intercepts and manipulates session IDs to test regeneration and fixation.
- **Postman**: Tests API endpoints for session ID handling during authentication.
- **cURL**: Sends requests with pre-set session IDs to verify acceptance.
- **Browser Developer Tools**: Inspects session cookies and URL parameters for fixation vectors.
- **Python Requests Library**: Automates session ID testing and validation.

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

This methodology follows OWASP’s black-box approach for WSTG-SESS-03, focusing on testing session ID regeneration, acceptance of pre-set IDs, invalidation, and transmission vectors.

### **1. Test Session ID Regeneration with Burp Suite**

Verify that the application regenerates session IDs upon login.

**Steps**:
1. **Configure Burp Suite**:
   - Set up browser proxy (127.0.0.1:8080).
   - Add `example.com` to the target scope in the “Target” tab.
2. **Capture Pre-Login Session**:
   - Access the application (e.g., `GET /`) as an unauthenticated user.
   - Check “HTTP History” for the `Set-Cookie` header (e.g., `session=abc123`).
3. **Log In**:
   - Log in with valid credentials and capture the `POST /login` response.
   - Check for a new `Set-Cookie` header with a different session ID.
4. **Analyze Findings**:
   - Compare pre-login and post-login session IDs.
   - Vulnerable: Same session ID persists.
   - Expected secure response: New session ID (e.g., `session=xyz789`).
5. **Document Findings**:
   - Save requests and responses in Burp Suite’s “Logger”.

**Burp Suite Commands**:
- **Command 1**: Capture pre-login session:
  ```
  HTTP History -> Select GET / -> Response tab -> Find Set-Cookie: session=abc123
  ```
- **Command 2**: Check post-login session:
  ```
  HTTP History -> Select POST /login -> Send to Repeater -> Submit username=test, password=Secure123 -> Click Send -> Check Set-Cookie for new session ID
  ```

**Example Vulnerable Response**:
```
[Pre-login]
Set-Cookie: session=abc123

[Post-login]
Set-Cookie: session=abc123
```

**Remediation**:
- Regenerate session ID on login:
  ```javascript
  app.post('/login', (req, res) => {
      // Authenticate user
      req.session.regenerate((err) => {
          if (err) return res.status(500).json({ error: 'Session error' });
          res.json({ status: 'success' });
      });
  });
  ```

### **2. Test Pre-Set Session ID Acceptance with Postman**

Check if the application accepts a forced session ID after authentication.

**Steps**:
1. **Identify Login Endpoint**:
   - Use Burp Suite to find `POST /login`.
   - Import into Postman.
2. **Set Pre-Defined Session ID**:
   - Send an unauthenticated request with a custom session ID (e.g., `session=attacker123`).
   - Log in using the same session ID.
3. **Test Session Access**:
   - Use the pre-set session ID to access a protected resource (e.g., `/dashboard`).
   - Check if access is granted.
4. **Analyze Findings**:
   - Vulnerable: Pre-set session ID is accepted post-login.
   - Expected secure response: New session ID issued; old ID rejected.
5. **Document Findings**:
   - Save Postman requests and responses.

**Postman Commands**:
- **Command 1**: Set pre-defined session ID:
  ```
  New Request -> GET http://example.com/ -> Headers: Cookie: session=attacker123 -> Send -> Note Set-Cookie
  ```
- **Command 2**: Log in with pre-set ID:
  ```
  New Request -> POST http://example.com/login -> Body -> JSON: {"username": "test", "password": "Secure123"} -> Headers: Cookie: session=attacker123 -> Send -> Check Set-Cookie
  ```

**Example Vulnerable Response**:
```
[Post-login]
HTTP/1.1 200 OK
Set-Cookie: session=attacker123
```

**Remediation**:
- Reject untrusted session IDs:
  ```python
  @app.post('/login')
  def login():
      if 'session' in request.cookies and not validate_session(request.cookies['session']):
          response = make_response({'error': 'Invalid session'})
          response.set_cookie('session', '', expires=0)
          return response, 401
      session['user'] = authenticate_user()
      return jsonify({'status': 'success'})
  ```

### **3. Test Old Session ID Reuse with cURL**

Verify that old session IDs are invalidated after authentication.

**Steps**:
1. **Capture Pre-Login Session**:
   - Access the application and note the session ID (e.g., `session=abc123`).
2. **Log In**:
   - Log in to obtain a new session ID (e.g., `session=xyz789`).
3. **Reuse Old Session ID**:
   - Send a request to a protected resource using the old session ID.
   - Check if access is granted.
4. **Analyze Findings**:
   - Vulnerable: Old session ID grants access.
   - Expected secure response: HTTP 401 or 403.
5. **Document Findings**:
   - Save cURL commands and responses.

**cURL Commands**:
- **Command 1**: Capture pre-login session:
  ```bash
  curl -i http://example.com/ | grep Set-Cookie
  ```
- **Command 2**: Test old session ID:
  ```bash
  curl -i -b "session=abc123" http://example.com/dashboard
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: text/html
Dashboard Content
```

**Remediation**:
- Invalidate old sessions:
  ```javascript
  app.post('/login', (req, res) => {
      req.session.destroy(() => {
          req.session.regenerate(() => {
              res.json({ status: 'success' });
          });
      });
  });
  ```

### **4. Test Session ID in URL with Browser Developer Tools**

Check if session IDs can be forced via URL parameters, enabling fixation.

**Steps**:
1. **Open Browser Developer Tools**:
   - Load `https://example.com` and press `F12` in Chrome/Firefox.
2. **Inspect URLs**:
   - Navigate the application and check “Network” tab for session IDs in URLs (e.g., `?sessionid=abc123`).
3. **Force Session ID**:
   - Modify the URL to include a custom session ID (e.g., `http://example.com/?sessionid=attacker123`).
   - Log in and check if the application uses the provided ID.
4. **Analyze Findings**:
   - Vulnerable: URL-based session ID is accepted.
   - Expected secure response: Session ID ignored; cookie-based ID used.
5. **Document Findings**:
   - Save screenshots and network logs.

**Browser Developer Tools Commands**:
- **Command 1**: Check for session in URL:
  ```
  Network tab -> Select GET / -> Request URL -> Look for ?sessionid=abc123
  ```
- **Command 2**: Force session ID:
  ```
  Network tab -> Edit URL to http://example.com/?sessionid=attacker123 -> Reload -> Log in -> Check Set-Cookie
  ```

**Example Vulnerable Request**:
```
GET /?sessionid=attacker123 HTTP/1.1
[Post-login]
Set-Cookie: session=attacker123
```

**Remediation**:
- Use cookies for session IDs:
  ```python
  @app.route('/')
  def home():
      if 'sessionid' in request.args:
          return jsonify({'error': 'Session IDs via URL not supported'}), 400
      response = make_response({'status': 'success'})
      response.set_cookie('session', secrets.token_urlsafe(32))
      return response
  ```

### **5. Automate Session Fixation Testing with Python Requests**

Automate testing to verify session ID regeneration across multiple login attempts.

**Steps**:
1. **Write Python Script**:
   - Create a script to test session ID changes:
     ```python
     import requests

     url = 'http://example.com'
     login_url = f'{url}/login'
     dashboard_url = f'{url}/dashboard'

     # Get pre-login session
     session = requests.Session()
     response = session.get(url)
     pre_login_session = session.cookies.get('session')
     print(f"Pre-login session: {pre_login_session}")

     # Log in
     login_data = {'username': 'test', 'password': 'Secure123'}
     response = session.post(login_url, data=login_data)
     post_login_session = session.cookies.get('session')
     print(f"Post-login session: {post_login_session}")

     # Check regeneration
     if pre_login_session == post_login_session:
         print("Vulnerable: Session ID not regenerated")
     else:
         print("Secure: Session ID regenerated")

     # Test old session ID
     old_session = requests.Session()
     old_session.cookies.set('session', pre_login_session)
     response = old_session.get(dashboard_url)
     print(f"Old session access: Status={response.status_code}, Response={response.text[:100]}")
     if response.status_code == 200:
         print("Vulnerable: Old session ID accepted")
     ```
2. **Run Script**:
   - Execute: `python3 test_session_fixation.py`.
   - Analyze output for session ID regeneration and old ID acceptance.
3. **Verify Findings**:
   - Vulnerable: Same session ID or old ID grants access.
   - Expected secure response: New ID; old ID rejected.
4. **Document Results**:
   - Save script output.

**Python Commands**:
- **Command 1**: Run fixation test:
  ```bash
  python3 test_session_fixation.py
  ```
- **Command 2**: Test single login:
  ```bash
  python3 -c "import requests; s=requests.Session(); s.get('http://example.com'); print(s.cookies.get('session')); s.post('http://example.com/login', data={'username': 'test', 'password': 'Secure123'}); print(s.cookies.get('session'))"
  ```

**Example Vulnerable Output**:
```
Pre-login session: abc123
Post-login session: abc123
Vulnerable: Session ID not regenerated
Old session access: Status=200, Response=Dashboard Content
Vulnerable: Old session ID accepted
```

**Remediation**:
- Regenerate and invalidate sessions:
  ```python
  from flask import Flask, session
  app = Flask(__name__)
  @app.post('/login')
  def login():
      session.clear() # Invalidate old session
      session['user'] = authenticate_user()
      return jsonify({'status': 'success'})
  ```

## **Real-World Test Cases**

These test cases extend OWASP’s WSTG-SESS-03 with practical scenarios based on common session fixation vulnerabilities observed in penetration testing.

### **Test 1: Session ID Regeneration on Login**

**Objective**: Verify that session IDs change after login.

**Steps**:
1. **Capture Pre-Login Session**:
   - Use Burp Suite to intercept `GET /`.
   - Command:
     ```
     HTTP History -> Select GET / -> Response tab -> Note Set-Cookie: session=abc123
     ```
2. **Log In**:
   - Command:
     ```
     HTTP History -> Select POST /login -> Send to Repeater -> Submit username=test, password=Secure123 -> Check Set-Cookie
     ```
3. **Analyze Response**:
   - Check for new session ID (e.g., `session=xyz789`).
   - Vulnerable: Same session ID.
4. **Save Results**:
   - Save Burp Suite outputs.

**Example Vulnerable Response**:
```
[Post-login]
Set-Cookie: session=abc123
```

**Remediation**:
```javascript
app.post('/login', (req, res) => {
    req.session.regenerate(() => {
        res.json({ status: 'success' });
    });
});
```

### **Test 2: Pre-Set Session ID Acceptance**

**Objective**: Test if a forced session ID is accepted post-login.

**Steps**:
1. **Set Custom Session ID**:
   - Use Postman to send `GET /` with `Cookie: session=attacker123`.
   - Command:
     ```
     New Request -> GET http://example.com/ -> Headers: Cookie: session=attacker123 -> Send
     ```
2. **Log In**:
   - Command:
     ```
     New Request -> POST http://example.com/login -> Body -> JSON: {"username": "test", "password": "Secure123"} -> Headers: Cookie: session=attacker123 -> Send
     ```
3. **Analyze Response**:
   - Check if `attacker123` is retained.
   - Expected secure response: New session ID.
4. **Save Results**:
   - Save Postman outputs.

**Example Vulnerable Response**:
```
Set-Cookie: session=attacker123
```

**Remediation**:
```python
@app.post('/login')
def login():
    session_id = secrets.token_urlsafe(32)
    response = make_response({'status': 'success'})
    response.set_cookie('session', session_id, httponly=True, secure=True)
    return response
```

### **Test 3: Old Session ID Reuse**

**Objective**: Verify that old session IDs are invalidated.

**Steps**:
1. **Capture Pre-Login Session**:
   - Use cURL:
     ```bash
     curl -i http://example.com/ | grep Set-Cookie
     ```
2. **Log In and Test Old ID**:
   - Log in, then use old session ID:
     ```bash
     curl -i -b "session=abc123" http://example.com/dashboard
     ```
3. **Analyze Response**:
   - Check if dashboard access is granted.
   - Expected secure response: HTTP 401.
4. **Save Results**:
   - Save cURL outputs.

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Dashboard Content
```

**Remediation**:
```javascript
app.post('/login', (req, res) => {
    req.session.destroy(() => {
        req.session.regenerate(() => {
            res.json({ status: 'success' });
        });
    });
});
```

### **Test 4: Session ID in URL**

**Objective**: Check if session IDs can be forced via URL parameters.

**Steps**:
1. **Inspect URLs**:
   - Use Browser Developer Tools:
     ```
     Network tab -> Select GET / -> Check for ?sessionid=abc123
     ```
2. **Force Session ID**:
   - Navigate to `http://example.com/?sessionid=attacker123` and log in.
   - Command:
     ```
     Network tab -> Edit URL to http://example.com/?sessionid=attacker123 -> Reload -> Log in -> Check Set-Cookie
     ```
3. **Analyze Response**:
   - Check if `attacker123` is used.
   - Expected secure response: URL parameter ignored.
4. **Save Results**:
   - Save screenshots.

**Example Vulnerable Response**:
```
Set-Cookie: session=attacker123
```

**Remediation**:
```python
@app.route('/')
def home():
    if 'sessionid' in request.args:
        return jsonify({'error': 'Invalid session'}), 400
    return jsonify({'status': 'success'})
```

## **Additional Tips**

- **Test All Authentication Points**: Check session ID regeneration for login, MFA, and privilege changes.
- **Combine Tools**: Use Burp Suite for manual testing, Postman for APIs, and Python for automation.
- **Gray-Box Testing**: If logs are accessible, verify session invalidation.
- **Document Thoroughly**: Save all commands, responses, and screenshots in a report.
- **Ethical Considerations**: Obtain explicit permission for testing, as session manipulation may disrupt user sessions or trigger security alerts.
- **References**: [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html), [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html).