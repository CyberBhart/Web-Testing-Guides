# **Testing for Logout Functionality**

## **Overview**

Testing for Logout Functionality (WSTG-SESS-06) involves assessing a web application’s logout mechanism to ensure that user sessions are securely terminated, session identifiers are invalidated, and no residual session data remains exploitable. According to OWASP, weak logout functionality can allow attackers to reuse old session IDs, leading to unauthorized access. This test focuses on verifying server-side session invalidation, client-side cookie clearing, and the accessibility of the logout feature to mitigate session reuse risks.

**Impact**: Weak logout functionality can lead to:
- Unauthorized access if old session IDs remain valid post-logout.
- Session hijacking by reusing intercepted session cookies.
- Data exposure from persistent session data in client-side storage.
- Account compromise on shared or public devices due to incomplete session termination.

This guide provides a practical, hands-on methodology for testing logout functionality, adhering to OWASP’s WSTG-SESS-06, with detailed tool setups, at least two specific commands or configurations per tool, real-world test cases, remediation strategies, and ethical considerations for professional penetration testing.

## **Testing Tools**

The following tools are recommended for testing logout functionality, with at least two specific commands or configurations per tool for real security testing:

- **Burp Suite Community Edition**: Intercepts requests to test session invalidation and cookie clearing.
- **Postman**: Tests logout endpoints and session behavior in APIs.
- **cURL**: Sends requests to verify session ID reuse post-logout.
- **Browser Developer Tools**: Inspects cookies, local storage, and logout functionality.
- **Python Requests Library**: Automates testing for session invalidation and client-side cleanup.

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

This methodology follows OWASP’s black-box approach for WSTG-SESS-06, focusing on testing session invalidation, cookie clearing, access after logout, multiple sessions, logout accessibility, and client-side cleanup.

### **1. Test Session Invalidation with Burp Suite**

Verify that the server invalidates the session ID upon logout.

**Steps**:
1. **Configure Burp Suite**:
   - Set up browser proxy (127.0.0.1:8080).
   - Add `example.com` to the target scope in the “Target” tab.
2. **Log In and Capture Session**:
   - Log in to the application and note the session cookie (e.g., `session=abc123`) in “HTTP History”.
3. **Log Out**:
   - Click the logout button/link and capture the `POST /logout` or `GET /logout` request/response.
   - Check for `Set-Cookie: session=; Max-Age=0` or similar to clear the cookie.
4. **Test Old Session ID**:
   - Replay a request to a protected resource (e.g., `GET /dashboard`) using the old session ID in Repeater.
   - Check if access is granted (HTTP 200).
5. **Analyze Findings**:
   - Vulnerable: Old session ID grants access.
   - Expected secure response: HTTP 401, 403, or redirect to login.
6. **Document Findings**:
   - Save requests and responses in Burp Suite’s “Logger”.

**Burp Suite Commands**:
- **Command 1**: Capture logout response:
  ```
  HTTP History -> Select POST /logout -> Response tab -> Check for Set-Cookie: session=; Max-Age=0
  ```
- **Command 2**: Test old session ID:
  ```
  HTTP History -> Select GET /dashboard -> Send to Repeater -> Set Cookie: session=abc123 -> Click Send -> Check response
  ```

**Example Vulnerable Response**:
```
[Post-logout GET /dashboard]
HTTP/1.1 200 OK
Content-Type: text/html
Dashboard Content
```

**Remediation**:
- Invalidate sessions on logout:
  ```javascript
  app.post('/logout', (req, res) => {
      req.session.destroy((err) => {
          if (err) return res.status(500).json({ error: 'Logout failed' });
          res.clearCookie('session');
          res.json({ status: 'success' });
      });
  });
  ```

### **2. Test Cookie Clearing with Browser Developer Tools**

Ensure session cookies are cleared or expired after logout.

**Steps**:
1. **Open Browser Developer Tools**:
   - Load `https://example.com` and press `F12` in Chrome/Firefox.
2. **Log In and Inspect Cookies**:
   - Go to “Application” tab (Chrome) or “Storage” tab (Firefox) -> Cookies -> Note `session=abc123`.
3. **Log Out**:
   - Click logout and refresh the Cookies section.
   - Check if the `session` cookie is removed or set to expire (e.g., `Expires=Thu, 01 Jan 1970`).
4. **Analyze Findings**:
   - Vulnerable: Cookie persists or has a future expiration.
   - Expected secure response: Cookie absent or expired.
5. **Document Findings**:
   - Save screenshots of Cookies section.

**Browser Developer Tools Commands**:
- **Command 1**: Check cookies pre-logout:
  ```
  Application tab -> Cookies -> https://example.com -> Verify session=abc123
  ```
- **Command 2**: Check cookies post-logout:
  ```
  Application tab -> Cookies -> https://example.com -> Log out -> Refresh -> Verify session cookie absent
  ```

**Example Vulnerable Cookie**:
```
Name: session
Value: abc123
Expires: [Future date]
```

**Remediation**:
- Clear cookies on logout:
  ```python
  from flask import Flask, make_response
  app = Flask(__name__)
  @app.post('/logout')
  def logout():
      response = make_response({'status': 'success'})
      response.set_cookie('session', '', expires=0, httponly=True, secure=True)
      return response
  ```

### **3. Test Access After Logout with cURL**

Confirm that protected resources are inaccessible using old session IDs post-logout.

**Steps**:
1. **Log In and Capture Session**:
   - Log in and note the session ID (e.g., `session=abc123`) using Burp Suite or cURL.
2. **Log Out**:
   - Send a logout request (e.g., `POST /logout`).
3. **Test Old Session ID**:
   - Send a request to a protected resource (e.g., `/dashboard`) with the old session ID.
   - Check the response status and content.
4. **Analyze Findings**:
   - Vulnerable: HTTP 200 with dashboard content.
   - Expected secure response: HTTP 401, 403, or redirect to login.
5. **Document Findings**:
   - Save cURL commands and responses.

**cURL Commands**:
- **Command 1**: Perform logout:
  ```bash
  curl -i -X POST -b "session=abc123" http://example.com/logout
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
- Reject invalid sessions:
  ```javascript
  app.get('/dashboard', (req, res) => {
      if (!req.session.user) {
          return res.status(401).json({ error: 'Unauthorized' });
      }
      res.send('Dashboard');
  });
  ```

### **4. Test Multiple Sessions with Postman**

Verify that logout terminates all user sessions across devices or browsers.

**Steps**:
1. **Identify Logout Endpoint**:
   - Use Burp Suite to find `POST /logout`.
   - Import into Postman.
2. **Log In Multiple Sessions**:
   - Log in from two browsers (e.g., Chrome, Firefox) or devices, capturing session cookies (e.g., `session=abc123`, `session=xyz789`).
3. **Log Out from One Session**:
   - Send a logout request from one browser using Postman.
4. **Test Other Session**:
   - Use the second session’s cookie to access a protected resource (e.g., `/dashboard`).
   - Check if access is granted.
5. **Analyze Findings**:
   - Vulnerable: Second session remains active.
   - Expected secure response: All sessions terminated; HTTP 401 or 403.
6. **Document Findings**:
   - Save Postman requests and responses.

**Postman Commands**:
- **Command 1**: Log out from first session:
  ```
  New Request -> POST http://example.com/logout -> Headers: Cookie: session=abc123 -> Send
  ```
- **Command 2**: Test second session:
  ```
  New Request -> GET http://example.com/dashboard -> Headers: Cookie: session=xyz789 -> Send
  ```

**Example Vulnerable Response**:
```
[Second session]
HTTP/1.1 200 OK
{"data": "Dashboard"}
```

**Remediation**:
- Terminate all sessions:
  ```python
  from flask import Flask, session
  app = Flask(__name__)
  @app.post('/logout')
  def logout():
      user_id = session.get('user_id')
      invalidate_all_sessions(user_id)  # Custom function to clear all user sessions
      session.clear()
      response = make_response({'status': 'success'})
      response.set_cookie('session', '', expires=0)
      return response
  ```

### **5. Automate Logout Testing with Python Requests**

Automate testing to verify session invalidation and client-side cleanup.

**Steps**:
1. **Write Python Script**:
   - Create a script to test logout functionality:
     ```python
     import requests

     base_url = 'http://example.com'
     login_url = f'{base_url}/login'
     logout_url = f'{base_url}/logout'
     dashboard_url = f'{base_url}/dashboard'

     # Log in
     session = requests.Session()
     login_data = {'username': 'test', 'password': 'Secure123'}
     session.post(login_url, data=login_data)
     session_cookie = session.cookies.get('session')
     print(f"Session cookie: {session_cookie}")

     # Log out
     response = session.post(logout_url)
     logout_cookie = response.headers.get('Set-Cookie', '')
     print(f"Logout Set-Cookie: {logout_cookie}")
     if 'session=; Max-Age=0' in logout_cookie or 'expires=Thu, 01 Jan 1970' in logout_cookie:
         print("Secure: Cookie cleared")
     else:
         print("Vulnerable: Cookie not cleared")

     # Test old session ID
     old_session = requests.Session()
     old_session.cookies.set('session', session_cookie)
     response = old_session.get(dashboard_url)
     print(f"Old session access: Status={response.status_code}, Response={response.text[:100]}")
     if response.status_code == 200 and 'dashboard' in response.text.lower():
         print("Vulnerable: Old session ID accepted")
     else:
         print("Secure: Old session ID rejected")
     ```
2. **Run Script**:
   - Execute: `python3 test_logout.py`.
   - Analyze output for cookie clearing and session invalidation.
3. **Verify Findings**:
   - Vulnerable: Cookie persists or old session ID grants access.
   - Expected secure response: Cookie cleared; old ID rejected.
4. **Document Results**:
   - Save script output.

**Python Commands**:
- **Command 1**: Run logout test:
  ```bash
  python3 test_logout.py
  ```
- **Command 2**: Test single logout:
  ```bash
  python3 -c "import requests; s=requests.Session(); s.post('http://example.com/login', data={'username': 'test', 'password': 'Secure123'}); c=s.cookies.get('session'); r=s.post('http://example.com/logout'); print(r.headers.get('Set-Cookie')); s.cookies.set('session', c); r=s.get('http://example.com/dashboard'); print(r.status_code)"
  ```

**Example Vulnerable Output**:
```
Session cookie: abc123
Logout Set-Cookie: session=abc123; Path=/
Vulnerable: Cookie not cleared
Old session access: Status=200, Response=Dashboard Content
Vulnerable: Old session ID accepted
```

**Remediation**:
- Secure logout handling:
  ```python
  from flask import Flask, session
  app = Flask(__name__)
  @app.post('/logout')
  def logout():
      session.clear()
      response = make_response({'status': 'success'})
      response.set_cookie('session', '', expires=0, httponly=True, secure=True, samesite='Strict')
      return response
  ```

## **Real-World Test Cases**

These test cases extend OWASP’s WSTG-SESS-06 with practical scenarios based on common logout functionality vulnerabilities observed in penetration testing.

### **Test 1: Session Invalidation**

**Objective**: Verify that sessions are invalidated server-side after logout.

**Steps**:
1. **Capture Session**:
   - Use Burp Suite to intercept login.
   - Command:
     ```
     HTTP History -> Select POST /login -> Response tab -> Note Set-Cookie: session=abc123
     ```
2. **Log Out and Test**:
   - Command:
     ```
     HTTP History -> Select GET /dashboard -> Send to Repeater -> Set Cookie: session=abc123 -> Log out -> Click Send
     ```
3. **Analyze Response**:
   - Check if dashboard is accessible.
   - Expected secure response: HTTP 401.
4. **Save Results**:
   - Save Burp Suite outputs.

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Dashboard Content
```

**Remediation**:
```javascript
app.post('/logout', (req, res) => {
    req.session.destroy();
    res.clearCookie('session');
    res.json({ status: 'success' });
});
```

### **Test 2: Cookie Clearing**

**Objective**: Ensure session cookies are cleared post-logout.

**Steps**:
1. **Inspect Cookies**:
   - Use Browser Developer Tools:
     ```
     Application tab -> Cookies -> https://example.com -> Log in -> Verify session=abc123
     ```
2. **Log Out**:
   - Command:
     ```
     Application tab -> Cookies -> Log out -> Refresh -> Check for session cookie
     ```
3. **Analyze Findings**:
   - Check if cookie persists.
   - Expected secure response: Cookie absent.
4. **Save Results**:
   - Save screenshots.

**Example Vulnerable Cookie**:
```
Name: session
Value: abc123
```

**Remediation**:
```python
response.set_cookie('session', '', expires=0)
```

### **Test 3: Multiple Session Termination**

**Objective**: Verify that logout terminates all sessions.

**Steps**:
1. **Log In Two Sessions**:
   - Use Postman to log in twice, capturing cookies.
   - Command:
     ```
     New Request -> POST http://example.com/login -> Body -> JSON: {"username": "test", "password": "Secure123"} -> Send
     ```
2. **Log Out and Test**:
   - Command:
     ```
     New Request -> POST http://example.com/logout -> Headers: Cookie: session=abc123 -> Send
     New Request -> GET http://example.com/dashboard -> Headers: Cookie: session=xyz789 -> Send
     ```
3. **Analyze Response**:
   - Check if second session is active.
   - Expected secure response: HTTP 401.
4. **Save Results**:
   - Save Postman outputs.

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
{"data": "Dashboard"}
```

**Remediation**:
```javascript
app.post('/logout', (req, res) => {
    invalidateAllUserSessions(req.session.userId);
    res.clearCookie('session');
    res.json({ status: 'success' });
});
```

### **Test 4: Logout Accessibility**

**Objective**: Ensure the logout option is accessible and functional.

**Steps**:
1. **Inspect UI**:
   - Use Browser Developer Tools:
     ```
     Elements tab -> Ctrl+F -> Search for "logout" -> Verify <a href="/logout"> or button
     ```
2. **Test Logout**:
   - Click logout and check Network tab for `POST /logout`.
   - Command:
     ```
     Network tab -> Select POST /logout -> Verify request sent
     ```
3. **Analyze Findings**:
   - Check if logout is hidden or non-functional.
   - Expected secure response: Logout triggers session termination.
4. **Save Results**:
   - Save screenshots.

**Example Vulnerable UI**:
```html
<!-- No logout link or button -->
```

**Remediation**:
```html
<a href="/logout" onclick="fetch('/logout', {method: 'POST'}).then(() => location.href='/login')">Logout</a>
```

## **Additional Tips**

- **Test All Scenarios**: Check logout from different browsers, devices, and user roles.
- **Combine Tools**: Use Burp Suite for session testing, Browser Developer Tools for client-side checks, and Python for automation.
- **Gray-Box Testing**: If logs are available, verify session invalidation in server records.
- **Document Thoroughly**: Save all commands, responses, and screenshots in a report.
- **Ethical Considerations**: Obtain explicit permission for testing, as session manipulation may disrupt user sessions or trigger security alerts.
- **References**: [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html), [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html).