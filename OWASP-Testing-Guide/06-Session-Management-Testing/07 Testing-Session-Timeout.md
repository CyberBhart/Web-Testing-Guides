# **Testing Session Timeout**

## **Overview**

Testing Session Timeout (WSTG-SESS-07) involves assessing a web application’s session timeout mechanisms to ensure that inactive sessions are terminated after an appropriate period, preventing unauthorized access. According to OWASP, inadequate session timeouts can allow attackers to reuse stolen session IDs, especially on shared or public devices. This test focuses on verifying server-side session invalidation, client-side cookie expiration, and user experience for idle and absolute timeouts to mitigate session reuse risks.

**Impact**: Inadequate session timeout mechanisms can lead to:
- Unauthorized access from persistent sessions on shared devices.
- Session hijacking by reusing stolen session IDs from prolonged sessions.
- Data exposure in environments with physical or network access risks.
- Increased attack surface for sensitive sessions (e.g., admin) with extended validity.

This guide provides a practical, hands-on methodology for testing session timeout, adhering to OWASP’s WSTG-SESS-07, with detailed tool setups, at least two specific commands or configurations per tool, real-world test cases, remediation strategies, and ethical considerations for professional penetration testing.

## **Testing Tools**

The following tools are recommended for testing session timeout, with at least two specific commands or configurations per tool for real security testing:

- **Burp Suite Community Edition**: Intercepts requests to test session validity after timeout.
- **Postman**: Tests API endpoints for session timeout behavior.
- **cURL**: Sends requests to verify session ID reuse post-timeout.
- **Browser Developer Tools**: Inspects cookies and client-side timeout behavior.
- **Python Requests Library**: Automates testing for session invalidation and timeout.

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

This methodology follows OWASP’s black-box approach for WSTG-SESS-07, focusing on testing idle timeout, server-side invalidation, client-side cookie expiration, session reuse, absolute timeout, and user experience.

### **1. Test Idle Timeout with Burp Suite**

Verify that sessions expire after a period of inactivity.

**Steps**:
1. **Configure Burp Suite**:
   - Set up browser proxy (127.0.0.1:8080).
   - Add `example.com` to the target scope in the “Target” tab.
2. **Log In and Capture Session**:
   - Log in and note the session cookie (e.g., `session=abc123`) in “HTTP History”.
3. **Wait for Timeout**:
   - Leave the session idle for a period exceeding the expected timeout (e.g., 30 minutes). Refer to application documentation or estimate 15–30 minutes if unknown.
4. **Test Session Validity**:
   - Send a request to a protected resource (e.g., `GET /dashboard`) using the session ID in Repeater.
   - Check if access is granted (HTTP 200).
5. **Analyze Findings**:
   - Vulnerable: Session remains valid after extended inactivity.
   - Expected secure response: HTTP 401, 403, or redirect to login.
6. **Document Findings**:
   - Save requests and responses in Burp Suite’s “Logger”.

**Burp Suite Commands**:
- **Command 1**: Capture session cookie:
  ```
  HTTP History -> Select POST /login -> Response tab -> Note Set-Cookie: session=abc123
  ```
- **Command 2**: Test session post-timeout:
  ```
  HTTP History -> Select GET /dashboard -> Send to Repeater -> Set Cookie: session=abc123 -> Wait 30 minutes -> Click Send -> Check response
  ```

**Example Vulnerable Response**:
```
[Post-timeout GET /dashboard]
HTTP/1.1 200 OK
Content-Type: text/html
Dashboard Content
```

**Remediation**:
- Implement idle timeout:
  ```javascript
  app.use(session({
      secret: 'secure-secret',
      cookie: { maxAge: 1800000 }, // 30 minutes
      store: new MemoryStore({ checkPeriod: 1800000 }) // Expire sessions server-side
  }));
  ```

### **2. Test Client-Side Cookie Expiration with Browser Developer Tools**

Ensure session cookies expire client-side after timeout.

**Steps**:
1. **Open Browser Developer Tools**:
   - Load `https://example.com` and press `F12` in Chrome/Firefox.
2. **Log In and Inspect Cookies**:
   - Go to “Application” tab (Chrome) or “Storage” tab (Firefox) -> Cookies -> Check `session` cookie for `Max-Age` or `Expires`.
3. **Wait for Timeout**:
   - Leave the session idle for the timeout period (e.g., 30 minutes).
   - Refresh the Cookies section to verify if the cookie is removed or expired.
4. **Analyze Findings**:
   - Vulnerable: Cookie persists or lacks `Max-Age`/`Expires`.
   - Expected secure response: Cookie absent or expired (e.g., `Expires=Thu, 01 Jan 1970`).
5. **Document Findings**:
   - Save screenshots of Cookies section.

**Browser Developer Tools Commands**:
- **Command 1**: Check cookie attributes:
  ```
  Application tab -> Cookies -> https://example.com -> Select session cookie -> Verify Max-Age or Expires
  ```
- **Command 2**: Verify cookie post-timeout:
  ```
  Application tab -> Cookies -> Wait 30 minutes -> Refresh -> Check if session cookie is absent
  ```

**Example Vulnerable Cookie**:
```
Name: session
Value: abc123
Expires: [None or future date]
```

**Remediation**:
- Set cookie expiration:
  ```python
  from flask import Flask, make_response
  app = Flask(__name__)
  @app.post('/login')
  def login():
      response = make_response({'status': 'success'})
      response.set_cookie('session', 'abc123', max_age=1800, httponly=True, secure=True) # 30 minutes
      return response
  ```

### **3. Test Session Reuse Post-Timeout with cURL**

Confirm that expired session IDs cannot access protected resources.

**Steps**:
1. **Log In and Capture Session**:
   - Log in and note the session ID (e.g., `session=abc123`) using Burp Suite or cURL.
2. **Wait for Timeout**:
   - Leave the session idle for the timeout period (e.g., 30 minutes).
3. **Test Old Session ID**:
   - Send a request to a protected resource (e.g., `/dashboard`) with the old session ID.
   - Check the response status and content.
4. **Analyze Findings**:
   - Vulnerable: HTTP 200 with dashboard content.
   - Expected secure response: HTTP 401, 403, or redirect to login.
5. **Document Findings**:
   - Save cURL commands and responses.

**cURL Commands**:
- **Command 1**: Capture session ID:
  ```bash
  curl -i -X POST -d "username=test&password=Secure123" http://example.com/login | grep Set-Cookie
  ```
- **Command 2**: Test session post-timeout:
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
- Validate session expiration:
  ```javascript
  app.get('/dashboard', (req, res) => {
      if (!req.session.user || req.session.expires < Date.now()) {
          return res.status(401).json({ error: 'Session expired' });
      }
      res.send('Dashboard');
  });
  ```

### **4. Test Absolute Timeout with Postman**

Verify that sessions have a maximum lifetime, regardless of activity.

**Steps**:
1. **Identify Protected Endpoint**:
   - Use Burp Suite to find `GET /dashboard`.
   - Import into Postman.
2. **Log In and Maintain Activity**:
   - Log in and periodically send requests (e.g., every 5 minutes) to keep the session active for an extended period (e.g., 24 hours).
3. **Test Session Validity**:
   - After the absolute timeout period (e.g., 8 hours), send a request to `/dashboard`.
   - Check if access is granted.
4. **Analyze Findings**:
   - Vulnerable: Session remains valid after 24 hours.
   - Expected secure response: HTTP 401 or redirect to login after 8 hours.
5. **Document Findings**:
   - Save Postman requests and responses.

**Postman Commands**:
- **Command 1**: Log in and capture session:
  ```
  New Request -> POST http://example.com/login -> Body -> JSON: {"username": "test", "password": "Secure123"} -> Send -> Note Cookie: session=abc123
  ```
- **Command 2**: Test session after 8 hours:
  ```
  New Request -> GET http://example.com/dashboard -> Headers: Cookie: session=abc123 -> Send
  ```

**Example Vulnerable Response**:
```
[After 24 hours]
HTTP/1.1 200 OK
{"data": "Dashboard"}
```

**Remediation**:
- Implement absolute timeout:
  ```python
  from flask import Flask, session
  app = Flask(__name__)
  @app.before_request
  def check_absolute_timeout():
      if session.get('created_at') and session['created_at'] + 28800 < time.time(): # 8 hours
          session.clear()
          return jsonify({'error': 'Session expired'}), 401
  ```

### **5. Automate Timeout Testing with Python Requests**

Automate testing to verify idle and absolute timeout behavior.

**Steps**:
1. **Write Python Script**:
   - Create a script to test session timeout:
     ```python
     import requests
     import time

     base_url = 'http://example.com'
     login_url = f'{base_url}/login'
     dashboard_url = f'{base_url}/dashboard'

     # Log in
     session = requests.Session()
     login_data = {'username': 'test', 'password': 'Secure123'}
     response = session.post(login_url, data=login_data)
     session_cookie = session.cookies.get('session')
     print(f"Session cookie: {session_cookie}")

     # Test idle timeout
     print("Waiting 30 minutes for idle timeout...")
     time.sleep(1800)  # 30 minutes
     response = session.get(dashboard_url)
     print(f"Idle timeout test: Status={response.status_code}, Response={response.text[:100]}")
     if response.status_code == 200 and 'dashboard' in response.text.lower():
         print("Vulnerable: Session valid after idle timeout")
     else:
         print("Secure: Session expired after idle timeout")

     # Test absolute timeout (simplified to 1 hour for testing)
     new_session = requests.Session()
     new_session.post(login_url, data=login_data)
     time.sleep(3600)  # 1 hour
     response = new_session.get(dashboard_url)
     print(f"Absolute timeout test: Status={response.status_code}, Response={response.text[:100]}")
     if response.status_code == 200 and 'dashboard' in response.text.lower():
         print("Vulnerable: Session valid after absolute timeout")
     else:
         print("Secure: Session expired after absolute timeout")
     ```
2. **Run Script**:
   - Execute: `python3 test_session_timeout.py`.
   - Analyze output for session validity after idle and absolute timeouts.
3. **Verify Findings**:
   - Vulnerable: Sessions remain valid after timeouts.
   - Expected secure response: Sessions expire with HTTP 401 or redirect.
4. **Document Results**:
   - Save script output.

**Python Commands**:
- **Command 1**: Run timeout test:
  ```bash
  python3 test_session_timeout.py
  ```
- **Command 2**: Test idle timeout:
  ```bash
  python3 -c "import requests, time; s=requests.Session(); s.post('http://example.com/login', data={'username': 'test', 'password': 'Secure123'}); c=s.cookies.get('session'); time.sleep(1800); r=s.get('http://example.com/dashboard'); print(r.status_code, r.text[:100])"
  ```

**Example Vulnerable Output**:
```
Session cookie: abc123
Idle timeout test: Status=200, Response=Dashboard Content
Vulnerable: Session valid after idle timeout
Absolute timeout test: Status=200, Response=Dashboard Content
Vulnerable: Session valid after absolute timeout
```

**Remediation**:
- Combine idle and absolute timeouts:
  ```javascript
  app.use(session({
      secret: 'secure-secret',
      cookie: { maxAge: 1800000 }, // 30 minutes idle
      store: new MemoryStore({
          checkPeriod: 1800000,
          ttl: 28800 // 8 hours absolute
      })
  }));
  ```

## **Real-World Test Cases**

These test cases extend OWASP’s WSTG-SESS-07 with practical scenarios based on common session timeout vulnerabilities observed in penetration testing.

### **Test 1: Idle Timeout**

**Objective**: Verify that sessions expire after inactivity.

**Steps**:
1. **Capture Session**:
   - Use Burp Suite to intercept login.
   - Command:
     ```
     HTTP History -> Select POST /login -> Response tab -> Note Set-Cookie: session=abc123
     ```
2. **Test Post-Timeout**:
   - Command:
     ```
     HTTP History -> Select GET /dashboard -> Send to Repeater -> Set Cookie: session=abc123 -> Wait 30 minutes -> Click Send
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
app.use(session({ cookie: { maxAge: 1800000 } }));
```

### **Test 2: Client-Side Cookie Expiration**

**Objective**: Ensure cookies expire client-side.

**Steps**:
1. **Inspect Cookies**:
   - Use Browser Developer Tools:
     ```
     Application tab -> Cookies -> https://example.com -> Check Max-Age
     ```
2. **Wait for Timeout**:
   - Command:
     ```
     Application tab -> Cookies -> Wait 30 minutes -> Refresh -> Check session cookie
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
Max-Age: None
```

**Remediation**:
```python
response.set_cookie('session', 'abc123', max_age=1800)
```

### **Test 3: Absolute Timeout**

**Objective**: Verify sessions expire after a maximum lifetime.

**Steps**:
1. **Log In and Test**:
   - Use Postman to maintain activity.
   - Command:
     ```
     New Request -> POST http://example.com/login -> Body -> JSON: {"username": "test", "password": "Secure123"} -> Send
     ```
2. **Test After 8 Hours**:
   - Command:
     ```
     New Request -> GET http://example.com/dashboard -> Headers: Cookie: session=abc123 -> Send
     ```
3. **Analyze Response**:
   - Check if session is active.
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
app.use(session({ store: new MemoryStore({ ttl: 28800 }) }));
```

### **Test 4: User Experience**

**Objective**: Ensure timeout redirects to login with a clear message.

**Steps**:
1. **Test Timeout**:
   - Use Browser Developer Tools:
     ```
     Network tab -> Wait 30 minutes -> Click link to /dashboard -> Check response
     ```
2. **Inspect Redirect**:
   - Command:
     ```
     Network tab -> Select GET /dashboard -> Verify redirect to /login and error message
     ```
3. **Analyze Findings**:
   - Check for clear timeout message.
   - Expected secure response: Redirect to `/login` with “Session expired” message.
4. **Save Results**:
   - Save screenshots.

**Example Vulnerable Response**:
```
HTTP/1.1 500 Internal Server Error
```

**Remediation**:
```python
@app.get('/dashboard')
def dashboard():
    if not session.get('user'):
        return redirect('/login?error=Session+expired')
    return 'Dashboard'
```

## **Additional Tips**

- **Test Different Roles**: Check timeouts for admin, user, and guest sessions.
- **Combine Tools**: Use Burp Suite for session testing, Postman for APIs, and Python for automation.
- **Gray-Box Testing**: If configuration is available, verify timeout settings (e.g., `session.maxAge`).
- **Document Thoroughly**: Save all commands, responses, and screenshots in a report.
- **Ethical Considerations**: Obtain explicit permission for testing, as prolonged session testing may disrupt user sessions or trigger security alerts.
- **References**: [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html), [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html).