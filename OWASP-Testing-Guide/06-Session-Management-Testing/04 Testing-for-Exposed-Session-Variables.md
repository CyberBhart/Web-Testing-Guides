# **Testing for Exposed Session Variables**

## **Overview**

Testing for Exposed Session Variables (WSTG-SESS-04) involves assessing a web application to ensure that session identifiers (e.g., session IDs, tokens) are not exposed in URLs, unencrypted channels, client-side code, logs, or other insecure locations, preventing attackers from intercepting or accessing them. According to OWASP, exposed session variables can lead to session hijacking or unauthorized access, compromising user accounts. This test focuses on verifying secure transmission, storage, and handling of session variables to mitigate exposure risks.

**Impact**: Exposed session variables can lead to:
- Session hijacking by intercepting session IDs over unencrypted connections.
- Unauthorized access if session IDs are exposed in URLs, logs, or client-side code.
- Information disclosure through referer headers or cached pages.
- Compromise of user sessions via network sniffing or server misconfigurations.

This guide provides a practical, hands-on methodology for testing exposed session variables, adhering to OWASP’s WSTG-SESS-04, with detailed tool setups, at least two specific commands or configurations per tool, real-world test cases, remediation strategies, and ethical considerations for professional penetration testing.

## **Testing Tools**

The following tools are recommended for testing exposed session variables, with at least two specific commands or configurations per tool for real security testing:

- **Burp Suite Community Edition**: Intercepts requests to detect session IDs in URLs or headers.
- **Postman**: Tests API responses for session variable exposure.
- **cURL**: Sends requests to analyze session transmission and exposure.
- **Browser Developer Tools**: Inspects client-side code and cookies for exposed session variables.
- **Wireshark**: Analyzes network traffic for unencrypted session data.
- **Python Requests Library**: Automates testing for session variable exposure.

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
5. **Wireshark**:
   - Download from [wireshark.org](https://www.wireshark.org/download.html).
   - Install and configure network interface (e.g., Wi-Fi, Ethernet).
   - Verify: `wireshark --version`.
6. **Python Requests Library**:
   - Install Python: `sudo apt install python3`.
   - Install Requests: `pip install requests`.
   - Verify: `python3 -c "import requests; print(requests.__version__)"`.

## **Testing Methodology**

This methodology follows OWASP’s black-box approach for WSTG-SESS-04, focusing on testing for session variable exposure in URLs, unencrypted channels, referer headers, client-side code, logs, and caches.

### **1. Test Session IDs in URLs with Burp Suite**

Check if session IDs are exposed in URLs as query parameters or path components.

**Steps**:
1. **Configure Burp Suite**:
   - Set up browser proxy (127.0.0.1:8080).
   - Add `example.com` to the target scope in the “Target” tab.
2. **Capture Requests**:
   - Navigate the application (e.g., login, dashboard) and check “HTTP History” for URLs containing session IDs (e.g., `?sessionid=abc123`).
   - Look for `GET` or `POST` requests with session parameters.
3. **Test Session ID Usage**:
   - Log in and visit a URL with a session ID (e.g., `http://example.com/dashboard?sessionid=abc123`).
   - Check if the session ID in the URL grants access to the session.
4. **Analyze Findings**:
   - Vulnerable: Session ID in URL is accepted and functional.
   - Expected secure response: Session IDs only in cookies; URL parameters ignored.
5. **Document Findings**:
   - Save requests and responses in Burp Suite’s “Logger”.

**Burp Suite Commands**:
- **Command 1**: Check for session ID in URL:
  ```
  HTTP History -> Select GET /dashboard -> Request tab -> Look for ?sessionid=abc123 in URL
  ```
- **Command 2**: Test session ID in URL:
  ```
  HTTP History -> Select GET /dashboard -> Send to Repeater -> Edit URL to /dashboard?sessionid=abc123 -> Click Send -> Check if session is valid
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

### **2. Test Unencrypted Transmission with Wireshark**

Verify that session variables are only transmitted over HTTPS.

**Steps**:
1. **Configure Wireshark**:
   - Start Wireshark and select the network interface (e.g., Wi-Fi).
   - Apply filter: `http` to capture HTTP traffic.
2. **Capture Traffic**:
   - Access the application over HTTP (e.g., `http://example.com/login`) and log in.
   - Check Wireshark for session cookies or IDs in HTTP requests.
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

### **3. Test Referer Header Leakage with cURL**

Check if session IDs in URLs are leaked via referer headers to external sites.

**Steps**:
1. **Identify URL with Session ID**:
   - Use Burp Suite to find a URL with a session ID (e.g., `http://example.com/dashboard?sessionid=abc123`).
2. **Simulate External Navigation**:
   - Click a link to an external site (e.g., `http://external.com`) or use cURL to mimic the request.
   - Check the `Referer` header for the session ID.
3. **Analyze Findings**:
   - Vulnerable: `Referer: http://example.com/dashboard?sessionid=abc123`.
   - Expected secure response: No session ID in referer (session in cookies or `Referrer-Policy` set).
4. **Document Findings**:
   - Save cURL commands and responses.

**cURL Commands**:
- **Command 1**: Test referer with session ID:
  ```bash
  curl -i -H "Referer: http://example.com/dashboard?sessionid=abc123" http://external.com
  ```
- **Command 2**: Check referer policy:
  ```bash
  curl -i http://example.com/dashboard?sessionid=abc123 | grep Referrer-Policy
  ```

**Example Vulnerable Header**:
```
Referer: http://example.com/dashboard?sessionid=abc123
```

**Remediation**:
- Set `Referrer-Policy` and avoid session IDs in URLs:
  ```python
  @app.route('/')
  def home():
      response = make_response({'status': 'success'})
      response.headers['Referrer-Policy'] = 'no-referrer'
      response.set_cookie('session', 'abc123', httponly=True, secure=True)
      return response
  ```

### **4. Test Client-Side Exposure with Browser Developer Tools**

Inspect client-side code for exposed session variables.

**Steps**:
1. **Open Browser Developer Tools**:
   - Load `https://example.com` and press `F12` in Chrome/Firefox.
2. **Inspect JavaScript and HTML**:
   - Go to “Sources” tab and search for `session`, `token`, or `id` in JavaScript files.
   - Check “Elements” tab for session IDs in hidden fields or comments.
   - Run `document.cookie` in “Console” tab to verify `HttpOnly` protection.
3. **Test Exposure**:
   - Look for variables like `var sessionId = "abc123";` or inline scripts exposing session data.
   - Vulnerable: Session ID accessible in JavaScript or HTML.
   - Expected secure response: No session data in client-side code.
4. **Document Findings**:
   - Save screenshots and code snippets.

**Browser Developer Tools Commands**:
- **Command 1**: Search for session ID:
  ```
  Sources tab -> Ctrl+F -> Search for "session" or "token" -> Check JavaScript files
  ```
- **Command 2**: Check document.cookie:
  ```
  Console tab -> Run: document.cookie -> Verify session=abc123 is not returned
  ```

**Example Vulnerable Code**:
```html
<script>
var sessionId = "abc123";
</script>
```

**Remediation**:
- Store session data server-side:
  ```javascript
  app.get('/dashboard', (req, res) => {
      if (!req.session.user) {
          return res.status(401).json({ error: 'Unauthorized' });
      }
      res.send('Dashboard');
  });
  ```

### **5. Automate Exposure Testing with Python Requests**

Automate testing to detect session variable exposure in URLs, headers, or responses.

**Steps**:
1. **Write Python Script**:
   - Create a script to check for session IDs in URLs and responses:
     ```python
     import requests
     import re

     url = 'http://example.com'
     login_url = f'{url}/login'
     dashboard_url = f'{url}/dashboard'

     session = requests.Session()
     # Get initial page
     response = session.get(url)
     initial_url = response.url
     if 'session' in initial_url or 'token' in initial_url.lower():
         print(f"Vulnerable: Session ID in URL: {initial_url}")

     # Log in
     login_data = {'username': 'test', 'password': 'Secure123'}
     response = session.post(login_url, data=login_data)
     # Check response for session exposure
     if re.search(r'session[\w]*=[\w-]+', response.text, re.IGNORECASE):
         print("Vulnerable: Session ID in response body")
     # Check headers
     for header, value in response.headers.items():
         if 'session' in value.lower() or 'token' in value.lower():
             print(f"Vulnerable: Session ID in header: {header}: {value}")

     # Test referer leakage
     response = session.get('http://external.com', headers={'Referer': dashboard_url})
     if 'session' in response.request.headers.get('Referer', '').lower():
         print("Vulnerable: Session ID in Referer header")

     # Test HTTP transmission
     response = session.get(dashboard_url.replace('https://', 'http://'))
     if 'session' in str(response.request.headers.get('Cookie', '')).lower():
         print("Vulnerable: Session ID sent over HTTP")
     ```
2. **Run Script**:
   - Execute: `python3 test_session_exposure.py`.
   - Analyze output for session ID exposure.
3. **Verify Findings**:
   - Vulnerable: Session IDs in URLs, responses, or HTTP traffic.
   - Expected secure response: Session IDs only in secure cookies.
4. **Document Results**:
   - Save script output.

**Python Commands**:
- **Command 1**: Run exposure test:
  ```bash
  python3 test_session_exposure.py
  ```
- **Command 2**: Test single request:
  ```bash
  python3 -c "import requests; r=requests.get('http://example.com/dashboard?sessionid=abc123'); print('Session in URL' if 'session' in r.url.lower() else 'No session in URL')"
  ```

**Example Vulnerable Output**:
```
Vulnerable: Session ID in URL: http://example.com/dashboard?sessionid=abc123
Vulnerable: Session ID sent over HTTP
```

**Remediation**:
- Secure session handling:
  ```python
  from flask import Flask, session
  app = Flask(__name__)
  @app.route('/login', methods=['POST'])
  def login():
      session['user'] = authenticate_user()
      response = make_response({'status': 'success'})
      response.set_cookie('session', session.sid, httponly=True, secure=True, samesite='Strict')
      return response
  ```

## **Real-World Test Cases**

These test cases extend OWASP’s WSTG-SESS-04 with practical scenarios based on common session variable exposure vulnerabilities observed in penetration testing.

### **Test 1: Session ID in URL**

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
     HTTP History -> Select GET /dashboard -> Send to Repeater -> Edit URL to /dashboard?sessionid=abc123 -> Click Send
     ```
3. **Analyze Response**:
   - Check if session ID grants access.
   - Expected secure response: URL parameter ignored.
4. **Save Results**:
   - Save Burp Suite outputs.

**Example Vulnerable Request**:
```
GET /dashboard?sessionid=abc123 HTTP/1.1
```

**Remediation**:
```javascript
app.get('/dashboard', (req, res) => {
    if (req.query.sessionid) {
        return res.status(400).json({ error: 'Invalid request' });
    }
    res.send('Dashboard');
});
```

### **Test 2: Unencrypted Session Transmission**

**Objective**: Ensure session variables are only sent over HTTPS.

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
@app.before_request
def enforce_https():
    if not request.is_secure:
        return redirect(request.url.replace('http://', 'https://'))
```

### **Test 3: Referer Header Leakage**

**Objective**: Check for session ID leakage in referer headers.

**Steps**:
1. **Test External Navigation**:
   - Use cURL to simulate navigation:
     ```bash
     curl -i -H "Referer: http://example.com/dashboard?sessionid=abc123" http://external.com
     ```
2. **Check Policy**:
   - Command:
     ```bash
     curl -i http://example.com/dashboard | grep Referrer-Policy
     ```
3. **Analyze Findings**:
   - Check for session ID in `Referer`.
   - Expected secure response: No session ID; `Referrer-Policy: no-referrer`.
4. **Save Results**:
   - Save cURL outputs.

**Example Vulnerable Header**:
```
Referer: http://example.com/dashboard?sessionid=abc123
```

**Remediation**:
```javascript
app.use((req, res, next) => {
    res.setHeader('Referrer-Policy', 'no-referrer');
    next();
});
```

### **Test 4: Client-Side Session Exposure**

**Objective**: Verify that session variables are not exposed in client-side code.

**Steps**:
1. **Inspect Code**:
   - Use Browser Developer Tools:
     ```
     Sources tab -> Ctrl+F -> Search for "session" or "token"
     ```
2. **Check Cookies**:
   - Command:
     ```
     Console tab -> Run: document.cookie -> Verify session=abc123 is not returned
     ```
3. **Analyze Findings**:
   - Look for session IDs in JavaScript or HTML.
   - Expected secure response: No session data client-side.
4. **Save Results**:
   - Save screenshots.

**Example Vulnerable Code**:
```html
<script>
var sessionId = "abc123";
</script>
```

**Remediation**:
```python
@app.route('/dashboard')
def dashboard():
    if not session.get('user'):
        return jsonify({'error': 'Unauthorized'}), 401
    return jsonify({'data': 'Dashboard'})
```

## **Additional Tips**

- **Test All Vectors**: Check URLs, headers, client-side code, logs, and caches for session exposure.
- **Combine Tools**: Use Burp Suite for interception, Wireshark for network analysis, and Python for automation.
- **Gray-Box Testing**: If logs are accessible, verify session ID sanitization.
- **Document Thoroughly**: Save all commands, responses, and screenshots in a report.
- **Ethical Considerations**: Obtain explicit permission for testing, as network sniffing or session manipulation may disrupt services or violate privacy.
- **References**: [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html), [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/).