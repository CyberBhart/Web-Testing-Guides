# **Testing for Account Enumeration and Guessable User Account**

## **Overview**

Testing for Account Enumeration and Guessable User Account (WSTG-IDNT-04) involves assessing a web application to identify vulnerabilities that allow attackers to determine valid usernames or accounts or guess usernames due to predictable patterns. According to OWASP, enumeration vulnerabilities, such as verbose error messages or response differences, and guessable usernames (e.g., `admin`, `user1`) can enable attackers to target valid accounts for brute-force attacks, phishing, or unauthorized access. This test focuses on analyzing authentication endpoints (login, registration, password reset), error messages, response timing, and username patterns to detect enumeration risks and ensure robust account protection.

**Impact**: Vulnerabilities in account enumeration or guessable usernames can lead to:
- Identification of valid accounts, facilitating targeted attacks (e.g., brute-force, phishing).
- Unauthorized access through guessing predictable usernames.
- Privacy breaches by exposing account existence to unauthenticated users.
- Increased risk of account compromise due to weak authentication controls.

This guide provides a practical, hands-on methodology for testing account enumeration and guessable user accounts, adhering to OWASP’s WSTG-IDNT-04, with detailed tool setups, at least two specific commands or configurations per tool, real-world test cases, remediation strategies, and ethical considerations for professional penetration testing.

## **Testing Tools**

The following tools are recommended for testing account enumeration and guessable user accounts, with at least two specific commands or configurations per tool for real security testing:

- **Burp Suite Community Edition**: Intercepts and analyzes authentication requests for response differences.
- **Postman**: Tests API endpoints for enumeration vulnerabilities.
- **cURL**: Sends crafted requests to compare responses for valid vs. invalid accounts.
- **Browser Developer Tools**: Inspects client-side responses and timing for enumeration clues.
- **Python Requests Library**: Automates enumeration tests and checks rate limiting.

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

This methodology follows OWASP’s black-box approach for WSTG-IDNT-04, focusing on testing authentication endpoints, error messages, response timing, username patterns, and rate limiting to detect enumeration and guessable account vulnerabilities.

### **1. Test Login Enumeration with Burp Suite**

Analyze login form responses to detect differences between valid and invalid usernames.

**Steps**:
1. **Configure Burp Suite**:
   - Set up browser proxy (127.0.0.1:8080).
   - Add `example.com/login` to the target scope in the “Target” tab.
2. **Capture Login Requests**:
   - Submit login attempts with:
     - Valid username, wrong password (e.g., `admin:wrongpass`).
     - Invalid username, wrong password (e.g., `nonexistent:wrongpass`).
   - Check “HTTP History” for POST requests to `/login`.
3. **Compare Responses**:
   - Look for differences in error messages (e.g., “Invalid password” vs. “Username not found”), HTTP status codes, or response lengths.
   - Expected secure response: Identical responses (e.g., “Invalid credentials”).
4. **Document Findings**:
   - Save requests and responses in Burp Suite’s “Logger”.

**Burp Suite Commands**:
- **Command 1**: Test valid username:
  ```
  HTTP History -> Select POST /login -> Send to Repeater -> Set username=admin, password=wrongpass -> Click Send -> Note response
  ```
- **Command 2**: Test invalid username:
  ```
  Repeater -> Change username=nonexistent, password=wrongpass -> Click Send -> Compare response with valid username
  ```

**Example Vulnerable Response**:
```
[Valid username]
HTTP/1.1 401 Unauthorized
{"error": "Incorrect password"}

[Invalid username]
HTTP/1.1 401 Unauthorized
{"error": "Username does not exist"}
```

**Remediation**:
- Use generic error messages:
  ```javascript
  app.post('/login', (req, res) => {
      const { username, password } = req.body;
      if (!validCredentials(username, password)) {
          return res.status(401).json({ error: 'Invalid credentials' });
      }
      // Proceed with login
  });
  ```

### **2. Test Password Reset Enumeration with Postman**

Check password reset endpoints for enumeration through response differences.

**Steps**:
1. **Identify Reset Endpoint**:
   - Use Burp Suite to find `POST /reset-password`.
   - Import into Postman.
2. **Submit Requests**:
   - Send requests with:
     - Valid email (e.g., `admin@example.com`).
     - Invalid email (e.g., `nonexistent@example.com`).
   - Compare responses for differences.
3. **Analyze Responses**:
   - Look for messages like “Reset link sent” vs. “Email not found.”
   - Check HTTP status codes or response lengths.
   - Expected secure response: Identical responses (e.g., “If the email exists, a reset link was sent”).
4. **Document Findings**:
   - Save Postman requests and responses.

**Postman Commands**:
- **Command 1**: Test valid email:
  ```
  New Request -> POST http://example.com/reset-password -> Body -> JSON: {"email": "admin@example.com"} -> Send
  ```
- **Command 2**: Test invalid email:
  ```
  New Request -> POST http://example.com/reset-password -> Body -> JSON: {"email": "nonexistent@example.com"} -> Send
  ```

**Example Vulnerable Response**:
```
[Valid email]
HTTP/1.1 200 OK
{"message": "Reset link sent"}

[Invalid email]
HTTP/1.1 404 Not Found
{"error": "Email not found"}
```

**Remediation**:
- Use consistent responses:
  ```python
  @app.post('/reset-password')
  def reset_password():
      email = request.json['email']
      # Process reset even if email doesn't exist
      return jsonify({'message': 'If the email exists, a reset link was sent'})
  ```

### **3. Test Guessable Usernames with cURL**

Attempt to log in or register with common or sequential usernames to identify guessable patterns.

**Steps**:
1. **Identify Authentication Endpoint**:
   - Use Burp Suite to find `POST /login` or `/register`.
2. **Test Common Usernames**:
   - Try usernames like `admin`, `user`, `test`, or sequential IDs (e.g., `user1`, `user2`).
   - Use cURL to send login or registration requests.
3. **Analyze Responses**:
   - Check if accounts exist (e.g., “Incorrect password” indicates a valid account).
   - Verify if sequential usernames are accepted during registration.
   - Expected secure response: No predictable usernames; generic errors.
4. **Document Findings**:
   - Save cURL commands and responses.

**cURL Commands**:
- **Command 1**: Test common username:
  ```bash
  curl -i -X POST -d "username=admin&password=wrongpass" http://example.com/login
  ```
- **Command 2**: Test sequential username:
  ```bash
  curl -i -X POST -d "username=user1&password=wrongpass" http://example.com/login
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 401 Unauthorized
Content-Type: application/json
{"error": "Incorrect password"}
```

**Remediation**:
- Enforce unique, non-predictable usernames:
  ```javascript
  app.post('/register', (req, res) => {
      const username = req.body.username;
      if (username.match(/^(admin|user\d+|test)$/i)) {
          return res.status(400).json({ error: 'Username not allowed' });
      }
      // Register user
  });
  ```

### **4. Test Response Timing with Browser Developer Tools**

Analyze response timing differences to detect enumeration vulnerabilities.

**Steps**:
1. **Open Browser Developer Tools**:
   - Load `https://example.com/login` and press `F12` in Chrome/Firefox.
2. **Submit Login Attempts**:
   - Log in with:
     - Valid username, wrong password.
     - Invalid username, wrong password.
   - Check “Network” tab for response times.
3. **Analyze Timing**:
   - Compare response times (e.g., valid username takes 500ms, invalid takes 100ms).
   - Significant differences may indicate enumeration.
   - Expected secure response: Consistent timing.
4. **Document Findings**:
   - Save screenshots and network logs.

**Browser Developer Tools Commands**:
- **Command 1**: Check timing for valid username:
  ```
  Network tab -> Select POST /login -> Submit username=admin, password=wrongpass -> Note Timing: 500ms
  ```
- **Command 2**: Check timing for invalid username:
  ```
  Network tab -> Submit username=nonexistent, password=wrongpass -> Note Timing: 100ms -> Compare
  ```

**Example Vulnerable Finding**:
```
Valid username: 500ms
Invalid username: 100ms
```

**Remediation**:
- Normalize response times:
  ```python
  import time
  @app.post('/login')
  def login():
      start = time.time()
      # Process login
      if not valid_credentials():
          time.sleep(0.5 - (time.time() - start)) # Ensure ~500ms response
          return jsonify({'error': 'Invalid credentials'}), 401
      return jsonify({'status': 'success'})
  ```

### **5. Test Rate Limiting with Python Requests**

Attempt automated enumeration to verify rate limiting or anti-automation controls.

**Steps**:
1. **Write Python Script**:
   - Create a script to send multiple login attempts:
     ```python
     import requests
     import time

     url = 'http://example.com/login'
     usernames = ['admin', 'user1', 'nonexistent', 'test']
     for i, username in enumerate(usernames):
         data = {'username': username, 'password': 'wrongpass'}
         response = requests.post(url, data=data)
         print(f"Attempt {i+1}: Username={username}, Status={response.status_code}, Response={response.text[:100]}")
         if response.status_code == 429 or 'CAPTCHA required' in response.text:
             print("Rate limiting or CAPTCHA detected")
             break
         time.sleep(1)
     ```
2. **Run Script**:
   - Execute: `python3 test_enumeration.py`.
   - Analyze responses for rate limits (HTTP 429) or CAPTCHA prompts.
3. **Verify Findings**:
   - Check if enumeration succeeds without restrictions.
   - Expected secure response: Rate limiting or CAPTCHA enforced.
4. **Document Results**:
   - Save script output.

**Python Commands**:
- **Command 1**: Run enumeration test:
  ```bash
  python3 test_enumeration.py
  ```
- **Command 2**: Test single login:
  ```bash
  python3 -c "import requests; r=requests.post('http://example.com/login', data={'username': 'admin', 'password': 'wrongpass'}); print(r.status_code, r.text[:100])"
  ```

**Example Vulnerable Output**:
```
Attempt 1: Username=admin, Status=401, Response={"error": "Incorrect password"}
Attempt 2: Username=user1, Status=401, Response={"error": "Incorrect password"}
```

**Remediation**:
- Implement rate limiting and CAPTCHA:
  ```javascript
  const rateLimit = require('express-rate-limit');
  app.use('/login', rateLimit({
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 5 // 5 requests
  }));
  app.post('/login', (req, res) => {
      if (!req.body.captcha) {
          return res.status(400).json({ error: 'CAPTCHA required' });
      }
      // Process login
  });
  ```

## **Real-World Test Cases**

These test cases extend OWASP’s WSTG-IDNT-04 with practical scenarios based on common account enumeration and guessable username vulnerabilities observed in penetration testing.

### **Test 1: Login Form Enumeration**

**Objective**: Detect enumeration through login form error messages.

**Steps**:
1. **Submit Login Requests**:
   - Use Burp Suite to intercept `POST /login`.
   - Command:
     ```
     HTTP History -> Select POST /login -> Send to Repeater -> Set username=admin, password=wrongpass -> Click Send
     ```
2. **Test Invalid Username**:
   - Command:
     ```
     Repeater -> Change username=nonexistent -> Click Send -> Compare response
     ```
3. **Analyze Responses**:
   - Check for distinct messages (e.g., “Incorrect password” vs. “Username not found”).
   - Expected secure response: Generic error.
4. **Save Results**:
   - Save Burp Suite outputs.

**Example Vulnerable Response**:
```
[Valid] {"error": "Incorrect password"}
[Invalid] {"error": "Username not found"}
```

**Remediation**:
```python
@app.post('/login')
def login():
    return jsonify({'error': 'Invalid credentials'}), 401
```

### **Test 2: Password Reset Enumeration**

**Objective**: Identify enumeration in password reset responses.

**Steps**:
1. **Submit Reset Requests**:
   - Use Postman to send `POST /reset-password`.
   - Command:
     ```
     New Request -> POST http://example.com/reset-password -> Body -> JSON: {"email": "admin@example.com"} -> Send
     ```
2. **Test Invalid Email**:
   - Command:
     ```
     New Request -> POST http://example.com/reset-password -> Body -> JSON: {"email": "nonexistent@example.com"} -> Send
     ```
3. **Analyze Responses**:
   - Check for “Reset link sent” vs. “Email not found.”
   - Expected secure response: Consistent message.
4. **Save Results**:
   - Save Postman outputs.

**Example Vulnerable Response**:
```
[Valid] {"message": "Reset link sent"}
[Invalid] {"error": "Email not found"}
```

**Remediation**:
```javascript
app.post('/reset-password', (req, res) => {
    return res.json({ message: 'If the email exists, a reset link was sent' });
});
```

### **Test 3: Guessable Username Login**

**Objective**: Test for predictable usernames in login.

**Steps**:
1. **Test Common Usernames**:
   - Use cURL to try `admin`, `user1`.
   - Command:
     ```bash
     curl -i -X POST -d "username=admin&password=wrongpass" http://example.com/login
     ```
2. **Test Sequential Usernames**:
   - Command:
     ```bash
     curl -i -X POST -d "username=user1&password=wrongpass" http://example.com/login
     ```
3. **Analyze Responses**:
   - Check for valid account indicators.
   - Expected secure response: No predictable usernames.
4. **Save Results**:
   - Save cURL outputs.

**Example Vulnerable Response**:
```
HTTP/1.1 401 Unauthorized
{"error": "Incorrect password"}
```

**Remediation**:
```php
if (preg_match('/^(admin|user\d+|test)$/i', $username)) {
    return json_encode(['error' => 'Invalid username']);
}
```

### **Test 4: Automated Enumeration**

**Objective**: Verify rate limiting against enumeration attempts.

**Steps**:
1. **Run Python Script**:
   - Command:
     ```bash
     python3 test_enumeration.py
     ```
2. **Analyze Output**:
   - Check for HTTP 429 or CAPTCHA prompts.
   - Expected secure response: Enumeration blocked.
3. **Verify Manually**:
   - Use Postman to send multiple requests:
     ```
     New Request -> POST http://example.com/login -> Body -> Form-data: username=admin, password=wrongpass -> Send 5 times
     ```
4. **Save Results**:
   - Save script and Postman outputs.

**Example Vulnerable Output**:
```
Attempt 5: Username=test, Status=401, Response={"error": "Incorrect password"}
```

**Remediation**:
```python
from flask_limiter import Limiter
limiter = Limiter(app, key_func=lambda: request.remote_addr)
@app.route('/login', methods=['POST'])
@limiter.limit('5 per minute')
def login():
    return jsonify({'error': 'Invalid credentials'}), 401
```

## **Additional Tips**

- **Test All Endpoints**: Check login, registration, password reset, and account recovery for enumeration.
- **Combine Tools**: Use Burp Suite for manual testing, Postman for APIs, and Python for automation.
- **Gray-Box Testing**: If logs are accessible, verify rate limiting or CAPTCHA triggers.
- **Document Thoroughly**: Save all commands, responses, and screenshots in a report.
- **Ethical Considerations**: Obtain explicit permission for enumeration testing, as automated attempts may trigger security alerts or disrupt live systems.
- **References**: [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html), [OWASP Account Lockout Guidance](https://owasp.org/www-community/controls/Account_Lockout).