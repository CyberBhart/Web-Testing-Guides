# **Testing for Weak or Unenforced Username Policy**

## **Overview**

Testing for Weak or Unenforced Username Policy (WSTG-IDNT-05) involves assessing a web application’s username policy to ensure it enforces strong, unique, and secure usernames, preventing vulnerabilities that could enable account enumeration, impersonation, or unauthorized access. According to OWASP, weak username policies that allow predictable (e.g., `admin`, `user1`), non-unique, or sensitive usernames (e.g., emails) can facilitate attacks like brute-forcing or phishing. This test focuses on validating username format, uniqueness, input sanitization, and server-side enforcement during registration or account creation to identify and mitigate risks.

**Impact**: Weak or unenforced username policies can lead to:
- Predictable usernames enabling account enumeration or targeted attacks.
- Impersonation through usernames mimicking privileged accounts (e.g., `administrator`).
- Privacy breaches by allowing sensitive data (e.g., emails, SSNs) in usernames.
- Account conflicts or hijacking due to non-unique or case-insensitive usernames.

This guide provides a practical, hands-on methodology for testing weak or unenforced username policies, adhering to OWASP’s WSTG-IDNT-05, with detailed tool setups, at least two specific commands or configurations per tool, real-world test cases, remediation strategies, and ethical considerations for professional penetration testing.

## **Testing Tools**

The following tools are recommended for testing username policies, with at least two specific commands or configurations per tool for real security testing:

- **Burp Suite Community Edition**: Intercepts and manipulates registration requests to test username validation.
- **Postman**: Tests API endpoints for weak username policies.
- **cURL**: Sends crafted registration requests to analyze username restrictions.
- **Browser Developer Tools**: Inspects client-side validation and hidden fields in registration forms.
- **Python Requests Library**: Automates tests for username patterns and enumeration risks.

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

This methodology follows OWASP’s black-box approach for WSTG-IDNT-05, focusing on testing username format, predictability, uniqueness, input validation, and server-side enforcement during account creation or registration.

### **1. Test Username Format with Burp Suite**

Submit various usernames to verify format restrictions and input validation.

**Steps**:
1. **Configure Burp Suite**:
   - Set up browser proxy (127.0.0.1:8080).
   - Add `example.com/register` to the target scope in the “Target” tab.
2. **Capture Registration Request**:
   - Fill out the registration form and submit.
   - Check “HTTP History” for the POST request to `/register`.
3. **Test Username Inputs**:
   - Try weak usernames: short (e.g., `a`), common (e.g., `admin`), sequential (e.g., `user1`).
   - Submit sensitive data (e.g., `test@email.com`, `123-45-6789`).
   - Test special characters or malicious inputs (e.g., `<script>`, `' OR '1'='1`).
4. **Analyze Responses**:
   - Check if weak or insecure usernames are accepted (HTTP 200).
   - Look for errors exposing system details (e.g., SQL errors).
   - Expected secure response: Rejection of invalid usernames with generic errors.
5. **Document Findings**:
   - Save requests and responses in Burp Suite’s “Logger”.

**Burp Suite Commands**:
- **Command 1**: Test short username:
  ```
  HTTP History -> Select POST /register -> Send to Repeater -> Change username=test to username=a -> Click Send -> Check if accepted
  ```
- **Command 2**: Test sensitive username:
  ```
  Repeater -> Change username=test to username=test@email.com -> Click Send -> Check if accepted
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
{"status": "Account created"}
```

**Remediation**:
- Enforce strong username format:
  ```javascript
  app.post('/register', (req, res) => {
      const username = req.body.username;
      if (!/^[a-zA-Z0-9]{6,}$/.test(username) || username.match(/^(admin|user\d+|test)$/i)) {
          return res.status(400).json({ error: 'Invalid username' });
      }
      // Register user
  });
  ```

### **2. Test Username Uniqueness with Postman**

Verify that the application prevents duplicate or case-insensitive usernames.

**Steps**:
1. **Identify Registration Endpoint**:
   - Use Burp Suite to find `POST /api/register`.
   - Import into Postman.
2. **Test Duplicate Usernames**:
   - Register a username (e.g., `testuser`).
   - Attempt to register the same username or variations (e.g., `TestUser`, `TESTUSER`).
3. **Analyze Responses**:
   - Check if duplicates are accepted or create conflicts.
   - Expected secure response: HTTP 400 with “Username already exists.”
4. **Document Findings**:
   - Save Postman requests and responses.

**Postman Commands**:
- **Command 1**: Register username:
  ```
  New Request -> POST http://example.com/api/register -> Body -> JSON: {"username": "testuser", "email": "test1@example.com", "password": "Secure123"} -> Send
  ```
- **Command 2**: Test case-insensitive duplicate:
  ```
  New Request -> POST http://example.com/api/register -> Body -> JSON: {"username": "TestUser", "email": "test2@example.com", "password": "Secure123"} -> Send
  ```

**Example Vulnerable Response**:
```
[Second attempt]
HTTP/1.1 200 OK
{"status": "Account created"}
```

**Remediation**:
- Ensure case-sensitive uniqueness:
  ```python
  @app.post('/api/register')
  def register():
      username = request.json['username']
      if db.users.find_one({'username': {'$regex': f'^{username}$', '$options': 'i'}}):
          return jsonify({'error': 'Username already exists'}), 400
      return jsonify({'status': 'success'})
  ```

### **3. Test Predictable Usernames with cURL**

Attempt to register common or sequential usernames to identify predictability.

**Steps**:
1. **Identify Registration Endpoint**:
   - Use Burp Suite to find `POST /register`.
2. **Test Common Usernames**:
   - Try usernames like `admin`, `user`, `test`, or sequential IDs (e.g., `user1`, `user2`).
   - Use cURL to send registration requests.
3. **Analyze Responses**:
   - Check if predictable usernames are accepted (HTTP 200).
   - Expected secure response: Rejection of common or sequential usernames.
4. **Document Findings**:
   - Save cURL commands and responses.

**cURL Commands**:
- **Command 1**: Test common username:
  ```bash
  curl -i -X POST -d "username=admin&email=test1@example.com&password=Secure123" http://example.com/register
  ```
- **Command 2**: Test sequential username:
  ```bash
  curl -i -X POST -d "username=user1&email=test2@example.com&password=Secure123" http://example.com/register
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
{"status": "Account created"}
```

**Remediation**:
- Block predictable usernames:
  ```php
  if (preg_match('/^(admin|user\d+|test)$/i', $username)) {
      return json_encode(['error' => 'Username not allowed']);
  }
  ```

### **4. Bypass Client-Side Validation with Browser Developer Tools**

Test if username validation relies on client-side checks that can be bypassed.

**Steps**:
1. **Open Browser Developer Tools**:
   - Load `https://example.com/register` and press `F12` in Chrome/Firefox.
2. **Inspect Form**:
   - Check for JavaScript validation (e.g., `onsubmit` checks for username length).
   - Identify hidden fields or constraints (e.g., `minlength="6"`).
3. **Bypass Validation**:
   - Disable JavaScript: `Settings -> Disable JavaScript` (Firefox) or modify the form.
   - Submit weak usernames (e.g., `a`, `admin`).
   - Alternatively, edit form attributes (e.g., remove `minlength`).
4. **Analyze Responses**:
   - Check if weak usernames are accepted server-side.
   - Expected secure response: Server-side rejection.
5. **Document Findings**:
   - Save screenshots and network logs.

**Browser Developer Tools Commands**:
- **Command 1**: Disable JavaScript:
  ```
  Network tab -> Submit form with username=admin after disabling JavaScript -> Check response
  ```
- **Command 2**: Modify form validation:
  ```
  Elements tab -> Find <input name="username" minlength="6"> -> Edit as HTML -> Remove minlength -> Submit form with username=a
  ```

**Example Vulnerable Script**:
```html
<input name="username" minlength="6" oninput="validateUsername(this)">
<script>
function validateUsername(input) {
    if (input.value.length < 6) input.setCustomValidity('Username too short');
}
</script>
```

**Remediation**:
- Enforce server-side validation:
  ```javascript
  app.post('/register', (req, res) => {
      const username = req.body.username;
      if (username.length < 6) {
          return res.status(400).json({ error: 'Username too short' });
      }
      // Register user
  });
  ```

### **5. Test Enumeration Risks with Python Requests**

Analyze registration responses for username enumeration risks during policy enforcement.

**Steps**:
1. **Write Python Script**:
   - Create a script to test username registration with existing and new usernames:
     ```python
     import requests

     url = 'http://example.com/register'
     usernames = ['admin', 'testuser', 'newuser123']
     for username in usernames:
         data = {
             'username': username,
             'email': f'{username}@example.com',
             'password': 'Secure123'
         }
         response = requests.post(url, data=data)
         print(f"Username={username}, Status={response.status_code}, Response={response.text[:100]}")
         if 'already exists' in response.text.lower():
             print("Enumeration risk: Username existence disclosed")
     ```
2. **Run Script**:
   - Execute: `python3 test_username_policy.py`.
   - Analyze responses for enumeration clues (e.g., “Username already exists”).
3. **Verify Findings**:
   - Compare responses for existing vs. new usernames.
   - Expected secure response: Generic errors (e.g., “Registration failed”).
4. **Document Results**:
   - Save script output.

**Python Commands**:
- **Command 1**: Run username policy test:
  ```bash
  python3 test_username_policy.py
  ```
- **Command 2**: Test single registration:
  ```bash
  python3 -c "import requests; r=requests.post('http://example.com/register', data={'username': 'admin', 'email': 'admin@example.com', 'password': 'Secure123'}); print(r.status_code, r.text[:100])"
  ```

**Example Vulnerable Output**:
```
Username=admin, Status=400, Response={"error": "Username already exists"}
Enumeration risk: Username existence disclosed
```

**Remediation**:
- Use generic error messages:
  ```python
  @app.post('/register')
  def register():
      username = request.form['username']
      if db.users.find_one({'username': username}):
          return jsonify({'error': 'Registration failed'}), 400
      return jsonify({'status': 'success'})
  ```

## **Real-World Test Cases**

These test cases extend OWASP’s WSTG-IDNT-05 with practical scenarios based on common weak username policy vulnerabilities observed in penetration testing.

### **Test 1: Weak Username Acceptance**

**Objective**: Verify if weak or predictable usernames are rejected.

**Steps**:
1. **Submit Weak Username**:
   - Use Burp Suite to intercept `POST /register`.
   - Command:
     ```
     HTTP History -> Select POST /register -> Send to Repeater -> Change username=test to username=admin -> Click Send
     ```
2. **Analyze Response**:
   - Check if `admin` is accepted (HTTP 200).
   - Expected secure response: HTTP 400 with “Username not allowed.”
3. **Verify with cURL**:
   - Command:
     ```bash
     curl -i -X POST -d "username=admin&email=test@example.com&password=Secure123" http://example.com/register
     ```
4. **Save Results**:
   - Save Burp Suite and cURL outputs.

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
{"status": "Account created"}
```

**Remediation**:
```javascript
app.post('/register', (req, res) => {
    const username = req.body.username;
    if (username.match(/^(admin|user\d+|test)$/i)) {
        return res.status(400).json({ error: 'Username not allowed' });
    }
    // Register user
});
```

### **Test 2: Case-Insensitive Duplicates**

**Objective**: Test if case-insensitive usernames create duplicates.

**Steps**:
1. **Register Username**:
   - Use Postman to register `testuser`.
   - Command:
     ```
     New Request -> POST http://example.com/api/register -> Body -> JSON: {"username": "testuser", "email": "test1@example.com", "password": "Secure123"} -> Send
     ```
2. **Test Duplicate**:
   - Command:
     ```
     New Request -> POST http://example.com/api/register -> Body -> JSON: {"username": "TestUser", "email": "test2@example.com", "password": "Secure123"} -> Send
     ```
3. **Analyze Response**:
   - Check if `TestUser` is accepted.
   - Expected secure response: HTTP 400 with “Username exists.”
4. **Save Results**:
   - Save Postman outputs.

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
{"status": "Account created"}
```

**Remediation**:
```php
$username = $_POST['username'];
if ($db->query("SELECT * FROM users WHERE UPPER(username) = UPPER(?)", [$username])->num_rows > 0) {
    return json_encode(['error' => 'Username already exists']);
}
```

### **Test 3: Sensitive Username Data**

**Objective**: Test if usernames can include sensitive information.

**Steps**:
1. **Submit Sensitive Username**:
   - Use Burp Suite to intercept `POST /register`.
   - Command:
     ```
     HTTP History -> Select POST /register -> Send to Repeater -> Change username=test to username=test@email.com -> Click Send
     ```
2. **Analyze Response**:
   - Check if `test@email.com` is accepted.
   - Expected secure response: HTTP 400 with “Invalid username.”
3. **Verify with cURL**:
   - Command:
     ```bash
     curl -i -X POST -d "username=test@email.com&email=test@example.com&password=Secure123" http://example.com/register
     ```
4. **Save Results**:
   - Save Burp Suite and cURL outputs.

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
{"status": "Account created"}
```

**Remediation**:
```python
@app.post('/register')
def register():
    username = request.form['username']
    if '@' in username or len(username) < 6:
        return jsonify({'error': 'Invalid username'}), 400
    return jsonify({'status': 'success'})
```

### **Test 4: Client-Side Validation Bypass**

**Objective**: Bypass client-side username checks to test server-side enforcement.

**Steps**:
1. **Inspect Form**:
   - Use Browser Developer Tools to check registration form.
   - Command:
     ```
     Elements tab -> Find <input name="username" minlength="6"> -> Edit as HTML -> Remove minlength -> Submit form with username=a
     ```
2. **Submit Weak Username**:
   - Command:
     ```
     Network tab -> Submit form with username=admin after disabling JavaScript -> Check response
     ```
3. **Analyze Response**:
   - Check if `a` or `admin` is accepted.
   - Expected secure response: Server-side rejection.
4. **Save Results**:
   - Save screenshots.

**Example Vulnerable Response**:
```json
{
  "status": "Account created"
}
```

**Remediation**:
```javascript
app.post('/register', (req, res) => {
    const username = req.body.username;
    if (username.length < 6 || username.match(/^(admin|user\d+|test)$/i)) {
        return res.status(400).json({ error: 'Invalid username' });
    }
    // Register user
});
```

## **Additional Tips**

- **Test All Scenarios**: Try usernames that are short, common, sequential, sensitive, or malicious.
- **Combine Tools**: Use Burp Suite for manual testing, Postman for APIs, and Python for automation.
- **Gray-Box Testing**: If documentation is available, verify username policy requirements.
- **Document Thoroughly**: Save all commands, responses, and screenshots in a report.
- **Ethical Considerations**: Obtain explicit permission for testing, as registering multiple accounts or testing enumeration may trigger security alerts or violate terms of service.
- **References**: [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html), [OWASP Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html).