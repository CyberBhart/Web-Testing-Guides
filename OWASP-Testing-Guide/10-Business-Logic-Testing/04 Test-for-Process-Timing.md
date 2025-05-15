# **Test for Process Timing**

## **Overview**

Testing for process timing (WSTG-BUSL-04) involves assessing whether a web application is vulnerable to race conditions or timing-based attacks that exploit the timing of operations in its business logic. According to OWASP, race conditions occur when multiple processes or threads access shared resources concurrently without proper synchronization, allowing attackers to manipulate the sequence or timing of actions to bypass logic (e.g., simultaneous transactions to overspend an account). This test focuses on identifying vulnerabilities where the application's failure to enforce proper timing controls allows unauthorized actions or data corruption.

**Impact**: Weak process timing controls can lead to:
- Financial fraud (e.g., double-spending in payment systems).
- Data corruption (e.g., inconsistent account balances).
- Unauthorized actions (e.g., bypassing approval workflows).
- Service disruption due to exploited race conditions.

This guide provides a step-by-step methodology for testing process timing, adhering to OWASP’s WSTG-BUSL-04, with practical tools, real-world test cases, and remediation strategies for professional penetration testing.

## **Testing Tools**

The following tools are recommended for testing process timing vulnerabilities, suitable for both novice and experienced testers:

- **Burp Suite Community Edition**: Intercepts and manipulates HTTP requests to simulate simultaneous actions.
- **OWASP ZAP**: Open-source web proxy for analyzing and timing request sequences.
- **cURL**: Command-line tool for sending rapid or timed HTTP requests.
- **Postman**: Tool for testing API endpoints with controlled timing.
- **Browser Developer Tools**: Built-in browser tools (Chrome/Firefox) for inspecting request timing.
- **FoxyProxy**: Browser extension to route traffic through Burp Suite or OWASP ZAP.
- **Charles Proxy**: Proxy tool for analyzing and timing mobile or web traffic.
- **Python Requests Library**: Python library for scripting simultaneous or timed HTTP requests.
- **Apache JMeter**: Load testing tool for simulating multiple concurrent requests.
- **Selenium WebDriver**: Automation tool for scripting browser-based timing tests.

### **Tool Setup Instructions**

1. **Burp Suite Community Edition**:
   - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
   - Configure browser proxy: 127.0.0.1:8080 (Firefox recommended).
   - Enable “Intercept” in Proxy tab.
2. **OWASP ZAP**:
   - Download from [owasp.org](https://www.zaproxy.org/download/).
   - Run: `./zap.sh` (Linux) or `zap.bat` (Windows).
   - Configure proxy: 127.0.0.1:8080.
3. **cURL**:
   - Install on Linux: `sudo apt install curl`.
   - Install on Windows/Mac: Pre-installed or download from [curl.se](https://curl.se/).
   - Verify: `curl --version`.
4. **Postman**:
   - Download from [postman.com](https://www.postman.com/downloads/).
   - Install and create a free account.
   - Verify: Open Postman and check version.
5. **Browser Developer Tools**:
   - Access in Chrome/Firefox: Press `F12` or right-click and select “Inspect”.
   - No setup required.
6. **FoxyProxy**:
   - Install as a browser extension (Chrome/Firefox).
   - Configure to route traffic through Burp Suite or OWASP ZAP (127.0.0.1:8080).
7. **Charles Proxy**:
   - Download from [charlesproxy.com](https://www.charlesproxy.com/).
   - Configure proxy: 127.0.0.1:8888.
   - Verify: Start proxy and check traffic.
8. **Python Requests Library**:
   - Install Python: `sudo apt install python3`.
   - Install Requests: `pip install requests`.
   - Verify: `python3 -c "import requests; print(requests.__version__)"`.
9. **Apache JMeter**:
   - Download from [jmeter.apache.org](https://jmeter.apache.org/download_jmeter.cgi).
   - Extract and run: `bin/jmeter.sh` (Linux) or `bin/jmeter.bat` (Windows).
   - Verify: Check JMeter GUI.
10. **Selenium WebDriver**:
    - Install Python: `sudo apt install python3`.
    - Install Selenium: `pip install selenium`.
    - Download browser driver (e.g., ChromeDriver from [chromedriver.chromium.org](https://chromedriver.chromium.org/)).
    - Verify: `python3 -c "from selenium import webdriver; print(webdriver.__version__)"`.

## **Testing Methodology**

This methodology follows OWASP’s black-box approach for WSTG-BUSL-04, focusing on simulating concurrent or precisely timed actions to exploit race conditions or timing vulnerabilities in business logic.

### **1. Identify Time-Sensitive Workflows with Burp Suite**

Map workflows where timing could affect outcomes, such as transactions or approvals.

**Steps**:
1. **Configure Burp Suite**:
   - Set up browser proxy (127.0.0.1:8080).
   - Add `example.com` to the target scope in the “Target” tab.
2. **Interact with the Application**:
   - Perform actions like transferring funds, placing orders, or approving requests.
   - Capture requests in Burp Suite’s “HTTP History”.
3. **Identify Time-Sensitive Workflows**:
   - Look for operations involving shared resources (e.g., account balances, inventory).
   - Note requests with sequential steps (e.g., `POST /transfer`, `POST /confirm`).
4. **Document Findings**:
   - Save request details (e.g., URLs, parameters) in Burp Suite’s “Logger”.

**Example Request**:
```
POST /transfer HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded

account_id=123&amount=100.00
```

**Remediation**:
- Implement locking mechanisms:
  ```php
  $lock = acquire_lock('account_' . $account_id);
  if (!$lock) {
      die('Transaction in progress');
  }
  // Process transfer
  release_lock($lock);
  ```

### **2. Simulate Concurrent Requests with Burp Suite Intruder**

Test for race conditions by sending multiple requests simultaneously.

**Steps**:
1. **Send to Intruder**:
   - Right-click a request in “HTTP History” and select “Send to Intruder”.
   - Set payload positions (e.g., `amount=100.00`).
2. **Configure Intruder**:
   - Use “Cluster Bomb” mode to send multiple identical requests.
   - Set threads to 10 for concurrent execution.
   - Run the attack.
3. **Analyze Results**:
   - Check if multiple requests are processed (e.g., double-spending $100.00).
   - Look for inconsistent states (e.g., negative balance).
4. **Document Findings**:
   - Save Intruder results and server responses.

**Example Vulnerable Response**:
- Request 1: `Transfer $100.00` -> `Balance: $0.00`
- Request 2: `Transfer $100.00` -> `Balance: -$100.00`

**Remediation**:
- Use atomic transactions:
  ```javascript
  const db = require('database');
  await db.transaction(async (trx) => {
      const balance = await trx('accounts').where('id', account_id).select('balance');
      if (balance[0].balance < amount) throw new Error('Insufficient funds');
      await trx('accounts').where('id', account_id).decrement('balance', amount);
  });
  ```

### **3. Test API Timing with Postman**

Test API endpoints for timing vulnerabilities in concurrent operations.

**Steps**:
1. **Identify API Endpoints**:
   - Use Burp Suite to find APIs (e.g., `/api/v1/transfer`).
   - Import endpoints into Postman.
2. **Send Concurrent Requests**:
   - Create a Postman Collection with multiple `POST /api/v1/transfer` requests.
   - Use Postman’s Collection Runner with minimal delay (e.g., 0ms) to simulate concurrency.
   - Run with 5 iterations.
3. **Analyze Response**:
   - Check if multiple transactions are processed (e.g., overspending).
   - Look for errors or inconsistent data.
4. **Document Findings**:
   - Save Postman run results and responses.

**Example Vulnerable API Response**:
```json
[
  {"status": "success", "balance": 0.00},
  {"status": "success", "balance": -100.00}
]
```

**Remediation**:
- Implement mutex locks for APIs:
  ```python
  from threading import Lock
  lock = Lock()
  def transfer(account_id, amount):
      with lock:
          account = db.query(f"SELECT balance FROM accounts WHERE id={account_id} FOR UPDATE")
          if account.balance < amount:
              raise ValueError("Insufficient funds")
          db.execute(f"UPDATE accounts SET balance = balance - {amount} WHERE id={account_id}")
  ```

### **4. Automate Concurrent Requests with Apache JMeter**

Use JMeter to simulate high-concurrency scenarios and test for race conditions.

**Steps**:
1. **Create JMeter Test Plan**:
   - Add a Thread Group with 10 threads and 1 loop.
   - Add an HTTP Request sampler for `POST /transfer` with parameters (e.g., `account_id=123`, `amount=100.00`).
   - Add a Constant Timer with 0ms delay.
2. **Run Test**:
   - Start JMeter: `bin/jmeter.sh`.
   - Execute the test plan.
3. **Analyze Results**:
   - Check the “View Results Tree” for responses.
   - Verify if multiple transfers are processed, leading to incorrect balances.
4. **Document Findings**:
   - Save JMeter results and server responses.

**Example Vulnerable Result**:
- 10 requests -> Balance: `-900.00` (expected: reject after first transfer).

**Remediation**:
- Use database row locking:
  ```sql
  BEGIN TRANSACTION;
  SELECT * FROM accounts WHERE id = 123 FOR UPDATE;
  UPDATE accounts SET balance = balance - 100.00 WHERE id = 123 AND balance >= 100.00;
  COMMIT;
  ```

### **5. Script Timing Tests with Python and Selenium**

Automate browser-based timing tests to simulate race conditions.

**Steps**:
1. **Write Python Script**:
   - Use Selenium to open multiple browser instances:
     ```python
     from selenium import webdriver
     from concurrent.futures import ThreadPoolExecutor
     import time

     def transfer_funds(driver_path, url):
         driver = webdriver.Chrome(driver_path)
         driver.get(url)
         driver.find_element_by_name('account_id').send_keys('123')
         driver.find_element_by_name('amount').send_keys('100.00')
         driver.find_element_by_css_selector('input[type=submit]').click()
         result = driver.find_element_by_id('balance').text
         driver.quit()
         return result

     url = 'http://example.com/transfer'
     driver_path = '/path/to/chromedriver'
     with ThreadPoolExecutor(max_workers=5) as executor:
         results = list(executor.map(lambda _: transfer_funds(driver_path, url), range(5)))
     print("Results:", results)
     ```
2. **Run Script**:
   - Execute: `python3 test.py`.
   - Analyze results for inconsistent balances.
3. **Verify Findings**:
   - Cross-check with Burp Suite or JMeter results.
4. **Document Results**:
   - Save script output and screenshots.

**Example Vulnerable Output**:
```
Results: ['Balance: 0.00', 'Balance: -100.00', 'Balance: -200.00', ...]
```

**Remediation**:
- Implement optimistic locking:
  ```php
  $account = DB::select('SELECT balance, version FROM accounts WHERE id = ?', [$account_id]);
  if ($account->balance < $amount) {
      die('Insufficient funds');
  }
  $rows = DB::update('UPDATE accounts SET balance = balance - ?, version = version + 1 WHERE id = ? AND version = ?', [$amount, $account_id, $account->version]);
  if ($rows === 0) {
      die('Transaction conflict');
  }
  ```

## **Real-World Test Cases**

These test cases extend OWASP’s WSTG-BUSL-04 with practical scenarios based on common process timing vulnerabilities observed in penetration testing.

### **Test 1: Double-Spend in Payment System**

Test whether concurrent transfers allow overspending an account balance.

**Steps**:
1. **Capture Request**:
   - Use Burp Suite to capture:
     ```
     POST /transfer HTTP/1.1
     Host: example.com
     account_id=123&amount=100.00
     ```
2. **Send Concurrent Requests**:
   - Use Intruder with 5 threads to send 5 identical requests simultaneously.
3. **Verify**:
   - Check if balance becomes negative (e.g., `-400.00`).

**Example Insecure Finding**:
- Initial Balance: $100.00
- After 5 transfers: `Balance: -$400.00`

**Example Secure Configuration**:
- Use pessimistic locking:
  ```sql
  SELECT * FROM accounts WHERE id = 123 FOR UPDATE;
  ```

**Remediation**:
- Implement database transactions.
- Use locking mechanisms.

### **Test 2: Race Condition in Order Placement**

Test whether concurrent orders deplete inventory incorrectly.

**Steps**:
1. **Capture Request**:
   - In Postman, send:
     ```json
     POST /api/v1/order
     {"item_id": 456, "quantity": 1}
     ```
2. **Send Concurrent Requests**:
   - Use Postman Collection Runner to send 10 orders for an item with 5 units in stock.
3. **Verify**:
   - Check if more than 5 units are ordered.

**Example Insecure Finding**:
- Stock: 5 units
- Orders: 10 units sold

**Example Secure Configuration**:
- Check stock atomically:
  ```python
  with db.transaction():
      stock = db.execute("SELECT quantity FROM inventory WHERE item_id = ? FOR UPDATE", (item_id,)).fetchone()
      if stock.quantity < quantity:
          raise ValueError("Out of stock")
      db.execute("UPDATE inventory SET quantity = quantity - ? WHERE item_id = ?", (quantity, item_id))
  ```

**Remediation**:
- Use row-level locking.
- Validate stock before processing.

### **Test 3: Concurrent Approval Bypass**

Test whether concurrent approval requests bypass workflow controls.

**Steps**:
1. **Capture Request**:
   - Use OWASP ZAP to capture:
     ```
     POST /approve HTTP/1.1
     Host: example.com
     request_id=789&action=approve
     ```
2. **Send Concurrent Requests**:
   - Use JMeter to send 5 approval requests simultaneously.
3. **Verify**:
   - Check if multiple approvals are processed.

**Example Insecure Finding**:
- Request 789: Approved 5 times

**Example Secure Configuration**:
- Use state validation:
  ```javascript
  const request = await db.query('SELECT status FROM requests WHERE id = ? FOR UPDATE', [request_id]);
  if (request.status !== 'pending') {
      throw new Error('Request already processed');
  }
  await db.query('UPDATE requests SET status = ? WHERE id = ?', ['approved', request_id]);
  ```

**Remediation**:
- Lock request records during processing.
- Track request states.

### **Test 4: Timing Attack in Coupon Redemption**

Test whether concurrent coupon redemptions allow multiple uses.

**Steps**:
1. **Automate with Selenium**:
   - Script 5 browser instances to redeem a single-use coupon simultaneously.
2. **Run Script**:
   - Execute the Python script above.
3. **Verify**:
   - Check if coupon is applied multiple times.

**Example Insecure Finding**:
- Coupon: 1 use
- Applied: 5 times

**Example Secure Configuration**:
- Use atomic updates:
  ```php
  $coupon = DB::select('SELECT uses FROM coupons WHERE code = ? FOR UPDATE', [$code]);
  if ($coupon->uses <= 0) {
      die('Coupon exhausted');
  }
  DB::update('UPDATE coupons SET uses = uses - 1 WHERE code = ?', [$code]);
  ```

**Remediation**:
- Implement atomic coupon checks.
- Log redemption attempts.

## **Additional Tips**

- **Map Workflows**: Identify operations involving shared resources (e.g., balances, inventory) to target for timing tests.
- **Combine Tools**: Use Burp Suite for initial capture, JMeter for concurrency, and Selenium for browser-based tests.
- **Gray-Box Testing**: If documentation is available, check for transaction or locking mechanisms.
- **Document Thoroughly**: Save all requests, responses, and test results in a report.
- **Bypass Defenses**: Test with varying delays or high concurrency to uncover subtle race conditions.
- **Stay Ethical**: Obtain explicit permission for active testing, especially high-concurrency tests, to avoid disrupting live systems.
- **Follow Best Practices**: Refer to OWASP’s Business Logic Testing section for additional techniques: [OWASP WSTG Business Logic Testing](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/10-Business_Logic_Testing/).