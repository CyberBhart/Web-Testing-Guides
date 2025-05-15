# **Test Upload of Malicious Files**

## **Overview**

Testing for the upload of malicious files (WSTG-BUSL-09) involves assessing whether a web application can detect and block files containing malicious content, such as exploits, malware, or code designed to harm the system or its users. According to OWASP, vulnerabilities in file upload mechanisms often stem from inadequate server-side validation, allowing attackers to upload files that could trigger code execution, compromise the server, or infect users accessing the files. Unlike WSTG-BUSL-08, which focuses on unexpected file types, this test targets files with harmful payloads, even if they have allowed extensions or MIME types (e.g., a `.jpg` file containing executable code). The goal is to verify the application’s ability to identify and reject malicious files through content analysis or antivirus integration.

**Impact**: Allowing malicious file uploads can lead to:
- Server-side code execution (e.g., uploading a malicious `.php` file).
- Malware distribution to users (e.g., infected PDFs).
- System compromise through exploits (e.g., buffer overflow in file parsers).
- Data breaches or service disruptions due to malicious payloads.

This guide provides a step-by-step methodology for testing the upload of malicious files, adhering to OWASP’s WSTG-BUSL-09, with practical tools, at least two specific commands or configurations per tool for real security testing, real-world test cases, remediation strategies, and ethical considerations for professional penetration testing.

## **Testing Tools**

The following tools are recommended for testing malicious file upload vulnerabilities, with at least two specific commands or configurations provided for each to enable real security testing:

- **Burp Suite Community Edition**: Intercepts and manipulates HTTP requests to test malicious file uploads.
- **cURL**: Command-line tool for crafting and sending malicious file upload requests.
- **Postman**: Tool for testing API-based file uploads with malicious content.
- **Browser Developer Tools**: Built-in browser tools (Chrome/Firefox) for inspecting and modifying upload forms.
- **Python Requests Library**: Python library for scripting custom malicious file upload requests.

### **Tool Setup Instructions**

1. **Burp Suite Community Edition**:
   - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
   - Configure browser proxy: 127.0.0.1:8080 (Firefox recommended).
   - Enable “Intercept” in Proxy tab.
   - Verify: Start Burp and check proxy functionality.
2. **cURL**:
   - Install on Linux: `sudo apt install curl`.
   - Install on Windows/Mac: Pre-installed or download from [curl.se](https://curl.se/).
   - Verify: `curl --version`.
3. **Postman**:
   - Download from [postman.com](https://www.postman.com/downloads/).
   - Install and create a free account.
   - Verify: Open Postman and check version.
4. **Browser Developer Tools**:
   - Access in Chrome/Firefox: Press `F12` or right-click and select “Inspect”.
   - No setup required.
5. **Python Requests Library**:
   - Install Python: `sudo apt install python3`.
   - Install Requests: `pip install requests`.
   - Verify: `python3 -c "import requests; print(requests.__version__)"`.

## **Testing Methodology**

This methodology follows OWASP’s black-box approach for WSTG-BUSL-09, focusing on attempting to upload files with malicious content and verifying whether the application detects and rejects them. **Ethical Note**: Use safe, non-destructive test files (e.g., EICAR test file) in controlled environments with explicit permission to avoid harm.

### **1. Identify File Upload Functionality with Burp Suite**

Locate file upload mechanisms and assess their validation mechanisms.

**Steps**:
1. **Configure Burp Suite**:
   - Set up browser proxy (127.0.0.1:8080).
   - Add `example.com` to the target scope in the “Target” tab.
2. **Interact with the Application**:
   - Navigate to upload features (e.g., profile picture upload, document submission).
   - Capture upload requests in Burp Suite’s “HTTP History”.
3. **Analyze Upload Requests**:
   - Identify endpoints (e.g., `POST /upload`), parameters (e.g., `file`), and headers (e.g., `Content-Type`).
   - Note any validation messages or restrictions (e.g., “Only .jpg, .png allowed”).
4. **Document Findings**:
   - Save request details in Burp Suite’s “Logger”.

**Burp Suite Commands**:
- **Command 1**: Capture and analyze a file upload request:
  ```
  Proxy tab -> HTTP History -> Filter by example.com -> Select POST /upload -> Inspect Request tab -> Note Content-Type (e.g., multipart/form-data) and file parameter -> Add to Site Map
  ```
- **Command 2**: Use Repeater to upload the EICAR test file disguised as a `.jpg`:
  ```
  Right-click POST /upload in HTTP History -> Send to Repeater -> Modify file content to "X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" -> Change filename to "eicar.jpg" -> Click "Send" -> Check response in "Response" pane
  ```

**Example Request**:
```
POST /upload HTTP/1.1
Host: example.com
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary123

------WebKitFormBoundary123
Content-Disposition: form-data; name="file"; filename="image.jpg"
Content-Type: image/jpeg

[Binary JPEG Data]
------WebKitFormBoundary123--
```

**Remediation**:
- Scan files for malicious content:
  ```php
  exec('clamscan ' . escapeshellarg($file['tmp_name']), $output, $return);
  if ($return !== 0) {
      die('Malicious file detected');
  }
  ```

### **2. Upload Malicious Test Files with cURL**

Test whether the application detects and blocks files with malicious content, such as the EICAR test file.

**Steps**:
1. **Create Test Files**:
   - Create an EICAR test file (`eicar.com`) with content: `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`.
   - Create a mock malicious file (`test.jpg`) with embedded script content (e.g., `<?php echo 'test'; ?>`).
2. **Send Upload Requests**:
   - Use cURL to upload test files, modifying filenames or MIME types to bypass checks.
3. **Analyze Response**:
   - Check if the file is rejected (e.g., HTTP 400) or accepted (e.g., HTTP 200).
   - Verify if the uploaded file is accessible or executable.
4. **Document Findings**:
   - Save cURL commands and responses.

**cURL Commands**:
- **Command 1**: Upload the EICAR test file as a `.txt`:
  ```bash
  curl -X POST -F "file=@eicar.com;filename=eicar.txt" -b "session=abc123" http://example.com/upload
  ```
- **Command 2**: Upload a `.jpg` with embedded PHP code:
  ```bash
  curl -X POST -F "file=@test.jpg;filename=image.jpg" -b "session=abc123" http://example.com/upload
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: text/html
File uploaded successfully: /uploads/eicar.txt
```

**Remediation**:
- Validate file content:
  ```python
  import magic
  mime = magic.from_file(file_path, mime=True)
  if mime != 'image/jpeg' or b'<?php' in open(file_path, 'rb').read():
      return jsonify({'error': 'Malicious content detected'}), 400
  ```

### **3. Test API Malicious File Uploads with Postman**

Test API endpoints for detection of malicious file uploads.

**Steps**:
1. **Identify API Endpoints**:
   - Use Burp Suite to find file upload APIs (e.g., `/api/v1/upload`).
   - Import into Postman.
2. **Upload Malicious Files**:
   - Send requests with test files like EICAR or script-embedded files.
   - Modify headers or filenames to bypass restrictions.
3. **Analyze Response**:
   - Check for rejection (e.g., HTTP 400) or acceptance (e.g., HTTP 200).
   - Verify if files are stored or accessible.
4. **Document Findings**:
   - Save Postman requests and responses.

**Postman Commands**:
- **Command 1**: Upload the EICAR test file to an API endpoint:
  ```
  New Request -> POST http://example.com/api/v1/upload -> Body -> form-data -> Key: file, Type: File, Value: eicar.com -> Headers: Cookie: session=abc123 -> Send
  ```
- **Command 2**: Upload a `.png` with embedded malicious script:
  ```
  New Request -> POST http://example.com/api/v1/upload -> Body -> form-data -> Key: file, Type: File, Value: test.png (with <?php echo 'test'; ?>) -> Headers: Content-Type: image/png, Cookie: session=abc123 -> Send
  ```

**Example Vulnerable API Response**:
```json
{
  "status": "success",
  "path": "/uploads/eicar.com"
}
```

**Remediation**:
- Integrate antivirus scanning:
  ```javascript
  const { exec } = require('child_process');
  exec(`clamscan ${file.path}`, (err, stdout, stderr) => {
      if (stdout.includes('Infected files: 1')) {
          return res.status(400).send('Malicious file detected');
      }
  });
  ```

### **4. Bypass Client-Side Validation with Browser Developer Tools**

Test whether client-side checks can be bypassed to upload malicious files.

**Steps**:
1. **Inspect Upload Form**:
   - Open Developer Tools (`F12`) on an upload page (e.g., `http://example.com/upload`).
   - Identify restrictions (e.g., `accept=".jpg,.png"` or JavaScript validation).
2. **Manipulate Form**:
   - Remove `accept` attributes or modify form actions.
   - Upload a malicious test file (e.g., EICAR).
3. **Analyze Response**:
   - Check if the server accepts the file.
   - Verify if the file is stored or executable.
4. **Document Findings**:
   - Save screenshots and responses.

**Browser Developer Tools Commands**:
- **Command 1**: Remove file type restrictions to upload EICAR:
  ```
  Elements tab -> Find <input type="file" accept=".jpg,.png"> -> Right-click -> Edit as HTML -> Remove accept attribute -> Upload eicar.com
  ```
- **Command 2**: Modify form submission to upload a malicious `.jpg`:
  ```
  Network tab -> Upload a file -> Right-click request -> Copy as cURL -> Modify file content to include "<?php echo 'test'; ?>" -> Replay in terminal
  ```

**Example Vulnerable Finding**:
- Uploaded `eicar.com` -> Response: `File uploaded: /uploads/eicar.com`.

**Remediation**:
- Server-side content validation:
  ```php
  $finfo = finfo_open(FILEINFO_MIME_TYPE);
  $mime = finfo_file($finfo, $_FILES['file']['tmp_name']);
  if ($mime !== 'image/jpeg' && $mime !== 'image/png') {
      die('Invalid file type');
  }
  ```

### **5. Script Malicious File Upload Tests with Python Requests**

Automate tests to upload malicious files and evaluate server-side detection.

**Steps**:
1. **Write Python Script**:
   - Create a script to upload test files with malicious content:
     ```python
     import requests

     url = 'http://example.com/upload'
     cookies = {'session': 'abc123'}
     files = [
         ('file', ('eicar.txt', 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*', 'text/plain')),
         ('file', ('image.jpg', '<?php echo "test"; ?>', 'image/jpeg')),
         ('file', ('doc.pdf', '%PDF-1.4\n<script>alert("xss")</script>', 'application/pdf'))
     ]

     for file_data in files:
         response = requests.post(url, files={'file': file_data}, cookies=cookies)
         print(f"File: {file_data[1]}")
         print(f"Status: {response.status_code}")
         print(f"Response: {response.text[:100]}\n")
     ```
2. **Run Script**:
   - Execute: `python3 test.py`.
   - Analyze responses for file acceptance or rejection.
3. **Verify Findings**:
   - Check if uploaded files are accessible (e.g., `http://example.com/uploads/image.jpg`).
4. **Document Results**:
   - Save script output and responses.

**Python Commands**:
- **Command 1**: Run the above script to test malicious file uploads:
  ```bash
  python3 test.py
  ```
- **Command 2**: Modify the script to test a malicious PDF and run:
  ```python
  import requests
  url = 'http://example.com/upload'
  files = {'file': ('doc.pdf', '%PDF-1.4\n<script>alert("xss")</script>', 'application/pdf')}
  cookies = {'session': 'abc123'}
  response = requests.post(url, files=files, cookies=cookies)
  print(f"Status: {response.status_code}")
  print(f"Response: {response.text}")
  ```
  ```bash
  python3 test_pdf.py
  ```

**Example Vulnerable Output**:
```
File: eicar.txt
Status: 200
Response: File uploaded successfully: /uploads/eicar.txt
```

**Remediation**:
- Use antivirus integration:
  ```python
  import subprocess
  result = subprocess.run(['clamscan', file_path], capture_output=True, text=True)
  if 'Infected files: 1' in result.stdout:
      return jsonify({'error': 'Malicious file detected'}), 400
  ```

## **Real-World Test Cases**

These test cases extend OWASP’s WSTG-BUSL-09 with practical scenarios based on common malicious file upload vulnerabilities observed in penetration testing. **Use safe test files like EICAR in controlled environments.**

### **Test 1: Upload EICAR Test File**

Test whether the application detects the EICAR antivirus test file.

**Steps**:
1. **Capture Request**:
   - Use Burp Suite to capture: `POST /upload`.
2. **Upload EICAR**:
   - Use cURL: `curl -X POST -F "file=@eicar.com;filename=eicar.txt" -b "session=abc123" http://example.com/upload`.
3. **Verify**:
   - Check if the file is rejected or stored.

**Example Insecure Finding**:
- Response: `File uploaded: /uploads/eicar.txt`.

**Example Secure Configuration**:
- Scan with ClamAV:
  ```php
  $result = shell_exec('clamscan ' . escapeshellarg($file['tmp_name']));
  if (strpos($result, 'Infected files: 1') !== false) {
      die('Malicious file detected');
  }
  ```

**Remediation**:
- Integrate antivirus scanning.
- Quarantine suspicious files.

### **Test 2: Upload Malicious Image**

Test whether a `.jpg` with embedded PHP code is detected.

**Steps**:
1. **Capture Request**:
   - Use Postman to send: `POST /api/v1/upload`.
2. **Upload Malicious Image**:
   - Use Postman command: Upload `test.jpg` with `<?php echo 'test'; ?>`.
3. **Verify**:
   - Access the file (e.g., `http://example.com/uploads/test.jpg`).
   - Check if PHP executes.

**Example Insecure Finding**:
- Response: `test` (PHP executed).

**Example Secure Configuration**:
- Verify image content:
  ```python
  from PIL import Image
  try:
      Image.open(file).verify()
  except:
      return jsonify({'error': 'Invalid image'}), 400
  ```

**Remediation**:
- Validate file content with libraries like PIL.
- Disable script execution in upload directories.

### **Test 3: Upload Malicious PDF**

Test whether a PDF with embedded scripts is detected.

**Steps**:
1. **Write Python Script**:
   - Use Python command: `python3 test_pdf.py`.
2. **Upload PDF**:
   - Send `doc.pdf` with `<script>alert("xss")</script>`.
3. **Verify**:
   - Check if the file is stored or triggers alerts when opened.

**Example Insecure Finding**:
- Response: `File uploaded: /uploads/doc.pdf`.

**Example Secure Configuration**:
- Scan PDFs:
  ```javascript
  const { exec } = require('child_process');
  exec(`pdftotext ${file.path} -`, (err, stdout) => {
      if (stdout.includes('<script>')) {
          return res.status(400).send('Malicious content detected');
      }
  });
  ```

**Remediation**:
- Parse PDFs for scripts.
- Use antivirus for file scanning.

### **Test 4: Bypass Client-Side Validation**

Test whether client-side checks allow malicious file uploads.

**Steps**:
1. **Inspect Form**:
   - Use Browser Developer Tools to remove `accept=".jpg,.png"`.
2. **Upload EICAR**:
   - Use modified form to upload `eicar.com`.
3. **Verify**:
   - Check if the file is accepted.

**Example Insecure Finding**:
- Response: `File uploaded: /uploads/eicar.com`.

**Example Secure Configuration**:
- Server-side validation:
  ```php
  $finfo = finfo_open(FILEINFO_MIME_TYPE);
  $mime = finfo_file($finfo, $_FILES['file']['tmp_name']);
  if (!in_array($mime, ['image/jpeg', 'image/png', 'application/pdf'])) {
      die('Invalid file type');
  }
  ```

**Remediation**:
- Implement server-side content checks.
- Avoid client-side validation.

## **Additional Tips**

- **Map Upload Points**: Identify all upload functionalities (e.g., profile pictures, documents) to test thoroughly.
- **Use Safe Test Files**: Use the EICAR test file or non-destructive payloads in controlled environments to avoid harm.
- **Combine Tools**: Use Burp Suite for initial capture, cURL for quick tests, and Python for automation.
- **Gray-Box Testing**: If documentation is available, check for antivirus integration or content validation.
- **Document Thoroughly**: Save all commands, responses, and screenshots in a report.
- **Bypass Defenses**: Test with disguised MIME types, double extensions, or embedded payloads to evade detection.
- **Stay Ethical**: Obtain explicit permission for active testing and avoid uploading actual malware to live systems. Use isolated test environments.
- **Follow Best Practices**: Refer to OWASP’s Business Logic Testing section for additional techniques: [OWASP WSTG Business Logic Testing](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/10-Business_Logic_Testing/).