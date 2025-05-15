# **Test Upload of Unexpected File Types**

## **Overview**

Testing for the upload of unexpected file types (WSTG-BUSL-08) involves assessing whether a web application properly restricts file uploads to only approved file types, preventing attackers from uploading unauthorized files that could bypass business logic or harm the system. According to OWASP, vulnerabilities in file upload mechanisms often arise from weak validation, such as relying solely on file extensions or client-side checks, allowing attackers to upload files like scripts or executables that could be executed or cause damage. This test focuses on verifying the application’s ability to reject unapproved file types that may not be inherently malicious but could disrupt functionality or exploit system weaknesses.

**Impact**: Allowing unexpected file types can lead to:
- Execution of unauthorized scripts (e.g., uploading a `.php` file to a web server).
- System compromise through exploitable file types (e.g., `.exe` files).
- Data corruption or application errors due to incompatible formats.
- Increased attack surface by enabling further exploitation (e.g., uploading configuration files).

This guide provides a step-by-step methodology for testing the upload of unexpected file types, adhering to OWASP’s WSTG-BUSL-08, with practical tools, at least two specific commands or configurations per tool for real security testing, real-world test cases, remediation strategies, and ethical considerations for professional penetration testing.

## **Testing Tools**

The following tools are recommended for testing file upload vulnerabilities, with at least two specific commands or configurations provided for each to enable real security testing:

- **Burp Suite Community Edition**: Intercepts and manipulates HTTP requests to test file uploads.
- **cURL**: Command-line tool for crafting and sending file upload requests.
- **Postman**: Tool for testing API-based file uploads.
- **Browser Developer Tools**: Built-in browser tools (Chrome/Firefox) for inspecting and modifying upload forms.
- **Python Requests Library**: Python library for scripting custom file upload requests.

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

This methodology follows OWASP’s black-box approach for WSTG-BUSL-08, focusing on attempting to upload unexpected file types and verifying whether the application rejects them securely.

### **1. Identify File Upload Functionality with Burp Suite**

Locate file upload mechanisms and determine their intended file types.

**Steps**:
1. **Configure Burp Suite**:
   - Set up browser proxy (127.0.0.1:8080).
   - Add `example.com` to the target scope in the “Target” tab.
2. **Interact with the Application**:
   - Navigate to upload features (e.g., profile picture upload, document submission).
   - Capture upload requests in Burp Suite’s “HTTP History”.
3. **Analyze Upload Requests**:
   - Identify endpoints (e.g., `POST /upload`), parameters (e.g., `file`), and headers (e.g., `Content-Type`).
   - Note accepted file types (e.g., `.jpg`, `.pdf`) from form restrictions or responses.
4. **Document Findings**:
   - Save request details in Burp Suite’s “Logger”.

**Burp Suite Commands**:
- **Command 1**: Capture and analyze a file upload request:
  ```
  Proxy tab -> HTTP History -> Filter by example.com -> Select POST /upload -> Inspect Request tab -> Note Content-Type (e.g., multipart/form-data) and file parameter -> Add to Site Map
  ```
- **Command 2**: Use Repeater to upload a `.php` file disguised as a `.jpg`:
  ```
  Right-click POST /upload in HTTP History -> Send to Repeater -> Modify file content to "<?php echo 'test'; ?>" -> Change filename to "test.php.jpg" -> Click "Send" -> Check response in "Response" pane
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
- Validate file types server-side:
  ```php
  $allowed_types = ['image/jpeg', 'image/png', 'application/pdf'];
  if (!in_array($_FILES['file']['type'], $allowed_types)) {
      die('Invalid file type');
  }
  ```

### **2. Upload Unexpected File Types with cURL**

Test whether the application accepts unauthorized file types by uploading files with unexpected extensions or MIME types.

**Steps**:
1. **Create Test Files**:
   - Create a `.php` file (e.g., `test.php` with `<?php echo 'test'; ?>`) and a `.txt` file (e.g., `test.txt` with random text).
2. **Send Upload Requests**:
   - Use cURL to upload unexpected file types.
   - Modify filenames or MIME types to bypass client-side checks.
3. **Analyze Response**:
   - Check if the file is accepted (e.g., HTTP 200) or rejected (e.g., error message).
   - Verify if the uploaded file is accessible (e.g., via a URL).
4. **Document Findings**:
   - Save cURL commands and responses.

**cURL Commands**:
- **Command 1**: Upload a `.php` file disguised as a `.jpg`:
  ```bash
  curl -X POST -F "file=@test.php;filename=image.jpg" -b "session=abc123" http://example.com/upload
  ```
- **Command 2**: Upload a `.txt` file to test non-standard file types:
  ```bash
  curl -X POST -F "file=@test.txt;type=text/plain" -b "session=abc123" http://example.com/upload
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: text/html
File uploaded successfully: /uploads/image.jpg
```

**Remediation**:
- Check file content:
  ```python
  from PIL import Image
  try:
      Image.open(file).verify()
  except:
      return jsonify({'error': 'Invalid image'}), 400
  ```

### **3. Test API File Uploads with Postman**

Test API endpoints for unexpected file type uploads.

**Steps**:
1. **Identify API Endpoints**:
   - Use Burp Suite to find file upload APIs (e.g., `/api/v1/upload`).
   - Import into Postman.
2. **Upload Unexpected Files**:
   - Send requests with unauthorized file types (e.g., `.php`, `.exe`).
   - Modify headers or filenames to bypass restrictions.
3. **Analyze Response**:
   - Check for acceptance (e.g., HTTP 200) or rejection (e.g., HTTP 400).
   - Verify if files are stored or accessible.
4. **Document Findings**:
   - Save Postman requests and responses.

**Postman Commands**:
- **Command 1**: Upload a `.php` file to an API endpoint:
  ```
  New Request -> POST http://example.com/api/v1/upload -> Body -> form-data -> Key: file, Type: File, Value: test.php -> Headers: Cookie: session=abc123 -> Send
  ```
- **Command 2**: Upload a `.txt` file with a fake MIME type:
  ```
  New Request -> POST http://example.com/api/v1/upload -> Body -> form-data -> Key: file, Type: File, Value: test.txt -> Headers: Content-Type: text/plain, Cookie: session=abc123 -> Send
  ```

**Example Vulnerable API Response**:
```json
{
  "status": "success",
  "path": "/uploads/test.php"
}
```

**Remediation**:
- Validate MIME types:
  ```javascript
  const allowedTypes = ['image/jpeg', 'image/png'];
  if (!allowedTypes.includes(req.files.file.mimetype)) {
      res.status(400).send('Invalid file type');
  }
  ```

### **4. Bypass Client-Side Validation with Browser Developer Tools**

Test whether client-side file type restrictions can be bypassed.

**Steps**:
1. **Inspect Upload Form**:
   - Open Developer Tools (`F12`) on an upload page (e.g., `http://example.com/upload`).
   - Identify file input restrictions (e.g., `accept=".jpg,.png"`).
2. **Manipulate Form**:
   - Remove or modify `accept` attributes.
   - Upload an unexpected file type (e.g., `.php`).
3. **Analyze Response**:
   - Check if the server accepts the file.
   - Verify if the file is stored or executable.
4. **Document Findings**:
   - Save screenshots and responses.

**Browser Developer Tools Commands**:
- **Command 1**: Remove file type restrictions from an upload form:
  ```
  Elements tab -> Find <input type="file" accept=".jpg,.png"> -> Right-click -> Edit as HTML -> Remove accept attribute -> Upload test.php
  ```
- **Command 2**: Change filename in form submission:
  ```
  Network tab -> Upload a file -> Right-click request -> Copy as cURL -> Modify filename to test.php.jpg -> Replay in terminal
  ```

**Example Vulnerable Finding**:
- Uploaded `test.php` -> Response: `File uploaded: /uploads/test.php`.

**Remediation**:
- Avoid client-side validation:
  ```php
  $finfo = finfo_open(FILEINFO_MIME_TYPE);
  $mime = finfo_file($finfo, $_FILES['file']['tmp_name']);
  if (!in_array($mime, ['image/jpeg', 'image/png'])) {
      die('Invalid file type');
  }
  ```

### **5. Script File Upload Tests with Python Requests**

Automate tests to upload unexpected file types and evaluate server-side validation.

**Steps**:
1. **Write Python Script**:
   - Create a script to upload various file types:
     ```python
     import requests

     url = 'http://example.com/upload'
     cookies = {'session': 'abc123'}
     files = [
         ('file', ('image.jpg', '<?php echo "test"; ?>', 'image/jpeg')),
         ('file', ('script.php', '<?php echo "test"; ?>', 'text/php')),
         ('file', ('text.txt', 'Sample text', 'text/plain'))
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
   - Check if uploaded files are accessible (e.g., `http://example.com/uploads/script.php`).
4. **Document Results**:
   - Save script output and responses.

**Python Commands**:
- **Command 1**: Run the above script to test multiple file types:
  ```bash
  python3 test.py
  ```
- **Command 2**: Modify the script to test a double-extension file and run:
  ```python
  import requests
  url = 'http://example.com/upload'
  files = {'file': ('test.php.jpg', '<?php echo "test"; ?>', 'image/jpeg')}
  cookies = {'session': 'abc123'}
  response = requests.post(url, files=files, cookies=cookies)
  print(f"Status: {response.status_code}")
  print(f"Response: {response.text}")
  ```
  ```bash
  python3 test_double_extension.py
  ```

**Example Vulnerable Output**:
```
File: script.php
Status: 200
Response: File uploaded successfully: /uploads/script.php
```

**Remediation**:
- Verify file extensions and content:
  ```python
  import magic
  allowed_extensions = ['jpg', 'png', 'pdf']
  file_ext = file.filename.rsplit('.', 1)[-1].lower()
  mime = magic.from_buffer(file.read(1024), mime=True)
  if file_ext not in allowed_extensions or mime not in ['image/jpeg', 'image/png', 'application/pdf']:
      return jsonify({'error': 'Invalid file'}), 400
  ```

## **Real-World Test Cases**

These test cases extend OWASP’s WSTG-BUSL-08 with practical scenarios based on common file upload vulnerabilities observed in penetration testing.

### **Test 1: Upload a PHP Script**

Test whether a `.php` file can be uploaded and executed.

**Steps**:
1. **Capture Request**:
   - Use Burp Suite to capture: `POST /upload`.
2. **Upload PHP File**:
   - Use cURL: `curl -X POST -F "file=@test.php;filename=image.jpg" -b "session=abc123" http://example.com/upload`.
3. **Verify**:
   - Access the file (e.g., `http://example.com/uploads/image.jpg`).
   - Check if PHP code executes.

**Example Insecure Finding**:
- Response: `test` (PHP executed).

**Example Secure Configuration**:
- Restrict file types:
  ```php
  if (!in_array(pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION), ['jpg', 'png'])) {
      die('Invalid extension');
  }
  ```

**Remediation**:
- Validate file content and extensions.
- Disable script execution in upload directories.

### **Test 2: Upload a Text File**

Test whether a non-standard `.txt` file is accepted.

**Steps**:
1. **Capture Request**:
   - Use Postman to send: `POST /api/v1/upload`.
2. **Upload Text File**:
   - Use Postman command: Upload `test.txt` with `Content-Type: text/plain`.
3. **Verify**:
   - Check if the file is stored or accessible.

**Example Insecure Finding**:
- Response: `File uploaded: /uploads/test.txt`.

**Example Secure Configuration**:
- Check MIME types:
  ```javascript
  if (!['image/jpeg', 'image/png'].includes(req.files.file.mimetype)) {
      res.status(400).send('Invalid file type');
  }
  ```

**Remediation**:
- Restrict uploads to specific MIME types.
- Scan files for valid content.

### **Test 3: Bypass Client-Side Restrictions**

Test whether client-side file type checks can be bypassed.

**Steps**:
1. **Inspect Form**:
   - Use Browser Developer Tools to remove `accept=".jpg,.png"`.
2. **Upload PHP File**:
   - Use modified form to upload `test.php`.
3. **Verify**:
   - Check if the file is accepted.

**Example Insecure Finding**:
- Response: `File uploaded: /uploads/test.php`.

**Example Secure Configuration**:
- Server-side validation:
  ```python
  from magic import Magic
  mime = Magic(mime=True)
  if mime.from_file(file.path) not in ['image/jpeg', 'image/png']:
      return jsonify({'error': 'Invalid file'}), 400
  ```

**Remediation**:
- Implement server-side MIME type checks.
- Avoid client-side restrictions.

### **Test 4: Double-Extension File Upload**

Test whether a file with a double extension (e.g., `test.php.jpg`) is accepted.

**Steps**:
1. **Write Python Script**:
   - Use Python command: `python3 test_double_extension.py`.
2. **Upload File**:
   - Send `test.php.jpg` with PHP content.
3. **Verify**:
   - Check if the file is executable.

**Example Insecure Finding**:
- Response: `File uploaded: /uploads/test.php.jpg` (executes as PHP).

**Example Secure Configuration**:
- Strict extension check:
  ```php
  $ext = pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION);
  if ($ext !== 'jpg' && $ext !== 'png') {
      die('Invalid file extension');
  }
  ```

**Remediation**:
- Check final extension only.
- Configure server to deny script execution.

## **Additional Tips**

- **Map Upload Points**: Identify all upload functionalities (e.g., profile pictures, documents) to test thoroughly.
- **Combine Tools**: Use Burp Suite for initial capture, cURL for quick tests, and Python for automation.
- **Gray-Box Testing**: If documentation is available, check for file validation or storage logic.
- **Document Thoroughly**: Save all commands, responses, and screenshots in a report.
- **Bypass Defenses**: Test with double extensions, fake MIME types, or null bytes to evade validation.
- **Stay Ethical**: Obtain explicit permission for active testing and avoid uploading harmful files to live systems.
- **Follow Best Practices**: Refer to OWASP’s Business Logic Testing section for additional techniques: [OWASP WSTG Business Logic Testing](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/10-Business_Logic_Testing/).