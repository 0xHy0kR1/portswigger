![[file-upload-vulnerabilities.jpg]]

## What are file upload vulnerabilities?
- File upload vulnerabilities are when a web server allows users to upload files to its filesystem without sufficiently validating things like their name, type, contents, or size.
- Failing to properly enforce restrictions on these could mean that even a basic image upload function can be used to upload arbitrary and potentially dangerous files instead.
- This could even include server-side script files that enable remote code execution(RCE).

## What is the impact of file upload vulnerabilities?
**The impact of file upload vulnerabilities generally depends on two key factors:**

- Which aspect of the file the website fails to validate properly, whether that be its size, type, contents, and so on.
- What restrictions are imposed on the file once it has been successfully uploaded.

In the worst case scenario, the file's type isn't validated properly, and the server configuration allows certain types of file (such as `.php` and `.jsp`) to be executed as code. In this case, an attacker could potentially upload a server-side code file that functions as a web shell, effectively granting them full control over the server.

- If the filename isn't validated properly, this could allow an attacker to overwrite critical files simply by uploading a file with the same name.
- If the server is also vulnerable to directory traversal, this could mean attackers are even able to upload files to unanticipated locations.
- Failing to make sure that the size of the file falls within expected thresholds could also enable a form of denial-of-service (DoS) attack, whereby the attacker fills the available disk space.

## How do file upload vulnerabilities arise?

1. **Lack of file type validation:**
	- When a web application does not properly validate the file type being uploaded, an attacker can bypass security measures by changing the file extension or manipulating the file header.
	- For instance, an attacker might upload an executable file with a disguised ".jpg" extension.
2. **Insufficient file size limits:**
	- If there are no appropriate size restrictions on file uploads, attackers can upload large files to exhaust server resources, leading to denial-of-service (DoS) attacks.
3. **Inadequate server-side checks:**
	- missing integrity checks, malware scanning, or insufficient access controls leads to malicious file execution.
4. **Trusting client-side validation alone:**
5. **Directory traversal:**
	- File upload mechanisms that do not properly handle filenames can be exploited for directory traversal attacks.
	- By uploading files with specially crafted names (e.g., "../malicious.php"), attackers can gain unauthorized access to sensitive directories on the server.
6. **Overwriting existing files:**
	- If a web application allows files to be overwritten upon upload without proper permission checks, an attacker can replace important files with malicious ones.
7. **[MIME_types](MIME_types.md) manipulation:**
	- Attackers may attempt to manipulate the MIME type of a file to bypass security controls and force the server to treat a malicious file as a harmless one.

## How do web servers handle requests for static files?

### Introduction
- Web servers handle requests for static files in a straightforward manner, as static files are files that remain unchanged and are served directly from the file system without any processing or modification by the server.
- **Examples of static files** - 
HTML files, CSS stylesheets, JavaScript files, images (e.g., JPEG, PNG), videos, and downloadable documents (e.g., PDF, DOCX).

**Here's a typical process for how web servers handle requests for static files:**

1. **Receiving the HTTP request:** 
	- When a user's web browser or client sends an HTTP request to the web server for a specific URL, the server receives the request.
2. **Parsing the request:**
	- The web server parses the HTTP request to extract information such as the requested URL, HTTP method (GET, POST, etc.), and any additional headers.
3. **Identifying static content:**
	- The server examines the requested URL to determine if it corresponds to a static file.
	- Typically, web servers have a designated directory (often called the "document root") where all static files are stored. If the requested URL matches a file within this directory, the server treats it as a request for static content.
4. **Checking file existence and permissions:**
	- The server checks whether the requested static file exists on the file system and verifies that the necessary read permissions are granted.
	- If the file is not found or cannot be read, the server will respond with an appropriate HTTP error status, such as 404 Not Found or 403 Forbidden.
5. **Sending the static file:**
6. **HTTP response:**
	- The web server sends the HTTP response containing the static file to the client's web browser.
7. **Caching:**
	- To optimize performance, web servers often utilize caching mechanisms to store static files temporarily.

# Tip
The `Content-Type` response header may provide clues as to what kind of file the server thinks it has served. If this header hasn't been explicitly set by the application code, it normally contains the result of the file extension/MIME type mapping.

**A more versatile web shell may look something like this:**
```php
<?php echo system($_GET['command']); ?>
```

**This script enables you to pass an arbitrary system command via a query parameter as follows:**
```php
GET /example/exploit.php?command=id HTTP/1.1
```

