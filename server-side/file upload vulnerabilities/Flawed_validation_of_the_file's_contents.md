## Introduction
- Instead of implicitly trusting the `Content-Type` specified in a request, more secure servers try to verify that the contents of the file actually match what is expected.
- In the case of an image upload function, the server might try to verify certain intrinsic properties of an image, such as its dimensions.
- If you try uploading a PHP script, for example, it won't have any dimensions at all. Therefore, the server can deduce that it can't possibly be an image, and reject the upload accordingly.
- Similarly, certain file types may always contain a specific sequence of bytes in their header or footer. These can be used like a fingerprint or signature to determine whether the contents match the expected type.
**Example** - 
JPEG files always begin with the bytes `FF D8 FF`.
- This is a much more robust way of validating the file type, but even this isn't foolproof. Using special tools, such as ExifTool, it can be easy to create a polyglot PHP/JPG file containing malicious code within its metadata.
**Polygot** 
- In simpler terms, it's a file that serves as more than one type of data. 
- Polyglot files are often designed to exploit the way different software interprets file formats or to achieve specific functionalities.
**PHP/JPG file:**
- This likely refers to a file that is simultaneously interpreted as both a PHP script and a JPG image file.
- In other words, the same file can be executed as PHP code and displayed as an image.
- This kind of file can be used for various purposes, including bypassing security measures or delivering malicious code in a disguised manner.
Combining these concepts, a "polyglot PHP/JPG file" would be a file that is designed to be both a PHP script and a JPG image file simultaneously
## Steps to solve lab
### Desc - Remote code execution via polyglot web shell upload
**Our end goal** - upload a basic PHP web shell, then use it to exfiltrate the contents of the file `/home/carlos/secret`. Submit this secret using the button provided in the lab banner.

1. Login with the given credentials(wiener:peter).
2. Log in and attempt to upload the script as your avatar. Observe that the server successfully blocks you from uploading files that aren't images, even if you try using some of the techniques you've learned in previous labs.
![[file-upload-vulnerabilities20.png]]

3. Now, we are going to use `exiftool` to create a polyglot PHP/JPG file that is fundamentally a normal image, but contains your PHP payload in its metadata.
**Command** - 
```python
exiftool -Comment="<?php echo 'START '. file_get_contents('/home/carlos/secret') .' END'; ?>" test.jpg -o polygot.php
```
This adds your PHP payload to the image's `Comment` field, then saves the image with a `.php` extension.
![[file-upload-vulnerabilities21.png]]

4. Now, just upload the `polygot.php` and submit the content of `secret` file.
![[file-upload-vulnerabilities22.png]]
