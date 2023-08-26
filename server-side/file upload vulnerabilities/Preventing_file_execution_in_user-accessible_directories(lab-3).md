## Introduction
- While it's clearly better to prevent dangerous file types being uploaded in the first place, the second line of defense is to stop the server from executing any scripts that do slip through the net.
- As a precaution, servers generally only run scripts whose MIME type they have been explicitly configured to execute.
	- Otherwise, they may just return some kind of error message or, in some cases, serve the contents of the file as plain text instead:
![[file-upload-vulnerabilities7.png]]
This behavior is potentially interesting in its own right, as it may provide a way to leak source code, but it nullifies any attempt to create a web shell.
This kind of configuration often differs between directories.

- A directory to which user-supplied files are uploaded will likely have much stricter controls than other locations on the filesystem that are assumed to be out of reach for end users.
	- If you can find a way to upload a script to a different directory that's not supposed to contain user-supplied files, the server may execute your script after all.

#### Tip - 
Web servers often use the `filename` field in `multipart/form-data` requests to determine the name and location where the file should be saved.

You should also note that even though you may send all of your requests to the same domain name, this often points to a reverse proxy server of some kind, such as a load balancer.
Your requests will often be handled by additional servers behind the scenes, which may also be configured differently.

## Steps to solve lab
### Desc - Web shell upload via path traversal

**Our end goal** - upload a basic PHP web shell and use it to exfiltrate the contents of the file `/home/carlos/secret`. Submit this secret using the button provided in the lab banner.

**Pre-requisite** --> In Burp, go to **Proxy > HTTP history**. Click the filter bar to open the **Filter settings** dialog. Under **Filter by MIME type**, enable the **Images** checkbox, then apply your changes

1. Login with the credentials.
2. Analyze the image uploading functionality by uploading an image.
![[file-upload-vulnerabilities8.png]]

**In burp** - 
![[file-upload-vulnerabilities9.png]]
Notice that your image is fetched using GET request. 

3. Now, try to upload a php script to get the content of secret file of user `carlos`.
![[file-upload-vulnerabilities10.png]]
Notice that server doesn't stop you from uploading a php file but on the other hand it doesn't execute that file and return the content of that file.

4. Now, we try to do directory traversal by using the `filename` parameter from `POST /my-account/avatar` request and find the part of the request body that relates to your PHP file. In the `Content-Disposition` header, change the `filename` to include a directory traversal.
`Content-Disposition: form-data; name="avatar"; filename="../exploit.php"`
![[file-upload-vulnerabilities11.png]]
Send the request. Notice that the response says `The file avatars/exploit.php has been uploaded.` This suggests that the server is stripping the directory traversal sequence from the file name.

5. Obfuscate the directory traversal sequence by URL encoding the forward slash (`/`) character, resulting in:
`filename="..%2fexploit.php"`
![[file-upload-vulnerabilities12.png]]
replace the top right value with the left one.

6. Send the request and observe that the message now says `The file avatars/../exploit.php has been uploaded.` This indicates that the file name is being URL decoded by the server.
![[file-upload-vulnerabilities13.png]]

7. In the browser, go back to your account page.
8. In Burp's proxy history, find the `GET /files/avatars/..%2fshell.php` request. Observe that Carlos's secret was returned in the response. This indicates that the file was uploaded to a higher directory in the filesystem hierarchy (`/files`), and subsequently executed by the server. Note that this means you can also request this file using `GET /files/shell.php`.
![[file-upload-vulnerabilities14.png]]

9. After navigating to `/files/shell.php`.
![[file-upload-vulnerabilities15.png]]

10. Submit this and you solve the lab.
