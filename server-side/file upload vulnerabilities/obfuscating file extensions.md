## Introduction
- Even the most exhaustive blacklists can potentially be bypassed using classic obfuscation techniques. Let's say the validation code is case sensitive and fails to recognize that `exploit.pHp` is in fact a `.php` file. but if the validation code is Case-insensitive then this doesn't work.

**You can pass php files to servers using the following techniques:**
1. **Provide multiple extensions:**
	- Depending on the algorithm used to parse the filename, the following file may be interpreted as either a PHP file or JPG image: `exploit.php.jpg`
2. **Add trailing characters:**
	- Some components will strip or ignore trailing whitespaces, dots, and suchlike: `exploit.php.`
3. **Try using the URL encoding:**
	- Use URL encoding (or double URL encoding) for dots, forward slashes, and backward slashes.
	- If the value isn't decoded when validating the file extension, but is later decoded server-side, this can also allow you to upload malicious files that would otherwise be blocked: `exploit%2Ephp`
4. **Add semicolons or URL-encoded null byte characters before the file extension:**
	- If validation is written in a high-level language like PHP or Java, but the server processes the file using lower-level functions in C/C++, for example, this can cause discrepancies in what is treated as the end of the filename:
`exploit.asp;.jpg` or `exploit.asp%00.jpg`
- For example, in the case of "exploit.asp%00.jpg," some systems might only see "shell.asp" as the file extension and treat it as an ASP file rather than a JPG file.
- In many programming languages and systems, the null byte is used to mark the end of a string or data structure.

5. **Try using multibyte unicode characters:**
	- This may be converted to null bytes and dots after unicode conversion or normalization. Sequences like `xC0 x2E`, `xC4 xAE` or `xC0 xAE` may be translated to `x2E` if the filename parsed as a UTF-8 string, but then converted to ASCII characters before being used in a path.

you can position the prohibited string in such a way that removing it still leaves behind a valid file extension.
**Example:**
`exploit.p.phphp`
This is just a small selection of the many ways it's possible to obfuscate file extensions.

## Steps to solve lab
### Desc - Web shell upload via obfuscated file extension
**Our end goal** - upload a basic PHP web shell, then use it to exfiltrate the contents of the file `/home/carlos/secret`. Submit this secret using the button provided in the lab banner.

1. Login with the given credentials.
2. First upload a image to analyze the functionality but when you upload `.php` files on the server, you see that server doesn't allow you to upload the `.php` files.
3. Now, let's to upload try to upload a `shell.asp%00.jpg`. In many programming languages and systems, the null byte is used to mark the end of a string or data structure, So in the end you see that you uploaded `shell.asp`.
![[file-upload-vulnerabilities19.png]]

4. Now, just browse `avatars/shell.asp` and you get the contents of `secret` file and submit it as a solution.
**Note** - Change the `.asp` with the `.php` to execute your script on the server side.