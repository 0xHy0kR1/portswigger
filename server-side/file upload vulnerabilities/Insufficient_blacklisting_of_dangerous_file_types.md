## Introduction
- One of the more obvious ways of preventing users from uploading malicious scripts is to blacklist potentially dangerous file extensions like `.php`.
- Such blacklists can sometimes be bypassed by using lesser known, alternative file extensions that may still be executable, such as `.php5`, `.shtml`, and so on.

## Overriding the server configuration
- servers typically won't execute files unless they have been configured to do so.
**Example** - before an Apache server will execute PHP files requested by a client, developers might have to add the following directives to their `/etc/apache2/apache2.conf` file:
```python
LoadModule php_module /usr/lib/apache2/modules/libphp.so 
AddType application/x-httpd-php .php`
```

- Many servers also allow developers to create special configuration files within individual directories in order to override or add to one or more of the global settings.
- Apache servers, for example, will load a directory-specific configuration from a file called `.htaccess` if one is present.
	- In simpler terms, the ".htaccess" file is like a set of custom rules that apply only to the folder it's placed in, allowing you to control how that specific part of your website works without affecting the rest of it.
- Similarly, developers can make directory-specific configuration on IIS servers using a `web.config` file.
	- This might include directives such as the following, which in this case allows JSON files to be served to users:
```js
<staticContent> 
	<mimeMap fileExtension=".json" mimeType="application/json" /> 
</staticContent>
```
- Web servers use these kinds of configuration files, but you're not normally allowed to access them using HTTP requests.
- However, you may occasionally find servers that fail to stop you from uploading your own malicious configuration file. In this case, even if the file extension you need is blacklisted, you may be able to trick the server into mapping an arbitrary, custom file extension to an executable MIME type.

## Steps to solve lab
### Desc - Web shell upload via extension blacklist bypass

**Our end goal** - upload a basic PHP web shell, then use it to exfiltrate the contents of the file `/home/carlos/secret`. Submit this secret using the button provided in the lab banner.

1. Login with the credentials.
2. Notice that you can upload `.php` files in the image upload function functionality but server doesn't execute `.php` files and directory also not possible.
3. Now, in `POST /my-account/avatar` notice that the server is `Apache` server that does all of this stuffs in the backend.
![[file-upload-vulnerabilities16.png]]
From past concepts, you now that Apache servers load a directory-specific configuration from a file called `.htaccess`. In simpler terms, the ".htaccess" file is like a set of custom rules that apply only to the folder it's placed in, allowing you to control how that specific part of your website works without affecting the rest of it.

So, before an Apache server will execute PHP files requested by a client, developers might have to add the following directives to their `/etc/apache2/apache2.conf` file:
```python
LoadModule php_module /usr/lib/apache2/modules/libphp.so 
AddType application/x-httpd-php .php`
```
We already know that php files execution is blocked by a server. therefore, we are going to do something below stuffs.

4. In Burp Repeater, go to the tab for the `POST /my-account/avatar` request and find the part of the body that relates to your PHP file. Make the following changes:
	- Change the value of the `filename` parameter to `.htaccess`.
	- Change the value of the `Content-Type` header to `text/plain`.
	- Replace the contents of the file (your PHP payload) with the following Apache directive:
	    `AddType application/x-httpd-php .l33t`
    This maps an arbitrary extension (`.l33t`) to the executable MIME type `application/x-httpd-php`. As the server uses the `mod_php` module, it knows how to handle this already.
![[file-upload-vulnerabilities17.png]]

5. Now, upload your `shell.php` payload with the `<?php echo file_get_contents('/home/carlos/secret'); ?>` to exfiltrate the contents of `secret` file but with `.l33t` extension like `shell.l33t` as we configure apache configuration file(`.htaccess`) to execute only `.133t` extension files.
![[file-upload-vulnerabilities18.png]]

6. Now, just go to `/files/avatars/shell.l33t` url and copy and paste. Now, required lab is solved.