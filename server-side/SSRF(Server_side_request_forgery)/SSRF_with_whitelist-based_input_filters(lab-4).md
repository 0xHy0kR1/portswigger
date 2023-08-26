## Introduction
- Some applications only allow input that matches, begins with, or contains, a whitelist of permitted values. In this situation, you can sometimes circumvent the filter by exploiting inconsistencies in URL parsing.
	
***You can embed credentials in a URL before the hostname, using the "@" character. For example:***
```js
	https://expected-host:username@evil-host
```

***You can use the `#` character to indicate a URL fragment. For example:***
```js
https://evil-host#expected-host
```

***You can leverage the DNS naming hierarchy to place required input into a fully-qualified DNS name that you control. For example:***
```js
https://expected-host.evil-host
```

**When you use URL-encoding, special characters in a URL are represented by specific codes. By doing this, you can confuse the code that reads the URL if it doesn't handle these encoded characters correctly. This confusion can be useful to bypass security filters or manipulate the URL's behavior.**
- Moreover, some servers may unintentionally decode the URL multiple times, which can cause even more confusion and discrepancies between the original input and the processed URL. This can be exploited to gain unintended access or perform unauthorized actions.

**You can use combinations of these techniques together.**

## Steps to solve lab
### Desc - SSRF with whitelist-based input filter
**Our end goal** - change the stock check URL to access the admin interface at `http://localhost/admin` and delete the user `carlos`.

1. Let's try to again request with `http://localhost/` as a value in `stockApi`.
![[SSRF13.png]]
From the response, we can clearly say that there is a white-list in the back-end that only allow request that contain `stock.weliketoshop.net` in request.

2. Now, let's try to put some credential in front of `stock.weliketoshop.net` so that url try parse the credential. Applications usually supports this formats for credentials.
![[SSRF14.png]]
Application is not able to resolve the credentials.

3. Now, lets try put "#" after "username" credential so that it just see  `@stock.weliketoshop.net` as a bookmark or a part of web page.
![[SSRF15.png]]
Now, the application see "username" as a valid url and `@stock.weliketoshop.net` as a part of that web page. We already know that "username" is not a valid url so, let's try put "localhost" in place of "username".

![[SSRF16.png]]

4. Now, just changed the url to `http://localhost%2523@stock.weliketoshop.net/admin`
![[SSRF17.png]]

5. Now, change the url to `http://localhost%2523@stock.weliketoshop.net/admin/delete?username=carlos` to solve the lab.
![[SSRF18.png]]
