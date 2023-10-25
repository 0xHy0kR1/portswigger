## What is the Access-Control-Allow-Origin response header?

   - In technical terms, the Access-Control-Allow-Origin response header indicates whether the response can be shared with requesting code from the given origin
   - Imagine Website A has data, and Website B wants to access it using JavaScript. To allow this, Website A includes the "Access-Control-Allow-Origin" header in its response like this:
```js
Access-Control-Allow-Origin: https://websiteB.com
```
Now, Website B can use JavaScript to fetch and use data from Website A because it's given permission in the header.

A web browser compares the Access-Control-Allow-Origin with the requesting website's origin and permits access to the response if they match.

![[cors7.png]]

## Implementing simple cross-origin resource sharing

   - Cross-Origin Resource Sharing (CORS) is a security feature implemented in web browsers to control and restrict how web pages from different domains can interact with each other.
   - It's a mechanism that allows or denies web resources (like scripts, fonts, and images) on one domain to be requested and used by web pages on another domain.

   - CORS is a security mechanism used in web development to control which websites can access resources on another website.
   - It's achieved through specific HTTP headers. The most important header is "Access-Control-Allow-Origin," which the server sends to permit or deny access to resources requested by a different website.
   - The "Origin" header is added by the browser to indicate where the request is coming from. These headers help ensure secure cross-domain data sharing.

#### Example - 

**Whole scenario in words** - 
Imagine you have two websites, "normal-website.com" and "robust-website.com." "normal-website.com" wants to request data from "robust-website.com." The browser, when making the request, includes an "Origin" header to show where it's coming from. If "robust-website.com" agrees to share its data with "normal-website.com," it sends back a response with an "Access-Control-Allow-Origin" header matching the requesting website. This match allows code on "normal-website.com" to access the response.

**suppose a website with origin `normal-website.com` causes the following cross-domain request:**
```js
GET /data HTTP/1.1 
Host: robust-website.com 
Origin : https://normal-website.com
```

**The server on `robust-website.com` returns the following response:**
```js
HTTP/1.1 200 OK 
... 
Access-Control-Allow-Origin: https://normal-website.com
```

- The browser will allow code running on `normal-website.com` to access the response because the origins match.

- Remember, the "Access-Control-Allow-Origin" header can specify multiple allowed origins, be set to "null," or use a wildcard "*", but there are restrictions on using these options. Most browsers don't support multiple origins, and using the wildcard has limitations.

## Handling cross-origin resource requests with credentials

   - By default, when a web page makes a request to a server on a different domain, the server doesn't include cookies and sensitive headers in the request.
   - If the server wants to allow this, it can set a header called 'Access-Control-Allow-Credentials' to 'true'. If the requesting web page explicitly states that it wants to send cookies with the request using JavaScript, then the server will include them in the request.

![[cors8.png]]


```js
GET /data HTTP/1.1 
Host: robust-website.com 
... 
Origin: https://normal-website.com 
Cookie: JSESSIONID=<value>
```

**And the response to the request is:**
```js
HTTP/1.1 200 OK 
... 
Access-Control-Allow-Origin: https://normal-website.com 
Access-Control-Allow-Credentials: true
```
Then the browser will permit the requesting website to read the response, because the `Access-Control-Allow-Credentials` response header is set to `true`. Otherwise, the browser will not allow access to the response.

#### Note - 
   If the server is configured with the wildcard("`*`") as the value of Access-Control-Allow-Origin header, then use of credentials is not allowed.
## Relaxation of CORS specifications with wildcards

   The header `Access-Control-Allow-Origin` supports wildcards. For example:
```js
Access-Control-Allow-Origin: *
```

#### Note
   Note that wildcards cannot be used within any other value. For example, the following header is **not** valid:
```js
Access-Control-Allow-Origin: https://*.normal-website.com
```


In terms of security, the use of a wildcard character (usually `*`) in certain settings is restricted by the specification. Specifically, you cannot use the wildcard in combination with the cross-origin transfer of credentials, which includes authentication, cookies, or client-side certificates. This means that a server's response to a cross-origin request with a wildcard in certain contexts is limited or disallowed for security reasons.
```js
Access-Control-Allow-Origin: * 
Access-Control-Allow-Credentials: true
```
   - It is not permitted as this would be dangerously insecure, exposing any authenticated content on the target site to everyone.
   - Given these constraints, some web servers dynamically create `Access-Control-Allow-Origin` headers based upon the client-specified origin. This is a workaround for CORS constraints that is not secure

## Pre-flight checks

   The pre-flight check in CORS (Cross-Origin Resource Sharing) is a safety measure. It ensures that when a web page requests data from another domain using non-standard HTTP methods or headers, the browser first asks the server if it's okay to make the request. This check helps prevent unexpected and potentially harmful interactions between websites. If the server approves, the browser allows the cross-origin request to proceed; otherwise, it's blocked.

**For example, this is a pre-flight request that is seeking to use the `PUT` method together with a custom request header called `Special-Request-Header`:**
```js
OPTIONS /data HTTP/1.1 
Host: <some website> 
... 
Origin: https://normal-website.com 
Access-Control-Request-Method: PUT 
Access-Control-Request-Headers: Special-Request-Header
```

**The server might return a response like the following:**
```js
HTTP/1.1 204 No Content 
... 
Access-Control-Allow-Origin: https://normal-website.com 
Access-Control-Allow-Methods: PUT, POST, OPTIONS 
Access-Control-Allow-Headers: Special-Request-Header 
Access-Control-Allow-Credentials: true 
Access-Control-Max-Age: 240
```
   - This response sets out the allowed methods (`PUT`, `POST` and `OPTIONS`) and permitted request headers (`Special-Request-Header`).
   - In this scenario, the server on a different domain permits the exchange of user credentials (like cookies or login data), and it specifies a maximum time for storing the pre-flight response to save time in future requests. If the server approves the requested methods and headers (which it does in this case), the browser handles the cross-origin request as it normally would. 
   - However, it's important to note that pre-flight checks introduce an additional HTTP request, which can make web browsing slower because it adds some extra processing time.

## Does CORS protect against CSRF?

   - CORS does not provide protection against [cross-site request forgery](https://portswigger.net/web-security/csrf) ([CSRF](https://portswigger.net/web-security/csrf)) attacks, this is a common misconception.
   - CORS is a controlled relaxation of the same-origin policy, so poorly configured CORS may actually increase the possibility of CSRF attacks or exacerbate their impact.
   - There are various ways to perform CSRF attacks without using CORS, including simple HTML forms and cross-domain resource includes.

