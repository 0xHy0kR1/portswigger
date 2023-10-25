## Introduction
   - The "Origin header" refers to an HTTP request header called "Origin" that the web browser sends when making cross-origin requests.
   - This header contains the origin (i.e., the domain or URL) of the web page that initiated the request.
   - The server that receives this header can then decide whether to allow or deny the request based on its CORS policy.

### Example - 
   Let's say you have a web page hosted on `https://example.com`, and within that web page, you have JavaScript code that makes an AJAX request to fetch data from an API hosted on `https://api.example2.com`. Since these two domains are different, the browser will automatically include an "Origin" header in the request.

1. The web page at `https://example.com` makes an HTTP request to `https://api.example2.com`.
 
2. In the HTTP request sent to `https://api.example2.com`, the browser includes the "Origin" header, which would look like this:
```js
Origin: https://example.com
```

3. The server at `https://api.example2.com` receives this request and checks the "Origin" header. It can then decide whether to allow the request based on its CORS policy. For instance, the server might be configured to only allow requests from certain origins, or it might allow any origin using a wildcard (`*`).

4. If the server's CORS policy allows the request, it will respond with the requested data. If it doesn't allow the request, the browser's JavaScript code will receive an error, and the data will not be accessible due to the same-origin policy.