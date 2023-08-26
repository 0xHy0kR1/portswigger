## Introduction
- The **HTTP Referer** header is a request-type header that identifies the address of the previous web page, which is linked to the current web page or resource.
- The usage of this header increases the risk of privacy and security breaches on a website but it allows websites and web servers to identify where the traffic is coming from.
- The Referer can not be sent by the browsers if the resource is the local file or data.

#### Syntax:
```js
Referer: <url>
```

#### Directives:
The HTTP Referer header accepts a single directive as mentioned above and described below:
- **"url"**: This directive is the address(partial or full) of the previous World Wide Web page which was followed by a link to the currently requested page.

**Examples:**
- In this example, geeksforgeeks.org is the address of the previous web page.
```js
    Referer: https://www.geeksforgeeks.org/
```
   
- In this example, google.com is the address of the previous web page.
```js
    Referer: https://www.google.com/
```
