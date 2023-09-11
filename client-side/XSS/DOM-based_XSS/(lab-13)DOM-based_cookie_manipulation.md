## What is DOM-based cookie manipulation?
- Some DOM-based vulnerabilities allow attackers to manipulate data that they do not typically control. This transforms normally-safe data types, such as cookies, into potential sources.
- DOM-based cookie-manipulation vulnerabilities arise when a script writes attacker-controllable data into the value of a cookie.
- An attacker may be able to use this vulnerability to construct a URL that, if visited by another user, will set an arbitrary value in the user's cookie.
- Many sinks are largely harmless on their own, but DOM-based cookie-manipulation attacks demonstrate how low-severity vulnerabilities can sometimes be used as part of an exploit chain for a high-severity attack

**Example** - 
if JavaScript writes data from a source into `document.cookie` without sanitizing it first, an attacker can manipulate the value of a single cookie to inject arbitrary values:
```js
document.cookie = 'cookieName='+location.hash.slice(1);
```

If the website unsafely reflects values from cookies without HTML-encoding them, an attacker can use cookie-manipulation techniques to exploit this behavior.

## Steps to solve lab
### Title - DOM-based cookie manipulation
**Desc** - This lab demonstrates DOM-based client-side cookie manipulation. To solve this lab, inject a cookie that will cause XSS on a different page and call the `print()` function. You will need to use the exploit server to direct the victim to the correct pages.

**Our end goal** - 
To solve this lab, inject a cookie that will cause XSS on a different page and call the `print()` function. You will need to use the exploit server to direct the victim to the correct pages.

1. Analyze the website functionality and every endpoint and using the browser's developer tools, you look at the HTML code and as well as javascript code to analyze the overall functionality of the web page.
![[XSS39.png]]

**View source code** - 
![[XSS40.png]]
From the above code, we can say that the cookie is stored in lastViewedProduct and the value of the cookie is stored in "Last viewed product". So, we can try to break the value of the cookie(which is current web page url) so that we can inject javascript code.
###### Code explaination - 
1. `document.cookie`: This is a JavaScript property that allows you to read and write cookies associated with the current web page. Cookies are small pieces of data that websites can store on a user's browser to remember information about them.
    
2. `'lastViewedProduct=' + window.location`: This part of the code is creating a cookie named "lastViewedProduct" and setting its value to the current URL of the web page. The `window.location` object represents the current URL in the browser's address bar.
    
3. `SameSite=None; Secure`: These are options for configuring how the cookie is sent by the browser to the server. Let's break them down:
    
    - `SameSite`: This attribute defines when cookies should be sent to the server along with cross-origin requests. In this case, it's set to "None," which means the cookie can be sent with cross-origin requests. This is often used for third-party integrations or when a website needs to share information with other websites.
        
    - `Secure`: This attribute indicates that the cookie should only be sent over secure (HTTPS) connections. It helps to ensure that the cookie's data is transmitted securely between the browser and the server.



2. Now, copy the below payload and paste it on browser to try to break the anchor tag so that our script gonna execute it.
```js
&'><script>console.log(1)</script>
```

![[XSS41.png]]


3. As per the lab description, we need to trigger "print()" and at the same time we need to direct the victim to the home page. So, for that copy the payload and paste it on the exploit server.
```jsx
<iframe src="https://0a2200eb03d25c6684ad14b400050064.web-security-academy.net/product?productId=1&'><script>print()</script>" onload="if(!window.x)this.src='https://0a2200eb03d25c6684ad14b400050064.web-security-academy.net/';window.x=1;">
```

![[XSS42.png]]
###### iframe code explaination -
1. `<iframe src="https://YOUR-LAB-ID.web-security-academy.net/product?productId=1&'><script>print()</script>"`: 
	- This starts with an iframe element, which is used to embed another web page within the current page. The `src` attribute points to the URL of the embedded content. In this case, the URL is constructed with a query parameter `productId=1` and a malicious script tag `'><script>print()</script>`.

2. `onload="if(!window.x)this.src='https://YOUR-LAB-ID.web-security-academy.net';window.x=1;"`: 
	- The `onload` attribute is an event handler that is triggered when the iframe has finished loading its content. The code inside it checks whether a global variable `window.x` exists. If it doesn't (`!window.x` is true), it sets the `src` of the iframe to `'https://YOUR-LAB-ID.web-security-academy.net'`, effectively redirecting the iframe to a new URL. Additionally, it sets `window.x` to `1` to indicate that the redirection has occurred.


**This code appears to be a way to exploit a vulnerability in a web application by injecting a malicious script into the URL parameters of an iframe. The injected script is `<script>print()</script>`, which will attempt to execute the `print()` function when the iframe is loaded.**
