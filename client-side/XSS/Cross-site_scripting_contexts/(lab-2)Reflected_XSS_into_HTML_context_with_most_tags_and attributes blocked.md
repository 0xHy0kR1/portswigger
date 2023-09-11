## Steps to solve lab
### Title - Reflected XSS into HTML context with most tags and attributes blocked
**Desc** - This lab contains a reflected XSS vulnerability in the search functionality but uses a web application firewall (WAF) to protect against common XSS vectors.

To solve the lab, perform a cross-site scripting attack that bypasses the WAF and calls the `print()` function.

**Our end goal** - To solve the lab, perform a cross-site scripting attack that bypasses the WAF and calls the `print()` function.

```jsx
<iframe src="https://0a79009c03582aa1812f7fda00300060.web-security-academy.net/?search=<body onresize=print() >" onload="this.style.width='100px'">
```

1. Analyze the website functionality and every endpoint and using the browser's developer tools, you look at the HTML code and as well as javascript code to analyze the overall functionality of the web page.
![[XSS43.png]]
After analyzing the front-end code, we cannot find anything as important.

![[XSS44.png]]

![[XSS45.png]]

2. From the above, we can say that there are tags that are blocked by WAF(web application firewall). So, let's try to brute-forcing to check which tags are allowed and for that we are going to use burp-suite intruder with tags payloads which you can find in the below link
Link --> https://portswigger.net/web-security/cross-site-scripting/cheat-sheet

**Below there are steps to brute-force for the tag to bypass WAF** - 
![[XSS47.png]]

![[XSS48.png]]

**Copy the below payloads for brute-forcing** - 
![[XSS46.png]]

![[XSS49.png]]

![[XSS50.png]]
From this, we get to know that "body" tag and "custom" tag are allowed here.

3. Now, we need know what javascript  attribute allowed here, so that we trigger `print()` function.

**Below there are steps to brute-force for the attributes to bypass WAF** - 
![[XSS51.png]]

![[XSS52.png]]

**Copy the below payloads for brute-forcing** - 
![[XSS53.png]]

![[XSS54.png]]

![[XSS55.png]]
From this, we get to know that "onbeforeinput", "onbeforetoggle", "onratechange", "onresize" and "onscrollend" tag are allowed here.

4. Now, we are going to use "onresize" event with "body" tag because it fits as per the lab note.

**Note** - *Your solution must not require any user interaction. Manually causing `print()` to be called in your own browser will not solve the lab.*

**Below payload we are going to use to make it work** - 
```jsx
<iframe src="https://0a79009c03582aa1812f7fda00300060.web-security-academy.net/?search=<body onresize=print() >" onload="this.style.width='100px'">
```
![[XSS56.png]]
The above `iframe` payload is fires when our page is resized and at the same time we resized it with the `onload` event.
