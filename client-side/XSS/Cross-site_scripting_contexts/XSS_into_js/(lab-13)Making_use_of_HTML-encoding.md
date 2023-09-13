- When the XSS context is some existing JavaScript within a quoted tag attribute, such as an event handler, it is possible to make use of HTML-encoding to work around some input filters.
- When your web browser receives a web page, it reads the HTML code in it and The browser looks for HTML tags (like `<div> or <p>`) and their attributes (like "href" or "src") in the code. Before doing anything else, the browser converts or decodes the values of these attributes. This means it turns special symbols into their normal form. 
- Sometimes, the server that sent the web page tries to protect against security problems like cross-site scripting (XSS). It may block or clean certain characters that could be used for harmful attacks. But, if you encode (convert to a special form) these characters using HTML encoding, you might get around this protection.

**For example, if the XSS context is as follows:**
```jsx
<a href="#" onclick="... var input='controllable data here'; ...">
```

**the application blocks or escapes single quote characters, you can use the following payload to break out of the JavaScript string and execute your own script:**
```jsx
&apos;-alert(document.domain)-&apos;
```
The `&apos;` sequence is an HTML entity representing an apostrophe or single quote. Because the browser HTML-decodes the value of the `onclick` attribute before the JavaScript is interpreted, the entities are decoded as quotes, which become string delimiters, and so the attack succeeds.

## Steps to solve lab
### Title - Stored XSS into `onclick` event with angle brackets and double quotes HTML-encoded and single quotes and backslash escaped

**Desc** - This lab contains a [stored cross-site scripting](https://portswigger.net/web-security/cross-site-scripting/stored) vulnerability in the comment functionality. To solve this lab, submit a comment that calls the `alert` function when the comment author name is clicked.

**Our end goal** - To solve this lab, submit a comment that calls the `alert` function when the comment author name is clicked.

1. First try to analyze the search functionality based on your input values.
![[XSS87.png]]

![[XSS88.png]]
The code shown above in the red block is that code that we use to exploit the web application.

2. Now, copy the below payload and paste it into the `Website` commentbox to perform "Stored XSS.
```python
http://codewithharry.com&apos;-alert(document.domain)-&apos;
```
When the user clicks on their name then `onclick` event run and the server receives the payload as `http://codewithharry.com&apos;-alert(document.domain)-&apos;` but the browser decode it to `http://codewithharry.com';-alert(document.domain)'` and making the alert function to run.

**the injected payload in the brower -**
![[XSS89.png]]
As you can see above, the injected html encoded single quote decoded in the browser and our payload is successful.

**For better understanding watch** --> [[Stored_XSS_in_onclick_Payload_obfuscation_with_HTML_encoding..mp4]]