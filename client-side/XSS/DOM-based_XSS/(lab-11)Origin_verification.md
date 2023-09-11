Even if an event listener does include some form of origin verification, this verification step can sometimes be fundamentally flawed.
**Example** - consider the following code:
```js
window.addEventListener('message', function(e) { 
	if (e.origin.indexOf('normal-website.com') > -1) { 
		eval(e.data); 
	} 
});
```
- The `indexOf` method is used to try and verify that the origin of the incoming message is the `normal-website.com` domain. However, in practice, it only checks whether the string `"normal-website.com"` is contained anywhere in the origin URL.
- As a result, an attacker could easily bypass this verification step if the origin of their malicious message was `http://www.normal-website.com.evil.net`

**for example:**
The same flaw also applies to verification checks that rely on the `startsWith()` or `endsWith()` methods.

**For example, the following event listener would regard the origin `http://www.malicious-websitenormal-website.com` as safe:**
```js
window.addEventListener('message', function(e) { 
	if (e.origin.endsWith('normal-website.com')) { 
		eval(e.data); 
	} 
});
```

## Steps to solve lab
### Title - [[DOM-based_XSS]] using web messages and `JSON.parse`
**Desc** - This lab uses web messaging and parses the message as JSON. To solve the lab, construct an HTML page on the exploit server that exploits this vulnerability and calls the `print()` function.

**Our end goal** - To solve the lab, construct an HTML page on the exploit server that exploits this vulnerability and calls the `print()` function.


1. Using the browser's developer tools, you look at the HTML code and as well as javascript code to analyze the overall functionality of the web page.
![[XSS34.png]]

#### Code explaination - 
1. **Event Listener Setup:**
```js
	window.addEventListener('message', function(e) {
    // Code to handle the received message
}, false);
```
This code sets up an event listener on the `window` object to listen for the `'message'` event. When another window or iframe sends a message to this window, the code inside the function will be executed.

2. **Creating an Iframe:**
```js
var iframe = document.createElement('iframe'), ACMEplayer = {element: iframe}, d;
document.body.appendChild(iframe);
```
An `<iframe>` (inline frame) element is created. This iframe is used to display content from another source within the current webpage. The `ACMEplayer` object is created, and it contains a reference to the newly created iframe. The iframe is then added to the document's `<body>`.

3. **Parsing the Received Message:**
```js
try {
    d = JSON.parse(e.data);
} catch(e) {
    return;
}
```
The received message's data (`e.data`) is assumed to be in JSON format. The code attempts to parse the JSON data into an object using `JSON.parse()`. If the parsing is successful, the resulting object is assigned to the variable `d`. If parsing fails (for example, if the message isn't valid JSON), the code inside the `catch` block is executed, and the function returns early.

4. **Switch Statement for Message Types:**
```js
switch(d.type) {
    case "page-load":
        ACMEplayer.element.scrollIntoView();
        break;
    case "load-channel":
        ACMEplayer.element.src = d.url;
        break;
    case "player-height-changed":
        ACMEplayer.element.style.width = d.width + "px";
        ACMEplayer.element.style.height = d.height + "px";
        break;
}
```
- The code uses a `switch` statement to handle different types of messages. The type of the message is expected to be in the `type` property of the parsed message object (`d`). Depending on the message type, different actions are taken:
	- If the message type is `"page-load"`, the `scrollIntoView()` method is called on the iframe element. This could scroll the page to bring the iframe into view.
	- If the message type is `"load-channel"`, the `src` attribute of the iframe element is set to the URL specified in the message object.
	- If the message type is `"player-height-changed"`, the width and height of the iframe element are updated based on the values provided in the message.



2. Now, after analyzing the front-end js code, we can craft the payload and send it to the client. As shown below;
```jsx
<iframe src="https://0a11005403622ef180536c8e0067002e.web-security-academy.net" onload='this.contentWindow.postMessage("{\"type\":\"load-channel\",\"url\":\"javascript:print()\"}","*")'>
```

![[XSS35.png]]

