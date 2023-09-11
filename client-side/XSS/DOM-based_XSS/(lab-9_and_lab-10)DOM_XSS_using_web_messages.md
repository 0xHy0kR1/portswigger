## Controlling the web message source

- If a page handles incoming web messages in an unsafe way, for example, by not verifying the origin of incoming messages correctly in the event listener, properties and functions that are called by the event listener can potentially become sinks.

**Example:**
 an attacker could host a malicious iframe and use the postMessage() method to pass web message data to the vulnerable event listener, which then sends the payload to a sink on the parent page. This behavior means that you can use web messages as the source for propagating malicious data to any of those sinks.

### What is the impact of DOM-based web message vulnerabilities?
- The potential impact of the vulnerability depends on the destination document's handling of the incoming message.
- If the destination document trusts the sender, and handles the data in an unsafe way by passing it into a sink, then the joint behavior of the two documents may allow an attacker to compromise the user.

### How to construct an attack using web messages as the source
**Consider the following code:**
```js
<script>
window.addEventListener('message', function(e) {
  eval(e.data);
});
</script>
```

## Which sinks can lead to DOM-based web message vulnerabilities?
As long as a website accepts web message data from an untrusted source due to a lack of adequate origin verification, any sinks that are used by the incoming message event listener could potentially lead to vulnerabilities.

###### Code explaination -
1. script: This is an HTML tag used to embed JavaScript code within an HTML document. The code inside the script tag will be executed by the browser when the HTML page is loaded.

2. window.addEventListener('message', function(e) { ... });: This line adds an event listener to the window object. The event being listened to is the 'message' event. The 'message' event is fired when a message is sent to the window through the window.postMessage() method.

	- 'message': The event type being listened to.
	- function(e) { ... }: This is the event handler function that will be executed when the 'message' event is triggered. The e parameter represents the event object, which contains information about the message being sent.
1. eval(e.data);: Inside the event handler function, this line uses the eval() function to execute the code contained in the data property of the event object e. The data property holds the content of the message that was sent to the window.

	- eval(): A JavaScript function that takes a string as an argument and executes it as code. It's a powerful but potentially risky function, as it can execute arbitrary code, which might lead to security vulnerabilities if not used carefully.

**This is vulnerable because an attacker could inject a JavaScript payload by constructing the following iframe:**
```js
<iframe src="//vulnerable-website" onload="this.contentWindow.postMessage('print()','*')">
```

As the event listener does not verify the origin of the message, and the postMessage() method specifies the targetOrigin "*", the event listener accepts the payload and passes it into a sink, in this case, the eval() function. 

## Steps to solve lab - 9
### Title - DOM XSS using web messages
**Desc** - This lab demonstrates a simple web message vulnerability. To solve this lab, use the exploit server to post a message to the target site that causes the `print()` function to be called.

**Our end goal** - To solve this lab, use the exploit server to post a message to the target site that causes the `print()` function to be called.

1. Using the browser's developer tools, you look at the HTML code and as well as javascript code to analyze the overall functionality of the web page.
![[XSS28.png]]

###### Code explaination - 
```js
window.addEventListener('message', function(e) {
    document.getElementById('ads').innerHTML = e.data;
});
```
1. **window.addEventListener('message', function(e) { ... });** 
	- This line of code attaches an event listener to the `window` object. The event being listened for is the `'message'` event. The `'message'` event is triggered when a message is sent to the current window from another window or iframe using the `postMessage` API.

2. **function(e) { ... }:**
	- This is an anonymous function that is the event handler for the `'message'` event. The function takes one parameter, `e`, which represents the event object containing information about the message.

3. **document.getElementById('ads'):**
	- This part of the code retrieves an HTML element with the ID `'ads'`. The `getElementById` function is used to select an element by its unique ID attribute.

4. **.innerHTML = e.data;**
	- This line assigns the content of the received message (which is contained in the `e.data` property) as the HTML content of the element with the ID `'ads'`. The `innerHTML` property is used to set or retrieve the HTML content of an element.



2. Now, after analyzing the front-end js code, we can craft the payload and send it to the client. As shown below;
```js
<iframe src="https://0a85002604c7d9f080252b68006c002b.web-security-academy.net" onload="this.contentWindow.postMessage('print()','*')">
```
The problem with the above payload is that it just send the `print()` function is that it get injected inside the div element but there is no way of the execution of `print()` function. As show below
![[XSS29.png]]

![[XSS30.png]]

3. Now, we are going to pass the below payload with the link to the victim.
```js
<iframe src="https://0a85002604c7d9f080252b68006c002b.web-security-academy.net" onload="this.contentWindow.postMessage('<img src=1 onerror=print()>','*')">
```
the `img` element pass to the `div` element as an message and as the source of message is 1 so the error occured and with that error the `onerror` event occurs and from that `print()` function executed.

![[XSS31.png]]

## Steps to solve - 10
### Title - [[DOM-based_XSS]] using web messages and a JavaScript URL
**Desc** - This lab demonstrates a DOM-based redirection vulnerability that is triggered by web messaging. To solve this lab, construct an HTML page on the exploit server that exploits this vulnerability and calls the `print()` function.

**Our end goal** - To solve this lab, construct an HTML page on the exploit server that exploits this vulnerability and calls the `print()` function.


1. Using the browser's developer tools, you look at the HTML code and as well as javascript code to analyze the overall functionality of the web page.
![[XSS32.png]]

###### Code explaination - 
1. `window.addEventListener('message', function(e) { ... }, false);`: 
	- This line attaches an event listener to the `window` object, listening for the `'message'`. The `'message'` event is triggered when a message is sent to the current window from another window or iframe using the `postMessage` API.

2. `function(e) { ... }`: 
	- This is the event handler function for the `'message'` event, which takes the event object as a parameter (`e`).

3. `var url = e.data;`: 
	- This line assigns the content of the received message (which is contained in the `e.data` property) to the variable `url`. In this context, it's assuming that the received message is a URL.

4. `if (url.indexOf('http:') > -1 || url.indexOf('https:') > -1) { ... }`:
	- This is a conditional statement that checks whether the `url` contains either `'http:'` or `'https:'`. The `indexOf` method is used to check if a specific substring is present in the `url` string. If the condition is true, it means the URL is an HTTP or HTTPS URL.

5. `location.href = url;`:
	- If the URL is determined to be an HTTP or HTTPS URL, this line changes the current window's location to the specified URL. This effectively redirects the user's browser to the new URL.



2. Now, after analyzing the front-end js code, we can craft the payload and send it to the client. As shown below;
```js
<iframe src="https://0a9600fd0302b1db802135ca005f00df.web-security-academy.net" onload="this.contentWindow.postMessage('javascript:print()//http:','*')">
```
###### Code explaination - 
  1. `<iframe src="https://YOUR-LAB-ID.web-security-academy.net/">`: This starts by creating an `<iframe>` element that loads content from the specified URL (`https://YOUR-LAB-ID.web-security-academy.net/`). The intention here is to embed the content of the target website within this `<iframe>`.
    
   2. `onload="this.contentWindow.postMessage('javascript:print()//http:','*')"`: The `onload` attribute is used to execute JavaScript code when the iframe has finished loading. In this case, it's using the `postMessage` method to send a message to the content window of the `<iframe>`. The message being sent is `'javascript:print()//http:'`.
    
      - `this.contentWindow.postMessage(...)`: The `this.contentWindow` refers to the window object of the loaded content within the `<iframe>`. `postMessage` is a browser feature that allows different windows or iframes to communicate with each other safely.
        
      - `'javascript:print()//http:'`: This is a JavaScript payload. It seems to be trying to execute the `print()` function, which would trigger printing the current page content. The `//http:` part at the end seems to be an attempt to bypass some security mechanisms.
    - `'*'`: The second argument to `postMessage` specifies the target origin to which the message can be sent. Using `'*'` means that the message can be sent to any origin.



![[XSS33.png]]
