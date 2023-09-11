## What is DOM-based open redirection?
DOM-based open-redirection vulnerabilities arise when a script writes attacker-controllable data into a sink that can trigger cross-domain navigation.

**Example** - 
the following code is vulnerable due to the unsafe way it handles the `location.hash` property:
```js
let url = /https?:\/\/.+/.exec(location.hash); 
if (url) {   
	location = url[0]; 
}
```
An attacker may be able to use this vulnerability to construct a URL that, if visited by another user, will cause a redirection to an arbitrary external domain.

## What is the impact of DOM-based open redirection?
This behavior can be leveraged to facilitate phishing attacks against users of the website.

**Example** - 
- The ability to use an authentic application URL targeting the correct domain and with a valid TLS certificate (if TLS is used) lends credibility to the phishing attack because many users, will not notice the subsequent redirection to a different domain.

- Now, if the attacker can control the beginning of the web address that causes the redirection, things can get even worse. They could put in some special code that tells your web browser to do things you definitely wouldn't want it to do. This could include running malicious JavaScript code, which can lead to all sorts of harm like stealing your personal info or messing up the website you're on. An attacker could construct a URL with the `javascript:` pseudo-protocol to execute arbitrary code when the URL is processed by the browser.

## Steps to solve lab
### Title - DOM-based open redirection
**Desc** - This lab contains a DOM-based open-redirection vulnerability. To solve this lab, exploit this vulnerability and redirect the victim to the exploit server.

**Our end goal** - To solve this lab, exploit this vulnerability and redirect the victim to the exploit server.

1. Analyze the website functionality and every endpoint and using the browser's developer tools, you look at the HTML code and as well as javascript code to analyze the overall functionality of the web page.
![[XSS36.png]]

**View source code** - 
![[XSS37.png]]

##### Code explaination - 
```jsx
<a href="#" onclick="returnUrl = /url=(https?:\/\/.+)/.exec(location); location.href = returnUrl ? returnUrl[1] : &quot;/&quot;">Back to Blog</a>
```
1. `<a href="#">`: 
	- This part creates a hyperlink. The `href` attribute usually specifies the URL that the link should go to. Here, it's set to `#`, which is often used to make a link that doesn't lead anywhere specific on the current page. In this case, it's like a placeholder link.

2. `onclick="..."`: 
	- This part specifies what should happen when the link is clicked. The `onclick` attribute contains JavaScript code that runs when the link is clicked.

**Now, let's break down the JavaScript code inside the `onclick` attribute:**
```js
returnUrl = /url=(https?:\/\/.+)/.exec(location);
location.href = returnUrl ? returnUrl[1] : &quot;/&quot;
```
3. `returnUrl = /url=(https?:\/\/.+)/.exec(location);`: 
	- This line of code tries to find a URL that matches a specific pattern in the current web page's URL. The pattern is `/url=(https?:\/\/.+)/`, which looks for a string that starts with `url=` and is followed by a web address (URL) that starts with `http://` or `https://`. It uses a regular expression to match this pattern. The `.exec(location)` part searches for this pattern in the current page's URL.
	- `returnUrl = ...`: This part is assigning the result of the operation to a variable called `returnUrl`.

4. `location.href = returnUrl ? returnUrl[1] : &quot;/&quot;`: 
	- This line of code changes the location (URL) of the web page. If a match was found in the previous line (`returnUrl` is not empty), it sets the page's location to the URL that was matched (`returnUrl[1]` contains the matched URL). If no match was found, it sets the page's location to `/`, which typically means the home page.
	- The use of `&quot;` in the code is a way of representing a double quotation mark (`"`) within an HTML attribute. It's used to avoid conflicts with the quotes used to define the `onclick` attribute.

In simpler terms, this code creates a link that, when clicked, tries to find a web address pattern in the current page's URL. If it finds a matching pattern, it takes you to that web address. If not, it takes you to the home page.

2. Now, visit the exploit server and copy the url of exploit server and with that url paste the below payload in the place of current web page url.
```python
https://0ab8002203ad915680c82b21000400b3.web-security-academy.net/post?postId=10&url=https://exploit-0a59004d03ca919780772ab001a0003e.exploit-server.net/#
```

![[XSS38.png]]
