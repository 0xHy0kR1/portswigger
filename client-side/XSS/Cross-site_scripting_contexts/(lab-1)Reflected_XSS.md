- Reflected XSS is the simplest variety of cross-site scripting.
- It arises when an application receives data in an HTTP request and includes that data within the immediate response in an unsafe way.

## Example - 
Suppose a website has a search function which receives the user-supplied search term in a URL parameter:
```js
https://insecure-website.com/status?message=All+is+well. 
```

**The application echoes the supplied search term in the response to this URL:**
```html
<p>Status: All is well.</p>
```

**The application doesn't perform any other processing of the data, so an attacker can easily construct an attack like this:**
```js
https://insecure-website.com/status?message=<script>/*+Bad+stuff+here...+*/</script> 
```

**This URL results in the following response:**
```html
<p>Status: <script>/* Bad stuff here... */</script></p>
```
If the user visits the URL constructed by the attacker, then the attacker's script executes in the user's browser, in the context of that user's session with the application. At that point, the script can carry out any action, and retrieve any data, to which the user has access.

## Impact of reflected XSS attacks
If an attacker can control a script that is executed in the victim's browser, then they can typically fully compromise that user.
**Amongst other things, the attacker can:**

- Perform any action within the application that the user can perform.
- View any information that the user is able to view.
- Modify any information that the user is able to modify.
- Initiate interactions with other application users, including malicious attacks, that will appear to originate from the initial victim user.

**Note** - the impact of reflected XSS is generally less severe than Stored XSS.

## Reflected XSS in different contexts
- The location of the reflected data within the application's response determines what type of payload is required to exploit it and might also affect the impact of the vulnerability.
- In addition, if the application performs any validation or other processing on the submitted data before it is reflected, this will generally affect what kind of XSS payload is needed.

## How to find and test for reflected XSS vulnerabilities
The vast majority of reflected cross-site scripting vulnerabilities can be found quickly and reliably using Burp Suite's web vulnerability scanner.

### Testing for reflected XSS vulnerabilities manually involves the following steps:
##### Test every entry point:
- Test separately every entry point for data within the application's HTTP requests.
- This includes parameters or other data within the URL query string and message body, and the URL file path.
- It also includes HTTP headers, although XSS-like behavior that can only be triggered via certain HTTP headers may not be exploitable in practice.

##### Submit random alphanumeric values:
- For each entry point, submit a unique random value and determine whether the value is reflected in the response. The value should be designed to survive most input validation, so needs to be fairly short and contain only alphanumeric characters. But it needs to be long enough to make accidental matches within the response. 
- A random alphanumeric value of around 8 characters is normally ideal.
- You can use Burp Intruder's number payloads with randomly generated hex values to generate suitable random values. And you can use Burp Intruder's grep payloads settings to automatically flag responses that contain the submitted value.

##### Determine the reflection context:
- For each location within the response where the random value is reflected, determine its context.

##### Test a candidate payload
- Based on the context of the reflection, test an initial candidate XSS payload that will trigger JavaScript execution if it is reflected unmodified within the response.
- The easiest way to test payloads is to send the request to Burp Repeater, modify the request to insert the candidate payload, issue the request, and then review the response to see if the payload worked.

##### Test alternative payloads
- If the candidate XSS payload was modified by the application, or blocked altogether, then you will need to test alternative payloads and techniques that might deliver a working XSS attack based on the context of the reflection and the type of input validation that is being performed.

##### Test the attack in a browser
- Finally, if you succeed in finding a payload that appears to work within Burp Repeater, transfer the attack to a real browser (by pasting the URL into the address bar, or by modifying the request in Burp Proxy's intercept view, and see if the injected JavaScript is indeed executed.
- Often, it is best to execute some simple JavaScript like `alert(document.domain)` which will trigger a visible popup within the browser if the attack succeeds.

## Common questions about reflected cross-site scripting
#### What is the difference between reflected XSS and stored XSS?
- Reflected XSS arises when an application takes some input from an HTTP request and embeds that input into the immediate response in an unsafe way.
- Reflected XSS arises when an application takes some input from an HTTP request and embeds that input into the immediate response in an unsafe way.

#### What is the difference between reflected XSS and self-XSS?
**Reflected XSS** - 
- Reflected XSS occurs when an attacker injects malicious code (usually JavaScript) into a web application, and this code is then reflected back to the user as part of the web page's response.
- The attacker usually tricks a user into clicking on a specially crafted link that contains the malicious code as a parameter. When the user clicks the link, the code is executed within the user's browser, allowing the attacker to steal sensitive information or perform actions on behalf of the user.

**Self-XSS** -
- Self-XSS, on the other hand, is a form of social engineering attack where the attacker tricks the victim into executing malicious code in their own browser.
- The attacker often disguises the malicious code as a harmless script, claim, or action that the victim is convinced to paste into their browser's developer console.
- I may ask you to paste a malicious JavaScript code into your browser URL bar which will give you logs about surfing data.
- Delivering a self-XSS attack normally involves socially engineering the victim to paste some attacker-supplied input into their browser. As such, it is normally considered to be a lame, low-impact issue.
## Steps to solve lab
### Desc - Reflected XSS into HTML context with nothing encoded
**Our end goal** - To solve the lab, perform a cross-site scripting attack that calls the `alert` function.

1. To solve the lab, just copy and paste the below payload into the search box to solve this lab.
```js
<script>alert(1)</script>
```
![[XSS2.png]]