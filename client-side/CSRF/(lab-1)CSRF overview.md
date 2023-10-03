## What is CSRF?
   - Cross-site request forgery (also known as CSRF) is a web security vulnerability that allows an attacker to induce users to perform actions that they do not intend to perform.
   - It allows an attacker to partly circumvent the same origin policy(Websites have a rule called the "same origin policy" to keep them separate, like neighbors with fences between their yards), which is designed to prevent different websites from interfering with each other.


![[csrf1.png]]
## What is the impact of a CSRF attack?
   - In a successful CSRF attack, the attacker causes the victim user to carry out an action unintentionally.
   - For example, this might be to change the email address on their account, to change their password, or to make a funds transfer.
   - Depending on the nature of the action, the attacker might be able to gain full control over the user's account. If the compromised user has a privileged role within the application, then the attacker might be able to take full control of all the application's data and functionality.


## How does CSRF work?
   For a CSRF attack to be possible, three key conditions must be in place:

   1. **A relevant action**:
	- There is an action within the application that the attacker has a reason to induce.
	- This might be a privileged action (such as modifying permissions for other users) or any action on user-specific data (such as changing the user's own password).
	  
   2. **Cookie-based session handling**:
	- Websites use cookies to remember who you are when you visit them.
	- If a website relies only on cookies to figure out who's doing what, it becomes vulnerable. There's no other way for the website to double-check if you're really you.

   3. **No unpredictable request parameters**:
	- Imagine you're changing your password on a website. If the website asks for your old password and your new password, an attacker could only trick you if they know both those things.
	- But if the website doesn't ask for your old password, just the new one, it's easier for an attacker to trick you.

>For example, suppose an application contains a function that lets the user change the email address on their account. When a user performs this action, they make an HTTP request like the following:
```js
POST /email/change HTTP/1.1 
Host: vulnerable-website.com 
Content-Type: application/x-www-form-urlencoded 
Content-Length: 30 
Cookie: session=yvthwsztyeQkAPzeQ5gHgTvlyxHfsAfE 

email=wiener@normal-user.com
```

**This meets the conditions required for CSRF:**
   - The action of changing the email address on a user's account is of interest to an attacker. Following this action, the attacker will typically be able to trigger a password reset and take full control of the user's account.
   - The application uses a session cookie to identify which user issued the request. There are no other tokens or mechanisms in place to track user sessions.
   - The attacker can easily determine the values of the request parameters that are needed to perform the action.

>The attacker can easily determine the values of the request parameters that are needed to perform the action.
```js
<html> 
	<body> 
		<form action="https://vulnerable-website.com/email/change" method="POST">                   <input type="hidden" name="email" value="pwned@evil-user.net" /> 
		</form> 
		<script> 
			document.forms[0].submit(); 
		</script> 
	</body> 
</html>
```

**If a victim user visits the attacker's web page, the following will happen:**
   - The attacker's page will trigger an HTTP request to the vulnerable web site.
   - If the user is logged in to the vulnerable web site, their browser will automatically include their session cookie in the request (assuming [SameSite cookies](https://portswigger.net/web-security/csrf#common-defences-against-csrf) are not being used).
   - The vulnerable web site will process the request in the normal way, treat it as having been made by the victim user, and change their email address.

#### Note
   Although CSRF is normally described in relation to cookie-based session handling, it also arises in other contexts where the application automatically adds some user credentials to requests, such as HTTP Basic authentication and certificate-based authentication.


## How to construct a CSRF attack
   - Manually creating the HTML needed for a CSRF exploit can be cumbersome, particularly where the desired request contains a large number of parameters, or there are other quirks in the request.
   - The easiest way to construct a CSRF exploit is using the [[Generate_CSRF_PoC]] that is built in to [Burp Suite Professional](https://portswigger.net/burp/pro):

- Select a request anywhere in Burp Suite Professional that you want to test or exploit.
- From the right-click context menu, select Engagement tools / Generate CSRF PoC.
- Burp Suite will generate some HTML that will trigger the selected request (minus cookies, which will be added automatically by the victim's browser).
- You can tweak various options in the CSRF PoC generator to fine-tune aspects of the attack. You might need to do this in some unusual situations to deal with quirky features of requests.
- Copy the generated HTML into a web page, view it in a browser that is logged in to the vulnerable web site, and test whether the intended request is issued successfully and the desired action occurs.

## How to deliver a CSRF exploit
   - Typically, the attacker will place the malicious HTML onto a web site that they control, and then induce victims to visit that web site.
   - This might be done by feeding the user a link to the web site, via an email or social media message. Or if the attack is placed into a popular web site (for example, in a user comment), they might just wait for users to visit the web site.
   - Note that some simple CSRF exploits employ the GET method and can be fully self-contained with a single URL on the vulnerable web site. In this situation, the attacker may not need to employ an external site, and can directly feed victims a malicious URL on the vulnerable domain.

>In the preceding example, if the request to change email address can be performed with the GET method, then a self-contained attack would look like this:
```js
<img src="https://vulnerable-website.com/email/change?email=pwned@evil-user.net">
```

## XSS vs CSRF

### What is the difference between XSS and CSRF?
   - Cross-site scripting (or XSS) allows an attacker to execute arbitrary JavaScript within the browser of a victim user.
   - Cross-site request forgery (or CSRF) allows an attacker to induce a victim user to perform actions that they do not intend to.

##### The consequences of XSS vulnerabilities are generally more serious than for CSRF vulnerabilities:
   - CSRF (Cross-Site Request Forgery) can sometimes only affect a few things a user can do on a website. Some websites protect against CSRF for most actions but forget to secure one or two specific actions. On the other hand, an XSS (Cross-Site Scripting) attack can trick a user into doing anything they're allowed to do on the site, no matter where the vulnerability is. So, it's more powerful in manipulating user actions compared to CSRF.
   - CSRF can be described as a "one-way" vulnerability, in that while an attacker can induce the victim to issue an HTTP request, they cannot retrieve the response from that request. Conversely, XSS is "two-way", in that the attacker's injected script can issue arbitrary requests, read the responses, and exfiltrate data to an external domain of the attacker's choosing.

### Can CSRF tokens prevent XSS attacks?
   - Some XSS attacks can indeed be prevented through effective use of CSRF tokens.

**Consider a simple reflected XSS vulnerability that can be trivially exploited like this:**
```js
https://insecure-website.com/status?message=<script>/*+Bad+stuff+here...+*/</script>
```

**Now, suppose that the vulnerable function includes a CSRF token:**
```js
https://insecure-website.com/status?csrf-token=CIwNZNlR4XbisJF39I8yWnWX9wX4WFoz&message=<script>/*+Bad+stuff+here...+*/</script>
```

   - Assuming that the server properly validates the CSRF token, and rejects requests without a valid token, then the token does prevent exploitation of the XSS vulnerability.
   - The clue here is in the name: "cross-site scripting", at least in its reflected form, involves a cross-site request. By preventing an attacker from forging a cross-site request, the application prevents trivial exploitation of the XSS vulnerability.

###### Some important caveats arise here:
   - If a reflected XSS vulnerability exists anywhere else on the site within a function that is not protected by a CSRF token, then that XSS can be exploited in the normal way.
   - If a website has a vulnerability called XSS (Cross-Site Scripting) in any part of it, that vulnerability can be used to make a user do things, even if those actions are guarded by CSRF tokens. The attacker's script can ask for the right page to get a valid CSRF token, and then use that token to carry out the protected action. So, XSS can bypass CSRF protections in this way.
   - CSRF tokens do not protect against stored XSS vulnerabilities. If a page that is protected by a CSRF token is also the output point for a stored XSS vulnerability, then that XSS vulnerability can be exploited in the usual way, and the XSS payload will execute when a user visits the page.

## Common defences against CSRF
   - Nowadays, successfully finding and exploiting CSRF vulnerabilities often involves bypassing anti-CSRF measures deployed by the target website, the victim's browser, or both.

#### The most common defenses you'll encounter are as follows:
1. **CSRF tokens:**
	- A CSRF token is a unique, secret, and unpredictable value that is generated by the server-side application and shared with the client.
	- When attempting to perform a sensitive action, such as submitting a form, the client must include the correct CSRF token in the request. 
	- This makes it very difficult for an attacker to construct a valid request on behalf of the victim.

2. **SameSite cookies:**
	- SameSite cookies are a security feature in web browsers. They control when a website's cookies are sent in requests from other websites.
	- Cookies are often used to verify a user's identity for sensitive actions on a website.
	- SameSite rules can stop an attacker from making these actions happen from a different website.
	- SameSite rules can stop an attacker from making these actions happen from a different website.
	- Starting in 2021, Google Chrome made Lax SameSite rules the default.
	- Other big browsers are likely to follow this standard in the future. This change enhances security by reducing the chances of cross-site attacks.

3. **Referer-based validation:**
	- Some applications make use of the HTTP Referer header to attempt to defend against CSRF attacks, normally by verifying that the request originated from the application's own domain. This is generally less effective than CSRF token validation.


## Steps to solve lab
### Title - CSRF vulnerability with no defenses

**Desc** - This lab's email change functionality is vulnerable to CSRF. To solve the lab, craft some HTML that uses a [CSRF attack](https://portswigger.net/web-security/csrf) to change the viewer's email address and upload it to your exploit server.
You can log in to your own account using the following credentials: `wiener:peter`

**Our end goal** - To solve the lab, craft some HTML that uses a [CSRF attack](https://portswigger.net/web-security/csrf) to change the viewer's email address and upload it to your exploit server.


1. Analyse the website and check that three key conditions must be in place for a CSRF attack to be possible:
After analysing the site, we come a endpoint where it is possible to change the email of a user. So, change your email and at the same time intercept it with burpsuite and sent it to Repeater.
![[csrf2.png]]
   - A relevant action - email change functionality.
   - Cookie based session handling.
   - No unpredictable request parameters - Satisfied(As you can see, there is no CSRF token that we can't predict it).

2. Now, we are going to create "CSRF POC" script with the help of burpsuite pro and for that right click on the request that we captured earlier with the help of burpsuite pro do the below steps:
"Engagement tools" > "Generate CSRF PoC"
![[csrf3.png]]

After doing the above steps, there is a new window pop up. 
![[csrf4.png]]
In this window, click on "Options" and make sure to select first and last options and click "Regenerate" and copy the script.

3. Paste the payload that copied in the step 2.
![[csrf5.png]]

If email is not changed after doing it with exploit server then In step 2 click "Test in browser". Now you will see the email has changed.
![[csrf6.png]]
paste the link in the browser, now you will see that the email has been changed.
You can also click on "View exploit" in the step 3 to see the email.

#### Without burpsuite professional

1. Analyse the website and check that three key conditions must be in place for a CSRF attack to be possible:
After analysing the site the site, we come a endpoint where it is possible to change the email of a user. So, change your email and at the same time intercept it with burpsuite and sent it to Repeater.
![[csrf2.png]]
   - A relevant action - email change functionality.
   - Cookie based session handling.
   - No unpredictable request parameters - Satisfied(As you can see, there is no CSRF token that we can't predict it).

2. Now, copy the below payload and paste where you wanted to start your web server.
```html
<html>
    <body>
        <h1>Hello World!</h1>
        <iframe style="display:none" name="csrf-iframe"></iframe>
        <form action="https://target-acb91feb1e053ea78076271500a20022.web-security-academy.net/my-account/change-email" method="POST" target="csrf-iframe" id="csrf-form">
            <input type="hidden" name="email" value="test5@test.ca">
        </form>

        <script>document.getElementById("csrf-form").submit()</script>
    </body>
</html>
```

![[csrf7.png]]

3. Now, start the python server with the help of below command:
```shell
┌──(hoax㉿kali)-[~]
└─$ pwd                                                               
/home/hoax                                                                              
┌──(hoax㉿kali)-[~]
└─$ python3 -m http.server 5555                                       
Serving HTTP on 0.0.0.0 port 5555 (http://0.0.0.0:5555/) ...
```

4. Make a GET request at the below endpoint.
![[csrf8.png]]

**For detail information watch** --> [[CSRF-Lab1_CSRF_vulnerability_with_no_defenses _ Long Version.mp4]]