**Some applications validate the `Referer` header in a naive way that can be bypassed.**

For example, if the application validates that the domain in the `Referer` starts with the expected value, then the attacker can place this as a subdomain of their own domain:
```js
http://vulnerable-website.com.attacker-website.com/csrf-attack
```

**Likewise, if the application simply validates that the `Referer` contains its own domain name, then the attacker can place the required value elsewhere in the URL:**
```js
http://attacker-website.com/csrf-attack?vulnerable-website.com
```


#### Note
Although you may be able to identify this behavior using Burp, you will often find that this approach no longer works when you go to test your proof-of-concept in a browser. In an attempt to reduce the risk of sensitive data being leaked in this way, many browsers now strip the query string from the `Referer` header by default.

You can override this behavior by making sure that the response containing your exploit has the `Referrer-Policy: unsafe-url` header set (note that `Referrer` is spelled correctly in this case, just to make sure you're paying attention!). This ensures that the full URL will be sent, including the query string.

## Steps to solve lab
### Title - CSRF with broken Referer validation

**Desc** - This lab's email change functionality is vulnerable to CSRF. It attempts to detect and block cross domain requests, but the detection mechanism can be bypassed. To solve the lab, use your exploit server to host an HTML page that uses a [CSRF attack](https://portswigger.net/web-security/csrf) to change the viewer's email address. 

**Creds** - You can log in to your own account using the following credentials: `wiener:peter`

1. Analyse the website and check that three key conditions must be in place for a CSRF attack to be possible:
After analysing the site, we come a endpoint where it is possible to change the email of a user. So, change your email and at the same time intercept it with burpsuite and sent it to Repeater.
![[csrf2.png]]
   - A relevant action - email change functionality.
   - Cookie based session handling.
   - No unpredictable request parameters - Satisfied(As you can see, there is no CSRF token that we can't predict it).

2. Testing Referer header for CSRF attacks:
	1. Remove the Referer header.
	  ![[csrf74.png]]
	  
	  ![[csrf75.png]]
	  As you can see above, Removing Referer header doesn't help us to change email.
	
	2. Check which portion of the Referrer header is the application validating.
	 ![[csrf76.png]]
	 As you can see above, "Referer" header only validates the "Host" value in the "Referer" header and we tested it by placing our domain and it works, no error in the response.

3. Now, we are going to create "CSRF POC" script with the help of burpsuite pro and for that right click on the request that we captured earlier with the help of burpsuite pro do the below steps:
"Engagement tools" > "Generate CSRF PoC"
![[csrf53.png]]

**After doing the above steps, there is a new window pop up.**
![[csrf54.png]]
In this window, click on "Options" and make sure to select first and last options and click "Regenerate" and copy the script.

4. Now, add the domain url as a query string in the third argument of "history.pushState('', '', '/?https://0a65000a0450dbd384bca5bb004200a0.web-security-academy.net/');" to bypass Referer header(or add the following URL as the value of Referer header) and add the below code in the head section of "exploit-server" to prevent browsers to strip the query string from the "Referer" header.
**Code** - 
```js
Referrer-Policy: unsafe-url
```

![[csrf77.png]]

