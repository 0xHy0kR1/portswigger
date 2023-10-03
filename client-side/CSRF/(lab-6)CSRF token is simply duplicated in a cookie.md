In a further variation on the preceding vulnerability, some applications do not maintain any server-side record of tokens that have been issued, but instead duplicate each token within a cookie and a request parameter.

When the subsequent request is validated, the application simply verifies that the token submitted in the request parameter matches the value submitted in the cookie.

>This is sometimes called the "double submit" defense against CSRF, and is advocated because it is simple to implement and avoids the need for any server-side state:
```js
POST /email/change HTTP/1.1 
Host: vulnerable-website.com 
Content-Type: application/x-www-form-urlencoded 
Content-Length: 68 Cookie: session=1DQGdzYbOJQzLP7460tfyiv3do7MjyPw; csrf=R8ov2YBfTYmzFyjit8o2hKBuoIjXXVpa 

csrf=R8ov2YBfTYmzFyjit8o2hKBuoIjXXVpa&email=wiener@normal-user.com
```

- In this situation, the attacker can again perform a CSRF attack if the web site contains any cookie setting functionality.
- Here, the attacker doesn't need to obtain a valid token of their own. They simply invent a token (perhaps in the required format, if that is being checked), leverage the cookie-setting behavior to place their cookie into the victim's browser, and feed their token to the victim in their CSRF attack.

## Steps to solve lab
### Title - CSRF where token is duplicated in cookie

**Desc** - This lab's email change functionality is vulnerable to CSRF. It attempts to use the insecure "double submit" CSRF prevention technique. To solve the lab, use your exploit server to host an HTML page that uses a [CSRF attack](https://portswigger.net/web-security/csrf) to change the viewer's email address.

**Creds** - You can log in to your own account using the following credentials: `wiener:peter`

1. Analyse the website and check that three key conditions must be in place for a CSRF attack to be possible:
After analysing the site, we come across a endpoint where it is possible to change the email of a user. So, change your email and at the same time intercept it with burpsuite.
![[csrf41.png]]
   - A relevant action - email change functionality.
   - Cookie based session handling.
   - No unpredictable request parameters - Satisfied(As you can see, there is CSRF token that we can't predict it). We can bypass CSRF token protection later on.

2. Testing CSRF Tokens:
	1. Remove the CSRF token and see if application accepts request.
	2. Change the request method from POST to GET.
	3. See if CSRF token is tied to user session.

To better understand STEP-2 please follow labs from 1 to 5.

3. Testing CSRF tokens and CSRF cookies
	1. Check if the CSRF token is tied to the  CSRF cookie.
		1. Submit an invalid CSRF token.
		2. Submit a valid CSRF token from another user.
	2. Submit valid CSRF token and cookie from another user.

From our analysation, we already know that "csrf" cookie and "CSRF" token is same. So, there isn't need for step 3 but for better understanding follow lab from 1 to 5.

4. In order to exploit this vulnerability, we need to perform 2 things:
	1. Inject a "csrf" cookie in the user's session (HTTP Header injection) - satisfied
	   ![[csrf42.png]]
	   
	   ![[csrf43.png]]
	   In the left, we've just set the "csrfKey" value in the searchTerm and we got a reply, it means we successfully set the value of "csrf" value from the search box.
	   It doesn't give us error that means we are able to inject "csrfKey" cookie into victim's browser later on.
	   
	2. Send a CSRF attack to the victim with a known CSRF token.
       **Generate CSRF PoC from the "POST /my-account/change-email" request of attacker email change**
	  ![[csrf44.png]]
	  
	  **Make a img tag with the value of "src" is the URL to front page of web app**
	  ![[csrf45.png]]
	  
	  **Copy the URL that you paste above in "img" tag of "src" attribute from the request as shown below:**
	  ![[csrf46.png]]
	  
	  **Now, copy the "search" value and parameter search to set the value of "csrf" of victim,   As shown below:**
	  ![[csrf47.png]]
	  As we already know that "CSRF" token should be equal to "csrf" cookie and web app doesn't record issued csrf tokens so, we don't need to assign it a valid CSRF token value to anyone.
	  
	  **Our final generated PoC looks as shown below**
	  ![[csrf48.png]]
	  
	  **Copy the html into the exploit server and add in the end "%3b%20SameSite=None"**
	  ![[csrf49.png]]

**SameSite=None:**
   - This means that the cookie can be sent in cross-site requests.
   - It allows the cookie to be included in requests made to a different domain.
   - This is often necessary for features like single sign-on (SSO) or when making cross-origin API requests.