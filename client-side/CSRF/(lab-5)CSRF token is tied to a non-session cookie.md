In a variation on the preceding vulnerability, some applications do tie the CSRF token to a cookie, but not to the same cookie that is used to track sessions.

>This can easily occur when an application employs two different frameworks, one for session handling and one for CSRF protection, which are not integrated together:
```js
POST /email/change HTTP/1.1 
Host: vulnerable-website.com 
Content-Type: application/x-www-form-urlencoded 
Content-Length: 68 
Cookie: session=pSJYSScWKpmC60LpFOAHKixuFuM4uXWF; csrfKey=rZHCnSzEp8dbI6atzagGoSYyqJqTz5dv 

csrf=RhV7yQDO0xcq9gLEah2WVbmuFqyOq7tY&email=wiener@normal-user.com
```

- This situation is harder to exploit but is still vulnerable. If the web site contains any behavior that allows an attacker to set a cookie in a victim's browser, then an attack is possible.
- The attacker can log in to the application using their own account, obtain a valid token and associated cookie, leverage the cookie-setting behavior to place their cookie into the victim's browser, and feed their token to the victim in their CSRF attack.

##### Note
   if there's a security weakness (CSRF vulnerability) in a website, attackers can use another website in the same domain to set cookies on the vulnerable site, even if they are not part of the same application. This can be a way for attackers to exploit the vulnerability and gain unauthorized access.
## Steps to solve lab
### Title - CSRF where token is tied to non-session cookie

**Desc** -  This lab's email change functionality is vulnerable to CSRF. It uses tokens to try to prevent CSRF attacks, but they aren't fully integrated into the site's session handling system. To solve the lab, use your exploit server to host an HTML page that uses a [CSRF attack](https://portswigger.net/web-security/csrf) to change the viewer's email address.

**Creds** - 
You have two accounts on the application that you can use to help design your attack. The credentials are as follows:
- `wiener:peter`
- `carlos:montoya`

1. Analyse the website and check that three key conditions must be in place for a CSRF attack to be possible:
After analysing the site, we come across a endpoint where it is possible to change the email of a user. So, change your email and at the same time intercept it with burpsuite.
![[csrf24.png]]

   - A relevant action - email change functionality.
   - Cookie based session handling.
   - No unpredictable request parameters - Satisfied(As you can see, there is CSRF token that we can't predict it). We can bypass CSRF token protection later on.

From the lab description, we already know that "csrfKey" parameter is tied to "CSRF token" and it means we need to have both "csrfKey" and "CSRF token" to change the victim's email address.

2. **Testing CSRF Token and CSRF cookies**:

	 1. **Check if the CSRF token is tied to the CSRF cookie**
		 1. Submit an invalid CSRF token.
	         ![[csrf25.png]]
	    
	        ![[csrf26.png]]
	    
	2. Submit a valid CSRF token from another user.
	   **Open browser in incognito mode and login with the credentials of "carlos" and copy the CSRF token of carlos**
	      ![[csrf27.png]]
	   
	      ![[csrf28.png]]
	   
	   **Now, paste the copied CSRF token to "POST /my-account/change-email" request of wiener**
	      ![[csrf29.png]]
	
	2. Submit valid CSRF token and cookie from another user.
	   ![[csrf30.png]]
	   
	   ![[csrf31.png]]
	   As you can see above, we are able change the email but with the help of another user "csrfKey" value as well as "CSRF token". From this we can say that session handling mechanism of web app is not tied to "CSRF protection" mechanism.

3. In order to exploit this vulnerability, we need to perform 2 things:
	1. Inject a "csrfKey" cookie in the user's session (HTTP header injection).
	   ![[csrf32.png]]
	   
	   ![[csrf33.png]]
	   In the left, we've just set the "csrfKey" value in the searchTerm and we got a reply, it means we successfully set the value of "csrfKey" value from the search box.
	   It doesn't give us error that means we are able to inject "csrfKey" cookie into victim's browser later on.
	   
	2. Send a CSRF attack to the victim with a known CSRF token.

	  **Generate CSRF PoC from the "POST /my-account/change-email" request of attacker email change**
	  ![[csrf34.png]]
	  
	  **Make a img tag with the value of "src" is the URL to front page of web app**
	  ![[csrf36.png]]
	  
	  **Copy the URL that you paste above in "img" tag of "src" attribute from the request as shown below:**
	  ![[csrf35.png]]
	  
	  **Now, copy the "search" value and parameter search to set the value of "csrfKey" of victim as the "csrfKey" value of attacker As shown below:**
	  ![[csrf37.png]]

	 
	  **Now, copy the "CSRF token" of attacker to the generated PoC as shown below:**
	  ![[csrf39.png]]
	  
	  **Our PoC** - 
	  ![[csrf38.png]]
	  
	  **Copy the html into the exploit server and add in the end "%3b%20SameSite=None"**
	  ![[csrf40.png]]

**SameSite=None:**
   - This means that the cookie can be sent in cross-site requests.
   - It allows the cookie to be included in requests made to a different domain.
   - This is often necessary for features like single sign-on (SSO) or when making cross-origin API requests.

