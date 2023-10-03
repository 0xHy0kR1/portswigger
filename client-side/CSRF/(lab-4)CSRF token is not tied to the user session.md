Some apps don't check if a token belongs to the same user session. They keep a list of issued tokens and accept any token from that list. 

In this situation, the attacker can log in to the application using their own account, obtain a valid token, and then feed that token to the victim user in their CSRF attack.

## Steps to solve lab
### Title - CSRF where token is not tied to user session

**Desc** - This lab's email change functionality is vulnerable to CSRF. It uses tokens to try to prevent CSRF attacks, but they aren't integrated into the site's session handling system. To solve the lab, use your exploit server to host an HTML page that uses a CSRF attack to change the viewer's email address. 

**Credentials** - 
You have two accounts on the application that you can use to help design your attack. The credentials are as follows:

- `wiener:peter`
- `carlos:montoya`

1. Analyse the website and check that three key conditions must be in place for a CSRF attack to be possible:
After analysing the site, we come across a endpoint where it is possible to change the email of a user. So, change your email and at the same time intercept it with burpsuite.
![[csrf9.png]]
  - A relevant action - email change functionality.
   - Cookie based session handling.
   - No unpredictable request parameters - Satisfied(As you can see, there is CSRF token that we can't predict it). We can bypass CSRF token protection later on.

2. Testing CSRF Tokens:
	1. Remove the CSRF token and see if application accepts request.
	   **Before removing CSRF Token** - 
	   ![[csrf14.png]]
	   
	   **After removing CSRF Token** - 
	   ![[csrf15.png]]
	   As you can see above, CSRF Token should be present otherwise it trigger error.

	2. Change the request method from POST to GET.
	   To change the request method from POST to GET look below.
	   ![[csrf16.png]]
	   
	   As you can see below, it triggers error and it doesn't except "GET" request.
	   ![[csrf17.png]]
	   
	   3. See if CSRF Token is tied to user session.
	    In order to test that CSRF Token is tied to user session or not, you need two accounts or you can also do this with incognito mode.
		1. Login from incognito mode and login in the below page with the help of another user credentials.
		   ![[csrf18.png]]
		   
		   2. Now, copy the CSRF Token of the user that you logged in from incognito mode.
		      ![[csrf20.png]]
		  
		  3. Paste the CSRF Token of user  "carlos" to the user wiener as shown below.
		     ![[csrf21.png]]
		     From the above testing, we can say that user session is not tied to CSRF Token it means we can exploit it with the below method
		     
3. Steps to exploit CSRF vulnerability when the user session is not tied to CSRF Token.
	1. Capture the "/my-account/change-email" request of wiener in burp pro and do the below steps:
        "Engagement tools" > "Generate CSRF PoC"
        ![[csrf22.png]]
        
        2. Grab the CSRF token of user "carlos" with the help of incognito 
        ![[csrf20.png]]
        
        3. Now, copy the CSRF Token to the "CSRF PoC" and paste the script in the exploit server as shown below:
           ![[csrf23.png]]
           