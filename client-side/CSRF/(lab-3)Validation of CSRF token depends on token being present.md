Some applications correctly validate the token when it is present but skip the validation if the token is omitted(missing).

>In this situation, the attacker can remove the entire parameter containing the token (not just its value) to bypass the validation and deliver a CSRF attack:
```js
POST /email/change HTTP/1.1 
Host: vulnerable-website.com 
Content-Type: application/x-www-form-urlencoded 
Content-Length: 25 
Cookie: session=2yQIDcpia41WrATfjPqvm9tOkDvkMvLm 

email=pwned@evil-user.net
```

## Steps to solve lab
### Title - CSRF where token validation depends on token being present

**Desc** - This lab's email change functionality is vulnerable to CSRF. To solve the lab, use your exploit server to host an HTML page that uses a CSRF attack to change the viewer's email address.

**Credentials** - You can log in to your own account using the following credentials: `wiener:peter`

1. Analyse the website and check that three key conditions must be in place for a CSRF attack to be possible:
After analysing the site, we come across a endpoint where it is possible to change the email of a user. So, change your email and at the same time intercept it with burpsuite.
![[csrf9.png]]
  - A relevant action - email change functionality.
   - Cookie based session handling.
   - No unpredictable request parameters - Satisfied(As you can see, there is CSRF token that we can't predict it). We can bypass CSRF token protection by changing the request method.

2. Now, we are going to create "CSRF POC" script with the help of burpsuite pro and for that right click on the request that we captured earlier with the help of burpsuite pro do the below steps:
"Engagement tools" > "Generate CSRF PoC"
![[csrf3.png]]

After doing the above steps, there is a new window pop up. 
Remove the "input" tag containing CSRF parameter and value because some applications correctly validate the token when it is present but skip the validation if the token is omitted(missing).
![[csrf12.png]]
In this window, click on "Options" and make sure to select first and last options and click "Regenerate" and copy the script.

3. Paste the payload that copied in the step 2.
![[csrf13.png]]
