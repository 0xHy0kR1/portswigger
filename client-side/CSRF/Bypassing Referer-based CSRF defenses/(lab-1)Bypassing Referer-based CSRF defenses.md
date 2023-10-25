some applications make use of the HTTP `Referer` header to attempt to defend against CSRF attacks, normally by verifying that the request originated from the application's own domain. This approach is generally less effective and is often subject to bypasses.

## Pre-requisite --> [[Referer header]]

## Validation of Referer depends on header being present

   - Some applications validate the `Referer` header when it is present in requests but skip the validation if the header is omitted.
   - In this situation, an attacker can craft their CSRF exploit in a way that causes the victim user's browser to drop the `Referer` header in the resulting request. There are various ways to achieve this, but the easiest is using a META tag within the HTML page that hosts the CSRF attack:
```js
<meta name="referrer" content="never">
```

## Steps to solve lab
### Title - CSRF where Referer validation depends on header being present

**Desc** - This lab's email change functionality is vulnerable to CSRF. It attempts to block cross domain requests but has an insecure fallback. To solve the lab, use your exploit server to host an HTML page that uses a CSRF attack to change the viewer's email address. 

**Creds** - You can log in to your own account using the following credentials: `wiener:peter`

1. Analyse the website and check that three key conditions must be in place for a CSRF attack to be possible:
After analysing the site, we come across a endpoint where it is possible to change the email of a user. So, change your email and at the same time intercept it with burpsuite and sent it to Repeater.
![[csrf71.png]]
   - A relevant action - email change functionality.
   - Cookie based session handling.
   - No unpredictable request parameters - Satisfied(As you can see, there is no CSRF token that we can't predict it).
In this lab, the defense is enforced with the help of [[Referer header]] and we already know that from the above theory that if the [[Referer header]] isn't present then this validation can be circumvented.

2. Now, we are going to create "CSRF POC" script with the help of burpsuite pro and for that right click on the request that we captured earlier with the help of burpsuite pro do the below steps:
"Engagement tools" > "Generate CSRF PoC"
![[csrf53.png]]

**After doing the above steps, there is a new window pop up.**
![[csrf54.png]]
In this window, click on "Options" and make sure to select first and last options and click "Regenerate" and copy the script.

3. Now, add the below code to make the victim to drop the [[Referer header]].
```js
<meta name="referrer" content="never">
```

![[csrf73.png]]
