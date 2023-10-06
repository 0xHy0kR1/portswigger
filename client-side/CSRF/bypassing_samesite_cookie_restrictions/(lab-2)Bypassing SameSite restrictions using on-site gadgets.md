- When a cookie has SameSite=Strict setting, it's very strict about where it can be used. Browsers won't send this cookie in requests to different websites (cross-site requests). This strict setting prevents the cookie from working on other websites.
- You can sometimes bypass this cookie limitation by using a trick or "gadget". One such trick is to create a redirect on a website that you control. This redirect is set up to go to a location that depends on what the attacker wants (like a URL parameter).

#### Example:
   Imagine a link on a website that says, "Go to this page," but the actual destination is determined by what the attacker puts in the link.
   
   This way, the attacker can use the cookie on their website even though it's supposed to be strict.

- Client-side redirects don't look like redirects to web browsers. Browsers treat them as regular requests. These requests are considered "same-site," so all site-related cookies are sent. Even if there were cookie restrictions, they're ignored.
- If manipulated cleverly, this can help bypass SameSite cookie restrictions, potentially causing security issues.

**Note** - 
When a website uses a server-side redirect, the browser knows that the redirect is happening because of a request made from a different website (cross-site request). Because of this, the browser applies certain security measures to protect your cookies (bits of data that store your login and session information). As a result, it's not possible for an attacker to easily steal your cookies when a server-side redirect is used, because the browser keeps those security measures in place.

## Steps to solve lab
### Title - SameSite Strict bypass via client-side redirect

**Desc** - This lab's change email function is vulnerable to CSRF. To solve the lab, perform a [CSRF attack](https://portswigger.net/web-security/csrf) that changes the victim's email address. You should use the provided exploit server to host your attack.

**Creds** - You can log in to your own account using the following credentials: `wiener:peter`


```python
https://0a9f00b10423335784d33baa00a60065.web-security-academy.net/post/comment/confirmation?postId=../my-account/change-email?email=sukuna%40gmail.com%26submit=1
```

1. Analyse the website and check that three key conditions must be in place for a CSRF attack to be possible:
After analysing the site, we come a endpoint where it is possible to change the email of a user. So, change your email and at the same time intercept it with burpsuite and sent it to Repeater.
![[csrf52.png]]
   - A relevant action - email change functionality.
   - Cookie based session handling.
   - No unpredictable request parameters - Satisfied(As you can see, there is no CSRF token that we can't predict it).

2. Now, it doesn't to just send cross-site request from exploit server to this endpoint because there is "SameSite=Strict" restriction is applied in "/login" endpoint.
![[csrf56.png]]

We already know that, we can bypass this restriction by client-redirect and for that we need to find the page on website where client redirect is happen.

After analyzing lots of endpoints, I got a page where it redirect when we successfully submitted the comment.
**Comment functionality in blog** - 
![[csrf57.png]]

**redirection upon comment submission** - 
![[csrf58.png]]

**js of Commnet confirmation page** - 
![[csrf59.png]]
As you see above, postId is added in "window.location" and executed. So, from this we can execute our tempered link to "/my-account/change-email" endpoint.

3. Now, copy the below payload and paste it in the exploit server.
```js
<html>
  <!-- CSRF PoC - generated by Burp Suite Professional -->
  <body>
      <script>
        window.location = "https://0a4800c703094803803735dc00c100f6.web-security-academy.net/post/comment/confirmation?postId=../my-account/change-email?email=sukuna%40gmail.com%26submit=1"
      </script>
  </body>
</html>
```

![[csrf60.png]]