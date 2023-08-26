## Resetting passwords using a URL
- When resetting passwords on websites, there are different methods used. One method involves sending users a unique URL that takes them to a password reset page.

**However, some implementations of this method are not secure.**
**First** - 
- In an insecure implementation, the URL contains a parameter that easily identifies the account being reset.
```js
http://vulnerable-website.com/reset-password?user=victim-user(http://vulnerable-website.com/reset-password?user=victim-user.
```
- An attacker can change the "user" parameter to any username they want, allowing them to directly access a page where they can potentially set a new password for that user.

**Second** - 
- A better approach is to generate a random and difficult-to-guess token.
```js
http://vulnerable-website.com/reset-password?token=a0ba0d1cb3b63d13822572fcff1a241895d893f659164d4cc550b421ebdd48a8.
```
- When a user visits this URL, the system should check if the token exists and which user's password it is meant to reset. The token should have a short expiration time and should be destroyed immediately after the password is reset.
- However, some websites fail to re-validate the token when the reset form is submitted. This means an attacker can visit the reset form from their own account, delete the token, and use this page to reset any user's password without proper authorization.

## Password reset poisoning via middleware(lab)
- If the URL in the reset email is generated dynamically, this may also be vulnerable to password reset poisoning. In this case, an attacker can potentially steal another user's token and use it change their password.