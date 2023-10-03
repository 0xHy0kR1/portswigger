## What is username enumeration?
- Username enumeration is a technique used by attackers to identify valid usernames or user accounts within a system or application.
- The process of username enumeration typically involves making repeated login attempts using different usernames and observing the system's response. By analyzing the system's behavior, an attacker can determine whether a particular username exists in the system or not.
- Username enumeration typically occurs either on the login page, for example, when you enter a valid username but an incorrect password, or on registration forms when you enter a username that is already taken.

**While attempting to brute-force a login page, you should pay particular attention to any differences in:**
1. Status codes:
	- During a brute-force attack, the returned HTTP status code is likely to be the same for the vast majority of guesses because most of them will be wrong. If a guess returns a different status code, this is a strong indication that the username was correct.

2. Error messages:
	- Sometimes the returned error message is different depending on whether both the username AND password are incorrect or only the password was incorrect.

3. Response times:
	- A website might only check whether the password is correct if the username is valid. This extra step might cause a slight increase in the response time, This may be subtle, but an attacker can make this delay more obvious by entering an excessively long password

## Brute force prevention ways:
#### 1. Account locking:
- Account locking also fails to protect against credential stuffing attacks.
- This involves using a massive dictionary of `username:password` pairs, composed of genuine login credentials stolen in data breaches. Credential stuffing relies on the fact that many people reuse the same username and password on multiple websites and, therefore, there is a chance that some of the compromised credentials in the dictionary are also valid on the target website.
- Account locking does not protect against credential stuffing because each username is only being attempted once.

#### 2. User rate limiting:
- In this case, making too many login requests within a short period of time causes your IP address to be blocked.
**Typically, the IP can only be unblocked in one of the following ways:**
- Automatically after a certain period of time has elapsed
- Manually by an administrator
- Manually by the user after successfully completing a CAPTCHA

As the limit is based on the rate of HTTP requests sent from the user's IP address, it is sometimes also possible to bypass this defense if you can work out how to guess multiple passwords with a single request(which is done if credentials sent to the server in the format of json data. check out --> [[Broken brute-force protection, multiple credentials per request]] lab).

## HTTP basic authentication
- In HTTP basic authentication, the client receives an authentication token from the server, which is constructed by concatenating the username and password, and encoding it in Base64.
- This token is stored and managed by the browser, which automatically adds it to the `Authorization` header of every subsequent request as follows:
```js
Authorization: Basic base64(username:password)
```
this is generally not considered a secure authentication method. Firstly, it involves repeatedly sending the user's login credentials with every request.
HTTP basic authentication is also particularly vulnerable to session-related exploits, notably [CSRF](https://portswigger.net/web-security/csrf)