- In addition to the basic login functionality, most websites provide supplementary functionality to allow users to manage their account. For example, users can typically change their password or reset their password when they forget it. These mechanisms can also introduce vulnerabilities that can be exploited by an attacker.
- This is especially important in cases where an attacker is able to create their own account and, consequently, has easy access to study these additional pages.

## Keeping users logged in
- A common feature is the option to stay logged in even after closing a browser session. This is usually a simple checkbox labeled something like "Remember me" or "Keep me logged in".
- This functionality is often implemented by generating a "remember me" token of some kind, which is then stored in a persistent cookie.
- However, some websites generate this cookie based on a predictable concatenation of static values, such as the username and a timestamp. Some even use the password as part of the cookie. This approach is particularly dangerous if an attacker is able to create their own account because they can study their own cookie and potentially deduce how it is generated. Once they work out the formula, they can try to brute-force other users' cookies to gain access to their accounts.
- Some websites assume that if the cookie is encrypted in some way it will not be guessable even if it does use static values.
- the cookie using a simple two-way encoding like Base64 offers no protection whatsoever. Even using proper encryption with a one-way hash function is not completely bulletproof. If the attacker is able to easily identify the hashing algorithm, and no salt is used, they can potentially brute-force the cookie by simply hashing their wordlists.
- This method can be used to bypass login attempt limits if a similar limit isn't applied to cookie guesses.

## Steps to solve lab
### Title - Brute-forcing a stay-logged-in cookie

**Desc** - This lab allows users to stay logged in even after they close their browser session. The cookie used to provide this functionality is vulnerable to brute-forcing. To solve the lab, brute-force Carlos's cookie to gain access to his "My account" page.

**Creds** - 
- Your credentials: `wiener:peter`
- Victim's username: `carlos`

1. Analyze every endpoint to find out any stay-logged-in cookie.
![[authentication1.png]]
You can see that above, the "stay-logged-in" cookie is base64 encoded.

After analyzing the hash type text present with "username" in "stay-logged-in" cookie, we came to know that it is md5 hash
![[authentication2.png]]

So, we have now gathered all of the information needed to brute-force the "stay-logged-in" cookie. Log out of your account.
`base64(username+':'+md5HashOfPassword)`

2. In the most recent `GET /my-account`, highlight the `stay-logged-in` cookie parameter and send the request to Burp Intruder.
**Settings for brute-forcing with burp intruder**

**Setting the injection points** - 
![[authentication3.png]]
Replace "wiener" from "carlos".

**Paste the passwords provided you from lab** - 
![[authentication4.png]]

**Add the below "Payload processing" rule**
![[authentication5.png]]

**We got the result and we successfully brute-force the carlos account page**
![[authentication6.png]]
