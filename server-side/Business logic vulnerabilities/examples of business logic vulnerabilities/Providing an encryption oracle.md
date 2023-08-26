Dangerous scenarios can occur when user-controllable input is encrypted and the resulting ciphertext is then made available to the user in some way. This kind of input is sometimes known as an "encryption oracle". An attacker can use this input to encrypt arbitrary data using the correct algorithm and asymmetric key.

This becomes dangerous when there are other user-controllable inputs in the application that expect data encrypted with the same algorithm. In this case, an attacker could potentially use the encryption oracle to generate valid, encrypted input and then pass it into other sensitive functions.

This issue can be compounded if there is another user-controllable input on the site that provides the reverse function. This would enable the attacker to decrypt other data to identify the expected structure.

The severity of an encryption oracle depends on what functionality also uses the same algorithm as the oracle.

## Steps to solve the lab-1
### Desc - Authentication bypass via encryption oracle

1. First we login with our our credentials.
2. When we enter into one of the blog then in the request to that endpoint, we can clearly see that there is a notification cookie.
![[Blv42.png]]
But when we enter an invalid email address then we can clearly see that our email address displayed in the plain text in the web page and in the response we get to see that this notification is there and as well as in the in request.
![[Blv43.png]]

**In web page** - 
![[Blv44.png]]

Deduce that email must be decrypted from the `notification` cookie. 

3. Send the `POST /post/comment` and the subsequent `GET /post?postId=x` request (containing the notification cookie) to Burp Repeater.
4. In Repeater, observe that you can use the `email` parameter of the `POST` request to encrypt arbitrary data and reflect the corresponding ciphertext in the `Set-Cookie` header of response. Likewise, you can use the `notification` cookie in the `GET` request to decrypt arbitrary ciphertext and reflect the output in the error message. For simplicity, double-click the tab for each request and rename the tabs `encrypt` and `decrypt` respectively.
**Example** - 
**In encryption tab of repeater** - 
![[Blv45.png]]

**In decryption tab of repeater** - 
![[Blv46.png]]

5. In the decrypt request, copy your `stay-logged-in` cookie and paste it into the `notification` cookie. Send the request. Instead of the error message, the response now contains the decrypted `stay-logged-in` cookie, for example:
    
    `wiener:1598530205184`
    
    This reveals that the cookie should be in the format `username:timestamp`. Copy the timestamp to your clipboard.

**In the decrypt tab** - 
![[Blv47.png]]

6. Go to the encrypt request and change the email parameter to `administrator:your-timestamp`. Send the request and then copy the new `notification` cookie from the response.
![[Blv48.png]]

7. Decrypt this new cookie and observe that the 23-character "`Invalid email address:` " prefix is automatically added to any value you pass in using the `email` parameter. Send the `notification` cookie to Burp Decoder.
![[Blv49.png]]
Now, we just need the `administrator:1689750376920` at the time of login(We don't need 23 bytes which is that `Invalid email address` part). So, we need the hash value of this and we put that hash value in the `stay-lagged-in` parameter when we come again after log out from wiener account.

8. Now, send the encrypted value of  `administrator:1689750376920` to decoder and first decode it with url decode then base64 decode then delete 23 characters(for `Invalid email address` part) and again encode it with base64 then url and you get encrypted value of `administrator`.
![[Blv50.png]]

9. Now, copy and paste the administrator hash to notification cookie and try to decrypt it but you get internal server error because you need almost 16 characters to decrypt it.
![[Blv51.png]]

10. Now, we are going to put `x` 9 times to get multiple of 16(which is 32 chars `Invalid email address xxxxxxxxxadministrator:1689750376920`) and we get the hash of this input.
![[Blv52.png]]

11. Now, we are going to send the notification hash value to the decoder and use the same process as mentioned above but we delete 32 chars this because `Invalid email address xxxxxxxxx` count as 32 and get the encrypted value of `administrator:1689750376920` 
![[Blv53.png]]

12. Now, copy the above notification cookie value and navigate to the home page and with turn on the intercept. Delete the session value and paste the above notification value in the stay-logged-in parameter.
![[Blv54.png]]

**In web page**
![[Blv55.png]]

13. Now, delete the user carlos.


