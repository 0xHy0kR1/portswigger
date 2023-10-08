## Steps to solve lab
### Title - Password reset poisoning via middleware

**Desc** - This lab is vulnerable to password reset poisoning. The user `carlos` will carelessly click on any links in emails that he receives. To solve the lab, log in to Carlos's account. Any emails sent to wiener account can be read via the email client on the exploit server.

**Creds** - `wiener:peter`

### Pre-requisite - [[X-Forwarded-Host header]]

1. Login with the given "wiener:peter" credentials and try to analyze the forgot password functionality.
![[authentication15.png]]

![[authentication16.png]]

Analyze in the exploit server email that the email domain is your "/forgot-password" Host header value.
![[authentication17.png]]

![[authentication18.png]]

2. Capture the request for "POST /forgot-password" and add the "X-Forwarded-Host" header with the value as your burp collaborator server URL.
![[authentication24.png]]

![[authentication25.png]]

Check your collaborator for HTTP request.
![[authentication26.png]]

3. Copy the above captured token and paste in the link that you got by making reset password request for wiener.
![[authentication18.png]]

4. visit the link and change the password for user carlos.
![[authentication22.png]]

![[authentication23.png]]
