## Steps to solve lab
### Title - Basic password reset poisoning

**Desc** - This lab is vulnerable to password reset poisoning. The user `carlos` will carelessly click on any links in emails that he receives. To solve the lab, log in to Carlos's account. 

**Creds** - You can log in to your own account using the following credentials: `wiener:peter`. Any emails sent to this account can be read via the email client on the exploit server.

1. Login with the given "wiener:peter" credentials and try to analyze the forgot password functionality.
![[authentication15.png]]

![[authentication16.png]]

Analyze in the exploit server email that the email domain is your "/forgot-password" Host header value.
![[authentication17.png]]

![[authentication18.png]]

2. Capture the request for "/forgot-password" and change the Host header from burp collaborator server URL as follows:
![[authentication19.png]]

![[authentication20.png]]

![[authentication21.png]]

3. Copy the above captured token and paste in the link that you got by making reset password request for wiener.
![[authentication18.png]]

4. visit the link and change the password for user carlos.
![[authentication22.png]]

![[authentication23.png]]

