## Introduction
- In some cases, an application does detect when the user is not permitted to access the resource, and returns a redirect to the login page.
- However, the response containing the redirect might still include some sensitive data belonging to the targeted user, so the attack is still successful.

## Steps to solve lab-3
### Desc - User ID controlled by request parameter with data leakage in redirect

1. Login with the credentials.
![[access_control27.png]]

2. Now, if try to change the query parameter from `wiener` to `carlos` then the website redirect us to login page but when we do this from burp then we get the api key for the user `carlos`.
![[access_control28.png]]

3. Now, just copy paste the api key and you are able to solve the lab.