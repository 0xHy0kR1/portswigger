## Introduction
- An alternative attack can arise in relation to the HTTP method used in the request.
- The front-end controls above restrict access based on the URL and HTTP method.
- Some web sites are tolerant of alternate HTTP request methods when performing an action. If an attacker can use the `GET` (or another) method to perform actions on a restricted URL, then they can circumvent the access control that is implemented at the platform layer.

## Steps to solve lab-6
### Desc - Method-based access control can be circumvented

1. Our end goal is to solve the lab, log in using the credentials `wiener:peter` and exploit the flawed access controls to promote yourself to become an administrator.
2. First we log in with the credentials `administrator:admin` and now we are analyzing admin-panel.
![[access_control18.png]]

3. Now, let's do this by being as a normal user(I just copy and paste the session of wiener)
![[access_control19.png]]

4. Now, let's just change the request method from `POST` to `GET`(right click in `request` section > `change request method`) because restriction is applied only in the front-end not in the back-end.
![[access_control20.png]]
**Note** - To solve the lab change user from `carlos` to `wiener`.
