## Introduction
- Some websites base access controls on the `Referer` header submitted in the HTTP request.
- The `Referer` header is generally added to requests by browsers to indicate the page from which a request was initiated.
**Example** - 
suppose an application robustly enforces access control over the main administrative page at `/admin`, but for sub-pages such as `/admin/deleteUser` only inspects the `Referer` header. If the `Referer` header contains the main `/admin` URL, then the request is allowed.

In this situation, since the `Referer` header can be fully controlled by an attacker, they can forge direct requests to sensitive sub-pages, supplying the required `Referer` header, and so gain unauthorized access.

## Steps to solve lab
### Desc - Referer-based access control

**Our end goal** - log in using the credentials `wiener:peter` and exploit the flawed access control to promote yourself to become an administrator.

1. Login with the credentials of admin and familarize yourself with the role downgrade and upgrade process and look for `Referer` header and send it to `Repeater`.
![[access_control37.png]]
We already know that, `Referer` header is generally added to requests by browsers to indicate the page from which a request was initiated.

2. Login with credentials of wiener and copy the session cookie of user `wiener`.
![[access_control38.png]]

3. Now, browse to `/admin-roles?username=carlos&action=upgrade`(before browsing you should need to logout or just put your cookie in the above below request and erase the `Referer` header).
![[access_control39.png]]

4. Now, just change `carlos` to `wiener` and you solve the lab.
![[access_control40.png]]

