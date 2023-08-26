## Introduction
- Some applications enforce access controls at the platform layer by restricting access to specific URLs and HTTP methods based on the user's role.
**Example** - 
An application might configure rules like the following:
```python
DENY: POST, /admin/deleteUser, managers
```
This rule denies access to the `POST` method on the URL `/admin/deleteUser`, for users in the managers group.

- Some application frameworks support various non-standard HTTP headers that can be used to override the URL in the original request, such as `X-Original-URL` and `X-Rewrite-URL`.
- If a web site uses rigorous front-end controls to restrict access based on URL, but the application allows the URL to be overridden via a request header, then it might be possible to bypass the access controls using a request like the following:
```python
POST / HTTP/1.1 
X-Original-URL: /admin/deleteUser 
...
```

## Steps to solve lab-5
### Desc - URL-based access control can be circumvented

1. First we try to access `/admin` but failed as per the front-end restriction.
![[access_control13.png]]

2. Let's try to add `X-Original-URL:` to the `request` because it just overwrites the request `url`.
![[access_control14.png]]

![[access_control15.png]]

3. Now, if try to delete the user `carlos` from the front-end then we again get the `access Denied` message.
![[access_control16.png]]

4. Now, let's try to delete the user `carlos` but we can't add parameters in the `X-Original-URL:` so that we need to add the parameter in the back of the `/` to overwrite the `url` and delete the user `carlos`.
![[access_control17.png]]

## Steps to solve-6
### Desc - 