## Introduction
- Some applications determine the user's access rights or role at login, and then store this information in a user-controllable location, such as a hidden field, cookie, or preset query string parameter.
- The application makes subsequent access control decisions based on the submitted value.
**Example** - 
```python
https://insecure-website.com/login/home.jsp?admin=true 
https://insecure-website.com/login/home.jsp?role=1
```

This approach is fundamentally insecure because a user can simply modify the value and gain access to functionality to which they are not authorized, such as administrative functions.

## Steps to solve lab-3
### Desc - user role controlled by request parameter

1. Login with the credentials
![[access_control6.png]]

2. From the lab description, we know there is something here in the cookie. So, when we navigate to the `/` then we see a parameter `Admin` just below the cookie with value `false` and set it to `true`  and we get the admin panel.
![[access_control7.png]]
**Note** - We need to do above stuffs in the `/admin` page.

**For simplicity just do the below stuffs** - 
![[access_control8.png]]

3. Now, we just need to delete the user `carlos`.

## Steps to solve lab-4
### Desc - # User role can be modified in user profile

1. Login with the credentials.
![[access_control9.png]]

2. After login with the credentials, we try to change the email and see `JSON` data in the `response` that defines our access rights.
![[access_control10.png]]

3. Now, we are going to place a JSON data `"roleid":2` in request and we get the `Admin panel` and from there we are able to delete the user carlos.
![[access_control11.png]]

