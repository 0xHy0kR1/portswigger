## Introduction
- Often, a horizontal privilege escalation attack can be turned into a vertical privilege escalation, by compromising a more privileged user.
**Example** - 
a horizontal escalation might allow an attacker to reset or capture the password belonging to another user. If the attacker targets an administrative user and compromises their account, then they can gain administrative access and so perform vertical privilege escalation.

**Let's take a more simple example in a practical way**
an attacker might be able to gain access to another user's account page using the parameter tampering technique already described for horizontal privilege escalation:
```python
https://insecure-website.com/myaccount?id=456
```

- If the target user is an application administrator, then the attacker will gain access to an administrative account page.
- This page might disclose the administrator's password or provide a means of changing it, or might provide direct access to privileged functionality.

## Steps to solve lab-1
### Desc - user ID controlled by request parameter with password disclosure

1. Login with the given credentials.
![[access_control29.png]]

2. Now, in the `/my-account` page we are able to see `/my-account?id=wiener` and from there we are just going to change it to `/my-account?id=administrator` and get the access to `administrator` account.
![[access_control30.png]]

3. Now, just login with administrator account and delete the user carlos.
