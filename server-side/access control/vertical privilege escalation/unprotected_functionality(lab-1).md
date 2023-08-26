## Introduction
- vertical privilege escalation arises where an application does not enforce any protection over sensitive functionality.
**Example** - administrative functions might be linked from an administrator's welcome page but not from a user's welcome page.

- However, a user might simply be able to access the administrative functions by browsing directly to the relevant admin URL.
**Example** - a website might host sensitive functionality at the following URL:
```python
https://insecure-website.com/admin
```

**In some cases, the administrative URL might be disclosed in other locations, such as the `robots.txt` file:**
```python
https://insecure-website.com/robots.txt
```

Even if the URL isn't disclosed anywhere, an attacker may be able to use a wordlist to brute-force the location of the sensitive functionality.

## Steps to solve lab-1
### Desc - Unprotected admin functionality

1. Now, let's try to browse `robots.txt` file in the website.
![[access_control3.png]]

2. Now, we just need to browse the `/administrator-panel` page and we are able to find the required page.
![[access_control4.png]]
