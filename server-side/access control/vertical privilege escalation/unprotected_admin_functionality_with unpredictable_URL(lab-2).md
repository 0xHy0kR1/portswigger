## Introduction
- In some cases, sensitive functionality is not robustly protected but is concealed by giving it a less predictable URL: so called security by obscurity.
**Example** - consider an application that hosts administrative functions at the following URL:
```python
https://insecure-website.com/administrator-panel-yb556
```

- This might not be directly guessable by an attacker. However, the application might still leak the URL to users.
**Example** - the URL might be disclosed in JavaScript that constructs the user interface based on the user's role:
```python
<script> 
var isAdmin = false; 
if (isAdmin) { 
			  ... 
			  var adminPanelTag = document.createElement('a'); adminPanelTag.setAttribute('https://insecure-website.com/administrator-panel-yb556'); adminPanelTag.innerText = 'Admin panel'; 
			  ... 
} 
</script>
```
This script adds a link to the user's UI if they are an admin user. However, the script containing the URL is visible to all users regardless of their role.

## Steps to solve(lab-2)
### Desc - Unprotected admin functionality with unpredictable URL

1. In any page, if we just look at the `source code` by `right click > view page source` then we are able to see the admin url.
![[access_control5.png]]

2. We get the required url to reach to the admin page and just delete the user carlos.
