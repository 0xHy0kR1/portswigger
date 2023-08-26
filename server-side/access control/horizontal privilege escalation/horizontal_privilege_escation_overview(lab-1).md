## Introduction
- Horizontal privilege escalation arises when a user is able to gain access to resources belonging to another user, instead of their own resources of that type.
**Example** - if an employee should only be able to access their own employment and payroll records, but can in fact also access the records of other employees, then this is horizontal privilege escalation.

- Horizontal privilege escalation attacks may use similar types of exploit methods to vertical privilege escalation.
**Example** - a user might ordinarily access their own account page using a URL like the following:
```python
https://insecure-website.com/myaccount?id=123
```

Now, if an attacker modifies the `id` parameter value to that of another user, then the attacker might gain access to another user's account page.

## Steps to solve lab-1
### Desc - User ID controlled by request parameter

1. First we just register with the required credentials.
![[access_control21.png]]

2. Now, let's try to change the query parameter from `wiener` to `carlos` for the API Key.
![[access_control22.png]]
We get the API key of `carlos`. 

3. Now, submit the API key as solution.