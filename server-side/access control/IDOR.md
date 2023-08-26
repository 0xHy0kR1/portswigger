## What are insecure direct object references (IDOR)?
- Insecure direct object references (IDOR) are a type of access control vulnerability that arises when an application uses user-supplied input to access objects directly.
- IDOR vulnerabilities are most commonly associated with horizontal privilege escalation, but they can also arise in relation to vertical privilege escalation.

## IDOR examples

### IDOR vulnerability with direct reference to database objects
- Consider a website that uses the following URL to access the customer account page, by retrieving information from the back-end database:
```python
https://insecure-website.com/customer_account?customer_number=132355
```
- Here, the customer number is used directly as a record index in queries that are performed on the back-end database. If no other controls are in place, an attacker can simply modify the `customer_number` value, bypassing access controls to view the records of other customers.
- This is an example of an IDOR vulnerability leading to horizontal privilege escalation.
- An attacker might be able to perform horizontal and vertical privilege escalation by altering the user to one with additional privileges while bypassing access controls

### IDOR vulnerability with direct reference to static files
**Example** - 
a website might save chat message transcripts to disk using an incrementing filename, and allow users to retrieve these by visiting a URL like the following:
```python
https://insecure-website.com/static/12144.txt
```
In this situation, an attacker can simply modify the filename to retrieve a transcript created by another user and potentially obtain user credentials and other sensitive data.

## Steps to solve lab-1
### Desc - Insecure direct object references

1. Login with the given credentials.
![[access_control31.png]]

2. Now, you need to analyze the back-end functionality in the live-chat page and analyze that where is the actual url goes after you press the `View transcript` button and from there you are able to see the user `carlos` password.
![[access_control32.png]]

3. Now, just login into the user `carlos` account with this password(5f6gasbpk73bvmjuy1tn).