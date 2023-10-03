For websites that adopt a password-based login process, users either register for an account themselves or they are assigned an account by an administrator.

**Guessing the login credentials of another user, can be done in a variety of ways**, as shown below:
1. Brute-force attacks
	- These attacks are typically automated using wordlists of usernames and passwords.
	- It also involve in using basic logic or publicly available knowledge.
	- The two most common ways of preventing brute-force attacks are:
		- Locking the account that the remote user is trying to access if they make too many failed login attempts
		- Blocking the remote user's IP address if they make too many login attempts in quick succession

2. Brute-forcing usernames
	- Usernames are especially easy to guess if they conform to a recognizable pattern, such as an email address. For example, business logins in the format `firstname.lastname@somecompany.com`.
	- You should also check HTTP responses to see if any email addresses are disclosed.

3. Brute-forcing passwords
	- However, while high-entropy passwords are difficult for computers alone to crack, we can use a basic knowledge of human behavior to exploit the vulnerabilities, users often take a password that they can remember