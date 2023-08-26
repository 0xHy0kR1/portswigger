## What is access control?
- Access control is the application of constraints on who (or what) can perform attempted actions or access resources that they have requested.
- In the context of web applications, access control is dependent on authentication and session management:
	- **Authentication** - identifies the user and confirms that they are who they say they are.
	- **Session management** identifies which subsequent HTTP requests are being made by that same user.
	- **Access control** determines whether the user is allowed to carry out the action that they are attempting to perform.

**From a user perspective, access controls can be divided into the following categories:**
- Vertical access controls
- Horizontal access controls
- Context-dependent access controls
![[access_control1.bmp]]

### Vertical access control
- Vertical access control is the mechanism that restricts the access to sensitive functionality from a group of users.
- With vertical access controls, different types of users have access to different application functions.
**Example** - an administrator might be able to modify or delete any user's account, while an ordinary user has no access to these actions.

### Horizontal access control
- Horizontal access control is the mechanism that allows a group of people to use a particular resource that is explicitly assigned to them.
**Example** - in a banking system, you can only view and modify your account not others.

### Context-dependent access controls
- These types of access control restrict the functionality based upon the state of the application or how users is interacting with it.
**Example** - Any e-commerce website might prevent users from modifying the prices of a commodity while shopping.

## BROKEN ACCESS CONTROL
![[access_control2.webp]]
So this vulnerability exists when a user can access the resource which is forbidden for them.

### Vertical privilege escalation
- If a user can gain access to functionality that they are not permitted to access then this is vertical privilege escalation.
- In simple terms, _Access the functionality which is not permitted for them_.
**Example** - if a non-administrative user can gain access to an admin page where they can delete user accounts, then this is vertical privilege escalation.

#### [Unprotected functionality](unprotected_functionality(lab-1).md)