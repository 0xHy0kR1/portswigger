## Introduction
- Many web sites implement important functions over a series of steps.
	1. This is often done when a variety of inputs or options need to be captured.
								OR
	2. when the user needs to review and confirm details before the action is performed.
**Example** - 
administrative function to update user details might involve the following steps:
1. Load form containing details for a specific user.
2. Submit changes.
3. Review the changes and confirm.

Sometimes, a web site will implement rigorous access controls over some of these steps, but ignore others.
**Example** - 
suppose access controls are correctly applied to the first and second steps, but not to the third step. Effectively, the web site assumes that a user will only reach step 3 if they have already completed the first steps, which are properly controlled.
Here, an attacker can gain unauthorized access to the function by skipping the first two steps and directly submitting the request for the third step with the required parameters.

## Steps to solve lab
### Desc - Multi-step process with no access control on one step

**Our end goal** - log in using the credentials `wiener:peter` and exploit the flawed access controls to promote yourself to become an administrator.

1. Now, login with the given credentials of the admin and try to analyze request and response of roles tab.
2. After analyzing everything we can say that there are three steps to `upgrade` or `Dowgrade` the role of user.
**First** - Select the specific user(for example carlos).
![[access_control33.png]]

**Second** - Make changes to that user(click on the Upgrade user button)
**Third** - Confirm those changes.
![[access_control34.png]]

3. After capturing the first step of `/admin-roles`, Now we try to put wiener session cookie and try to promote user `carlos` but it doesn't in first step.
![[access_control35.png]]

4. Now, in the second step(confirmation step). Let's try to do the same and we success this time.
![[access_control36.png]]
As shown above, just put wiener in place of carlos and you solve this lab.



