In this section, we'll provide some cautionary examples of common assumptions that should be avoided and demonstrate how they can lead to dangerous logic flaws.

#### Trusted users won't always remain trustworthy
If business rules and security measures are not applied consistently throughout the application, this can lead to potentially dangerous loopholes that may be exploited by an attacker.

## Steps to solve lab-1
### Desc - Inconsistent security controls

1. Register with username and password.
![[Blv18.png]]

2. Now, login with this credentials and update the email address as shown below;
![[Blv19.png]]

3. Now, we get admin panel access and now, we are able to delete the user.
![[Blv20.png]]


### Users won't always supply mandatory input
- One misconception is that users will always supply values for mandatory input fields.
- Browsers may prevent ordinary users from submitting a form without a required input, but as we know, attackers can tamper with parameters in transit. This even extends to removing parameters entirely. In this case, the presence or absence of a particular parameter may determine which code is executed.
- Removing parameter values may allow an attacker to access code paths that are supposed to be out of reach.

**When probing for logic flaws, you should try removing each parameter in turn and observing what effect this has on the response. You should make sure to:**
- Only remove one parameter at a time to ensure all relevant code paths are reached.
- Try deleting the name of the parameter as well as the value. The server will typically handle both cases differently.
- Follow multi-stage processes through to completion. Sometimes tampering with a parameter in one step will have an effect on another step further along in the workflow.
**This applies to both URL and `POST` parameters, but don't forget to check the cookies too.**

*This simple process can reveal some bizarre application behavior that may be exploitable.*

## Steps to solve lab-2
### Desc - Weak isolation on dual-use endpoint

1. Registering as wiener.
![[Blv21.png]]

2. Let's try changing the administrator password from client side but we don't know current password of administrator so we change it with the help of burp by deleting the current password parameter.
![[Blv22.png]]
**Result** - We successfully change the password of `administrator`.

3. Now, login with that password and you are able to delete the user `carlos`.

### Users won't always follow the intended sequence
- Many transactions rely on predefined workflows consisting of a sequence of steps. The web interface will typically guide users through this process, taking them to the next step of the workflow each time they complete the current one.
- However, attackers won't necessarily adhere to this intended sequence. Failing to account for this possibility can lead to dangerous flaws that may be relatively simple to exploit.
**Example** - 
many websites that implement two-factor authentication (2FA) require users to log in on one page before entering a verification code on a separate page.
Assuming that users will always follow this process through to completion and, as a result, not verifying that they do, may allow attackers to bypass the 2FA step entirely.

- Using tools like Burp Proxy and Repeater, once an attacker has seen a request, they can replay it at will and use forced browsing to perform any interactions with the server in any order they want. This allows them to complete different actions while the application is in an unexpected state.
- To identify these kinds of flaws, you should use forced browsing to submit requests in an unintended sequence
**Example** - 
you might skip certain steps, access a single step more than once, return to earlier steps, and so on.

- Take note of how different steps are accessed. Although you often just submit a `GET` or `POST` request to a specific URL, sometimes you can access steps by submitting different sets of parameters to the same URL.
- As with all logic flaws, try to identify what assumptions the developers have made and where the attack surface lies. You can then look for ways of violating these assumptions.

## Steps to solve lab-3
### Desc - Insufficient workflow validation

1. login into the website.
![[Blv23.png]]

2. POST request in burp for jacket
![[Blv24.png]]
We are going to changing the above parameters with the `GET` request to order confirmation.

3. We was just buy light bulb from the below request.
![[Blv25.png]]

4. Below, there is a changed `POST` request order confirmation after placing jacket in the CART.
![[Blv26.png]]

## Steps to solve lab-4
### Desc - Authentication bypass via flawed state machine

1. login to the website.
![[Blv28.png]]

2. Selecting the role for the user.
![[Blv29.png]]
After the role selection, the website redirects us to home page.

3. Now, We are going to directly access the home page without reaching to the role selection page and for that we need use the burpsuite intercept feature to drop the role selection request and at that time we've to request the home page.

4. Now, turn on the intercept while you're in the login page and forward the request and while you get the chance to forward the request to role-selector then at that time just drop the request.
5. In the web page, you just need to forward the request to home page and then you get the admin panel.
![[Blv32.png]]

6. Delete the user.
