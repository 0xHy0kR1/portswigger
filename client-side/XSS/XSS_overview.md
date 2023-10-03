## What is cross-site scripting (XSS)?
- Cross-site scripting (XSS) is a type of online attack. It lets attacker sneak harmful code into a website or app that you use. This code can then affect how the website behaves for you and steal your data. It's a way for attackers to trick the website into doing things it shouldn't.
- Cross-site scripting vulnerabilities normally allow an attacker to masquerade as a victim user, to carry out any actions that the user is able to perform, and to access any of the user's data
- If the victim user has privileged access within the application, then the attacker might be able to gain full control over all of the application's functionality and data.
- The traditional way to prove that you've found a [cross-site scripting](https://portswigger.net/web-security/cross-site-scripting) vulnerability is to create a popup using the `alert()` function. This isn't because [XSS](https://portswigger.net/web-security/cross-site-scripting) has anything to do with popups; it's simply a way to prove that you can execute arbitrary JavaScript on a given domain.

## How does XSS work?
Cross-site scripting works by manipulating a vulnerable web site so that it returns malicious JavaScript to users. When the malicious code executes inside a victim's browser, the attacker can fully compromise their interaction with the application.

![[XSS1.bmp]]

## XSS proof of concept
- You can confirm most kinds of XSS vulnerability by injecting a payload that causes your own browser to execute some arbitrary JavaScript. It's long been common practice to use the `alert()` function for this purpose because it's short, harmless, and pretty hard to miss when it's successfully called. In fact, you solve the majority of our XSS labs by invoking `alert()` in a simulated victim's browser.
- Unfortunately, there's a slight hitch if you use Chrome. From version 92 onward (July 20th, 2021), cross-origin iframes are prevented from calling `alert()`. As these are used to construct some of the more advanced XSS attacks, you'll sometimes need to use an alternative PoC payload. In this scenario, we recommend the `print()` function

## What are the types of XSS attacks?
There are three main types of XSS attacks. These are:

1. [[(lab-1)Reflected_XSS]], where the malicious script comes from the current HTTP request.
2. [[Stored_XSS]], where the malicious script comes from the website's database.
3. [[DOM-based_XSS]], where the vulnerability exists in client-side code rather than server-side code.