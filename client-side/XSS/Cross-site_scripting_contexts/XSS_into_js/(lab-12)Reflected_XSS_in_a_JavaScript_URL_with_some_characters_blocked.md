- Some websites make XSS more difficult by restricting which characters you are allowed to use. This can be on the website level or by deploying a WAF that prevents your requests from ever reaching the website.
- In these situations, you need to experiment with other ways of calling functions which bypass these security measures.
- One way of doing this is to use the `throw` statement with an exception handler. This enables you to pass arguments to a function without using parentheses

**In these situations, use the payload** - 
```js
onerror=alert;throw 1
```
1. `onerror=alert;`: This part of the code assigns the `alert` function to the global exception handler. In simpler terms, it says that if there is an error or exception in the code, use the `alert` function to show a message to the user.
    
2. `throw 1`: This part of the code generates an error or exception by using the `throw` statement and passing the value `1` as the error message.

There are multiple ways of using this technique to call [functions without parentheses](https://portswigger.net/research/xss-without-parentheses-and-semi-colons).

The next lab demonstrates a website that filters certain characters. You'll have to use similar techniques to those described above in order to solve it.

## Steps to solve lab 
### Title - Reflected XSS in a JavaScript URL with some characters blocked
**Desc** - This lab reflects your input in a JavaScript URL, but all is not as it seems. This initially seems like a trivial challenge; however, the application is blocking some characters in an attempt to prevent XSS attacks.
To solve the lab, perform a cross-site scripting attack that calls the `alert` function with the string `1337` contained somewhere in the `alert` message.

**Our end goal** - To solve the lab, perform a cross-site scripting attack that calls the `alert` function with the string `1337` contained somewhere in the `alert` message.

1. First try to analyze the search functionality based on your input values.
![[XSS83.png]]

![[XSS84.png]]
The code shown above in the red block is that code that we use to exploit the web application.

2. Now, copy the below payload and paste it into the `Website` searchbox to perform "Reflected XSS".
```python
https://YOUR-LAB-ID.web-security-academy.net/post?postId=5&%27},x=x=%3E{throw/**/onerror=alert,1337},toString=x,window%2b%27%27,{x:%27
```
When the user clicks on their name field then automatically the url executed and the "fetch" function makes the request to `postId=5&%27},x=x=%3E{throw/**/onerror=alert,1337},toString=x,window%2b%27%27,{x:%27
and the alert gets popup to the screen.

for better understanding refer --> [[Reflected_XSS_in_a_JavaScript_URL_with_some_characters_blocked-Explaining_the_Payload.mp4]]


![[XSS85.png]]

![[XSS86.png]]
