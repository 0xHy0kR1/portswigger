Websites may also store data on the server and reflect it elsewhere. In a stored DOM XSS vulnerability, the server receives data from one request, stores it, and then includes the data in a later response. 

**A script within the later response contains a sink which then processes the data in an unsafe way.**

## Steps to solve lab
### Title - Stored DOM XSS
**Desc** - This lab demonstrates a stored DOM vulnerability in the blog comment functionality. 
**Our end goal** - To solve this lab, exploit this vulnerability to call the alert() function. 

1. To check if this vulnerability exists, use a h1 tag to analyze the functionality and see how it renders the html elements in the page.
![[XSS25.png]]

2. Using the browser's developer tools, you look at the js code of the loadCommentsWithVulnerableEscapeHtml.js page to analyze how your string is processed in the backend.
![[XSS26.png]]

![[XSS27.png]]

3. Now, Copy the below and it will bypass this function and execute the alert on the page and the lab has been solved.
```js
<><img src=1 onerror="alert(1)">
```

**For better understanding** --> https://www.youtube.com/watch?v=kjPwxAPt318