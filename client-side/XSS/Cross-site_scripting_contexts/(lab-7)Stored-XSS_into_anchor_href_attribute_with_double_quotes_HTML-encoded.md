Sometimes the XSS context is into a type of HTML tag attribute that itself can create a scriptable context. Here, you can execute JavaScript without needing to terminate the attribute value.

For example, if the XSS context is into the `href` attribute of an anchor tag, you can use the `javascript` pseudo-protocol to execute script. For example:
```jsx
<a href="javascript:alert(document.domain)">
```

## Steps to solve lab
### Title - Stored XSS into anchor `href` attribute with double quotes HTML-encoded
**Desc** - This lab contains a [[Stored_XSS]] vulnerability in the comment functionality. To solve this lab, submit a comment that calls the `alert` function when the comment author name is clicked.

**Our end goal** - To solve this lab, submit a comment that calls the `alert` function when the comment author name is clicked.


1. Analyze the website blog functionality towards your input.
![[XSS70.png]]

![[XSS71.png]]

![[XSS72.png]]
By analyzing above code, we can clearly say that the value that we have provided as a website is stored with even sanitization.

2. Now, copy the below payload and paste in the website input field.
**Payload** - 
```jsx
javascript:alert(document.domain)
```

![[XSS74.png]]
