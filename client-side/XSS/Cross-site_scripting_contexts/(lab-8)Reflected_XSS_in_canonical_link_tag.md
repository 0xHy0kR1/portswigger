- You might encounter websites that encode angle brackets but still allow you to inject attributes but still sometimes, these injections are possible even within tags that don't usually fire events automatically, such as a canonical tag.
- You can exploit this behavior using access keys and user interaction on Chrome. Access keys allow you to provide keyboard shortcuts that reference a specific element.
- The `accesskey` attribute allows you to define a letter that, when pressed in combination with other keys (these vary across different platforms), will cause events to fire.

## Steps to solve lab - 
### Title - Reflected XSS in canonical link tag
**Desc** - This lab reflects user input in a canonical link tag and escapes angle brackets. To solve the lab, perform a cross-site scripting attack on the home page that injects an attribute that calls the `alert` function. To assist with your exploit, you can assume that the simulated user will press the following key combinations:
```python
 ALT+SHIFT+X
 CTRL+ALT+X
 Alt+X
```

**Our end goal** - To solve the lab, perform a cross-site scripting attack on the home page that injects an attribute that calls the `alert` function.



1. Analyze the website code and front-end code and as per the lab description there is a canonical tag in the website.
![[XSS75.png]]
current url value is injected in the `href` attribute but this element is not shown in the web page that's why we can't exploit it and for that we are going to use `accesskey` to exploit this.

2. Now, copy the below payload and paste it on the web url.
```jsx
?'accesskey='x'onclick='alert(1)
```
![[XSS76.png]]
