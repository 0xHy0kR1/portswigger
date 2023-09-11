- In the simplest case, it is possible to simply close the script tag that is enclosing the existing JavaScript, and introduce some new HTML tags that will trigger execution of JavaScript.

**For example, if the XSS context is as follows:**
```js
<script> 
... 
var input = 'controllable data here'; 
... 
</script>
```

**then you can use the following payload to break out of the existing JavaScript and execute your own:**
```jsx
</script><img src=1 onerror=alert(document.domain)>
```
   - The reason this works is that the browser first performs HTML parsing to identify the page elements including blocks of script, and only later performs JavaScript parsing to understand and execute the embedded scripts.
   - The above payload leaves the original script broken, with an unterminated string literal. But that doesn't prevent the subsequent script being parsed and executed in the normal way.

## Steps to solve lab - 
### Title - Reflected XSS into a JavaScript string with single quote and backslash escaped
**Desc** - This lab contains a reflected cross-site scripting vulnerability in the search query tracking functionality. The reflection occurs inside a JavaScript string with single quotes and backslashes escaped. To solve this lab, perform a cross-site scripting attack that breaks out of the JavaScript string and calls the `alert` function.

**Our end goal** - To solve this lab, perform a cross-site scripting attack that breaks out of the JavaScript string and calls the `alert` function.

1. First try to analyze the search functionality based on your input values.
![[XSS77.png]]

2. Now, copy the below payload and directly paste in the searchbox to break the javascript code.
```jsx
</script><img src=1 onerror=alert(document.domain)>
```

![[XSS78.png]]
