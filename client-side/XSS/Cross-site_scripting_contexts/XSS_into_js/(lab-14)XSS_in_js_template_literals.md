JavaScript template literals are string literals that allow [[embedded JavaScript expressions]]. The embedded expressions are evaluated and are normally concatenated into the surrounding text. Template literals are encapsulated in backticks instead of normal quotation marks, and embedded expressions are identified using the `${...}` syntax.

**For example, the following script will print a welcome message that includes the user's display name:**
```js
document.getElementById('message').innerText = `Welcome, ${user.displayName}.`;
```

When the XSS context is into a JavaScript template literal, there is no need to terminate the literal. Instead, you simply need to use the `${...}` syntax to embed a JavaScript expression that will be executed when the literal is processed.

**For example, if the XSS context is as follows:**
```js
<script> 
...
var input = `controllable data here`; 
... 
</script>
```

**then you can use the following payload to execute JavaScript without terminating the template literal:**
```js
${alert(document.domain)}
```

## Steps to solve lab
### Title - Reflected XSS into a template literal with angle brackets, single, double quotes, backslash and backticks Unicode-escaped

**Desc** - This lab contains a [reflected cross-site scripting](https://portswigger.net/web-security/cross-site-scripting/reflected) vulnerability in the search blog functionality. The reflection occurs inside a template string with angle brackets, single, and double quotes HTML encoded, and backticks escaped. To solve this lab, perform a cross-site scripting attack that calls the `alert` function inside the template string.

**Our end goal** - To solve this lab, perform a cross-site scripting attack that calls the `alert` function inside the template string.

1. First try to analyze the search functionality based on your input values.
![[XSS90.png]]

![[XSS91.png]]
The code shown in the red block is the that we are going to exploit.

2.  Now, copy the below payload and paste it into the Website search box to perform reflected XSS.
```js
${alert(1)}
```
The alert function is injected into the template literals and executed directly onto the page resulting in a reflected xss.
Source --> [template_listerals](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Template_literals)

![[XSS92.png]]

**For better understanding please watch** --> [[Reflected XSS into Template Literal.mp4]]