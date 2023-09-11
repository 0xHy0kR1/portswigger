- Some applications attempt to prevent input from breaking out of the JavaScript string by escaping any single quote characters with a backslash.
- A backslash before a character tells the JavaScript parser that the character should be interpreted literally, and not as a special character such as a string terminator. In this situation, applications often make the mistake of failing to escape the backslash character itself.
- This means that an attacker can use their own backslash character to neutralize the backslash that is added by the application.

#### Example - 

**For example, suppose that the input:**
```js
';alert(document.domain)//
```

gets converted to:
```js
\';alert(document.domain)//
```

**You can now use the alternative payload:**
```js
\';alert(document.domain)//
```

which gets converted to:
```js
\\';alert(document.domain)//
```

Here, the first backslash means that the second backslash is interpreted literally, and not as a special character. This means that the quote is now interpreted as a string terminator, and so the attack succeeds.

## Steps to solve lab - 
### Title - Reflected XSS into a JavaScript string with angle brackets and double quotes HTML-encoded and single quotes escaped
**Desc** - This lab contains a reflected cross-site scripting vulnerability in the search query tracking functionality where angle brackets and double quotes are HTML encoded and single quotes are escaped. To solve this lab, perform a cross-site scripting attack that breaks out of the JavaScript string and calls the `alert` function.

**Our end goal** - To solve this lab, perform a cross-site scripting attack that breaks out of the JavaScript string and calls the `alert` function.

1. First try to analyze the search functionality based on your input values.
![[XSS81.png]]
Your input string is directly assigned to the `searchTerms` variable.

2. Now, copy the below payload and directly paste in the searchbox to break the javascript string.
```js
\';alert(document.domain)//
```

![[XSS82.png]]
