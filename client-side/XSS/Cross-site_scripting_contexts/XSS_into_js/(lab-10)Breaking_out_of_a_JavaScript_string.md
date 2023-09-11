- In cases where the XSS context is inside a quoted string literal, it is often possible to break out of the string and execute JavaScript directly.
- It is essential to repair the script following the XSS context, because any syntax errors there will prevent the whole script from executing.

**Some useful ways of breaking out of a string literal are:**
```js
'-alert(document.domain)-'
```

```js
';alert(document.domain)//
```

## Steps to solve lab 
### Title - Reflected XSS into a JavaScript string with angle brackets HTML encoded
**Desc** - This lab contains a reflected cross-site scripting vulnerability in the search query tracking functionality where angle brackets are encoded. The reflection occurs inside a JavaScript string. To solve this lab, perform a cross-site scripting attack that breaks out of the JavaScript string and calls the `alert` function.

**Our end goal** - To solve this lab, perform a cross-site scripting attack that breaks out of the JavaScript string and calls the `alert` function.

1. First try to analyze the search functionality based on your input values.
![[XSS79.png]]
Your injected string "0xl33t" is directly entered in `searchTerms` variable.

2. Now, copy the below payload and directly paste in the searchbox to break the javascript string.
```js
';alert(document.domain)//
```
![[XSS80.png]]
