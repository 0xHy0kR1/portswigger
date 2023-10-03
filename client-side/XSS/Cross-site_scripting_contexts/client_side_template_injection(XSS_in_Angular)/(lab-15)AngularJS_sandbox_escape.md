## What is client-side template injection?
   - Client-side template injection vulnerabilities arise when applications using a client-side template framework dynamically embed user input in web pages.
   - When rendering a page, the framework scans it for template expressions and executes any that it encounters. An attacker can exploit this by supplying a malicious template expression that launches a cross-site scripting (XSS) attack.

## What is the AngularJS sandbox?
   - The AngularJS sandbox is a mechanism that prevents access to potentially dangerous objects, such as `window` or `document`, in [[AngularJS template expressions]].
   - It also prevents access to potentially dangerous properties, such as `__proto__`.
   - Although bypassing the sandbox was initially challenging, security researchers have discovered numerous ways of doing so. As a result, it was eventually removed from AngularJS in version 1.6. However, many legacy applications still use older versions of AngularJS and may be vulnerable as a result.

## How does the AngularJS sandbox work?
   - Sandbox starts by looking at the code expressions in your AngularJS templates. It modifies the JavaScript code within those expressions. The sandbox then employs functions like `ensureSafeObject()` to examine the modified code for potentially risky objects, such as the "window" object or the "Function" constructor. If any of these risky objects are detected, the sandbox takes steps to prevent them from causing harm, ensuring your web application remains secure.
   - The `ensureSafeMemberName()` function checks each property access of the object and, if it contains dangerous properties such as `__proto__` or `__lookupGetter__`, the object will be blocked.
   - The `ensureSafeFunction()`function prevents `call()`, `apply()`, `bind()`, or `constructor()` from being called.

## How does an AngularJS sandbox escape work?
   - A sandbox escape involves tricking the sandbox into thinking the malicious expression is benign.

>The most well-known escape uses the modified `charAt()` function globally within an expression:
```js
'a'.constructor.prototype.charAt=[].join
```
The attack works by overwriting the function using the `[].join` method, which causes the `charAt()` function to return all the characters sent to it, rather than a specific single character.

- Due to the logic of the `isIdent()` function in AngularJS, it compares what it thinks is a single character against multiple characters. As single characters are always less than multiple characters, the `isIdent()` function always returns true

>As demonstrated by the following example:
```js
isIdent = function(ch) { 
	return ('a' <= ch && ch <= 'z' || 'A' <= ch && ch <= 'Z' || '_' === ch || ch === '$'); 
} isIdent('x9=9a9l9e9r9t9(919)')
```
Once the `isIdent()` function is fooled, you can inject malicious JavaScript.
- For example, an expression such as `$eval('x=alert(1)')` would be allowed because AngularJS treats every character as an identifier.
- Note that we need to use AngularJS's `$eval()` function because overwriting the `charAt()` function will only take effect once the sandboxed code is executed. This technique would then bypass the sandbox and allow arbitrary JavaScript execution.

### Constructing an advanced AngularJS sandbox escape
   - So you've learned how a basic sandbox escape works, but you may encounter sites that are more restrictive with which characters they allow. For example, a site may prevent you from using double or single quotes. In this situation, you need to use functions such as `String.fromCharCode()` to generate your characters.
   - Although AngularJS prevents access to the `String` constructor within an expression, you can get round this by using the constructor property of a string instead. This obviously requires a string, so to construct an attack like this, you would need to find a way of creating a string without using single or double quotes.
   - In a standard sandbox escape, you would use `$eval()` to execute your JavaScript payload, but in the lab below, the `$eval()` function is undefined.

>Fortunately, we can use the `orderBy` filter instead. The typical syntax of an `orderBy` filter is as follows:
```js
[123]|orderBy:'Some string'
```
   - Note that the `|` operator has a different meaning than in JavaScript. Normally, this is a bitwise `OR` operation, but in AngularJS it indicates a filter operation.
   - In the code above, we are sending the array `[123]` on the left to the `orderBy` filter on the right.
   - The colon signifies an argument to send to the filter, which in this case is a string.
   - The `orderBy` filter is normally used to sort an object, but it also accepts an expression, which means we can use it to pass a payload.

## Steps to solve lab
### Title - Reflected XSS with AngularJS sandbox escape without strings
**Desc** - This lab uses AngularJS in an unusual way where the `$eval` function is not available and you will be unable to use any strings in AngularJS.
To solve the lab, perform a cross-site scripting attack that escapes the sandbox and executes the `alert` function without using the `$eval` function.

**Our end goal** - To solve the lab, perform a cross-site scripting attack that escapes the sandbox and executes the `alert` function without using the `$eval` function.

1. 