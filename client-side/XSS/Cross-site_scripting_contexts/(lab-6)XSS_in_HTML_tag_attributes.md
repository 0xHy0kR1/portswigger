When the XSS context is into an HTML tag attribute value, you might sometimes be able to terminate the attribute value, close the tag, and introduce a new one.

##### Example - 
```js
"><script>alert(document.domain)</script>
```
- More commonly in this situation, angle brackets are blocked or encoded, so your input cannot break out of the tag in which it appears.

Provided you can terminate the attribute value, you can normally introduce a new attribute that creates a scriptable context, such as an event handler.

##### Example - 
```js
" autofocus onfocus=alert(document.domain) x="
```
The above payload creates an `onfocus` event that will execute JavaScript when the element receives the focus, and also adds the `autofocus` attribute to try to trigger the `onfocus` event automatically without any user interaction. Finally, it adds `x="` to gracefully repair the following markup.

## Steps to solve lab 
### Title - Reflected XSS into attribute with angle brackets HTML-encoded

**Desc** - This lab contains a reflected cross-site scripting vulnerability in the search blog functionality where angle brackets are HTML-encoded. To solve this lab, perform a cross-site scripting attack that injects an attribute and calls the `alert` function.

**Our end goal** - To solve this lab, perform a cross-site scripting attack that injects an attribute and calls the `alert` function.



1. Analyze how the website behaves on your input.
![[XSS67.png]]

![[XSS68.png]]
Now, we can try to break the "value" attribute after all angle brackets are HTML-encoded.

2. Now, copy the below payload and paste it on the search box.
```js
" onmouseover=alert() x="
```
![[XSS69.png]]