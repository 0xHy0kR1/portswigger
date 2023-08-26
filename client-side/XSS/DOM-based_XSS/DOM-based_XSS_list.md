**The following are some of the main sinks that can lead to DOM-XSS vulnerabilities:**
```js
document.write() 
document.writeln() 
document.domain 
element.innerHTML 
element.outerHTML 
element.insertAdjacentHTML 
element.onevent
```

**The following jQuery functions are also sinks that can lead to DOM-XSS vulnerabilities:**
```js
add() 
after() 
append() 
animate() 
insertAfter() 
insertBefore() 
before() 
html() 
prepend() 
replaceAll() 
replaceWith() 
wrap() 
wrapInner() 
wrapAll() 
has() 
constructor() 
init() 
index() 
jQuery.parseHTML() 
$.parseHTML()
```