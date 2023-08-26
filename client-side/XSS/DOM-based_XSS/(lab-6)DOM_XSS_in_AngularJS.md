If a framework like Angularjs is used, it may be possible to execute JavaScript without angle brackets or events.

When a site uses the `ng-app` attribute on an HTML element, it will be processed by AngularJS. In this case, AngularJS will execute JavaScript inside double curly braces that can occur directly in HTML or inside attributes.

## Steps to solve lab - 
### Title - DOM-XSS in AngularJS expression with angle brackets and double quotes HTML-encoded
**Desc** - This lab contains a [[DOM-based_XSS]] vulnerability in a Angularjs expression within the search functionality.
AngularJS is a popular JavaScript library, which scans the contents of HTML nodes containing the `ng-app` attribute (also known as an AngularJS directive). When a directive is added to the HTML code, you can execute JavaScript expressions within double curly braces. This technique is useful when angle brackets are being encoded.

**Our end goal** - To solve this lab, perform a [[DOM-based_XSS]] attack that executes an AngularJS expression and calls the `alert` function.

1.  To check if this vulnerability exists, insert any alphanumeric string in searchbox and inspect the page for `ng-app` attribute because when a site uses the `ng-app` attribute on an HTML element, it will be processed by AngularJS.

In this case, AngularJS will execute JavaScript inside double curly braces that can occur directly in HTML or inside attributes.

2. Now, try to put the below payload inside the searchbox to test that Angularjs will execute it on html element.
![[XSS17.png]]
`{{$on.constructor('alert(1)')()}}`
3. Now, paste the below payload to show an alert box.
```js
{{$on.constructor('alert(1)')()}}
```
###### Code explaination - 
1. `{{$on.constructor`: This part of the expression is using the `$on` feature of AngularJS, which is typically used for event handling within directives. Here, `constructor` is being used as an event name.
    
2. `('alert(1)')`: This is the payload that is being passed to the event handler. It's a JavaScript string containing the code `alert(1)`, which is a common way to trigger an alert box displaying the number 1. In a legitimate context, this would be the place where legitimate event data would be provided.
    
3. `()}}`: The closing parenthesis and curly braces close the expression.


**For better understanding** --> https://www.youtube.com/watch?v=QpQp2JLn6JA