## What is DOM-based cross-site scripting?
- DOM-based XSS vulnerabilities usually arise when JavaScript takes data from an attacker-controllable source, such as the URL, and passes it to a sink that supports dynamic code execution, such as `eval()` or `innerHTML`. This enables attackers to execute malicious JavaScript, which typically allows them to hijack other user accounts.
	- A "sink" is a place in the code where the attacker-controlled data gets used. In this case, the sink is a function or method that can execute code dynamically. For example, the `eval()` function can execute code passed to it as a string, and the `innerHTML` property can set HTML content dynamically.

- To deliver a DOM-based XSS attack, you need to place data into a source so that it is propagated to a sink and causes execution of arbitrary JavaScript.
- The most common source for DOM XSS is the URL, which is typically accessed with the `window.location` object.

## How to test for DOM-based cross-site scripting
- The majority of DOM XSS vulnerabilities can be found quickly and reliably using Burp Suite's web vulnerability scanner.
- To test for DOM-based cross-site scripting manually, you generally need to use a browser with developer tools, such as Chrome.

### Testing HTML sinks
**Testing HTML sinks** means checking points in a web application where user input can be processed.

**Note** - `location.search` represents the query parameters in the URL, like `?param=value`.
#### Pre-requisite --> [[sinks]]
- To test for DOM XSS in an HTML sink, place a random alphanumeric string into the source (such as `location.search`), then use developer tools to inspect the HTML and find where your string appears. Note that the browser's "View source" option won't work for DOM XSS testing because it doesn't take account of changes that have been performed in the HTML by JavaScript.
- In Chrome's developer tools, you can use `Control+F` (or `Command+F` on MacOS) to search the DOM for your string.
- For each location where your string appears within the DOM, you need to identify the context. Based on this context, you need to refine your input to see how it is processed.
	- For example, if your string appears within a double-quoted attribute then try to inject double quotes in your string to see if you can break out of the attribute.
- Note that browsers behave differently with regards to URL-encoding, Chrome, Firefox, and Safari will URL-encode `location.search` and `location.hash`, while IE11 and Microsoft Edge (pre-Chromium) will not URL-encode these sources. If your data gets URL-encoded before being processed, then an XSS attack is unlikely to work.

#### Example - 
Suppose you have a search feature on your website that takes a search term and displays results. An attacker might try to insert malicious code into the search term to exploit a vulnerability and steal user data.

1. **Testing for DOM XSS**: To check if this vulnerability exists, use a random alphanumeric string (like "abc123") as the search term.
    
2. **Inspecting with Developer Tools**: Using the browser's developer tools, you look at the HTML code of the search results page to find where your string ("abc123") appears.
    
3. **Identifying Context**: You then examine the context in which your string appears. For instance, is it within a double-quoted attribute like `<input value="abc123">`?
    
4. **Refining Input**: Based on the context, you modify your input to test if you can inject malicious code. For example, you might try `"abc123"` to see if you can break out of the attribute.
    
5. **URL-Encoding**: Depending on the browser, some parts of the URL might be encoded differently. This can affect how your input is processed and whether an XSS attack will work.

## Testing javascript execution sinks
Suppose you have a web page that uses JavaScript to dynamically change content on the page based on user input. An attacker might try to exploit this by injecting malicious code into the user input.

1. **Testing for JavaScript Execution Sinks**: To check for this kind of vulnerability, you need to identify places in the JavaScript code where user input is processed and executed.
    
2. **Finding JavaScript References**: For each potential source of user input (like the URL parameters), you need to search the webpage's JavaScript code to find instances where that source is referenced.
    
3. **Using JavaScript Debugger**: Using the browser's JavaScript debugger, you can add breakpoints to the code. A breakpoint is like a pause button that lets you inspect what's happening at a specific point in the code.
    
4. **Tracing Input Processing**: When the code reaches a breakpoint, you can follow how the user input (the source) is used in the code. It might be assigned to variables or used in functions.
    
5. **Identifying Variable Assignments**: If the source value is assigned to other variables, you need to trace those variables as well.
    
6. **Checking for Sinks**: Look for points where these variables are passed to functions or parts of the code that execute. These are potential "sinks" where the input could be processed and executed.
    
7. **Inspecting Values**: Use the debugger to inspect the values of these variables as they flow through the code. You can hover over a variable to see its value at a specific point in the code.
    
8. **Refining Input**: Similar to testing HTML sinks, you refine your input to see if you can insert malicious code that successfully executes. For example, if the input is used in a function that writes content to the page, you might try to inject a script that steals user data.

### Testing for DOM XSS using DOM Invader
If you use Burp's browser, however, you can take advantage of its built-in DOM Invader extension, which does a lot of the hard work for you.

