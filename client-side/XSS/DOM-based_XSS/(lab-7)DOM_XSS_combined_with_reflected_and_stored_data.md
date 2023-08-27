**DOM-based vulnerabilities:** These are security issues that occur when a web application's client-side code (JavaScript) manipulates the Document Object Model (DOM) in an unsafe manner, allowing attackers to execute malicious code.

**Pure DOM-based vulnerabilities:** These vulnerabilities are confined to a single web page and don't involve server-side components. If a script takes data from the URL and puts it into a dangerous place in the DOM without proper sanitization, it's considered a client-side issue.

**Reflected DOM XSS:** In this type of vulnerability, the server takes data from the user's request and includes it directly in the web page's response. If this reflected data is used improperly by the page's JavaScript code, it can lead to an attacker injecting and executing malicious code.

A script on the page then processes the reflected data in an unsafe way, ultimately writing it to a dangerous sink
```js
eval('var data = "reflected string"');
```

##### Example - 
```js
<!DOCTYPE html>
<html>
<head>
    <title>Search Page</title>
</head>
<body>
    <h1>Search Page</h1>
    <form>
        <input type="text" id="searchInput" placeholder="Enter your search query">
        <button type="button" onclick="search()">Search</button>
    </form>
    <div id="results"></div>

    <script>
        function search() {
            var query = document.getElementById('searchInput').value;

            // Display the search results
            var resultsDiv = document.getElementById('results');
            resultsDiv.innerHTML = 'Search results for: ' + query;
        }
    </script>
</body>
</html>
```
In this example, the JavaScript code takes the search query from the URL's query parameters and directly injects it into the resultsDiv element. 

**If an attacker crafts a malicious query like:**
```js
<script>alert('Malicious script!');</script>
```

**The URL becomes:**
```js
http://example.com/search.html?query=<script>alert('Malicious script!');</script>
```
The JavaScript code on the page would execute the attacker's script, resulting in a pop-up alert with the message "Malicious script!".

*This is an example of reflected DOM XSS because the server took the data from the URL and echoed it directly into the response without proper sanitization, allowing the malicious script to be executed on the client-side.*

## Steps to solve lab
### Title - Reflected DOM XSS
###### Desc - 
This lab demonstrates a reflected DOM vulnerability. Reflected DOM vulnerabilities occur when the server-side application processes data from a request and echoes the data in the response. A script on the page then processes the reflected data in an unsafe way, ultimately writing it to a dangerous sink. 

**Our end goal** - To solve this lab, create an injection that calls the alert() function. 

1. To check if this vulnerability exists, use a random alphanumeric string (like "abc123") as the search term.
![[XSS19.png]]

2. Using the browser's developer tools, you look at the js code of the search results page to analyze how your string is processed in the backend.
**Viewing the external js file** - 
![[XSS20.png]]

**Right-click the (2) and click open in debugger and analyze the js file.**

2. You then examine the context in which your string appears. For instance, is it within a double-quoted attribute like `<input value="abc123">`?
For that, let's take a look at that Ajax HTTP request that's sent to the search Results endpoint which returns the json object
![[XSS22.png]]

3. Now, send this to Repeater and try to break the "abc123" so that it executes the alert() and for that we are going use below payload.
```js
abc123/"-alert()}//
```
As you have injected a backslash and the site isn't escaping them, when the JSON response attempts to escape the opening double-quotes character, it adds a second backslash. The resulting double-backslash causes the escaping to be effectively canceled out. This means that the double-quotes are processed unescaped, which closes the string that should contain the search term.

An arithmetic operator (in this case the subtraction operator) is then used to separate the expressions before the `alert()` function is called. Finally, a closing curly bracket and two forward slashes close the JSON object early and comment out what would have been the rest of the object.
![[XSS23.png]]

4. Now, place this payload in the search box because you already know that you are able to break the normal string and make the alert function to run separately.
![[XSS24.png]]

**For better understanding visit** --> https://www.youtube.com/watch?v=bg_xH4Dp-6E