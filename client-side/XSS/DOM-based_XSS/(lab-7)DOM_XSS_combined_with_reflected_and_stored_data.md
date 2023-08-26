- **DOM-based vulnerabilities:** These are security issues that occur when a web application's client-side code (JavaScript) manipulates the Document Object Model (DOM) in an unsafe manner, allowing attackers to execute malicious code.
    
- **Pure DOM-based vulnerabilities:** These vulnerabilities are confined to a single web page and don't involve server-side components. If a script takes data from the URL and puts it into a dangerous place in the DOM without proper sanitization, it's considered a client-side issue.
    
- **Reflected DOM XSS:** In this type of vulnerability, the server takes data from the user's request and includes it directly in the web page's response. If this reflected data is used improperly by the page's JavaScript code, it can lead to an attacker injecting and executing malicious code.

