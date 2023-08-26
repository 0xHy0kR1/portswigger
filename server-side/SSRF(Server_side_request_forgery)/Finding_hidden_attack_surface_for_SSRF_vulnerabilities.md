## Partial URLs in requests
1. Some applications use only a part of a web address (URL) as input when requesting information from a server.
2. The input(url) is combined with other parts on the server to form the complete web address that is requested.
3. Even if the input appears to be a web address (like a hostname or a URL path), the risk of a full-scale attack might be limited because you, as an attacker, don't have complete control over the entire web address that the server requests.

## URLs within data formats
- Some applications use data formats (like XML) to transmit information between the client (you) and the server (the website). These data formats allow the inclusion of URLs (web addresses) as part of the data.
- When the application receives this data and processes it, it might be vulnerable to a type of attack called "XXE injection".
- XXE injection can be exploited to make the application request URLs specified in the data, which could lead to another type of attack called "SSRF" (Server-Side Request Forgery).

## SSRF via the Referer header
- Some applications use server-side analytics software to track visitors (users). This software logs the "Referer" header in requests, which tells where visitors come from (incoming links).
- The analytics software may visit any third-party URL found in the "Referer" header to analyze the content of referring sites and the links they use. 
- This behavior can create a vulnerability called "SSRF" (Server-Side Request Forgery) because attackers can manipulate the "Referer" header to make the server request unintended URLs, potentially leading to security issues.
- Examples of vulnerabilities related to the "Referer" header can be found in Blind SSRF vulnerabilities.