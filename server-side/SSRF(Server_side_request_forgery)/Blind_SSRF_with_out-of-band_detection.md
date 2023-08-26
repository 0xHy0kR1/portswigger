## What is blind SSRF?
Blind SSRF vulnerabilities arise when an application can be induced to issue a back-end HTTP request to a supplied URL, but the response from the back-end request is not returned in the application's front-end response.
## What is the impact of blind SSRF vulnerabilities?
The impact of blind SSRF vulnerabilities is often lower than fully informed SSRF vulnerabilities because of their one-way nature. They cannot be trivially exploited to retrieve sensitive data from back-end systems, although in some situations they can be exploited to achieve full remote code execution.
## How to find and exploit blind SSRF vulnerabilities
- The most reliable way to detect blind SSRF vulnerabilities is using out-of-band (OAST) techniques
- This involves attempting to trigger an HTTP request to an external system that you control, and monitoring for network interactions with that system.
- The easiest and most effective way to use out-of-band techniques is using Burp Collaborator.
- Burp Collaborator to generate unique domain names, send these in payloads to the application, and monitor for any interaction with those domains.
- If an incoming HTTP request is observed coming from the application, then it is vulnerable to SSRF.

## Steps to solve lab
### Desc - Blind SSRF with out-of-band detection
**Our end goal** - This site uses analytics software which fetches the URL specified in the Referer header when a product page is loaded. To solve the lab, use this functionality to cause an HTTP request to the public Burp Collaborator server.

1. Now, first we are going to change the value of "[[Referer]]" header from burp collaborator domain, as it contains the location to the previous web page.
![[SSRF23.png]]

![[SSRF24.png]]

2. Now, check the collaborator tab in burp suite for DNS request.
![[SSRF25.png]]
You get a dns request to your collaborator domain it means that it is vulnerable to blind SSRF.

