In this topic, we'll learn how to manipulate WebSocket messages and connections, describe the kinds of security vulnerabilities that can arise with WebSockets, and give some examples of exploiting WebSockets vulnerabilities.

## What is WebSockets?
   - WebSockets are commonly used in modern web applications for streaming data and other asynchronous traffic.
   - These connections or communication methods start over HTTP (a protocol for the internet) and allow for long-lasting connections where information can be sent back and forth in both directions, without waiting for one side to finish before the other can respond.

![[WebSockets1.png]]

   - WebSockets are used for all kinds of purposes, including performing user actions and transmitting sensitive information.
   - Virtually any web security vulnerability that arises with regular HTTP can also arise in relation to WebSockets communications.
   - WebSockets are a bi-directional, full duplex communications protocol initiated over HTTP.

## What is the difference between HTTP and WebSockets?
 
 1. **Request-Response vs. Full-Duplex Communication:**
	- **HTTP (Hypertext Transfer Protocol):** It is primarily a request-response protocol. A client (usually a web browser) sends a request to a server, and the server responds with data. This is suitable for most web interactions, like fetching web pages, images, or other resources.    

	- **WebSockets:** WebSockets provide full-duplex communication, meaning both the client and server can send messages to each other independently, without waiting for a request or response. This is ideal for real-time applications like chat, online gaming, or collaborative tools.

2. **Connection Persistence:**
	- Each HTTP request creates a new connection to the server, and once the response is received, the connection is closed. This makes it stateless by default, and subsequent requests don't retain information from previous ones.

	- WebSockets create a long-lived, persistent connection between the client and server. This connection remains open until either side decides to close it. This persistence allows for efficient real-time communication.

3. **Data Format:**
	- **HTTP:** HTTP is typically used to transfer structured data, usually in formats like HTML, JSON, XML, or other document-based formats.

	- **WebSockets:** WebSockets transmit data as raw binary or text, making it more flexible for various real-time communication needs.

In summary, HTTP is suitable for traditional web applications where clients make occasional requests for data or resources. WebSockets, on the other hand, are designed for real-time, interactive applications where low latency and bidirectional communication are essential.

## How are WebSocket connections established?

**WebSocket connections are normally created using client-side JavaScript like the following:**
```js
var ws = new WebSocket("wss://normal-website.com/chat");
```

**Note** - 
The `wss` protocol establishes a WebSocket over an encrypted TLS connection, while the `ws` protocol uses an unencrypted connection.


**To establish the connection, the browser and server perform a WebSocket handshake over HTTP. The browser issues a WebSocket handshake request like the following:**
```js
GET /chat HTTP/1.1 
Host: normal-website.com 
Sec-WebSocket-Version: 13 
Sec-WebSocket-Key: wDqumtseNBJdhkihL6PW7w== 
Connection: keep-alive, Upgrade 
Cookie: session=KOsEJNuflw4Rd9BDNrVmvwBF9rEijeE2 
Upgrade: websocket
```

**If the server accepts the connection, it returns a WebSocket handshake response like the following:**
```js
HTTP/1.1 101 Switching Protocols 
Connection: Upgrade 
Upgrade: websocket 
Sec-WebSocket-Accept: 0FFP+2nmNIf/h+4BP36k9uzrYGk=`
```
At this point, the network connection remains open and can be used to send WebSocket messages in either direction.

**Note** - 
Several features of the WebSocket handshake messages are worth noting:
   - The `Connection` and `Upgrade` headers in the request and response indicate that this is a WebSocket handshake.
   - The `Sec-WebSocket-Version` request header specifies the WebSocket protocol version that the client wishes to use. This is typically `13`.
   - The `Sec-WebSocket-Key` request header contains a Base64-encoded random value, which should be randomly generated in each handshake request.
   - The `Sec-WebSocket-Accept` response header contains a hash of the value submitted in the `Sec-WebSocket-Key` request header, concatenated with a specific string defined in the protocol specification. This is done to prevent misleading responses resulting from misconfigured servers or caching proxies.

## What do WebSocket messages look like?
   Once a WebSocket connection has been established, messages can be sent asynchronously in either direction by the client or server.

**A simple message could be sent from the browser using client-side JavaScript like the following:**
```js
ws.send("Peter Wiener");
```

In modern applications, it is common for JSON to be used to send structured data within WebSocket messages.

**For example, a chat-bot application using WebSockets might send a message like the following:**
```json
{"user":"Hal Pline","content":"I wanted to be a Playstation growing up, not a device to answer your inane questions"}
```


## Manipulating WebSocket traffic
   Finding WebSockets security vulnerabilities generally involves manipulating them in ways that the application doesn't expect. You can do this using Burp Suite.

**You can use Burp Suite to:**
   - Intercept and modify WebSocket messages.
   - Replay and generate new WebSocket messages.
   - Manipulate WebSocket connections.

#### Intercepting and modifying WebSocket messages
   
  You can use Burp Proxy to intercept and modify WebSocket messages, as follows:

   - Open Burp's browser.
   - Browse to the application function that uses WebSockets. You can determine that WebSockets are being used by using the application and looking for entries appearing in the WebSockets history tab within Burp Proxy.
   - In the Intercept tab of Burp Proxy, ensure that interception is turned on.
   - When a WebSocket message is sent from the browser or server, it will be displayed in the Intercept tab for you to view or modify. Press the Forward button to forward the message.

#### Note
You can configure whether client-to-server or server-to-client messages are intercepted in Burp Proxy. Do this in the Settings dialog, in the [[WebSocket interception rules]] settings.

#### Replaying and generating new WebSocket messages

  As well as intercepting and modifying WebSocket messages on the fly, you can replay individual messages and generate new messages. You can do this using Burp Repeater:
  
  - In Burp Proxy, select a message in the WebSockets history, or in the Intercept tab, and choose "Send to Repeater" from the context menu.
  - In Burp Repeater, you can now edit the message that was selected, and send it over and over.
  - You can enter a new message and send it in either direction, to the client or server.
  - In the "History" panel within Burp Repeater, you can view the history of messages that have been transmitted over the WebSocket connection. This includes messages that you have generated in Burp Repeater, and also any that were generated by the browser or server via the same connection.
  - If you want to edit and resend any message in the history panel, you can do this by selecting the message and choosing "Edit and resend" from the context menu.

#### Manipulating WebSocket connections

  As well as manipulating WebSocket messages, it is sometimes necessary to manipulate the WebSocket handshake that establishes the connection.
  
  There are various situations in which manipulating the WebSocket handshake might be necessary:
  
   - It can enable you to reach more attack surface.
   - Some attacks might cause your connection to drop so you need to establish a new one.
   - Tokens or other data in the original handshake request might be stale and need updating.
 
 **You can manipulate the WebSocket handshake using Burp Repeater:**
   - Send a WebSocket message to Burp Repeater as already described.
   - In Burp Repeater, click on the pencil icon next to the WebSocket URL. This opens a wizard that lets you attach to an existing connected WebSocket, clone a connected WebSocket, or reconnect to a disconnected WebSocket.
   - If you choose to clone a connected WebSocket or reconnect to a disconnected WebSocket, then the wizard will show full details of the WebSocket handshake request, which you can edit as required before the handshake is performed.
   - When you click "Connect", Burp will attempt to carry out the configured handshake and display the result. If a new WebSocket connection was successfully established, you can then use this to send new messages in Burp Repeater.

## WebSockets security vulnerabilities

  In principle, practically any web security vulnerability might arise in relation to WebSockets:

   - User-supplied input transmitted to the server might be processed in unsafe ways, leading to vulnerabilities such as SQL injection or XML external entity injection.
   - Some blind vulnerabilities reached via WebSockets might only be detectable using out-of-band (OAST) techniques.
   - If attacker-controlled data is transmitted via WebSockets to other application users, then it might lead to XSS or other client-side vulnerabilities.

## Manipulating WebSocket messages to exploit vulnerabilities

  The majority of input-based vulnerabilities affecting WebSockets can be found and exploited by tampering with the contents of WebSocket messages
  
  For example, suppose a chat application uses WebSockets to send chat messages between the browser and the server. When a user types a chat message, a WebSocket message like the following is sent to the server:
```json
{"message":"Hello Carlos"}
```

**The contents of the message are transmitted (again via WebSockets) to another chat user, and rendered in the user's browser as follows:**
```html
<td>Hello Carlos</td>
```

>In this situation, provided no other input processing or defenses are in play, an attacker can perform a proof-of-concept XSS attack by submitting the following WebSocket message:
```json
{"message":"<img src=1 onerror='alert(1)'>"}
```

## Steps to solve lab
### Title - Manipulating WebSocket messages to exploit vulnerabilities

**Desc** - This online shop has a live chat feature implemented using WebSockets. Chat messages that you submit are viewed by a support agent in real time. To solve the lab, use a WebSocket message to trigger an `alert()` popup in the support agent's browser.

1. Browse to the application function that uses WebSockets and also look for entries appearing in the WebSockets history tab within Burp Proxy.
![[WebSockets2.png]]

2. In the Intercept tab of Burp Proxy, ensure that interception is turned on. 
![[WebSockets3.png]]

3. When a WebSocket message is sent from the browser or server, it will be displayed in the Intercept tab for you to view or modify.
![[WebSockets5.png]]

![[WebSockets4.png]]

4. In this situation, provided no other input processing or defenses are in play, an attacker can perform a proof-of-concept XSS attack by submitting the following WebSocket message:
```json
{"message":"<img src=1 onerror='alert(1)'>"}
```

![[WebSockets6.png]]

Send the XSS payload after some chatting.
![[WebSockets7.png]]
