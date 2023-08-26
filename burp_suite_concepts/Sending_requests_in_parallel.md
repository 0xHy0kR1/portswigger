## Introduction
- If you select **Send group in parallel**, Repeater sends the requests from all of the group's tabs at once. This is useful as a way to identify and exploit race conditions.
- Repeater synchronizes parallel requests to ensure that they all arrive in full at the same time.

**It uses different synchronization techniques depending on the HTTP version used:**
- When sending over HTTP/1, Repeater uses last-byte synchronization. This is where multiple requests are sent over concurrent connections, but the last byte of each request in the group is withheld. After a short delay, these last bytes are sent down each connection simultaneously.
- When sending over HTTP/2+, Repeater sends the group using a single packet attack. This is where multiple requests are sent via a single TCP packet.

When you select a tab containing a response to a parallel request, an indicator in the bottom-right corner displays the order in which that response was received within the group

**Note** - You cannot send macro requests in parallel. This is to prevent macros from interfering with request synchronization.

### Send in parallel prerequisites

To send a group of requests in parallel, the group must meet the following criteria:

- All requests in the group must use the same host, port, and transport layer protocols.
- HTTP/1 keep-alive must not be enabled for the project.