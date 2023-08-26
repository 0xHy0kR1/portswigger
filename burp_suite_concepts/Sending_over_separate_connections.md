## Introduction
- If you select **Send group in sequence (separate connections)**, Repeater establishes a connection to the target, sends the request from the first tab, and then closes the connection. It repeats this process for all of the other tabs in the order they are arranged in the group.
- Sending requests over separate connections makes it easier to test for vulnerabilities that require a multi-step process.

### Send in sequence prerequisites

**To send a sequence of requests, the group must meet the following criteria:**
- There must not be any WebSocket message tabs in the group.
- There must not be any empty tabs in the group.

**There are also some additional criteria to send over a single connection:**
- All tabs must have the same target.
- All tabs must use the same HTTP version (that is, they must either all use HTTP/1 or all use HTTP/2).

