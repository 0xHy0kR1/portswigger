- You can send requests in sequence using either a single connection or multiple connections.
- To cancel the send sequence, click **Cancel** on one of the group's tabs while the requests are being sent.

### Sending over a single connection
- If you select **Send group in sequence (single connection)**, Repeater establishes a connection to the target, sends the requests from all of the tabs in the group, and then closes the connection.
- Sending requests over a single connection enables you to test for potential client-side desync vectors.
- It also reduces the "jitter" that can occur when establishing TCP connections.
- This is useful for timing-based attacks that rely on being able to compare responses with very small differences in timings.

