  These settings control which WebSocket messages Burp holds for viewing and editing in the **Intercept** tab:
  
   - **Intercept client-to-server messages**.
   - **Intercept server-to-client messages**.
   - **Only intercept in-scope messages**.
	   - Select this setting if you only want to intercept WebSocket messages where the `upgrade` request is within the target scope of the project. Out-of-scope messages will not be held. Deselect this setting if you want to intercept all WebSocket messages, regardless whether they are within your project's target scope or not.


**Note** - The WebSocket interception rules settings are project settings. They apply to the current project only.
