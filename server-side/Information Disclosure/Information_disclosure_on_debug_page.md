## Introduction
5. **Debugging data**
	- For debugging purposes, many websites generate custom error messages and logs that contain large amounts of information about the application's behavior. While this information is useful during development, it is also extremely useful to an attacker if it is leaked in the production environment.
**Debug messages can sometimes contain vital information for developing an attack, including:**
- Values for key session variables that can be manipulated via user input
- Hostnames and credentials for back-end components
- File and directory names on the server
- Keys used to encrypt data transmitted via the client

**Note** - Debugging information may sometimes be logged in a separate file.

## Steps to solve lab-2
1. In the description, it states that there is a debug page that discloses sensitive information about the application. Therefore, now we are going to find any hidden files that contain `SECRET_KEY` environment variable.
2. Now, In `HTTP history` sub-tab of `Proxy` right click on `/` and clicks in `engagement tools` then `content discovery` and click on `Session is not running`.
![[info_dis3.png]]

3. Now, navigate to `Site map` and look for a find that seems interesting like `phpinfo.php` send it to `Repeater` and send the request and filter for `SECRET_KEY`.
![[info_dis4.png]]

4. Now, submit the value of this.
