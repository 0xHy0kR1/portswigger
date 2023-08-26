## Introduction
- Obtaining source code access makes it much easier for an attacker to understand the application's behavior and construct high-severity attacks.
- Sensitive data is sometimes even hard-coded within the source code.

**Example** - API keys and credentials for accessing back-end components.

When mapping out a website, you might find that some source code files are referenced explicitly. Unfortunately, requesting them does not usually reveal the code itself. When a server handles files with a particular extension, such as `.php`, it will typically execute the code, rather than simply sending it to the client as text. However, in some situations, you can trick a website into returning the contents of the file instead.

**Example** - 
text editors often generate temporary backup files while the original file is being edited. These temporary files are usually indicated in some way, such as by appending a tilde (`~`) to the filename or adding a different file extension. Requesting a code file using a backup file extension can sometimes allow you to read the contents of the file in the response.

## Steps to solve lab-3
1. Our end goal is to find the database password, which is present inside of backup file.
2. Now, we are going to use engagement tools to find the hidden files by right clicking on `/` and click onto the `engagement tools` then `content discovery` 
![[info_dis5.png]]

3. Now, a pop-up opens and then click in the `session is not running` and look for hidden files in the `site map` 
![[info_dis6.png]]
Send the above file to `Repeater` and click on `Send` and analyse the `Response` section and you find the database password. 

4. Now, submit these password.

