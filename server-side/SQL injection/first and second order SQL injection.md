## First order SQL injection:
- First order SQL injection, also known as classic or traditional SQL injection.
- It occurs when user input is directly embedded into an SQL query without proper validation or sanitization.
- The attacker can inject malicious SQL code into the input fields of a vulnerable application, which is then executed by the database server.

### Example
consider a login form where the user enters their username and password. If the application concatenates the user input directly into the SQL query without proper handling, an attacker can input a malicious string that alters the query's intended behavior.
For instance, by entering a username like "admin' OR '1'='1", the attacker can manipulate the query to always evaluate to true, effectively bypassing the login mechanism and gaining unauthorized access.

## Second order SQL injection:
- Second order SQL injection, also known as persistent or stored SQL injection.
- It occurs when user input is stored in a database and later used in an SQL query without adequate validation.
- Unlike first order SQL injection, the malicious payload is not directly executed but is stored in the application's database for future use.

### Example
imagine a blog application where users can post comments. If the application fails to properly sanitize the input before storing it in the database, an attacker can inject malicious SQL code as part of their comment.
When the comment is displayed on a webpage, the application retrieves it from the database and includes it in an SQL query without proper validation. This can result in the execution of the injected code whenever the comment is viewed by other users, leading to data theft or unauthorized actions.