NoSQL databases often use query operators, which provide ways to specify conditions that data must meet to be included in the query result.

Examples of MongoDB query operators include:
   - `$where` - Matches documents that satisfy a JavaScript expression.
   - `$ne` - Matches all values that are not equal to a specified value.
   - `$in` - Matches all of the values specified in an array.
   - `$regex` - Selects documents where values match a specified regular expression.

You may be able to inject query operators to manipulate NoSQL queries. To do this, systematically submit different operators into a range of user inputs, then review the responses for error messages or other changes.

### Submitting query operators

- In JSON messages, you can insert query operators as nested objects.
For example, `{"username":"wiener"}` becomes `{"username":{"$ne":"invalid"}}`.

- For URL-based inputs, you can insert query operators via URL parameters.
For example, `username=wiener` becomes `username[$ne]=invalid`. If this doesn't work, you can try the following:
   1. Convert the request method from `GET` to `POST`.
   2. Change the `Content-Type` header to `application/json`.
   3. Add JSON to the message body.
   4. Inject query operators in the JSON.

Consider a vulnerable application that accepts a username and password in the body of a `POST` request:
```json
{"username":"wiener","password":"peter"}
```

- Test each input with a range of operators.
For example, to test whether the username input processes the query operator, you could try the following injection:
```json
{"username":{"$ne":"invalid"},"password":{"peter"}}
```
If the `$ne` operator is applied, this queries all users where the username is not equal to `invalid`.

- If both the username and password inputs process the operator, it may be possible to bypass authentication using the following payload:
```json
{"username":{"$ne":"invalid"},"password":{"$ne":"invalid"}}
```
This query returns all login credentials where both the username and password are not equal to `invalid`. As a result, you're logged into the application as the first user in the collection.

- To target an account, you can construct a payload that includes a known username, or a username that you've guessed. For example:
```json
{"username":{"$in":["admin","administrator","superadmin"]},"password":{"$ne":""}}
```

## Steps to solve lab - 
### Title - Exploiting NoSQL operator injection to bypass authentication

**Desc** - The login functionality for this lab is powered by a MongoDB NoSQL database. It is vulnerable to [NoSQL injection](https://portswigger.net/web-security/nosql-injection) using MongoDB operators. To solve the lab, log into the application as the `administrator` user. You can log in to your own account using the following credentials: `wiener:peter`.

1. Test each end-point of application for the possibility of NoSQL injection and from the lab description we already know that vulnerability is in the my-account page.

2. Login with given credentials analyze the request using burp suite.
![[nosql11.png]]

2. Try to inject numerous query operators to analyze the backend.
![[nosql12.png]]

3. Now, send the request with the below json value to login as admin.
![[nosql13.png]]
Above json username property means, match every username that starts with any character and any number of times and in anywhere there could be word "admin" and at last the word should end with any character and any number of times. The real username of admin is "adminmjm1m8n2".
