- In cases where the results of a SQL query are returned within the application's responses, an attacker can leverage a SQL injection vulnerability to retrieve data from other tables within the database.
- This is done using the `UNION` keyword, which lets you execute an additional `SELECT` query and append the results to the original query.

- For example, if an application executes the following query containing the user input "Gifts":
```sql
`SELECT name, description FROM products WHERE category = 'Gifts'`
```
- then an attacker can submit the input:
```sql 
`' UNION SELECT username, password FROM users--`
```
- This will cause the application to return all usernames and passwords along with the names and descriptions of products.

Related --> [[Determining the number of columns required in a SQL injection UNION attack]]