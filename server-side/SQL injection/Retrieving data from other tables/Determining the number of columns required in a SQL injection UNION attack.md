- The `UNION` keyword lets you execute one or more additional `SELECT` queries and append the results to the original query. For example:
```sql 
`SELECT a, b FROM table1 UNION SELECT c, d FROM table2`
```
- This SQL query will return a single result set with two columns, containing values from columns `a` and `b` in `table1` and columns `c` and `d` in `table2`.

#### For a `UNION` query to work, two key requirements must be met:
- The individual queries must return the same number of columns.
- The data types in each column must be compatible between the individual queries.

To carry out a SQL injection UNION attack, you need to make sure the above things should be on place.

## determining how many columns are being returned from the original query for SQL injection UNION attack

### Using `ORDER BY` 
- The first method involves injecting a series of `ORDER BY` clauses and incrementing the specified column index until an error occurs.
- you would submit:
```sql 
	`' ORDER BY 1-- 
	' ORDER BY 2-- 
	' ORDER BY 3-- 
	etc.`
```
**Note** - 
1. The column in an `ORDER BY` clause can be specified by its index, so you don't need to know the names of any columns.
2. When the specified column index exceeds the number of actual columns in the result set, the database returns an error(Before the error occur the index in the ORDER BY is the actual no. of columns returned by orginal query) such as:
```text
`The ORDER BY position number 3 is out of range of the number of items in the select list.`
```
- The application might actually return the database error in its HTTP response, or it might return a generic error, or simply return no results.

## Using series of `UNION SELECT`
- submitting a series of `UNION SELECT` payloads specifying a different number of null values:
```sql 
' UNION SELECT NULL-- 
' UNION SELECT NULL,NULL-- 
' UNION SELECT NULL,NULL,NULL-- 
etc.
```
- If the number of nulls does not match the number of columns, the database returns an error, such as:
```text
`All queries combined using a UNION, INTERSECT or EXCEPT operator must have an equal number of expressions in their target lists.`
```
- Again, the application might actually return this error message, or might just return a generic error or no results.
- When the number of nulls matches the number of columns, the database returns an additional row in the result set, containing null values in each column.

## Lab solution `UNION SELECT NULL` 
![[SQL_injection_UNION_attack_determining_no._of_columns.png]]
- The reason for using `NULL` with second `SELECT` query is that the data types in each column must be compatible between the original and the injected queries. Since `NULL` is convertible to every commonly used data type, using `NULL` maximizes the chance that the payload will succeed.
### Using burpsuite 
![[SQL_injection_UNION_attack_determining_no._of_columns_burp.png]]

## Lab solution `ORDER BY`
![[SQL_injection_UNION_attack_determining_no._of_columns_orderby_burp.png]]
**Note** - The number just before the 4 is the actual number of columns present in the database.
**For database specific syntax of SQL visit** - [[SQL injection cheat sheet]]