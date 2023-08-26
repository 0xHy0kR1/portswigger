- Having already determined the number of required columns, you can probe each column to test whether it can hold string data by submitting a series of `UNION SELECT`.
- place a string value into each column in turn. For example, if the query returns four columns, you would submit:
```sql
' UNION SELECT 'a',NULL,NULL,NULL-- 
' UNION SELECT NULL,'a',NULL,NULL-- 
' UNION SELECT NULL,NULL,'a',NULL-- 
' UNION SELECT NULL,NULL,NULL,'a'--`
```
- If the data type of a column is not compatible with string data, the injected query will cause a database error, such as:
```sql
`Conversion failed when converting the varchar value 'a' to data type int.`
```
- If an error does not occur, and the application's response contains some additional content including the injected string value, then the relevant column is suitable for retrieving string data.
**Note** - The results from the query are returned in the application's response, so you can use a UNION attack to retrieve data from other tables.

## Lab solution
**Pre-requisite** - [[Determining the number of columns required in a SQL injection UNION attack]]
![[SQL_injection_UNION_attack_determining_data_type_of_column.png]]