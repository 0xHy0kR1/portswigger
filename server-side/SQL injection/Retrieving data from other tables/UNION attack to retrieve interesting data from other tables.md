- When you have determined the number of columns returned by the original query and found which columns can hold string data, you are in a position to retrieve interesting data.
- you can retrieve the contents of the `users` table by submitting the input:
```sql
'  UNION SELECT username, password FROM users--
```
- Of course, the crucial information needed to perform this attack is that there is a table called `users` with two columns called `username` and `password`
- Without this information, you would be left trying to guess the names of tables and columns.

## Lab solution
![[SQL_injection_UNION_attack_retrieving_data_from_mul_table1.png]]
- below there is I get the administrator password just after performing this query.
![[SQL_injection_UNION_attack_retrieving_data_from_mul_table2.png]]