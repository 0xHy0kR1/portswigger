## Non-oracle based databases
- There is a schema, which is `information_schema` which provide information about the database.
- You can query `information_schema.tables` to list the tables in the database:
```sql
SELECT * FROM information_schema.tables
```

- This returns output like the following:
```sql
TABLE_CATALOG TABLE_SCHEMA TABLE_NAME TABLE_TYPE ===================================================== 
MyDatabase    dbo          Products   BASE TABLE 
MyDatabase    dbo          Users      BASE TABLE 
MyDatabase    dbo          Feedback   BASE TABLE
```

- You can then query `information_schema.columns` to list the columns in individual tables:
```sql
SELECT * FROM information_schema.columns WHERE table_name = 'Users'
```

- This returns output like the following:
```sql
TABLE_CATALOG TABLE_SCHEMA TABLE_NAME COLUMN_NAME DATA_TYPE ================================================================= 
MyDatabase    dbo          Users      UserId      int 
MyDatabase    dbo          Users      Username    varchar 
MyDatabase    dbo          Users      Password    varchar
```
- This output shows the columns in the specified table and the data type of each column.

## Steps to solve Lab-1
### Desc - SQL injection attack, listing the database contents on non-Oracle databases

1. First check the website is vulnerable to sql injection or not(putting a single quote in the mid of sql query).
![[SQL_injection_listing_database_contents1.png]]

2. Finding the number of columns in the database:
![[SQL_injection_listing_database_contents2.png]]
- We do the above step because `UNION` query have condition that original query and second `SELECT` query should be contain equal no. of columns.

3. Finding that the column contains text data or not:
![[SQL_injection_listing_database_contents3.png]]
**Result** - both columns of original query contains text data.

4. Find the version of the database(whether it is postgresql, MySQL, Microsoft)
![[SQL_injection_listing_database_contents4.png]]
- **Result** - The database used here is postgresql.

5. Finding the table name(users table name) reside in the information schema and for that we need to find the column name where these table name reside in information_schema(for that follow https://www.postgresql.org/docs/current/infoschema-columns.html)
![[SQL_injection_listing_database_contents5.png]]
- **Result** - We find one table(users_jykigp)

6. Finding the columns inside the `users_jykigp` table:
![[SQL_injection_listing_database_contents6.png]]
- Using this query --> 
```sql
' UNION SELECT column_name, 'a' FROM information_schema.columns WHERE table_name = 'users_jykigp'--
```
**Result** - We get the two column names which contains passwords and usernames of users
![[SQL_injection_listing_database_contents7.png]]

7.  Listing the username and password of users from 'users_jykigp' table:
![[SQL_injection_listing_database_contents8.png]]
**Result** - 
![[SQL_injection_listing_database_contents9.png]]

8. Login as an administrator and this lab is solved.

## Oracle based databases
- You can list tables by querying `all_tables`:
```sql
SELECT * FROM all_tables
```

- And you can list columns by querying `all_tab_columns`:
```sql
SELECT * FROM all_tab_columns WHERE table_name = 'USERS'
```

## Steps to solve Lab-2
### Desc - # SQL injection attack, listing the database contents on Oracle

1. First check the website is vulnerable to sql injection or not(putting a single quote in the mid of sql query).
![[SQL_injection_listing_database_contents_oracle1.png]]

2. Finding the number of columns in the database:
![[SQL_injection_listing_database_contents_oracle2.png]]
- On Oracle databases, every `SELECT` statement must specify a table to select `FROM`. If your `UNION SELECT` attack does not query from a table, you will still need to include the `FROM` keyword followed by a valid table name.
- There is a built-in table on Oracle called `dual` which you can use for this purpose. For example: `UNION SELECT 'abc' FROM dual`

3. Finding that the column contains text data or not:
![[SQL_injection_listing_database_contents_oracle3.png]]
**Result** - both columns of original query contains text data.

4. Find the version of the database(whether it is postgresql, MySQL, Microsoft)
![[SQL_injection_listing_database_contents_oracle4.png]]
**Result** - The database used here is oracle.

5. Finding the table name(users table name) reside in the information schema and for that we need to find the column name where these table name reside in information_schema(for that follow --> https://docs.oracle.com/en/database/oracle/oracle-database/19/refrn/ALL_TABLES.html)
![[SQL_injection_listing_database_contents_oracle5.png]]
- **Result** - We find one table(USERS_THEARS)

6. Finding the columns inside the `USERS_THEARS` table:
![[SQL_injection_listing_database_contents_oracle6.png]]
Using this query --> 
```sql
 ' UNION SELECT column_name,NULL FROM all_tab_columns WHERE table_name='USERS_THEARS'--
```
Result columns - PASSWORD_MCQAZI, USERNAME_HEPIFD.

7.  Listing the username and password of users from 'users_jykigp' table:
![[SQL_injection_listing_database_contents_oracle7.png]]
Using this query --> 
```sql
' UNION SELECT USERNAME_HEPIFD,PASSWORD_MCQAZI FROM USERS_THEARS--
```

**Result** - We get the administrator password.
![[SQL_injection_listing_database_contents_oracle8.png]]

8. Login as an administrator and this lab is solved.