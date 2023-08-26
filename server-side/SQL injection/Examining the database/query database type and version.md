- Different databases provide different ways of querying their version.
- You often need to try out different queries to find one that works, allowing you to determine both the type and version of the database.
- The queries to determine the database version for some popular database types are as follows:
| Oracle     | SELECT banner FROM v$version ||
| Microsoft  | SELECT @@version             |
| PostgreSQL | SELECT version()             |
| MySQL      | SELECT @@version             | 

## Steps to solve lab-1
### Desc - SQL injection attack, querying the database type and version on Oracle
1. First check the website is vulnerable to sql injection or not(putting a single quote in the mid of sql sql query).
![[sql_injection_or_not.png]]
- **From Internal server Error**, we can say that it is vulnerable to sql injection(You can also try to put double dash(comment))

2. Finding the number of columns in the database:
![[SQL_examining_database_type_version_column_count.png]]
**Note** - for **Oracle** database we use `dual` as an database name(It is a built-in database in oracle) becoz doesn't allow only `SELECT` without `FROM`.
**Result** - There are two columns in the original query.

3. Finding that the column contains text data or not:
![[SQL_examining_database_type_version_column_text_or_not.png]]
**Result** - both columns of original query contains text data.

4. Finding the version and type of database:
![[SQL_examining_database_type_version_result.png]]
**Note** - we put 'A' in the above query is for just compatibility between original query and second query.

## Steps to solve lab-2
### Desc - SQL injection attack, querying the database type and version on MySQL and Microsoft databases

1. First check the website is vulnerable to sql injection or not(putting a single quote in the mid of sql query).
![[sql_injection_or_not.png]]
- to comment the rest of things see below:
![[SQL_injection_comment_in_MySQL_Microsoft_databases.png]]

2. Finding the number of columns in the database:
![[SQL_examining_database_type_version_column_count_microsoft_oracle.png]]

3. Finding that the column contains text data or not:
![[SQL_examining_database_type_version_column_text_or_not_microsoft_mysql.png]]
**Result** - both columns of original query contains text data.

4. Finding the version and type of database:
![[SQL_examining_database_type_version_result_microsoft_mysql.png]]
- **Note** - we put 'a' in the above query is for just compatibility between original query and second query.

**Related** - [[SQL injection cheat sheet]]