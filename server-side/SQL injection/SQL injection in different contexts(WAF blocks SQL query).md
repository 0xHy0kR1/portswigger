However, it's important to note that you can perform SQL injection attacks using any controllable input that is processed as a SQL query by the application.
For example, some websites take input in JSON or XML format and use this to query the database.

These different formats may even provide alternative ways for you to [obfuscate attacks](https://portswigger.net/web-security/essential-skills/obfuscating-attacks-using-encodings#obfuscation-via-xml-encoding) that are otherwise blocked due to WAFs and other defense mechanisms.
so you may be able to bypass these filters by simply encoding or escaping characters

For example, the following XML-based SQL injection uses an XML escape sequence to encode the `S` character in `SELECT`:
```xml
<stockCheck> 
	<productId> 123 </productId> 
	<storeId> 
		999 &#x53;ELECT * FROM information_schema.tables 
	</storeId> 
</stockCheck>`
```

## Lab solution
### Desc - SQL injection with filter bypass via XML encoding

1. install the **Hackvertor** from **BApp Store**:
![[hackvertor_install.png]]

2. To encode your sql query go **right click on repeater** > **Extensions** > **Hackvertor** > **encode** > choose any encode method(for this lab we choose **hax_entities**).
**Before encoding** - 
![[SQL_injection_in_different_context1.png]]

**After encoding** - 
![[SQL_injection_in_different_context2.png]]

3. checking no. of columns:
![[SQL_injection_in_different_context3.png]]
**Result** - From right panel, we can clearly see that when I try to find that if there is two column then it returns **0 units** which indicates that there is only one column which contains **usernames** and **passwords** of users.

4. Taking out username and password of all the users:
query --> 
```sql
UNION SELECT username || '-' || password FROM users
```

**Below performing on burp**:
![[SQL_injection_in_different_context4.png]]
**Result** - Administrator password is ez17s9hjzskyj69471ms.