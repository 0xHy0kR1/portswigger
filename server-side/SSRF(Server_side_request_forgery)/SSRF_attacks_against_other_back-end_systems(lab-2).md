## Introduction
- Another type of trust relationship that often arises with server-side request forgery is where the application server is able to interact with other back-end systems that are not directly reachable by users. These systems often have non-routable private IP addresses.
- Since the back-end systems are normally protected by the network topology, they often have a weaker security posture.
- In many cases, internal back-end systems contain sensitive functionality that can be accessed without authentication by anyone who is able to interact with the systems.
**Example** - 
suppose there is an administrative interface at the back-end URL `https://192.168.0.68/admin`.
Here, an attacker can exploit the SSRF vulnerability to access the administrative interface by submitting the following request:
```js
POST /product/stock HTTP/1.0 
Content-Type: application/x-www-form-urlencoded 
Content-Length: 118 

stockApi=http://192.168.0.68/admin
```

## Steps to solve lab
### Desc - Basic SSRF against another back-end system
**Our end goal** - use the stock check functionality to scan the internal `192.168.0.X` range for an admin interface on port 8080, then use it to delete the user `carlos`.

1. From the question description, we have defined range `192.168.0.X` but we don't have particular ip of another back-end system. So, we send this request to burp intruder.
![[SSRF4.png]]

2. Payload settings in the intruder tab.
![[SSRF5.png]]

3. From brute-forcing for a back-end ip and we get the required ip.
![[SSRF6.png]]

4. Now, in repeater just paste the url marked with red border(http://192.168.0.187:8080/admin/delete?username=carlos) to solve the lab.
