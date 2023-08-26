# Pre-requisite -> [[Finding_hidden_attack_surface_for_XXE_injection]] and [[soap_service_and_soap_request]]
## Introduction
- Some applications receive client-submitted data, embed it on the server-side into an XML document, and then parse the document.
**Example** - 
An example of this occurs when client-submitted data is placed into a back-end SOAP request, which is then processed by the backend SOAP service.

- In this situation, you cannot carry out a classic XXE attack, because you don't control the entire XML document and so cannot define or modify a `DOCTYPE` element. However, you might be able to use `XInclude` instead.
- `XInclude` is a part of the XML specification that allows an XML document to be built from sub-documents.
- You can place an `XInclude` attack within any data value in an XML document, so the attack can be performed in situations where you only control a single item of data that is placed into a server-side XML document.

**To perform an `XInclude` attack, you need to reference the `XInclude` namespace and provide the path to the file that you wish to include. For example:**
```js
<foo xmlns:xi="http://www.w3.org/2001/XInclude"> 
<xi:include parse="text" href="file:///etc/passwd"/></foo>
```

**Note** - By default, `XInclude` will try to parse the included document as XML. Since `/etc/passwd` isn't valid XML, you will need to add an extra attribute to the `XInclude` directive to change this behavior.
## Steps to solve lab
### Desc - Exploiting XInclude to retrieve files
This lab has a "Check stock" feature that embeds the user input inside a server-side XML document that is subsequently parsed.

Because you don't control the entire XML document you can't define a DTD to launch a classic XXE attack.
**Our end goal** - To solve the lab, inject an `XInclude` statement to retrieve the contents of the `/etc/passwd` file.

1. Send `POST /product/stock` to burp Repeater and analyse that there is no xml document because `productId` and `storeId` is embeded in the xml document through server side.
![[XXE25.png]]
From the above, we can clearly say that this can't be exploited using previous methods but for now we are going to use `XInclude`.

2. Now, we going to place `XInclude` directive as the value of one of the parameter.
```js
<foo xmlns:xi="http://www.w3.org/2001/XInclude"> 
<xi:include parse="text" href="file:///etc/passwd"/></foo>
```
![[XXE26.png]]

