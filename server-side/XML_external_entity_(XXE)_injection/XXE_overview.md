## Introduction
- XML external entity injection (also known as XXE) is a web security vulnerability that allows an attacker to interfere with an application's processing of XML data.
- It often allows an attacker to view files on the application server filesystem, and to interact with any back-end or external systems that the application itself can access.
- In some situations, an attacker can escalate an XXE attack to compromise the underlying server or other back-end infrastructure, by leveraging the XXE vulnerability to perform server-side request forgery(SSRF) attacks.
![[XXE1.bmp]]

## How do XXE vulnerabilities arise?
- Some applications use XML to send data between the browser and the server.
- To handle XML data, these applications rely on standard libraries or platform tools provided by the server.
- XXE vulnerabilities occur because XML has certain features that can be dangerous, and these features are supported by the standard parsers even if the application doesn't use them.
- These dangerous features can be exploited by attackers to manipulate the XML data and potentially access sensitive information on the server.

## What are the types of XXE attacks?
[[Exploiting_XXE_to_retrieve_files(lab-1)]] - 
where an external entity is defined containing the contents of a file, and returned in the application's response.

[[Exploiting_XXE_to_perform_SSRF_attacks(lab-2)]] - 
where an external entity is defined based on a URL to a back-end system.

[[Exploiting_blind_XXE_exfiltrate_data_out-of-band(lab-3)]] - 
where sensitive data is transmitted from the application server to a system that the attacker controls.

[[Exploiting_blind_XXE_to_retrieve_data_via_error_messages(lab-3)]] - 
where the attacker can trigger a parsing error message containing sensitive data.
