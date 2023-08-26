## What is SSRF?
- Server-side request forgery (also known as SSRF) is a web security vulnerability that allows an attacker to induce the server-side application to make requests to an unintended location.
- The attacker tricks the server to connect to services inside the organization that should not be accessible from the internet.
- They can also make the server connect to any external system of the attacker's choice. This can lead to leaking sensitive data, like login credentials or other private information.
![[il74kjh4.bmp]]
## What is the impact of SSRF attacks?
1. **Data Exposure**: Attackers can access sensitive data from internal systems, such as user credentials, private documents, or other confidential information.
2. **Unauthorized Access**: They might be able to connect to and manipulate internal-only services, leading to unauthorized access to resources and functionalities.
3. **System Compromise**: An SSRF vulnerability could allow attackers to bypass security controls and potentially take control of the entire server or infrastructure.
4. **Application Manipulation**: Attackers can force the server to interact with external systems, enabling them to manipulate the application's behavior or use it for malicious purposes.
5. **Denial of Service (DoS)**: SSRF can be used to trigger repeated requests to an external system, causing a DoS condition and disrupting the system's availability.

