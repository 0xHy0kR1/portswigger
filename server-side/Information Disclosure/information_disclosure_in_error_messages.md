## Introduction
4. **Error messages**
	- One of the most common causes of information disclosure is verbose error messages.
	- Verbose error messages can also provide information about different technologies being used by the website.
**Example**
they might explicitly name a template engine, database type, or server that the website is using, along with its version number.

## Steps to solve lab-1
1. Our end goal is to cause an error in the website so that it reveals third party framework version.
2. Now, we are going to capture request and change the integer parameter of `productId` to string and we get to see verbose error message in the response.
![[info_dis2.png]]