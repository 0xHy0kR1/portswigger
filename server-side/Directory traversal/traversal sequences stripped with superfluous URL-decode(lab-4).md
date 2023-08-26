- In some contexts, such as in a URL path or the `filename` parameter of a `multipart/form-data` request, web servers may strip any directory traversal sequences before passing your input to the application. You can sometimes bypass this kind of sanitization by URL encoding, or even double URL encoding, the `../` characters, resulting in `%2e%2e%2f` or `%252e%252e%252f` respectively.

## Steps to solve the lab:
1. Encoding the payload:
![[traversal_sequences_stripped_with_superfluous_URL-decode1.png]]

2. Moving forward in step 1:
![[traversal_sequences_stripped_with_superfluous_URL-decode2.png]]

3. Single encoding the payload:
![[traversal_sequences_stripped_with_superfluous_URL-decode3.png]]
click the below "Apply changes" button to put encoded payload in the url.

4. Double encoding done by clicking on the right side of "Decoded from:" "+" sign and select "URL encoding" and then apply changes to put double encoded payload in as the url parameter.
5. After the attack performed.
![[traversal_sequences_stripped_with_superfluous_URL-decode4.png]]

