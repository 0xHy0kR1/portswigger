1. Analysing request in repeater:
![[Broken_brute-force_protection_multiple_credentials_per_request1.png]]
You can see that our request has been sent with json format, it means, we can send multiple password or username with single request in a json format(carlos --> victim username).

2. Making a file of passwords:
![[Broken_brute-force_protection_multiple_credentials_per_request2.png]]

3. Now, paste this data in place of above red marked json data and send the request and then you get 302 ok code.
4. Showing the 302 ok code in browser.
![[Broken_brute-force_protection_multiple_credentials_per_request3.png]]
Right click on this panel and click **Show response in browser** and copy the url and paste in search bar.

