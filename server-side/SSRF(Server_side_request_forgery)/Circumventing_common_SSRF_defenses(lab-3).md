## SSRF with blacklist-based input filters

**Some applications block input containing hostnames like `127.0.0.1` and `localhost`, or sensitive URLs like `/admin`. In this situation, you can often circumvent the filter using various techniques:**

- Using an alternative IP representation of `127.0.0.1`, such as `2130706433`, `017700000001`, or `127.1`.
- Registering your own domain name that resolves to `127.0.0.1`. You can use `spoofed.burpcollaborator.net` for this purpose.
- Obfuscating blocked strings using URL encoding or case variation.
- Providing a URL that you control, which subsequently redirects to the target URL. Try using different redirect codes, as well as different protocols for the target URL. For example, switching from an `http:` to `https:` URL during the redirect has been shown to bypass some anti-SSRF filters.

## Steps to solve lab
### Desc - SSRF with blacklist-based input filter
**Our end goal** - change the stock check URL to access the admin interface at `http://localhost/admin` and delete the user `carlos`.

1. Now, first try changing the value of `stockApi` to `127.0.0.1`, such as `2130706433`, `017700000001`, or `127.1` like http://127.1/ and with http://127.1/ you observer that you are able to bypass access control. 
![[SSRF7.png]]

2. Now, try changing http://127.1/ to http://127.1/admin and you see that you are not able to access this page. 
![[SSRF8.png]]

3. Now, try to obfuscate "admin" word to access this page or try to capitalise the letters.

![[SSRF11.png]]

After double url encoding the word "admin", we get the response
![[SSRF9.png]]
4. After double url encoding `admin/delete?username=carlos`, we get 302 response(user carlos deleted).
![[SSRF12.png]]
After double url encoding of `admin/delete?username=carlos` - 
![[SSRF10.png]]