## Introduction
- Websites are sometimes vulnerable as a result of improper configuration. This is especially common due to the widespread use of third-party technologies, whose vast array of configuration options are not necessarily well-understood by those implementing them.
- In other cases, developers might forget to disable various debugging options in the production environment.
**Example** - 
- the HTTP `TRACE` method is designed for diagnostic purposes. If enabled, the web server will respond to requests that use the `TRACE` method by echoing in the response the exact request that was received.
	- This behavior is often harmless, but occasionally leads to information disclosure, such as the name of internal authentication headers that may be appended to requests by reverse proxies.

## Steps to solve lab-4
### Desc - Authentication bypass via information disclosure

1. log in to the account as a wiener and try to browse the admin page.
![[info_dis7.png]]

2. Now, We are trying to send the same request but with `TRACE` method.
![[info_dis8.png]]
The `X-Custom-IP-Authorization:` header defines our current ip address.

3. As per the description shown above in the `/admin`, local users have access to `/admin`. It means we need to send request to this web application with `X-Custom-IP-Authorization: 127.0.0.1` so that we able to access the admin-panel.
4. Now, we are going to add `X-Custom-IP-Authorization: 127.0.0.1` header to each and every request we sent to this web application and for that, we are going to set this from `Proxy > Proxy settings > Match and replace` then add this header in the replace filed.
![[info_dis9.png]]

5. Now, just browse the `/` and you get the admin-panel and delete user `carlos`.