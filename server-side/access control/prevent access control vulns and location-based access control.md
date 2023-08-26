## Location-based access control
Some web sites enforce access controls over resources based on the user's geographical location.
**Example** - 
to banking applications or media services where state legislation or business restrictions apply. These access controls can often be circumvented by the use of web proxies, VPNs, or manipulation of client-side geolocation mechanisms.

## How to prevent access control vulnerabilities
1. Never rely on obfuscation alone for access control.
	- In simple terms, Don't just rely on making things hard to find to protect them. Instead, use proper access control methods.
2. Unless a resource is intended to be publicly accessible, deny access by default.
	- In simple terms, By default, don't let anyone access something unless you've specifically said they can.
3. Wherever possible, use a single application-wide mechanism for enforcing access controls.
	- In simple terms, Have a single method or system that controls who can access what in your application.
4. At the code level, make it mandatory for developers to declare the access that is allowed for each resource, and deny access by default.
	- When developers write the code, they should say who can access each thing. And, once again, don't let anyone access something unless it's been allowed.
5. Thoroughly audit and test access controls to ensure they are working as designed.
	- In simple terms, Keep an eye on your access controls and test them often to make sure they are working correctly.