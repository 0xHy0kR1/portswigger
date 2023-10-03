- SameSite is a browser security mechanism It tells your browser when it's allowed to share these cookies with other websites.
- SameSite cookie restrictions provide partial protection against a variety of cross-site attacks, including CSRF, cross-site leaks, and some CORS exploits.

### There are three possible rules for SameSite:
   1. **Strict**:
       - If a cookie has this setting, your web browser won't share it in any requests to other websites. It only sends the cookie if you're on the exact same website as shown in the address bar. 
	- This means the cookies are like a secret recipe, and they can only be used by the website they came from.
	- This is super secure. It's good for cookies that let you do important stuff, like changing data or accessing private pages when you're logged in.
	- But, it can sometimes make your online experience less smooth when you need to use features that work across different websites because it doesn't share the cookie.

   2. **Lax**:
	- This is a bit more relaxed. It allows the cookies to be shared, but only in certain situations.
	- `Lax` SameSite restrictions mean that browsers will send the cookie in cross-site requests, but only if both of the following conditions are met:
		- The request uses the `GET` method.
		- The request resulted from a top-level navigation by the user, such as clicking on a link.
		  This means that the cookie is not included in cross-site `POST` requests, for example. As `POST` requests are generally used to perform actions that modify data or state (at least according to best practice), they are much more likely to be the target of CSRF attacks.
		
		   Likewise, the cookie is not included in background requests, such as those initiated by scripts, iframes, or references to images and other resources.
		
	   - For example, if you click on a link to visit another website from the first website, then the cookies can be shared.

   3. **None**:
	- This is the most open rule. It means the cookies can be shared freely with any other website.


- Since 2021, Chrome applies `Lax` SameSite restrictions by default if the website that issues the cookie doesn't explicitly set its own restriction level.

## What is a site in the context of SameSite cookies?
   - In the context of SameSite cookie rules, a "site" is like a specific neighborhood on the internet. It's made up of the main domain (like .com or .net) plus one more part of the web address.
   - For example, if you have "example.com," that's one site. If you add something like "app.example.com," that's still part of the same site because it's like the same neighborhood.
   - But, here's the tricky part: Browsers also care about whether a website uses "http://" or "https://" in its address. So, if you go from a "http://" site to an "https://" site within the same neighborhood (like from ("http://app.example.com" to "https://app.example.com"), it might be treated as if you're going to a different neighborhood (cross-site) for security reasons.
![[csrf50.png]]

#### Note
You may come across the term "effective top-level domain" (eTLD). This is just a way of accounting for the reserved multipart suffixes that are treated as top-level domains in practice, such as `.co.uk`.

## What's the difference between a site and an origin?
   - The difference between a site and an origin is their scope; a site encompasses multiple domain names, whereas an origin only includes one.
   - Although they're closely related, it's important not to use the terms interchangeably.
   - Two URLs are considered to have the same origin if they share the exact same scheme, domain name, and port.

![[csrf51.png]]

  - "Site" is less specific, only looks at scheme (like http or https) and last part of the web address.
  - "Same-site" means both the scheme and the last part of the web address match.
  - "Same-origin" means both the scheme, domain name, and port (if specified) all match.

#### Examples:
1. If you visit "[https://example.com](https://example.com/)" from "[https://example.com](https://example.com/)," it's both same-site and same-origin.
2. But if you visit "[https://app.example.com](https://app.example.com/)" from "[https://intranet.example.com](https://intranet.example.com/)," it's same-site but not same-origin because the domain names don't match.
3. If you visit "[https://example.com](https://example.com/)" from "[https://example.com:8080](https://example.com:8080/)," it's same-site but not same-origin due to a port mismatch.
4. When you visit "[https://example.com](https://example.com/)" from "[https://example.co.uk](https://example.co.uk/)," it's neither same-site nor same-origin due to different domain names.
5. Lastly, if you visit "[https://example.com](https://example.com/)" from "[http://example.com](http://example.com/)," it's neither same-site nor same-origin because the schemes don't match.

#### Why it matters:
   This difference matters because if a security vulnerability allows malicious code to run on one part of a website (like "[https://app.example.com](https://app.example.com/)"), it might try to attack other parts (like "[https://intranet.example.com](https://intranet.example.com/)") if they are on the same "site" but not the same "origin." This highlights the importance of understanding these distinctions for web security.

## How does SameSite work?
   - Before SameSite, browsers shared cookies with any website, even if it was unrelated.
   - SameSite stops this by letting websites say which cookies can or cannot be used by other websites. This helps prevent harmful actions caused by cross-site requests.
   - This can help to reduce users' exposure to CSRF attacks, which induce the victim's browser to issue a request that triggers a harmful action on the vulnerable website. As these requests typically require a cookie associated with the victim's authenticated session, the attack will fail if the browser doesn't include this.

   **All major browsers currently support the following SameSite restriction levels:**
   - Strict
   - Lax
   - None

   - Developers can manually configure a restriction level for each cookie they set, giving them more control over when these cookies are used.
 >To do this, they just have to include the `SameSite` attribute in the `Set-Cookie` response header, along with their preferred value:
```js
Set-Cookie: session=0F8tgdOhi9ynR1M9wa3ODa; SameSite=Strict
```

Although this offers some protection against CSRF attacks, none of these restrictions provide guaranteed immunity.

#### Note
   - If the website issuing the cookie doesn't explicitly set a `SameSite` attribute, Chrome automatically applies `Lax` restrictions by default.
   - This means that the cookie is only sent in cross-site requests that meet specific criteria, even though the developers never configured this behavior.