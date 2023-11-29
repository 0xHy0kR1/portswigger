- We have discussed a commonly encountered browser-side prevention mechanism, namely frame busting scripts. However, we have seen that it is often straightforward for an attacker to circumvent these protections.
- To prevent a security threat called clickjacking, certain protocols have been created for servers. These protocols limit how web browsers can use iframes (a way to embed one webpage within another) to make it more secure.
- To protect against ClickJacking, servers set rules on how iframes can be used. But whether these rules work depends on how well web browsers follow them. Two ways to protect against clickjacking are X-Frame-Options and Content Security Policy.

### X-Frame-Options

   - X-Frame-Options was originally introduced as an unofficial response header in Internet Explorer 8 and it was rapidly adopted within other browsers.
   

**The header provides the website owner with control over the use of iframes or objects so that inclusion of a web page within a frame can be prohibited with the `deny` directive:**
```js
X-Frame-Options: deny
```

**Alternatively, you can limit iframe embedding to only the same website's pages using the below header setting**
```js
X-Frame-Options: sameorigin
```

**or to a named website using the `allow-from` directive:**
```js
X-Frame-Options: allow-from https://normal-website.com
```

X-Frame-Options is not implemented consistently across browsers (the `allow-from` directive is not supported in Chrome version 76 or Safari 12 for example). However, when properly applied in conjunction with Content Security Policy as part of a multi-layer defense strategy it can provide effective protection against clickjacking attacks.

### Content Security Policy ([CSP](https://portswigger.net/web-security/cross-site-scripting/content-security-policy))

   - Content Security Policy (CSP) is a detection and prevention mechanism that provides mitigation against attacks such as XSS and clickjacking.
   - Content Security Policy (CSP) is often set up on the web server by adding a specific header to the server's responses.
```js
Content-Security-Policy: policy
```
where policy is a string of policy directives separated by semicolons.

   - CSP tells the web browser where it's allowed to load resources from, helping it stop malicious actions on a website.
   - The recommended clickjacking protection is to incorporate the `frame-ancestors` directive in the application's Content Security Policy.
   - The `frame-ancestors 'none'` directive is similar in behavior to the X-Frame-Options `deny` directive.
   - The `frame-ancestors 'self'` directive is broadly equivalent to the X-Frame-Options `sameorigin` directive.

**The following allows iframe embedding only from the same website's domain.**
```js
Content-Security-Policy: frame-ancestors 'self';
```

**Alternatively, framing can be restricted to named sites:**
```js
Content-Security-Policy: frame-ancestors normal-website.com;
```
To be effective against clickjacking and XSS, CSPs need careful development, implementation and testing and should be used as part of a multi-layer defense strategy.

## Protecting against clickjacking using CSP

**The following directive will only allow the page to be framed by other pages from the same origin:**
```js
frame-ancestors 'self'
```

**The following directive will prevent framing altogether:**
```js
frame-ancestors 'none'
```

**Using content security policy to prevent [clickjacking](https://portswigger.net/web-security/clickjacking) is more flexible than using the X-Frame-Options header because you can specify multiple domains and use wildcards. For example:**
```js
frame-ancestors 'self' https://normal-website.com https://*.robust-website.com
```

CSP also validates each frame in the parent frame hierarchy, whereas `X-Frame-Options` only validates the top-level frame.

Using CSP to protect against clickjacking attacks is recommended. You can also combine this with the `X-Frame-Options` header to provide protection on older browsers that don't support CSP, such as Internet Explorer.