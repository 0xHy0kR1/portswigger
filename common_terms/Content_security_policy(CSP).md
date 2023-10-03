- CSP is a browser security mechanism that aims to mitigate XSS and some other attacks.
- It works by restricting the resources (such as scripts and images) that a page can load and restricting whether a page can be framed by other pages.
- To enable CSP, a response needs to include an HTTP response header called Content-Security-Policy with a value containing the policy.

#### Example to set CSP
Let's say you want to allow scripts to run only from your own domain, and not load any content from other domains. Your CSP header might look like this:
```js
Content-Security-Policy: script-src 'self';
```
- `script-src` is a directive that controls where scripts can come from.
- `'self'` means scripts can only come from the same domain as the web page.

So, CSP is like a security guard for your website, making sure it only talks to trusted friends (domains) and doesn't let any strangers (malicious scripts) in.

