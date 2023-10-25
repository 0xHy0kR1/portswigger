## Same-origin policy

   - The same-origin policy is a web security rule that stops a website from freely using content from other websites, making sure it can only interact with resources from its own domain for security reasons.
   - The same-origin policy was defined many years ago in response to potentially malicious cross-domain interactions, such as one website stealing private data from another. It generally allows a domain to issue requests to other domains, but not to access the responses.
   - The same-origin policy is a web browser security mechanism that aims to prevent websites from attacking each other.
   - The same-origin policy restricts scripts on one origin from accessing data from another origin.
   - Same-Origin Policy(SOP) is a rule that is enforced by browsers to control access to data between web applications.
	   - This policy doesn't prevent writing between web applications, it prevents reading between web applications.
	   - Access is determined based on the origin.

![[cors1.png]]

#### For example, consider the following URL:
```js
http://ranakhalil.com/courses.
```

**The following table shows how the same-origin policy will be applied**
 
   ![[cors3.png]]

#### Examples
   What happens when the ranakhalil.com origin tries to access resources from the google.com origin?
   ![[cors4.png]]
   
## Why is the same-origin policy necessary?

   When a browser sends an HTTP request from one origin to another, any cookies, including authentication session cookies, relevant to the other domain are also sent as part of the request. This means that the response will be generated within the user's session, and include any relevant data that is specific to the user. Without the same-origin policy, if you visited a malicious website, it would be able to read your emails from GMail, private messages from Facebook, etc.

## How is the same-origin policy implemented?

   The same-origin policy mostly restricts JavaScript from reading content loaded from other domains, but it allows loading external resources like images("`<img>` tag") and videos(`<video>` tag) on a web page. However, while these external resources can be loaded by the page, any JavaScript on the page won't be able to read the contents of these resources.

**There are various exceptions to the same-origin policy:**

   - Some objects are writable but not readable cross-domain, such as the `location` object or the `location.href` property from iframes or new windows.
   - Some objects are readable but not writable cross-domain, such as the `length` property of the `window` object (which stores the number of frames being used on the page) and the `closed` property.
   - The `replace` function can generally be called cross-domain on the `location` object.

The same-origin policy is looser for cookies, allowing them to work across subdomains within a site, even though subdomains are technically separate origins. To enhance security, you can use the HttpOnly cookie flag.

It's possible to relax same-origin policy using `document.domain`. This special property allows you to relax SOP for a specific domain, but only if it's part of your FQDN (fully qualified domain name).

**For example, you might have a domain**
```js
marketing.example.com
```
You would like to read the contents of that domain on `example.com`. To do so, both domains need to set `document.domain` to `example.com`. Then SOP will allow access between the two domains despite their different origins.

- In the past it was possible to set `document.domain` to a TLD such as `com`, which allowed access between any domains on the same TLD, but now modern browsers prevent this.

