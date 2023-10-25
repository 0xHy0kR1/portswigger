## Use CSRF tokens

   The most robust way to defend against CSRF attacks is to include a CSRF token within relevant requests. The token must meet the following criteria:
   
   - Unpredictable with high entropy, as for session tokens in general. 
   - Tied to the user's session.
   - Strictly validated in every case before the relevant action is executed.

### How should CSRF tokens be generated?

   - CSRF tokens should contain significant entropy and be strongly unpredictable, with the same properties as session tokens in general.
   - You should use a cryptographically secure pseudo-random number generator (CSPRNG), seeded with the timestamp when it was created plus a static secret.
   - If you need further assurance beyond the strength of the CSPRNG, you can generate individual tokens by concatenating its output with some user-specific entropy and take a strong hash of the whole structure. This presents an additional barrier to an attacker who attempts to analyze the tokens based on a sample that are issued to them.

### How should CSRF tokens be transmitted?

   An approach that is normally effective is to transmit the token to the client within a hidden field of an HTML form that is submitted using the POST method. The token will then be included as a request parameter when the form is submitted:
```js
<input type="hidden" name="csrf-token" value="CIwNZNlR4XbisJF39I8yWnWX9wX4WFoz" />
```

   - To make a website more secure against certain attacks, you should put the CSRF token field at the beginning of your HTML code, even before other input fields or areas where users can add their own data. This helps protect against attacks where an attacker tries to manipulate your website's code to steal information. Placing the CSRF token early makes it harder for them to do that.

**An alternative approach, of placing the token into the URL query string, is somewhat less safe because the query string:**
   - Is logged in various locations on the client and server side;
   - Is liable to be transmitted to third parties within the HTTP Referer header; and
   - can be displayed on-screen within the user's browser.

An another approach, CSRF tokens are sent as a custom request header, making it harder for attackers to misuse them. However, this method restricts the application to using XHR for secure requests, which might be too complex for some situations.

CSRF tokens should not be transmitted within cookies.

### How should CSRF tokens be validated?

   When a CSRF token is generated, it should be stored server-side within the user's session data. When a subsequent request is received that requires validation, the server-side application should verify that the request includes a token which matches the value that was stored in the user's session.
   
   This validation must be performed regardless of the HTTP method or content type of the request. If the request does not contain any token at all, it should be rejected in the same way as when an invalid token is present.

## Use Strict SameSite cookie restrictions

   In addition to implementing robust CSRF token validation, we recommend explicitly setting your own [SameSite](https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions) restrictions with each cookie you issue. By doing so, you can control exactly which contexts the cookie will be used in, regardless of the browser.
   
   "Even if all browsers use the "Lax" policy as the default for cookies, it's not the best choice for every situation, as it's less secure and can be circumvented more easily compared to the stricter "Strict" policy."
   
   Never disable SameSite restrictions with `SameSite=None` unless you're fully aware of the security implications.

## Be wary of cross-origin, same-site attacks

  While SameSite restrictions help against certain attacks, they can't stop same-origin attacks. To enhance security, consider keeping unsafe content on a separate site from sensitive data. Also, thoroughly check all parts of your site, including related domains, for potential vulnerabilities.

