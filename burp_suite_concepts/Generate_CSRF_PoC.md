You can use this function to generate a proof-of-concept (PoC) cross-site request forgery (CSRF) attack for a given request.

**To access this function:**
 1. Select a URL or HTTP request from anywhere in Burp.
 2. Right-click and select **Engagement tools > Generate CSRF PoC**.

Burp shows the full request you selected in the top panel, and the generated CSRF HTML in the lower panel. The HTML uses a form and/or JavaScript to generate the required request in the browser.

You can edit the request manually. Click **Regenerate** to regenerate the CSRF HTML based on your edited request.

#### To test the effectiveness of the generated PoC in Burp's browser:
  1. Click **Test in browser**.
  2. Copy and paste the unique URL into Burp's browser. The browser request is served by Burp with the currently displayed HTML.
  3. To determine whether the PoC is effective, monitor the requests that are made through the Proxy.

#### Some points should be noted regarding CSRF techniques:

   - The cross-domain XmlHttpRequest (XHR) technique only works on modern HTML5-capable browsers that support [cross-origin resource sharing](https://portswigger.net/web-security/cors) ([CORS](https://portswigger.net/web-security/cors)). The technique has been tested on current versions of Firefox and Chrome. The browser must have JavaScript enabled. 
	   - With this technique, the application's response is not processed by the browser in the normal way, This change makes it unsuitable for launching a specific type of attack called "reflected cross-site scripting" (XSS) through cross-domain requests(Cross-domain requests are requests that come from a different website. This technique doesn't work well with them).
	   - There are rules and limitations when using this technique with cross-domain requests, which may cause it to not work as expected.
	   - The tool called "Burp" will show a warning if it thinks this technique might not work well with cross-domain requests when generating a proof-of-concept for a Cross-Site Request Forgery (CSRF) attack.

   - Some requests in web apps have data (like XML or JSON) that can only be created using a regular form or a cross-domain request (XHR).
	   - If created using a regular form, the request will have a "Content-Type: text/plain" header.
	   - If created using cross-domain XHR, the request can have any "Content-Type" header, but it should match standard values used in regular HTML forms to avoid extra steps that could disrupt an attack.
	   - Using standard "Content-Type" values in cross-domain XHR helps avoid the need for a pre-flight request, which can complicate the attack.
	   - Sometimes, even if the request body is correct, an unexpected "Content-Type" header can cause the application to reject the request. This can resemble a CSRF (Cross-Site Request Forgery) situation but may not be easily exploitable.
	   - The tool "Burp" will warn you if it thinks such issues might happen when generating a proof-of-concept for a CSRF attack.

   - If you [manually select](https://portswigger.net/burp/documentation/desktop/tools/engagement-tools/generate-csrf-poc#csrf-poc-options) a CSRF technique that cannot be used to produce the required request, Burp generates a best effort at a PoC and displays a warning.
   - When generating a CSRF PoC using plain text encoding, the request body should have an equals sign (=).
	   - This equals sign is important because it helps Burp create an HTML form that reproduces the exact request body.
	   - If the original request doesn't have an equals sign, you might be able to add one in the request without causing problems for the server. This ensures Burp can generate the PoC accurately.

## CSRF PoC options

**To access the options, click Options**:

- **CSRF technique** - 
	- Specify the type of CSRF technique to use in the HTML that generates the CSRF request.
	- The **Auto** option is generally preferred, and causes Burp to select the most appropriate technique capable of generating the required request.

- **Include auto-submit script** - 
	- Burp includes a script in the HTML that causes a JavaScript-enabled browser to automatically issue the CSRF request when the page is loaded.