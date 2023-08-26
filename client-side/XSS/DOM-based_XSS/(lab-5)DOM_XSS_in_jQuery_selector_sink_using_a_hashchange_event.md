# Pre-requisite --> 
[hashchange](https://www.w3schools.com/jsref/event_onhashchange.asp) 
Another potential sink to look out for is jQuery's `$()` selector function, which can be used to inject malicious objects into the DOM.

jQuery used to be extremely popular, and a classic DOM XSS vulnerability was caused by websites using this selector in conjunction with the `location.hash` source for animations or auto-scrolling to a particular element on the page

**This behavior was often implemented using a vulnerable `hashchange` event handler, similar to the following:**
```js
$(window).on('hashchange', function() { 
	var element = $(location.hash); 
	element[0].scrollIntoView(); 
});
```
- As the `hash` is user controllable, an attacker could use this to inject an XSS vector into the `$()` selector sink.
- More recent versions of jQuery have patched this particular vulnerability by preventing you from injecting HTML into a selector when the input begins with a hash character (`#`). However, you may still find vulnerable code in the wild.

**To actually exploit this classic vulnerability, you'll need to find a way to trigger a `hashchange` event without user interaction. One of the simplest ways of doing this is to deliver your exploit via an `iframe`:**
```js
<iframe src="https://vulnerable-website.com#" onload="this.src+='<img src=1 onerror=alert(1)>'">
```
For understanding above code visit --> `https://pastecord.com/wotoqowari.coffee`
##### Concept to above code - 
1. `<iframe src="https://vulnerable-website.com#"`: This starts by creating an `<iframe>` element with its `src` attribute pointing to a vulnerable website. The `#` at the end of the URL signifies an empty fragment identifier (hash value). Fragments are typically used to navigate to specific sections within a webpage, but in this case, it's being manipulated for malicious purposes.
    
2. `onload="this.src+='<img src=1 onerror=alert(1)>'"`: The `onload` attribute is an event handler that gets triggered when the content of the `<iframe>` has finished loading. In this case, the `onload` event is being exploited to execute malicious code.
    
    - `this.src+=...`: This part modifies the `src` attribute of the `<iframe>` element itself by appending a string that includes an `<img>` tag with an `onerror` attribute. This attribute contains JavaScript code to be executed when the image fails to load.
        
    - `<img src=1 onerror=alert(1)>`: This is an image tag with a source attribute of "1". The `onerror` attribute is where the malicious JavaScript code is injected. In this case, the code is `alert(1)`, which is a simple JavaScript function that creates an alert dialog with the message "1". This is a common payload used in XSS attacks to demonstrate the exploit.



## Steps to solve lab - 
## Title - DOM-XSS in jQuery selector sink using a hashchange event
**Desc** - This lab contains a [[DOM-based_XSS]] vulnerability on the home page. It uses jQuery's `$()` selector function to auto-scroll to a given post, whose title is passed via the `location.hash` property
**Our end goal** - To solve the lab, deliver an exploit to the victim that calls the `print()` function in their browser.

1. To check if this vulnerability exists, inspect the web page and look for jquery `$()` selector function.
![[XSS14.png]]
```js
$(window).on('hashchange', function(){
    var post = $('section.blog-list h2:contains(' + decodeURIComponent(window.location.hash.slice(1)) + ')');
    if (post) post.get(0).scrollIntoView();
});
```
##### Code explaination - 
1. **$(window).on('hashchange', function(){ ... })** - The `hashchange` event is triggered whenever the URL's hash fragment (the part of the URL after the "#" symbol) changes. In other words, this code will run every time the hash fragment of the URL changes.

2. **var post = $('section.blog-list h2:contains(' + decodeURIComponent(window.location.hash.slice(1)) + ')');** - 
This line of code does the following:
- `window.location.hash`: This retrieves the current hash fragment from the URL.
- `.slice(1)`: This removes the "#" symbol from the hash fragment.
- `decodeURIComponent(...)`: This decodes the URL-encoded hash fragment to its original form. For example, `%20` will be converted to a space.
- `$(':contains(...)', 'section.blog-list h2')`: This uses the `:contains(...)` selector to find `h2` elements within the `section.blog-list` element that contain the decoded hash fragment text. This effectively searches for a specific blog post title within the `section.blog-list`.

3. `if (post) post.get(0).scrollIntoView();`:  - 
- This part of the code checks if the `post` variable holds a reference to an HTML element (in this case, an `h2` element containing the specific blog post title). If such an element is found, the `scrollIntoView()` method is called on it. This method scrolls the page so that the element becomes visible within the viewport, ensuring that the user can see the relevant content.

The $() selector is a potential sink we have been looking around, which can be used to inject malicious objects into the DOM. From this we can say that it is vulnerable.

2. Now, if we look onto the page jquery/javascript, we can analyze and deduce the functionality and exploit it.
![[XSS15.png]]

3. Now, deliver a malicious iframe element with this website url and deliver it to the victim.
```javascript
<iframe src="https://0af3005d031512f0806a9e1700c00097.web-security-academy.net/#" onload="this.src+='<img src=1 onerror=print()>'">
```
![[XSS16.png]]
the lab is solved here.
