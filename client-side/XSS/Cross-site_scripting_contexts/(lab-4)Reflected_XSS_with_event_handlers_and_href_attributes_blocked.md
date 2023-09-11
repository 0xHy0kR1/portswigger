## Steps to solve lab 
### Title - Reflected XSS with event handlers and href attributes blocked EXPERT LAB Not solved
**Desc** - This lab contains a [[(lab-1)Reflected_XSS]] vulnerability with some whitelisted tags, but all events and anchor `href` attributes are blocked..

To solve the lab, perform a cross-site scripting attack that injects a vector that, when clicked, calls the `alert` function.

Note that you need to label your vector with the word "Click" in order to induce the simulated lab user to click your vector. For example:
```jsx
<a href="">Click me</a>
```

**Our end goal** - 
To solve the lab, perform a cross-site scripting attack that injects a vector that, when clicked, calls the `alert` function.
Note that you need to label your vector with the word "Click" in order to induce the simulated lab user to click your vector. For example:



1. This lab is same as [[(lab-2)Reflected_XSS_into_HTML_context_with_most_tags_and attributes blocked]] 

2. Now, we need to find which tags are allowed and which are not allowed and for that we're going to use burpsuite intruder to brute-force and try to find any such tags.

**Burpsuite intruder settings to brute-force for allowed tags** - 

**Positions** - 
![[XSS59.png]]

**Payloads** - 
![[XSS60.png]]
Source for above tags --> https://portswigger.net/web-security/cross-site-scripting/cheat-sheet

**Start the attack** - 
![[XSS61.png]]
As you can see above, there are four tags which are allowed here. In which 3 tags are useful for us to create a payload "animate", "image", "svg".

3. Now, we are going to construct a payload to inject in the search box. As shown below:
**Payload** - 
```jsx
<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg">
  <a>
	  <animate
      attributeName="href"
      values="javascript:alert(1)" />
    <text x="2" y="2" text-anchor="middle">Click me</text>
  </a>
</svg>
```

Source to learn about svg --> https://developer.mozilla.org/en-US/docs/Web/SVG/Element

Source to learn about animate element --> https://developer.mozilla.org/en-US/docs/Web/SVG/Element/animate

4. Now, inject the payload in the searchbox to trigger an alert whenever the user clicks on the "Click me" image text.
![[XSS62.png]]
