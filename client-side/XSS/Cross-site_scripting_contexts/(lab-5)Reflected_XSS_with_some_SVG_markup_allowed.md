## Steps to solve lab - 
### Title - Reflected XSS with some SVG markup allowed
**Desc** - This lab has a simple [[(lab-1)Reflected_XSS]] vulnerability. The site is blocking common tags but misses some SVG tags and events. To solve the lab, perform a cross-site scripting attack that calls the `alert()` function.

**Our end goal** - To solve the lab, perform a cross-site scripting attack that calls the `alert()` function.


1. This lab is same as [[(lab-4)Reflected_XSS_with_event_handlers_and_href_attributes_blocked]]

2. Now, we need to find which tags are allowed and which are not allowed and for that we're going to use burpsuite intruder to brute-force and try to find any such tags.

**Burpsuite intruder settings to brute-force for allowed tags** - 

**Positions** - 
![[XSS63.png]]

**Payloads** - 
![[XSS64.png]]
**Source for the tags** --> https://portswigger.net/web-security/cross-site-scripting/cheat-sheet

**Start the attack** - 
![[XSS65.png]]
When the attack is finished, review the results. Observe that all payloads caused an HTTP 400 response, except for the ones using the `<svg>`, `<animatetransform>`, `<title>`, and `<image>` tags, which received a 200 response.

3. Now, we need to check for which events are allowed so that we can construct our payload with that event.
Due to protocol error we are not able find the exact which event is allowed but with the help of solution we can say that it's `onbegin` attribute of `svg` tag.

You can learn about `onbegin` attribute from --> https://osbo.com/svg/attributes/onbegin/

4. Now, we are going to construct a payload to inject in the search box. As shown below:

**Payload** - 

```jsx
<svg><animateTransform onbegin="javascript:alert(1)"/></svg>
```

Source to learn about svg --> https://developer.mozilla.org/en-US/docs/Web/SVG/Element

Source to learn about animatetransform --> https://developer.mozilla.org/en-US/docs/Web/SVG/Element/animateTransform

5. Now, inject the payload in the searchbox to trigger an alert.
![[XSS66.png]]
