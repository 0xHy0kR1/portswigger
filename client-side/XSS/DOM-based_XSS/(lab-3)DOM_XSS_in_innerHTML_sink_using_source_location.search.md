The `innerHTML` sink doesn't accept `script` elements on any modern browser, nor will `svg onload` events fire. This means you will need to use alternative elements like `img` or `iframe`.

**Event handlers such as `onload` and `onerror` can be used in conjunction with these elements. For example:**
```js
element.innerHTML='... <img src=1 onerror=alert(document.domain)> ...'
```

## Steps to solve lab
### Title - DOM-XSS in `innerHTML` sink using source `location.search`
**Desc** - This lab contains a [[DOM-based_XSS]] vulnerability in the search blog functionality. It uses an `innerHTML` assignment, which changes the HTML contents of a `div` element, using data from `location.search`.

**Our end goal** - To solve this lab, perform a [[DOM-based_XSS]] attack that calls the `alert` function.

1. After analyzing the dom, we get to know that there is a `search` paramenter in url query string and the value of `search` parameter directly inserted into the DOM using `innerHTML` sink.
![[XSS10.png]]

2. Now, we try to insert a fake image and from there we try to call the `alert` function by using the below payload:
```js
abc123 <img src="1" onerror='alert(1)'>
```
![[XSS11.png]]

