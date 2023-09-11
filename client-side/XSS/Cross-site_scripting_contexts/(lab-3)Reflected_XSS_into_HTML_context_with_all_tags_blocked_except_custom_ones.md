## Steps to solve lab
### Title - Reflected XSS into HTML context with all tags blocked except custom ones
**Desc** - This lab blocks all HTML tags except custom ones.
           To solve the lab, perform a cross-site scripting attack that injects a custom tag and automatically alerts `document.cookie`.

**Our end goal** - To solve the lab, perform a cross-site scripting attack that injects a custom tag and automatically alerts `document.cookie`.

1. This lab is same as [[(lab-2)Reflected_XSS_into_HTML_context_with_most_tags_and attributes blocked]] but the custom one are allowed here as per the lab description.
   
2. Now, we are going to construct a custom tag and for that visit [custom-tag](https://matthewjamestaylor.com/custom-tags). As shown below:
```jsx
<custom-tag onfocus='alert(document.cookie)' id='x' tabindex="1">
```
for tabindex visit --> [learn](https://www.w3schools.com/tags/att_global_tabindex.asp)
This is a custom tag in which whenever the "custom-tag" have focus then the "alert" function pops up with an victim cookie. The purpose to write it with an "id" attribute is to just give it focus when the victim just visit the web page where our payload is already present.

3. Now, copy the below payload and paste it on the exploit server to deliver victim.
```jsx
<script>
location = 'https://0a2e00e7043e7e3d83f1c32700ef00fe.web-security-academy.net/?search=%3Ccustom-tag+onfocus%3D%27alert%28document.cookie%29%27+id%3D%27x%27+tabindex%3D%221%22%3E#x'
</script>
```
**Note** - Copy the "custom-tag" and paste it on the search box and copy the url and paste in between above "script" tag with at the end add "#x" to provide the focus to this element when the victim open the url.

![[XSS58.png]]
