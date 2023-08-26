## What is stored cross-site scripting?
- Stored cross-site scripting (also known as second-order or persistent XSS) arises when an application receives data from an untrusted source and includes that data within its later HTTP responses in an unsafe way.
- The data in question might be submitted to the application via HTTP requests; for example, comments on a blog post, user nicknames in a chat room, or contact details on a customer order.
- In other cases, the data might arrive from other untrusted sources; for example, a webmail application displaying messages received over SMTP, a marketing application displaying social media posts, or a network monitoring application displaying packet data from network traffic.
- Suppose a website allows users to submit comments on blog posts, which are displayed to other users. Users submit comments using an HTTP request like the following:
```js
POST /post/comment HTTP/1.1 
Host: vulnerable-website.com 
Content-Length: 100 

postId=3&comment=This+post+was+extremely+helpful.&name=Carlos+Montoya&email=carlos%40normal-user.net
```

After this comment has been submitted, any user who visits the blog post will receive the following within the application's response:
```html
<p>This post was extremely helpful.</p>
```

**Assuming the application doesn't perform any other processing of the data, an attacker can submit a malicious comment like this:**
```js
<script>/* Bad stuff here... */</script>
```

**Within the attacker's request, this comment would be URL-encoded a**
```js
comment=%3Cscript%3E%2F*%2BBad%2Bstuff%2Bhere...%2B*%2F%3C%2Fscript%3E
```

**Any user who visits the blog post will now receive the following within the application's response:**
```js
<p><script>/* Bad stuff here... */</script></p>
```
The script supplied by the attacker will then execute in the victim user's browser, in the context of their session with the application.

## Impact of stored XSS attacks
If an attacker can control a script that is executed in the victim's browser, then they can typically fully compromise that user.

## Stored XSS in different contexts
1. **Comment Sections:**
2. **User Profiles:**
3. **Message Systems:**
	- Websites with messaging or communication features can be vulnerable to stored XSS if attackers insert malicious scripts into their messages.
	- When recipients open the message, the scripts can run in their browsers.
4. **Blogs or Forums:**
	- Attackers can inject malicious scripts into posts, and when other users read those posts, the scripts execute.
5. **E-commerce Sites:**
	- Even e-commerce websites with product reviews or user comments can be targeted.
	- Malicious scripts can be injected into reviews or comments, and when potential buyers read them, the scripts can trigger.
6. **Calendars and Event Listings:**
	- Websites that display events or calendars, often with user-generated descriptions, can also be vulnerable.
	- Malicious scripts can be inserted into event descriptions and trigger when users view those events.

## How to find and test for stored XSS vulnerabilities
- Many stored XSS vulnerabilities can be found using Burp Suite's web vulnerability scanner.
- Testing for stored XSS vulnerabilities manually can be challenging. You need to test all relevant "entry points" via which attacker-controllable data can enter the application's processing, and all "exit points" at which that data might appear in the application's responses.

**Entry points into the application's processing include:**
- Parameters or other data within the URL query string and message body.
- The URL file path.
- HTTP request headers that might not be exploitable in relation to reflected XSS.
- Any out-of-band routes via which an attacker can deliver data into the application. a webmail application will process data received in emails; an application displaying a Twitter feed might process data contained in third-party tweets; and a news aggregator will include data originating on other web sites.

**The exit points for stored XSS attacks are all possible HTTP responses**
- The first step in testing for stored XSS vulnerabilities is to locate the links between entry and exit points, whereby data submitted to an entry point is emitted from an exit point.
- The reasons why this can be challenging(here, we discuss the link between entry point and exit point) are that:
	- Data submitted to any entry point could in principle be emitted from any exit point. **Example** - user-supplied display names could appear within an obscure audit log that is only visible to some application users.
	- Data that is currently stored by the application is often vulnerable to being overwritten due to other actions performed within the application. **Example** - a search function might display a list of recent searches, which are quickly replaced as users perform other searches.

To comprehensively identify links between entry and exit points would involve testing each permutation separately, submitting a specific value into the entry point, navigating directly to the exit point, and determining whether the value appears there. However, this approach is not practical in an application with more than a few pages.
## Steps to solve lab
### Desc - Stored XSS into HTML context with nothing encoded
**Our end goal** - To solve this lab, submit a comment that calls the `alert` function when the blog post is viewed.

1. Now, just copy and paste the below command as a comment below the blog.
![[XSS3.png]]

