## Introduction
- When you upload a file to a website, the server needs to know what type of file it is to handle it safely. MIME types help in this by specifying the format and purpose of the file.
- In an HTTP request, the MIME type is specified in the "Content-Type" header. The "Content-Type" header tells the server what type of data is being sent in the request's body. This is often used when uploading files or sending data in formats other than plain text.
- MIME types follow the format `<type>/<subtype>`.
- MIME is based on the extension of the file, this is extremely easy to bypass.
**Example** - 
if you want to upload an image file to a server using an HTTP POST request, you would include the "Content-Type" header with the appropriate MIME type for the image.
```js
POST /upload HTTP/1.1
Host: example.com
Content-Type: image/jpeg

<binary data of the image file>
```
the "Content-Type" header is set to "image/jpeg," indicating that the data being sent in the request body is an image in JPEG format.

**Similarly, if you were uploading a PDF document, the request would look like this:**
```js
POST /upload HTTP/1.1
Host: example.com
Content-Type: application/pdf

<binary data of the PDF document>
```
