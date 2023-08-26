**Consider a shopping application that displays images of items for sale. Images are loaded via some HTML like the following:**
```html
<img src="/loadImage?filename=218.png">`
```
- The `loadImage` URL takes a `filename` parameter and returns the contents of the specified file.
- The image files themselves are stored on disk in the location `/var/www/images/`
- To return an image, the application appends the requested filename to this base directory and uses a filesystem API to read the contents of the file.

**In the above case, the application reads from the following file path:**
```js
/var/www/images/218.png
```

**The application implements no defenses against directory traversal attacks, so an attacker can request the following URL to retrieve an arbitrary file from the server's filesystem:**
```js
https://insecure-website.com/loadImage?filename=../../../etc/passwd
```
This causes the application to read from the following file path:
```js
/var/www/images/../../../etc/passwd
```
- The sequence `../` is valid within a file path, and means to step up one level in the directory structure.
- The three consecutive `../` sequences step up from `/var/www/images/` to the filesystem root, and so the file that is actually read is:
```js
/etc/passwd
```

## Imp points
- On Unix-based operating systems, this is a standard file containing details of the users that are registered on the server.
- On Unix-based operating systems, this is a standard file containing details of the users that are registered on the server.
```js
https://insecure-website.com/loadImage?filename=..\..\..\windows\win.ini
```

## File path traversal, simple case(lab-1)
1. Got a file(image) which is vulnerable.
![[File_path_traversal_simple_case1.png]]

2. Executing the payload:
![[File_path_traversal_simple_case2.png]]

3. Performing on burpsuite:
![[File_path_traversal_simple_case3.png]]

