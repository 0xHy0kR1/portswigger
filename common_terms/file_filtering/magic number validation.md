## Introduction
- Magic numbers are the more accurate way of determining the contents of a file.
- The "magic number" of a file is a string of bytes at the very beginning of the file content which identify the content.
**Example** - a PNG file would have these bytes at the very top of the file: `89 50 4E 47 0D 0A 1A 0A`.
![[file_filtering.png]]

- Unlike Windows, Unix systems use magic numbers for identifying files; however, when dealing with file uploads, it is possible to check the magic number of the uploaded file to ensure that it is safe to accept.
- This is by no means a guaranteed solution, but it's more effective than checking the extension of a file.