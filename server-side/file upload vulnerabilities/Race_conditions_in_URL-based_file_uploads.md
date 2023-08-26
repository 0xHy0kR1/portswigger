## Introduction
- Similar race conditions can occur in functions that allow you to upload a file by providing a URL. In this case, the server has to fetch the file over the internet and create a local copy before it can perform any validation.
- As the file is loaded using HTTP, developers are unable to use their framework's built-in mechanisms for securely validating files. Instead, they may manually create their own processes for temporarily storing and validating the file, which may not be quite as secure.
**Example** - 
if the file is loaded into a temporary directory with a randomized name, in theory, it should be impossible for an attacker to exploit any race conditions. If they don't know the name of the directory, they will be unable to request the file in order to trigger its execution. On the other hand, if the randomized directory name is generated using pseudo-random functions like PHP's `uniqid()`, it can potentially be brute-forced.

**For full explaination to above paragraph reach** --> https://pastecord.com/umiwiseriq.sql
In summary, by uploading a large file with extra padding data, an attacker can exploit the processing time of the system to make it easier to guess the directory name and potentially gain unauthorized access to sensitive files.

