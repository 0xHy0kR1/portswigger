## What is information disclosure?
- Information disclosure, also known as information leakage, is when a website unintentionally reveals sensitive information to its users.
- Depending on the context, websites may leak all kinds of information to a potential attacker, including:
	- Data about other users, such as usernames or financial information
	- Sensitive commercial or business data
	- Technical details about the website and its infrastructure
![[info_dis1.png]]

### Examples of information disclosure
- Revealing the names of hidden directories, their structure, and their contents via a `robots.txt` file or directory listing
- Providing access to source code files via temporary backups
- Explicitly mentioning database table or column names in error messages
- Unnecessarily exposing highly sensitive information, such as credit card details
- Hard-coding API keys, IP addresses, database credentials, and so on in the source code
- Hinting at the existence or absence of resources, usernames, and so on via subtle differences in application behavior

## How to test for information disclosure vulnerabilities
Generally speaking, it is important not to develop "tunnel vision" during testing. In other words, you should avoid focussing too narrowly on a particular vulnerability.

**The following are some examples of high-level techniques and tools that you can use to help identify information disclosure vulnerabilities during testing.**
- Fuzzing
- Using Burp Scanner
- Using Burp's engagement tools
- Engineering informative responses

### Fuzzing
- you can try submitting unexpected data types and specially crafted fuzz strings to see what effect this has.
- You can automate much of this process using tools such as Burp Intruder.

	**Burp intruder provides several benefits. Most notably, you can:**
	- Add payload positions to parameters and use pre-built wordlists of fuzz strings to test a high volume of different inputs in quick succession.
	- Easily identify differences in responses by comparing HTTP status codes, response times, lengths, and so on.
	- Use grep matching rules to quickly identify occurrences of keywords, such as `error`, `invalid`, `SELECT`, `SQL`, and so on.
	- Apply grep extraction rules to extract and compare the content of interesting items within responses.

**Note** - 
You can also use the Logger++ extension, it allows you to define advanced filters for highlighting interesting entries.

### Using Burp Scanner
- This provides live scanning features for auditing items while you browse, or you can schedule automated scans to crawl and audit the target site on your behalf.
- Burp Scanner will alert you if it finds sensitive information such as private keys, email addresses, and credit card numbers in a response. It will also identify any backup files, directory listings, and so on.

### Using Burp's engagement tools
You can access the engagement tools from the context menu - just right-click on any HTTP message, Burp Proxy entry, or item in the site map and go to "Engagement tools".

**The following tools are particularly useful in this context.**
#### Search
- You can fine-tune the results using various advanced search options, such as regex search or negative search. This is useful for quickly finding occurrences (or absences) of specific keywords of interest.

#### Find comments

#### Discover content
- You can use this tool to identify additional content and functionality that is not linked from the website's visible content.
- This can be useful for finding additional directories and files that won't necessarily appear in the site map automatically.

### Engineering informative responses
- Verbose error messages can sometimes disclose interesting information while you go about your normal testing workflow.
- In some cases, you will be able to manipulate the website in order to extract arbitrary data via an error message.

**Example**
submitting an invalid parameter value might lead to a stack trace or debug response that contains interesting details. You can sometimes cause error messages to disclose the value of your desired data in the response.

## Common sources of information disclosure
**The following are some common examples of places where you can look to see if sensitive information is exposed.**

- Files for web crawlers
- Directory listings
- Developer comments
- [Error messages](information_disclosure_in_error_messages.md)
- [Debugging data](Information_disclosure_on_debug_page.md)
- [User account pages](user_account_pages.md)
- [Backup files](Source_code_disclosure_via_backup_files.md)
- [Insecure configuration](Insecure_configuration.md)
- Version control history

1. **Files for web crawlers
	- Many websites provide files at `/robots.txt` and `/sitemap.xml` to help crawlers navigate their site. Among other things, these files often list specific directories that the crawlers should skip, for example, because they may contain sensitive information.
	- As these files are not usually linked from within the website, they may not immediately appear in Burp's site map. However, it is worth trying to navigate to `/robots.txt` or `/sitemap.xml` manually to see if you find anything of use.

2. **Directory listings**
	- Web servers can be configured to automatically list the contents of directories that do not have an index page present.
	- It particularly increases the exposure of sensitive files within the directory that are not intended to be accessible to users, such as temporary files and crash dumps.
	- Directory listings themselves are not necessarily a security vulnerability. However, if the website also fails to implement proper access control, leaking the existence and location of sensitive resources in this way is clearly an issue.

3. **Developer comments**
	- comments can sometimes be forgotten, missed, or even left in deliberately because someone wasn't fully aware of the security implications. Although these comments are not visible on the rendered page, they can easily be accessed using Burp, or even the browser's built-in developer tools.
	- Occasionally, these comments contain information that is useful to an attacker.
**Example**
they might hint at the existence of hidden directories or provide clues about the application logic.

