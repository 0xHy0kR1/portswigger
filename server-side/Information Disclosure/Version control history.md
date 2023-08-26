## Introduction
- Virtually all websites are developed using some form of version control system, such as Git.
- By default, a Git project stores all of its version control data in a folder called `.git`. Occasionally, websites expose this directory in the production environment. In this case, you might be able to access it by simply browsing to `/.git`.
- While it is often impractical to manually browse the raw file structure and contents, there are various methods for downloading the entire `.git` directory. You can then open it using your local installation of Git to gain access to the website's version control history.
- This might not give you access to the full source code, but comparing the diff will allow you to read small snippets of code.

## Steps to solve lab-5
### Desc - Information disclosure in version control history

1. As per the lab description, we know there is a `.git` folder in the website. Therefore we search for `/.git` in the url.
![[info_dis10.png]]

2. To download this file locally we use `wget -r https://0aaa006104ca8d358134765a00b4002a.web-security-academy.net/.git` in the terminal.
![[info_dis11.png]]

3. Now, we are going to open this folder(.git) with `Git Cola`.
![[info_dis12.png]]
Above, you can clearly see that admin password already been replaced with environment variables.

4. Now, we are going to undo one commit because in the COMMIT_EDITMSG file we see a commit that admin password is replaced with env variable.
**commit** - 
![[info_dis13.png]]

![[info_dis14.png]]

![[info_dis15.png]]

5. Now, just login with these credentials and user carlos.