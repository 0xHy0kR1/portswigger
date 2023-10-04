Outlining every possible measure you can take to protect your own websites is clearly not possible. However, there are several general principles that you should always follow.

## Take care with user credentials
- It should go without saying that you should never send any login data over unencrypted connections.
- Although you may have implemented HTTPS for your login requests, make sure that you enforce this by redirecting any attempted HTTP requests to HTTPS as well.
- You should also audit your website to make sure that no username or email addresses are disclosed either through publicly accessible profiles or reflected in HTTP responses, for example.

## Don't count on users for security
- The most obvious example is to implement an effective password policy.
- it can be more effective to implement a simple password checker of some kind, which allows users to experiment with passwords and provides feedback about their strength in real time.
- A popular example is the JavaScript library `zxcvbn`, which was developed by Dropbox. By only allowing passwords which are rated highly by the password checker, you can enforce the use of secure passwords more effectively than you can with traditional policies.

## Implement robust brute-force protection
- Ideally, you should require the user to complete a CAPTCHA test with every login attempt after a certain limit is reached.
- making the process as tedious and manual as possible increases the likelihood that any would-be attacker gives up and goes in search of a softer target instead.

## Triple-check your verification logic
## Don't forget supplementary functionality
- Be sure not to just focus on the central login pages and overlook additional functionality related to authentication. This is particularly important in cases where the attacker is free to register their own account and explore this functionality.

## Implement proper multi-factor authentication
- Ideally, 2FA should be implemented using a dedicated device or app that generates the verification code directly. As they are purpose-built to provide security, these are typically more secure.
