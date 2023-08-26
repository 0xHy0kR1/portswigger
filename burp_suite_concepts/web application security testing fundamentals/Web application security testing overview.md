## What is web application security testing?
Web application security testing aims to determine whether or not a web app is vulnerable to attack. It covers both automated and manual techniques across a number of different methodologies.

## Types of web application security testing
**There are various concepts in web application security testing. Among the best-known are:**

### Dynamic application security testing (DAST)
- DAST works from the outside-in on a running app.
- It's a lot like having a team of experts try and break into your bank vault for you.
- This is what's known as a "black box" security testing technique - because the code running behind the web app is not visible to the test.
- DAST is a practical technique - simulating a real attack on a running web app - its results can generally be assumed to be correct.

### Static application security testing (SAST)
- SAST is more or less the opposite of DAST.
- It works from the inside-out on static code.
- an expert view the blueprints for your bank vault to look for flaws.
- This is what's known as a "white box" security testing technique - because the test can see the web app's code in its entirety (unlike most real attackers).
- Unfortunately, because SAST works on a theoretical, rather than a practical level, it is prone to reporting false positives.
- The main problem here is that because SAST doesn't actually execute any code, it can only see what "might" be going on.
- SAST will produce a larger, noisier set of results than DAST. This noise comes in the form of false positives.

### Interactive application security testing (IAST)
- IAST modifies a running application in order to find vulnerabilities.
- It's a lot like placing sensors inside your bank vault to see what effect your (DAST) attacks are having.
- This is known as a "gray box" security testing technique - effectively being a mixture of black box and white box methodologies.
- Because of its invasive nature, IAST should not be used in production systems.
- It's also a reason that OAST can be considered a "best of all worlds" security testing technique.

### Out-of-band application security testing (OAST)
So OAST reaps many of the benefits of the three techniques above, while minimizing their downsides. Like SAST and IAST it can see vulnerabilities that DAST cannot - but it's not prone to reporting false positives in the way that SAST is. And while IAST is an invasive method to use, OAST doesn't make such changes - so it's much safer.

