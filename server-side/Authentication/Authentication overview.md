## Authentication
- Authentication is the process of verifying the identity of a given user or client.
- In other words, it involves making sure that they really are who they claim to be.

#### There are three authentication factors
- Something you **know**, such as a password or the answer to a security question. These are sometimes referred to as "knowledge factors".
- Something you **have**, that is, a physical object like a mobile phone or security token. These are sometimes referred to as "possession factors".
- Something you **are** or do, for example, your biometrics or patterns of behavior. These are sometimes referred to as "inherence factors".

## Authentication VS Authorization
- Authentication is the process of verifying that a user really **is who they claim to be**, whereas authorization involves verifying whether a user **is allowed to do something**.
	- In the context of a website or web application, authentication determines whether someone attempting to access the site with the username `Carlos123` really is the same person who created the account.
	- Once `Carlos123` is authenticated, his permissions determine whether or not he is authorized, for example, to access personal information about other users or perform actions such as deleting another user's account.

## How do authentication vulnerabilities arise?
- The authentication mechanisms are weak because they fail to adequately protect against brute-force attacks.
- Logic flaws or poor coding in the implementation allow the authentication mechanisms to be bypassed entirely by an attacker. This is sometimes referred to as "broken authentication".

## What is the impact of vulnerable authentication?
- If they are able to compromise a high-privileged account, such as a system administrator, they could take full control over the entire application and potentially gain access to internal infrastructure.
- Even compromising a low-privileged account might still grant an attacker access to data that they otherwise shouldn't have. 