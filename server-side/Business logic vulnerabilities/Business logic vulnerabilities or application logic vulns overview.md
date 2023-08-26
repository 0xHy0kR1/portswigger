## What are business logic vulnerabilities?
- Business logic vulnerabilities are flaws in the design and implementation of an application that allow an attacker to elicit unintended behavior. 
- This potentially enables attackers to manipulate legitimate functionality to achieve a malicious goal.
- These flaws are generally the result of failing to anticipate unusual application states that may occur and, consequently, failing to handle them safely.

## How do business logic vulnerabilities arise?
Business logic vulnerabilities often arise because the design and development teams make flawed assumptions about how users will interact with the application.

**Example** - 
if the developers assume that users will pass data exclusively via a web browser, the application may rely entirely on weak client-side controls to validate input. These are easily bypassed by an attacker using an intercepting proxy.

- To avoid logic flaws, developers need to understand the application as a whole. This includes being aware of how different functions can be combined in unexpected ways.

## What is the impact of business logic vulnerabilities?
- Fundamentally, the impact of any logic flaw depends on what functionality it is related to. If the flaw is in the authentication mechanism, for example, this could have a serious impact on your overall security. Attackers could potentially exploit this for privilege escalation, or to bypass authentication entirely, gaining access to sensitive data and functionality.
- Flawed logic in financial transactions can obviously lead to massive losses for the business through stolen funds, fraud, and so on.


