## Introduction
a single action you take online (like clicking a button) can set off a series of steps that happen in the background. These steps have different stages that the application goes through, and we'll call these stages "sub-states."

##### Example-1
For instance, think about submitting an online order for a limited-stock item:

1. You click "Buy Now" (single action/request).
2. Behind the scenes, the application goes through several steps: checking stock, processing payment, and confirming the order (sub-states).
3. If someone else also tries to buy the same item at the same time, a "race condition" can occur, where the application gets confused about the order of these actions.

This can lead to problems because the application might not handle these simultaneous requests correctly. It could mistakenly sell the same item to both you and the other person because it didn't handle the situation properly. This is a type of security vulnerability that goes beyond just overloading the system, which we'll call "race condition exploits."

##### Example-2
1. You enter your username and password (first part of the login).
2. Normally, the application would ask for another piece of information (like a code from your phone) to complete the login (MFA).
3. But in some cases, there can be a problem in how this process is set up.
4. Someone might find a way to skip the MFA step by "forcefully browsing" to a specific part of the application directly after the first login part.

This is a flaw because the MFA, which is supposed to make your account more secure, can be bypassed or "skipped" if the application isn't handling the steps properly.

## Methodology
![[race_condition13.bmp]]

### 1 - Predict potential collisions
Testing every endpoint is impractical. After mapping out the target site as normal, you can reduce the number of endpoints that you need to test by asking yourself the following questions:

- **Is this endpoint security critical?**
	- Many endpoints don't touch critical functionality, so they're not worth testing.

- **Is there any collision potential?**
	- For a successful collision, you typically need two or more requests that trigger operations on the same record. 

**For example, think about resetting passwords on a website:**
##### Example - 1
If two people reset their passwords at the same time, they're changing different things. So, there's not much chance of a crash.

##### Example - 2
But if the website lets you change the same thing for two different people at once, that's risky. They could mess up each other's stuff.

### 2 - Probe for clues
- To recognize clues, you first need to benchmark how the endpoint behaves under normal conditions. You can do this in Burp Repeater by grouping all of your requests and using the **Send group in sequence (separate connections)** option.
- Next, send the same group of requests at once using the single-packet attack (or last-byte sync if HTTP/2 isn't supported) to minimize network jitter. You can do this in Burp Repeater by selecting the **Send group in parallel** option.
- Anything at all can be a clue. Just look for some form of deviation from what you observed during benchmarking. This includes a change in one or more responses, but don't forget second-order effects like different email contents or a visible change in the application's behavior afterward.

### 3 - Prove the concept
- Understand what's happening, Remove superfluous requests(get rid of unnecessary steps), and make sure it works every time.
- Advanced race conditions can cause odd situations due to speed, so the path to maximum impact isn't always immediate. 
- It may help to think of each race condition as a structural weakness rather than an isolated vulnerability.

## Multi-endpoint race conditions
- Perhaps the most intuitive form of these race conditions are those that involve sending requests to multiple endpoints at the same time. Think about the classic logic flaw in online stores where you add an item to your basket or cart, pay for it, then add more items to the cart before force-browsing(Go quickly to a page) to the order confirmation page.

##### Scenario of above concept - 
A variation of this vulnerability can occur when payment validation and order confirmation are performed during the processing of a single request. The state machine for the order status might look something like this:

![[server-side/Race_Conditions/images/race_condition14.bmp]]

In this case, you can potentially add more items to your basket during the race window between when the payment is validated and when the order is finally confirmed.

### Aligning multi-endpoint race windows
When testing for multi-endpoint race conditions, there can be problems. even if you send them all at exactly the same time using the single-packet technique.

![[race_condition15.bmp]]

This common problem is primarily caused by the following two factors:
1. **Delays introduced by network architecture**
	- For example, there may be a delay whenever the front-end server establishes a new connection to the back-end. The protocol used can also have a major impact.

2. **Different Processing Times**
	- Different parts of the system can take different times to do their work. This can be because of what kind of tasks they're doing.

**there are ways to find solutions for both of these problems.**

#### Connection warming
- **back-end connection delays** usually don't mess up **race condition attacks** because they delay all actions equally, so they still happen at the same time.
- To differentiate back-end connection delays from other delays, you can perform "connection warming." This involves sending a few unimportant requests to "warm up" or prepare the connection.
**Example**: Let's say you're testing a website for vulnerabilities. You suspect there might be delays caused by back-end processing. You start by sending a simple GET request (like loading the homepage) before your actual testing requests. This warms up the connection, making subsequent requests potentially smoother.

- In Burp Repeater, you can try adding a `GET` request for the homepage to the start of your tab group, then using the **Send group in sequence (single connection)** option. If the first request still has a longer processing time, but the rest of the requests are now processed within a short window, you can ignore the apparent delay and continue testing as normal.

## Steps to solve lab
### Desc - Multi-endpoint race conditions
**Our end goal** - To solve the lab, successfully purchase a **Lightweight L33t Leather Jacket**.

1. 