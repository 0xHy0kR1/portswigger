## Introduction
- Race conditions are a common type of vulnerability closely related to business logic flaws.
- "Race conditions" occur when multiple actions are performed simultaneously on the same data, leading to unexpected outcomes. 
- A race condition attack uses carefully timed requests to cause intentional collisions and exploit this unintended behavior for malicious purposes.
- The period of time during which a collision is possible is known as the **"race window"**

## Example - 
![[race_condition1.bmp]]
Imagine a website that offers single-use gift cards for discounts. Each gift card has a unique code and can only be used once. However, due to a race condition vulnerability, multiple users can attempt to redeem the same gift card code simultaneously.

1. User A and User B both have a gift card with the code "12345".
2. Both users click the "Redeem" button at almost the same time.
3. The website's server processes both requests simultaneously.
4. Due to the race condition, both requests are treated as valid, and both users get the discount using the same gift card code.
5. The website intended for each code to be used once, but it allowed two redemptions due to the timing of the requests.

**This vulnerability could result in financial losses for the business and an unfair advantage for users.**