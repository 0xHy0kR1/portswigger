## Introduction
- In many cases, you will encounter logic flaws that are specific to the business domain.
- The discounting functionality of online shops is a classic attack surface when hunting for logic flaws. This can be a potential gold mine for an attacker, with all kinds of basic logic flaws occurring in the way discounts are applied.

**Example** - 
consider an online shop that offers a 10% discount on orders over $1000. This could be vulnerable to abuse if the business logic fails to check whether the order was changed after the discount is applied. In this case, an attacker could simply add items to their cart until they hit the $1000 threshold, then remove the items they don't want before placing the order. They would then receive the discount on their order even though it no longer satisfies the intended criteria.

**Note** - 
1. You should pay particular attention to any situation where prices or other sensitive values are adjusted based on criteria determined by user actions.
2. you may at some point encounter applications from less familiar domains. In this case, you should read as much documentation as possible and, where available, talk to subject-matter experts from the domain to get their insight. This may sound like a lot of work, but the more obscure the domain is, the more likely other testers will have missed plenty of bugs.

**Example** - 
To use a simple example, you need to understand social media to understand the benefits of forcing a large number of users to follow you.

## Steps to solve lab-1
### Desc - Flawed enforcement of business rules

1. login to the website and getting the discount code.
![[Blv33.png]]

2. Now, if we look around this website we are able to find the sign up for news letter at the bottom and with that code we get the huge discount.
![[Blv34.png]]

3. Now, if you enter both the coupons one after another then you are able to use same coupon code multiple time and at the end you are able to buy the jacket.
![[Blv35.png]]

## Steps to solve lab-2
### Desc - Infinite money logic flaw

1. Login with the credentials.
![[Blv36.png]]

2. Now, we just signup for news letter and get the coupon code and purchase the gift card with the help of gift card.
![[Blv37.png]]
From above, you can clearly say that you get benefit of $3 every time you purchase the gift card.

2. Now, we create a macro based on the below requests.
![[Blv38.png]]

3. Now, we take the gift card code from response 4 and put it inside of response 5.
![[Blv39.png]]

![[Blv40.png]]

4. Now, send the my-account GET request to the intruder and set the payload to NULL and set any random no. more than 411 and in Resource pool max concurrent request to 1 and start the attack.
5. Now, refresh the my-account page and buy the jacket.
