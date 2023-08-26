## Introduction
The most well-known type of race condition enables you to exceed some kind of limit imposed by the business logic of the application.

## Example - 
consider an online store that lets you enter a promotional code during checkout to get a one-time discount on your order. 

**To apply this discount, the application may perform the following high-level steps:**
1. Check that you haven't already used this code.
2. Apply the discount to the order total.
3. Update the record in the database to reflect the fact that you've now used this code.

**If you later attempt to reuse this code, the initial checks performed at the start of the process should prevent you from doing this:**
![[race_condition2.bmp]]

**Now consider what would happen if a user who has never applied this discount code before tried to apply it twice at almost exactly the same time:**
![[race_condition3.bmp]]
As you can see, the application transitions through a temporary sub-state; that is, a state that it enters and then exits again before request processing is complete.
In this case, the sub-state begins when the server starts processing the first request, and ends when it updates the database to indicate that you've already used this code. This introduces a small race window during which you can repeatedly claim the discount as many times as you like.

**There are many variations of this kind of attack, including:**
- Redeeming a gift card multiple times
- Rating a product multiple times
- Withdrawing or transferring cash in excess of your account balance
- Reusing a single CAPTCHA solution
- Bypassing an anti-brute-force rate limit

**Limit overruns are a subtype of so-called "time-of-check to time-of-use" (TOCTOU) flaws**

### Detecting and exploiting limit overrun race conditions with Burp Repeater

**The process of detecting and exploiting limit overrun race conditions is relatively simple. In high-level terms, all you need to do is:**
1. Identify a single-use or rate-limited endpoint that has some kind of security impact or other useful purpose.
2. Issue multiple requests to this endpoint in quick succession to see if you can overrun this limit.

- The primary challenge is timing the requests so that at least two race windows line up, causing a collision. This window is often just milliseconds and can be even shorter.

**Even if you send all of the requests at exactly the same time, in practice there are various uncontrollable and unpredictable external factors that affect when the server processes each request and in which order.**
![[race_condition4.bmp]]
- Burp Suite 2023.9 adds powerful new capabilities to Burp Repeater that enable you to easily send a group of parallel requests in a way that greatly reduces the impact of one of these factors, namely network jitter.

**Burp automatically adjusts the technique it uses to suit the HTTP version supported by the server:**
- For HTTP/1, it uses the classic last-byte synchronization technique.
- For HTTP/2, it uses the single-packet attack technique, first demonstrated by PortSwigger Research at Black Hat USA 2023.

**The single-packet attack enables you to completely neutralize interference from network jitter by using a single TCP packet to complete 20-30 requests simultaneously.**
![[race_condition5.bmp]]
Although you can often use just two requests to trigger an exploit, sending a large number of requests like this helps to mitigate internal latency, also known as server-side jitter. This is especially useful during the initial discovery phase.

## Pre-requisite - 
[[Sending_over_separate_connections]]
[[Sending_requests_over_sequence]]
[[Sending_requests_in_parallel]]
[[Creating_a_new_tab_group]]
## Steps to solve lab
### Desc - Limit overrun race conditions
**Our end goal** - This lab's purchasing flow contains a race condition that enables you to purchase items for an unintended price.

To solve the lab, successfully purchase a **Lightweight L33t Leather Jacket**.

1. Login with the given credentials.
## Predict a potential collision

1. Log in and buy the cheapest item possible, making sure to use the provided discount code so that you can study the purchasing flow.
    
2. Consider that the shopping cart mechanism and, in particular, the restrictions that determine what you are allowed to order, are worth trying to bypass.
    
3. In Burp, from the proxy history, identify all endpoints that enable you to interact with the cart. For example, a `POST /cart` request adds items to the cart and a `POST /cart/coupon` request applies the discount code.
    
4. Try to identify any restrictions that are in place on these endpoints. For example, observe that if you try applying the discount code more than once, you receive a `Coupon already applied` response.
    
5. Make sure you have an item to your cart, then send the `GET /cart` request to Burp Repeater.
    
6. In Repeater, try sending the `GET /cart` request both with and without your session cookie. Confirm that without the session cookie, you can only access an empty cart. From this, you can infer that:
    
    - The state of the cart is stored server-side in your session.
    - Any operations on the cart are keyed on your session ID or the associated user ID.
    
    This indicates that there is potential for a collision.
    
7. Consider that there may be a race window between when you first apply a discount code and when the database is updated to reflect that you've done this already.
    

## Benchmark the behavior

1. Make sure there is no discount code currently applied to your cart.
    
2. Send the request for applying the discount code (`POST /cart/coupon`) to Repeater 20 times. **Tip:** You can do this quickly using the `Ctrl/Cmd + R` hotkey.
    
3. In Repeater, add all 20 of these tabs to a new group. For details on how to do this, see [[Creating_a_new_tab_group]]
    
4. Send the group of requests in sequence, using separate connections to reduce the chance of interference. For details on how to do this, see [[Sending_requests_over_sequence]].
    
5. Observe that the first response confirms that the discount was successfully applied, but the rest of the responses consistently reject the code with the same **Coupon already applied** message.
    

## Probe for clues

1. Remove the discount code from your cart.
    
2. In Repeater, send the group of requests again, but this time in parallel, effectively applying the discount code multiple times at once. For details on how to do this, see [[Sending_requests_in_parallel]]
    
3. Study the responses and observe that multiple requests received a response indicating that the code was successfully applied. If not, remove the code from your cart and repeat the attack.
    
4. In the browser, refresh your cart and confirm that the 20% reduction has been applied more than once, resulting in a significantly cheaper order.
    

## Prove the concept

1. Remove the applied codes and the arbitrary item from your cart and add the leather jacket to your cart instead.
    
2. Resend the group of `POST /cart/coupon` requests in parallel.
    
3. Refresh the cart and check the order total:
    
    - If the order total is still higher than your remaining store credit, remove the discount codes and repeat the attack.
    - If the order total is less than your remaining store credit, purchase the jacket to solve the lab.

## In burp demonstration
1. Login with the credentials.
2. Now, Observe the discount and process by applying it to another item.
3. Now, Send the `POST /cart/coupon` to Burp Repeater 20 times(with ctrl + R) and add all of this into a group with right clicking on the anyone of the request and select "add tab to group".
![[race_condition6.png]]

![[race_condition7.png]]

![[race_condition8.png]]

4. After you click on "Send group (parallel)", you will get a huge discount and lab has been solved here. 
![[race_condition9.png]]

