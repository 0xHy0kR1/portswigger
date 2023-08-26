## Introduction
- A fundamentally flawed assumption is that users will only interact with the application via the provided web interface.
- This is especially dangerous because it leads to the further assumption that client-side validation will prevent users from supplying malicious input. However, an attacker can simply use tools such as Burp Proxy to tamper with the data after it has been sent by the browser but before it is passed into the server-side logic. This effectively renders the client-side controls useless.
- Accepting data at face value, without performing proper integrity checks and server-side validation, can allow an attacker to do all kinds of damage with relatively minimal effort.

## Steps to solve lab-1
### Desc - Excessive trust in client-side controls

1. Login with the credentials:
![[Blv2.png]]

2. With Burp running, log in and attempt to buy the leather jacket. The order is rejected because you don't have enough store credit.
2. In Burp, go to "Proxy" > "HTTP history" and study the order process. Notice that when you add an item to your cart, the corresponding request contains a `price` parameter. Send the `POST /cart` request to Burp Repeater.
3. In Burp Repeater, change the price to an arbitrary integer and send the request. Refresh the cart and confirm that the price has changed based on your input.
4. Repeat this process to set the price to any amount less than your available store credit.
5. Complete the order to solve the lab.