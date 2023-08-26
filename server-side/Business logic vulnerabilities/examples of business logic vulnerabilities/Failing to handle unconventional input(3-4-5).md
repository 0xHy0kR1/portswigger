## Introduction
- One aim of the application logic is to restrict user input to values that adhere to the business rules.
**Example** - 
the application may be designed to accept arbitrary values of a certain data type, but the logic determines whether or not this value is acceptable from the perspective of the business.

**Let's take the simple example of an online shop.**
When ordering products, users typically specify the quantity that they want to order. Although any integer is theoretically a valid input, the business logic might prevent users from ordering more units than are currently in stock, for example.
To implement rules like this, developers need to tell the application whether it should allow a given input and how it should react based on various conditions.

**Consider a funds transfer between two bank accounts.**
This functionality will almost certainly check whether the sender has sufficient funds before completing the transfer:
```php
$transferAmount = $_POST['amount']; 
$currentBalance = $user->getBalance(); 
if ($transferAmount <= $currentBalance) 
	{ // Complete the transfer } 
else 
	{ // Block the transfer: insufficient funds }
```
- But if the logic doesn't sufficiently prevent users from supplying a negative value in the `amount` parameter, this could be exploited by an attacker to both bypass the balance check and transfer funds in the "wrong" direction.
- If the attacker sent -$1000 to the victim's account, this might result in them receiving $1000 from the victim instead. The logic would always evaluate that -1000 is less than the current balance and approve the transfer.

## Some points to be noted while web development:
- When auditing an application, you should use tools such as Burp Proxy and Repeater to try submitting unconventional values.
- In particular, try input in ranges that legitimate users are unlikely to ever enter. This includes exceptionally high or exceptionally low numeric inputs and abnormally long strings for text-based fields.
- You can even try unexpected data types. By observing the application's response, you should try and answer the following questions:
	- Are there any limits that are imposed on the data?
	- What happens when you reach those limits?
	- Is any transformation or normalization being performed on your input?

## Steps to solve lab-3
### Desc - High-level logic vulnerability

1. login with my credentials:
![[Blv2.png]]

2. Adding the jacket to cart
![[Blv3.png]]

3. Changing the quantity to negative value 
![[Blv4.png]]

4. Interface of CART after sending the above request
![[Blv5.png]]
If you add -$1388 + $1337 then you get $51 and you have $100 credits. So, you can purchase the jacket at the end.

5. Adding the jacket in the CART
![[Blv6.png]]
You need to do some **Quantity** adjustments because in the end there could be a calc mistake.

6. Now, you are able to purchase the jacket.

## Steps to solve lab-4
### Desc - Low-level logic flaw

1. Login with the credentials.
2. Analyzing and grabing the post request to cart
![[Blv7.png]]

3. Now, we send this request to repeater and in client side we see that value of "quantity" cannot exceed 99.
4. Now, we send the request to intruder to break the backend integer datatype of total price.
![[Blv8.png]]

5. In the payload option, we set the NULL payload because we want to break the integer limit and for that we constantly increases the quantity with 99 each time intruder send the request.
![[Blv9.png]]
With intruder running in the background, you should keep refreshing the cart until you get to see that the price of jacket becomes a negative value.

6. Total price interface after the limit was break
![[Blv10.png]]

Note - set maximum concurrent request to 1 in resource pool.

7. Now, you need to use mathematics to decrease this amount in that amount that you can purchase it.
8. After purchasing the jacket
![[Blv11.png]]

## Steps to solve lab-4
### Desc - Inconsistent handling of exceptional input

1. First we register for the account.
![[Blv14.png]]

2. Now, when we come across to my-account page then we are able to see that our email has been truncated to 255 characters(which is the limit imposed in the login page for email)
![[Blv16.png]]

3. Now, we are going to use this vulnerability to get access to /admin as the email validation for admin panel access checked at the login page.
4. Now, we are going to register again but with 38 more a's to erase .exploit--- at the login page.
![[Blv15.png]]

5. At the login page, we get access to admin panel.
![[Blv17.png]]

