1. First we intercept the request and send to turbo intruder:
right click on repeater > extensions > turbo intruder
2. Select the basic.py script in **turbo intruder** tab and adding the below red box code:
![[username_enumeration via_account_lock1.png]]

2. Setting the path of username wordlists and grep line to extract the valid username:
![[username_enumeration via_account_lock2.png]]

3. At the time of attack:
![[username_enumeration via_account_lock3.png]]
**Result** - The valid user is **user**.

4. Setting up password wordlists and injection for the password payload:
![[username_enumeration via_account_lock4.png]]

5. Setting up password positions for payload:
![[username_enumeration via_account_lock5.png]]

6. Setting up payload for password:
![[username_enumeration via_account_lock6.png]]

7. Setting up extract text for attack:
![[username_enumeration via_account_lock7.png]]

9. Inside **Grep - Extract**:
![[username_enumeration via_account_lock8.png]]
10. At the time of attack, we found out username "accounts" and password "qwerty".