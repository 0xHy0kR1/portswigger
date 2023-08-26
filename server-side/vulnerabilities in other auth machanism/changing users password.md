- Typically, changing your password involves entering your current password and then the new password twice. These pages fundamentally rely on the same process for checking that usernames and current passwords match as a normal login page does.
- Password change functionality can be particularly dangerous if it allows an attacker to access it directly without being logged in as the victim user. For example, if the username is provided in a hidden field, an attacker might be able to edit this value in the request to target arbitrary users. This can potentially be exploited to enumerate usernames and brute-force passwords.

## Steps to solve the lab - 
1. Inspecting for hidden username in the password request:
![[Password_brute-force_via_password_change1.png]]

2. Analyzing the new-password setting:
   ![[Password_brute-force_via_password_change4.png]]
   **Result** - When we enter current password correct but two different new password then it generates the error.

3. Sending the above captured request to burp intruder with modification to username as "carlos"
![[Password_brute-force_via_password_change5.png]]

4. Setting up payloads for the brute-forcing:
![[Password_brute-force_via_password_change6.png]]

5. At the time of attack:
![[Password_brute-force_via_password_change7.png]]
**Result** - username is carlos and password is matrix.