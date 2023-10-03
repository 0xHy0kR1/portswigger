## Pre-requisite --> [[x-forwarded-for header]]
1. Adding **X-Forwarded-For** header to prevent server from blocking our request:
   ![[username_enumeration_via_response_timing1.png]]

2. Setting up positions in intruder:
![[username_enumeration_via_response_timing2.png]]

3. Setting up payload 1 for **x-forwarded-for** header:
   ![[username_enumeration_via_response_timing3.png]]

4. Setting up payload 2 for usernames:
![[username_enumeration_via_response_timing4.png]]

5. At the time of Attack:
   ![[username_enumeration_via_response_timing5.png]]
 **Result** - The correct username is arkansas.

6. Now, setting up positions for the password with hard coding username as arkansas:
![[username_enumeration_via_response_timing6.png]]

7. Setting up second payload for the password:
   ![[username_enumeration_via_response_timing7.png]]

8. At the time of attack:
   ![[username_enumeration_via_response_timing8.png]]
   **Result** - The password is jessica. 

9. login with password jessica and username arkansas.