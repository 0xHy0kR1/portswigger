Some websites attempt to prevent this by automatically logging a user out if they enter a certain number of incorrect verification codes.
This is ineffective in practice because an advanced attacker can even automate this multi-step process by [[Burp macros]] for Burp Intruder.

## Lab Solution
1. Navigating to **Session handling rules** by **Settings > Sessions**:
![[2FA_bypass_using_a_brute_force_attack1.png]]

2. Setting the name of session handling rule:
![[2FA_bypass_using_a_brute_force_attack2.png]]

3. setting up the session handling scope:
![[2FA_bypass_using_a_brute_force_attack3.png]]
also tick on extensions.

4. Now, set a rule action by going to **Rule actions** and then click **Add** then select **Run a macro**.
![[2FA_bypass_using_a_brute_force_attack4.png]]

5. Selecting a macro:
![[2FA_bypass_using_a_brute_force_attack5.png]]

6. Setting up urls in the macro recorder:
![[2FA_bypass_using_a_brute_force_attack6.png]]

7. Testing the above created macro:
![[2FA_bypass_using_a_brute_force_attack7.png]]

8. Now, click ok, ok, ok... and exit and send login2 post request to repeater from http history.
9. Now, from repeater send login2 post request to **turbo intruder**.
10. Finally find the password
![[2FA_bypass_using_a_brute_force_attack9.png]]