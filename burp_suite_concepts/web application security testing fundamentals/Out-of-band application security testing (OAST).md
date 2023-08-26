## How does OAST work?

### Attacking from the outside
In essence it sends payloads to a target application and analyses the responses that come back - just like a real attacker might:
![[oast1.png]]
- When you send a DAST payload and your target comes back to you with a response suggesting a vulnerability, you can be pretty sure it's real. Dynamic testing has achieved the success it has, because it works well in these situations.
- But what if a target app doesn't send back a response to a payload, even though the target is actually vulnerable? This is a particular problem when an app is working asynchronously. Traditional DAST techniques alone just won't see it. This is where OAST comes in.

**Moving forward to burp collaborator** - 
Burp Collaborator performs OAST by introducing a new channel of communication into the dynamic testing process:
![[oast2.png]]

**So, what's actually happening here?**
If a vulnerability is blind, then it sends back no useful response to us when we send a test attack - even if that attack is successful.
We need a way to bypass this. Out-of-band testing methods are that bypass. It is done by sending an attack payload that causes an interaction with an external system we have control over, that sits outside the target domain.

## The advantages of testing out of band
![[oast3.png]]

