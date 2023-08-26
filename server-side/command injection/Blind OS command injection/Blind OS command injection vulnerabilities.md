- Many instances of OS command injection are blind vulnerabilities. This means that the application does not return the output from the command within its HTTP response.

**Example** - 
Consider a web site that lets users submit feedback about the site. The user enters their email address and feedback message.

The server-side application then generates an email to a site administrator containing the feedback. To do this, it calls out to the `mail` program with the submitted details

```python
mail -s "This site is great" -aFrom:peter@normal-user.net feedback@vulnerable-website.com
```
The output from the `mail` command (if any) is not returned in the application's responses, and so using the `echo` payload would not be effective.

### Detecting blind OS command injection using time delays
- You can use an injected command that will trigger a time delay, allowing you to confirm that the command was executed based on the time that the application takes to respond.
- The `ping` command is an effective way to do this, as it lets you specify the number of ICMP packets to send, and therefore the time taken for the command to run:
```bash
ping -c 10 127.0.0.1 
```
This command will cause the application to ping its loopback network adapter for 10 seconds.