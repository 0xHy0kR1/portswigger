If an application requires that the user-supplied filename must start with the expected base folder, such as `/var/www/images`, then it might be possible to include the required base folder followed by suitable traversal sequences.

**Example** - 
```python
filename=/var/www/images/../../../etc/passwd
```
## Steps to solve the lab
1. Before injecting the payload:
![[validation_of_start_of_path1.png]]

2. Injecting our payload:
![[validation_of_start_of_path2.png]]

