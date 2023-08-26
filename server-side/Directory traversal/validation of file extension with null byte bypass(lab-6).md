If an application requires that the user-supplied filename must end with an expected file extension, such as `.png`, then it might be possible to use a null byte to effectively terminate the file path before the required extension

**Example** - 
```python
filename=../../../etc/passwd%00.png
```

## Steps to solve lab-6
1. Before injecting our payload:
![[validation_of_file_extension_with_null_byte_bypass1.png]]

2. After injecting our payload:
![[validation_of_file_extension_with_null_byte_bypass2.png]]

