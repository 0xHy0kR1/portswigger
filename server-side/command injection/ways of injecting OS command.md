**The following command separators work on both Windows and Unix-based systems:**
```python
&
```

```python
&&
```

```python
|
```

```python
||
```


**The following command separators work only on Unix-based systems:**
```python
;
```

```python
Newline (`0x0a` or `\n`)
```

**Note** - 
1. the different shell metacharacters have subtly different behaviors that might affect whether they work in certain situations, and whether they allow in-band retrieval of command output or are useful only for blind exploitation.
2. Sometimes, the input that you control appears within quotation marks in the original command. In this situation, you need to terminate the quoted context (using `"` or `'`) before using suitable shell metacharacters to inject a new command.


