# Crypto - ECB oracle


## Description 

This challenge has been taken from http://aes.cryptohack.org/ecb_oracle/.
What we have is an function that concats the FLAG to a plaintext given as parameter
and encrypts it through EAS in ECB mode.

Here's ```chall.py```:

```python
#!/usr/bin/python3

from flag import FLAG
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

KEY = os.urandom(16)

def encrypt(plaintext):
    plaintext = plaintext.encode()
    # concat plaintext with 16 - len(plaintext) bytes 
    # with value 16 - len(plaintext)
    padded = pad(plaintext + FLAG.encode(), 16)
    cipher = AES.new(KEY, AES.MODE_ECB)
    try:
        encrypted = cipher.encrypt(padded)
    except ValueError as e:
        return {"error": str(e)}

    return encrypted.hex()

if __name__ == '__main__':
    while True:
        plain = input("encrypt> ")
        print(bytes.fromhex(encrypt(plain)))
```


## Exploit

Let's first take a look how AES ECB works:

![https://upload.wikimedia.org/wikipedia/commons/thumb/d/d6/ECB_encryption.svg/1920px-ECB_encryption.svg.png](./aes-ecb-enc.png)

We can state that:
- The flag is concatenated after the plaintext input;
- ECB encodes blocks of 16 bytes with the same key;
- The flag is 26 chars long.

The main idea to exploit this bad implementation is to start to encode a string of:
$$\Bigl \lceil \dfrac{\text{flagSize}}{\text{blockSize}} \Bigr \rceil * \text{blockSize} - 1$$

bytes, so in this case of 31. If we do so, there's the first char of the flag that gets encrypted in the last byte of the second block. In order to solve this challenge we can brute force this last char and then repeat the process for the remaining characters decreasing the input plaintext. 

For instance, first plaintext that the oracle encrypts is the following one:

$$\text{Oracle}(\text{"A"} * 31 + \text{flag} + \text{padding}) \newline= E(\text{"A"} * 16) + E(\text{"A"} * 15 + ch_1) + E(ch_2 + ... + ch_n +  \text{padding})$$

Proceed finding the next chars decrementing the size of the "A"'s until the entire flag is known.

```Exploit.py```:

```python
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
from binascii import hexlify, unhexlify 
import string
from pwn import process

p = process("./chall.py")

def recvuntil_sendl(p, ustring, payload):
    p.recvuntil(ustring.encode())
    p.sendline(payload.encode())
    a = p.recvline().decode()
    # remove b and '' on the sides of the encrypted text 
    a = a[2:-1]   
    return list(bytes(a, "utf-8"))

def getflag(p):
    flag = ""
    for i in range(1, 27):
        payload = "A" * (32 - i)
        answer = recvuntil_sendl(p, "encrypt> ", payload) 
        
        # brute force the char
        for s in string.printable:
            bf = payload + flag + s

            bf_answer = recvuntil_sendl(p, "encrypt> ", bf)

            # each hex is two char so compare until 32 * 2
            if bf_answer[0:32 * 2] == answer[0:32 * 2]:
                flag = flag + s
                break

    print(flag)


getflag(p)
p.close()
```

```python3 exploit.py```

>[+] Starting local process './chall.py': pid 38213 \
>flag{4tt3nt1_4d_u54r3_3cb}\
>[*] Stopped process './chall.py' (pid 38213)
