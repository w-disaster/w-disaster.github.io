# Crypto - Lazy CBC


## Description 

A bad implementation of the AES in CBC mode choosed the key as the IV (Initialization Vector) parameter, since it was considered not important to reach the scope.

What we have is a python script which encodes every string you insert from stdin
and the goal is to find the key e.i. the flag.

## Exploit

```python
#!/usr/bin/env python3

from Crypto.Cipher import AES
from flag import FLAG

key = FLAG.encode()

def encrypt(plaintext, IV, key):
    if len(plaintext) % 16 != 0:
        return "Input length must be multiple of 16"

    plaintext = bytes.fromhex(plaintext)
    cipher = AES.new(key, AES.MODE_CBC, IV)
    enc = cipher.encrypt(plaintext)
    return enc.hex()

def decrypt(ciphertext, IV, key):
    if len(ciphertext) % 16 != 0:
        return "Input length must be multiple of 16"

    cipher = AES.new(key, AES.MODE_CBC, IV)
    plain = cipher.decrypt(bytes.fromhex(ciphertext))
    return plain.hex()

if __name__ == '__main__':
    while True:
        print("1) Encrypt a message")
        print("2) Decrypt a massage")
        choice = str(input("> "))
        print(choice.encode())
        if choice == "1":
            plain = input("enter message> ")
            enc = encrypt(plain, key, key)
            print(enc)
        if choice == "2":
            ciphertext = input("enter ciphertext> ")
            plain = decrypt(ciphertext, key, key)
            print(plain)
```

Let's take a look at AES encryption and decription in CBC mode:

![https://upload.wikimedia.org/wikipedia/commons/thumb/8/80/CBC_encryption.svg/1200px-CBC_encryption.svg.png](./CBC_encryption.svg.png)

![https://upload.wikimedia.org/wikipedia/commons/thumb/2/2a/CBC_decryption.svg/1920px-CBC_decryption.svg.png](./CBC_decryption.svg.png)

to solve this challenge we must play with the XOR operator: if
in the encryption step we pass as plaintext a string of all zeros (16, the block size), for instance in the first block, the correspondent ciphertext will be the following:

$$C\_0 = E\_0(\text{IV} \oplus P\_0) = E\_0(\text{IV} \oplus "0000000000000000") = E\_0(\text{IV})
$$

because $$(1 \oplus 0) = 1 \text{ and } (0 \oplus 0) = 0$$

Now, that's the idea: since AES is a simmetric key cipher it uses the same key for the message decryption, so filling the first ciphertext block with all zeros and putting as \\(C_1\\) the \\(C_0\\) just discussed we can determine IV: 

$$P_1 = ("0000000000000000" \oplus E_1(C_1))  \newline = ("0000000000000000" \oplus \text{IV}) = \text{IV}$$


Exploit:
```python
import pwn

BLK_SIZE = 16

if __name__ == '__main__':
    p = pwn.process("./chall.py")

    # Encrypt
    p.sendline("1".encode())
    p.recvuntil("enter message> ".encode())
    p.sendline(BLK_SIZE * "00".encode())
    c2 = p.recvline().decode()
    c1 = "00" * BLK_SIZE
    
    # Decrypt
    p.sendline("2".encode())
    p.sendline((c1 + c2).encode())
    p.recvuntil("enter ciphertext> ".encode())

    plain = p.recvline().decode()   
    print(bytes.fromhex(str(plain)))

    p.close()
```

```bash
python3 exploit.py
```
> [+] Starting local process './chall.py': pid 68990 \
> b'\x0cLN\xd6\x85\x07\xfa?z\xaf\xd6\xf6\xdea<bflag{b4d_c1ph3r}' \
> [*] Stopped process './chall.py' (pid 68990)


---


