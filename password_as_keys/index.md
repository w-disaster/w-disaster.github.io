# Crypto - Password as keys


## Description 

This challenge has been taken from http://aes.cryptohack.org/passwords_as_keys/.
The FLAG has been encoded with the AES cipher in ECB mode using as key an hash of a predictable word (a bad password).

The website gives us an API through which we can get the encoded flag and it's also shown where the word has been drawn.
Here's the code:

```python
from Crypto.Cipher import AES
import hashlib
import random


# /usr/share/dict/words from
# https://gist.githubusercontent.com/wchargin/8927565/raw/d9783627c731268fb2935a731a618aa8e95cf465/words
with open("/usr/share/dict/words") as f:
    words = [w.strip() for w in f.readlines()]
keyword = random.choice(words)

KEY = hashlib.md5(keyword.encode()).digest()
FLAG = ?


@chal.route('/passwords_as_keys/decrypt/<ciphertext>/<password_hash>/')
def decrypt(ciphertext, password_hash):
    ciphertext = bytes.fromhex(ciphertext)
    key = bytes.fromhex(password_hash)

    cipher = AES.new(key, AES.MODE_ECB)
    try:
        decrypted = cipher.decrypt(ciphertext)
    except ValueError as e:
        return {"error": str(e)}

    return {"plaintext": decrypted.hex()}


@chal.route('/passwords_as_keys/encrypt_flag/')
def encrypt_flag():
    cipher = AES.new(KEY, AES.MODE_ECB)
    encrypted = cipher.encrypt(FLAG.encode())

    return {"ciphertext": encrypted.hex()}
```

## Exploit

In order to find the flag first get the encoded FLAG and then brute force the key 
from the word dict:

```bash
curl http://aes.cryptohack.org/passwords_as_keys/encrypt_flag/                     
```
> {"ciphertext":"c92b7734070205bdf6c0087a751466ec13ae15e6f1bcdd3f3a535ec0f4bbae66"}

```bash
curl https://gist.githubusercontent.com/wchargin/8927565/raw/d9783627c731268fb2935a731a618aa8e95cf465/words > words.txt
```

```python
from Crypto.Cipher import AES
import hashlib
import random

# AES ECB decrypt
def decrypt(ciphertext, password_hash):
    ciphertext = bytes.fromhex(ciphertext)
    key = bytes.fromhex(password_hash)

    cipher = AES.new(key, AES.MODE_ECB)
    try:
        decrypted = cipher.decrypt(ciphertext)
    except ValueError as e:
        return {"error": str(e)}

    return decrypted.hex()


with open("words.txt") as f:
    words = [w.strip() for w in f.readlines()]

if __name__ == '__main__':
    # Encoded flag
    enc = "c92b7734070205bdf6c0087a751466ec13ae15e6f1bcdd3f3a535ec0f4bbae66"
    # The flag starts with "crypto"
    plain = ''.join(['{:02x}'.format(ord(c)) for c in "crypto"])

    # Brute force the key
    for i in range(len(words)):
        key = hashlib.md5(words[i].encode()).digest().hex()
        res = decrypt(enc, key)
        if plain in res:
            print(bytearray.fromhex(res).decode())
            break
  
```

> crypto{k3y5__r__n07__p455w0rdz?}


