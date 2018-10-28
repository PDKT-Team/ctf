# mnemonic
---
**Points:** 260 | **Solves:** 62/653 | **Category:** Crypto

Read me.

[Download](mnemonic.txt)

---

[Bahasa Indonesia](#bahasa-indonesia)

## English
During contest, we didn't know that this challenge is related to blockchain. With some googling, we figured out this *mnemonic* term and found this [json file](https://github.com/trezor/python-mnemonic/blob/master/vectors.json), similar to our challenge. We learned the python code and found out what our challenge file is.

```json
{
  // language
  "japanese": [
  [
    // entropy
    "d3a02b9706507552f0e70709f1d4921275204365b4995feae1d949fb59c663cc",
    // mnemonic
    "ふじみ　あさひ　みのう　いっち　いがく　とない　はづき　ますく　いせえび　たれんと　おとしもの　おどろかす　ことし　おくりがな　ちょうし　ちきゅう　さんきゃく　こんとん　せつだん　ちしき　ぬいくぎ　まんなか　たんい　そっと",
    // seed
    "338c161dbdb47c570d5d75d5936e6a32178adde370b6774d40d97a51835d7fec88f859e0a6660891fc7758d451d744d5d3b1a1ebd1123e41d62d5a1550156b1f"
  ],
  // ...
}
```

Our goal is to find the entropy that starts with `c0f`, given mnemonic with missing one word. We can bruteforce the japanese word list and verify the seed starts with `e9a`. Using this script, we got the flag.

```python
import sys
from binascii import hexlify, unhexlify
from mnemonic import Mnemonic
from hashlib import md5

def b2h(b):
    h = hexlify(b)
    return h if sys.version < '3' else h.decode('utf8')

mnemo = Mnemonic("japanese")
words = "とかす　なおす　よけい　ちいさい　さんらん　けむり　ていど　かがく　とかす　そあく　きあい　ぶどう　こうどう　ねみみ　にあう　ねんぐ　ひねる　おまいり　いちじ　ぎゅうにく　みりょく　ろしゅつ　あつめる"
words = mnemo.normalize_string(words).split(" ")
for word in mnemo.wordlist:
  guess = [word] + words
  seed = Mnemonic.to_seed(" ".join(guess), passphrase="")
  if not b2h(seed).startswith("e9a"):
    continue

  entropy = b2h(mnemo.to_entropy(guess))
  if entropy.startswith("c0f"):
    print(entropy)
    print("SECCON{%s}" % (md5(entropy.encode()).hexdigest()))
    break
```

Flag: `SECCON{cda2cb1742d1b6fc21d05c879c263eec}`

## Bahasa Indonesia
Saat kontes, kami tidak tahu kalau soal ini terkait dengan blockchain. Dengan bantuan Google, kami mendapat istilah *mnemonic* ini dan menemukan [file json](https://github.com/trezor/python-mnemonic/blob/master/vectors.json) yang mirip dengan soal. Kami juga mempelajari kode python-nya dan akhirnya mengetahui arti dari string yang ada di soal.

```json
{
  // language
  "japanese": [
  [
    // entropy
    "d3a02b9706507552f0e70709f1d4921275204365b4995feae1d949fb59c663cc",
    // mnemonic
    "ふじみ　あさひ　みのう　いっち　いがく　とない　はづき　ますく　いせえび　たれんと　おとしもの　おどろかす　ことし　おくりがな　ちょうし　ちきゅう　さんきゃく　こんとん　せつだん　ちしき　ぬいくぎ　まんなか　たんい　そっと",
    // seed
    "338c161dbdb47c570d5d75d5936e6a32178adde370b6774d40d97a51835d7fec88f859e0a6660891fc7758d451d744d5d3b1a1ebd1123e41d62d5a1550156b1f"
  ],
  // ...
}
```

Tujuan kita adalah mencari entropy yang diawali string `c0f`, dengan mnemonic yang satu katanya dihilangkan. Kita dapat melakukan bruteforce kata-kata dalam bahasa Jepang yang ada di wordlist, dan memverifikasi seed-nya diawali dengan string `e9a`. Dengan menggunakan script ini, kami mendapatkan flag.

```python
import sys
from binascii import hexlify, unhexlify
from mnemonic import Mnemonic
from hashlib import md5

def b2h(b):
    h = hexlify(b)
    return h if sys.version < '3' else h.decode('utf8')

mnemo = Mnemonic("japanese")
words = "とかす　なおす　よけい　ちいさい　さんらん　けむり　ていど　かがく　とかす　そあく　きあい　ぶどう　こうどう　ねみみ　にあう　ねんぐ　ひねる　おまいり　いちじ　ぎゅうにく　みりょく　ろしゅつ　あつめる"
words = mnemo.normalize_string(words).split(" ")
for word in mnemo.wordlist:
  guess = [word] + words
  seed = Mnemonic.to_seed(" ".join(guess), passphrase="")
  if not b2h(seed).startswith("e9a"):
    continue

  entropy = b2h(mnemo.to_entropy(guess))
  if entropy.startswith("c0f"):
    print(entropy)
    print("SECCON{%s}" % (md5(entropy.encode()).hexdigest()))
    break
```

Flag: `SECCON{cda2cb1742d1b6fc21d05c879c263eec}`