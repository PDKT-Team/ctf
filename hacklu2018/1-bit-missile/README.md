# 1-bit-missile
---
**Points:** 271 | **Solves:** 39/1035 | **Category:** Reverse

The laser cannon is aiming in the wrong direction.

Maybe a precise shot can calibrate it.

`nc arcade.fluxfingers.net 1816`

[Download](1_bit_missile_2869d5c89c974929b5b585b0586345ff.zip)
---

[Bahasa Indonesia](#bahasa-indonesia)

## English
The binary provided is a dumped ROM that can be run with `qemu`.


```
qemu-system-i386 -bios rom -serial stdio
```

In binary there is also a flag string at offset 143075.

```
$ strings -a -t d rom | grep flag
143075 flag{xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx}
148568 %s%s resource base %llx size %llx align %d gran %d limit %llx flags %lx index %lx
152945 Code: %d eflags: %08x cr2: %08x
```

Service at 'arcade.fluxfingers.net: 1816' run the similar program with different flag. We can convert 1 bit from ROM to 0 at any offset. Before changing the bit, the service also displays bytes at the selected offset.


```
Enter target byte [0 - 262143]: 140000
]> 01001101 <[
Enter target bit: [0 - 7]: 0
}X> ---------------------------------------{0}
]> 01001100 <[


coreboot-4.8-1707-g33cd6d5-dirty Sun Oct 14 23:58:10 UTC 2018 ramstage starting...
...
Jumping to boot code at 00100000(00fd7000)
FLAG if hit confirmed:
MISSED!
```

By using the bytes leak, we can leak the flag string at offset 143075.

The following is the script used.

```python

from pwn import *

now = ''
flag_offset = 143075
flag = ''

while (now != '}'):
    r = remote('arcade.fluxfingers.net', 1816)
    r.recvuntil(': ')
    r.sendline(str(flag_offset))
    leak = r.recvline()[3:-4]
    now = chr(int(leak, 2))
    flag += now
    flag_offset += 1

print flag
```

Flag: **flag{only_cb_can_run_this_simple_elf}**


## Bahasa Indonesia
Binary yang diberikan adalah sebuah ROM dump yang dapat dijalankan dengan `qemu`.

```
qemu-system-i386 -bios rom -serial stdio
```

Pada binary juga terdapat flag pada offset 143075

```
$ strings -a -t d rom | grep flag
143075 flag{xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx}
148568 %s%s resource base %llx size %llx align %d gran %d limit %llx flags %lx index %lx
152945 Code: %d eflags: %08x cr2: %08x
```

Layanan pada `arcade.fluxfingers.net:1816` menjalankan program yang sepertinya flagnya sudah diubah. Kita dapat mengubah 1 bit dari ROM menjadi 0 pada offset manapun. Sebelum diubah, layanan juga menampilkan byte pada offset yang dipilih.

```
Enter target byte [0 - 262143]: 140000
]> 01001101 <[
Enter target bit: [0 - 7]: 0
}X> ---------------------------------------{0}
]> 01001100 <[


coreboot-4.8-1707-g33cd6d5-dirty Sun Oct 14 23:58:10 UTC 2018 ramstage starting...
...
Jumping to boot code at 00100000(00fd7000)
FLAG if hit confirmed:
MISSED!
```

Dengan memanfaatkan leak pada bytes, kita dapat melakukan leak pada string flag yang ada di offset 143075.

Berikut adalah script yang digunakan.

```python

from pwn import *

now = ''
flag_offset = 143075
flag = ''

while (now != '}'):
    r = remote('arcade.fluxfingers.net', 1816)
    r.recvuntil(': ')
    r.sendline(str(flag_offset))
    leak = r.recvline()[3:-4]
    now = chr(int(leak, 2))
    flag += now
    flag_offset += 1

print flag
```

Flag: **flag{only_cb_can_run_this_simple_elf}**
