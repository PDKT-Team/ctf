# Special Instructions
---
**Points:** 262 | **Solves:** 61/653 | **Category:** Reversing

Execute this file and get the flag.

References: Assembly samples for many architectures
http://kozos.jp/books/asm/cross-gcc494-v1.0.zip

See the assembly samples.

```
$ unzip cross-gcc494-v1.0.zip
$ cd cross-gcc494/sample
$ ls *.d
```

See the sample programs running on GDB simulator.

```
$ cd cross-gcc494/exec
$ ls *.d
```

[Download](runme_f3abe874e1d795ffb6a3eed7898ddcbcd929b7be)

---

[Bahasa Indonesia](#bahasa-indonesia)

## English
We were given an ELF 32-bit with unknown architecture.
```sh
$ file runme_f3abe874e1d795ffb6a3eed7898ddcbcd929b7be
runme_f3abe874e1d795ffb6a3eed7898ddcbcd929b7be: ELF 32-bit MSB executable, *unknown arch 0xdf* version 1 (SYSV), statically linked, not stripped
```

Basic recon using `strings`, we found the architecture is `moxie`.
```sh
$ strings runme_f3abe874e1d795ffb6a3eed7898ddcbcd929b7be
,.U7
0123456789abcdef
This program uses special instructions.
SETRSEED: (Opcode:0x16)
	RegA -> SEED
GETRAND: (Opcode:0x17)
	xorshift32(SEED) -> SEED
	SEED -> RegA
GCC: (GNU) 4.9.4
moxie-elf.c
...
```

We couldn't disassemble it with `objdump` or `IDA`. We decided to make our own [simple disassembler](disas_moxie.py) by reading [this documentation](http://moxielogic.org/blog/pages/architecture.html).
```
$ python disas_moxie.py
function main
0x136c:    06 18    push $sp, $r6
0x136e:    91 18    dec $sp, 0x24
0x1370:    01 20    ldi.l $r0, 0x92d68ca2
0x1376:    03 00    jsra set_random_seed
0x137c:    01 80    ldi.l $r6, puts
0x1382:    01 20    ldi.l $r0, 0x1
0x1388:    01 30    ldi.l $r1, "This program uses special instructions.\n\n"
0x138e:    19 80    jsr $r6
0x1390:    01 20    ldi.l $r0, 0x1
0x1396:    01 30    ldi.l $r1, "SETRSEED: (Opcode:0x16)\n"
0x139c:    19 80    jsr $r6
0x139e:    01 20    ldi.l $r0, 0x1
0x13a4:    01 30    ldi.l $r1, "    RegA -> SEED\n\n"
0x13aa:    19 80    jsr $r6
0x13ac:    01 20    ldi.l $r0, 0x1
0x13b2:    01 30    ldi.l $r1, "GETRAND: (Opcode:0x17)\n"
0x13b8:    19 80    jsr $r6
0x13ba:    01 20    ldi.l $r0, 0x1
0x13c0:    01 30    ldi.l $r1, "    xorshift32(SEED) -> SEED\n"
0x13c6:    19 80    jsr $r6
0x13c8:    01 20    ldi.l $r0, 0x1
0x13ce:    01 30    ldi.l $r1, "    SEED -> RegA\n\n"
0x13d4:    19 80    jsr $r6
0x13d6:    01 20    ldi.l $r0, flag
0x13dc:    01 30    ldi.l $r1, randval
0x13e2:    03 00    jsra decode
0x13e8:    02 32    mov $r1, $r0
0x13ea:    01 20    ldi.l $r0, 0x1
0x13f0:    19 80    jsr $r6
0x13f2:    01 20    ldi.l $r0, 0x1
0x13f8:    01 30    ldi.l $r1, "\n"
0x13fe:    19 80    jsr $r6
0x1400:    2e 22    xor $r0, $r0
0x1402:    03 00    jsra exit

function decode
0x136c:    06 18    push $sp, $r6
0x136e:    06 19    push $sp, $r7
0x1370:    06 1a    push $sp, $r8
0x1372:    06 1b    push $sp, $r9
0x1374:    06 1c    push $sp, $r10
0x1376:    06 1d    push $sp, $r11
0x1378:    91 18    dec $sp, 0x24
0x137a:    02 d2    mov $r11, $r0
0x137c:    1c 42    ld.b $r2, ($r0)
0x137e:    2e 22    xor $r0, $r0
0x1380:    0e 42    cmp $r2, $r0
0x1382:    c0 12    beq 0x???
0x1384:    02 a3    mov $r8, $r1
0x1386:    02 9d    mov $r7, $r11
0x1388:    01 c0    ldi.l $r10, get_random_value
0x138e:    1c 8a    ld.b $r6, ($r8)
0x1390:    2e 22    xor $r0, $r0
0x1392:    19 c0    jsr $r10
0x1394:    2e 82    xor $r6, $r0
0x1396:    1c 29    ld.b $r0, ($r7)
0x1398:    2e 82    xor $r6, $r0
0x139a:    1e 98    st.b ($r7), $r6
0x139c:    89 01    inc $r7, 0x1
0x139e:    8a 01    inc $r8, 0x1
0x13a0:    1c 39    ld.b $r1, ($r7)
0x13a2:    2e 22    xor $r0, $r0
0x13a4:    0e 32    cmp $r1, $r0
0x13a6:    c7 f3    bne 0x???
0x13a8:    02 2d    mov $r0, $r11
0x13aa:    02 e0    mov $r12, $fp
0x13ac:    9e 18    dec $r12, 0x24
0x13ae:    07 ed    pop $r12, $r11
0x13b0:    07 ec    pop $r12, $r10
0x13b2:    07 eb    pop $r12, $r9
0x13b4:    07 ea    pop $r12, $r8
0x13b6:    07 e9    pop $r12, $r7
0x13b8:    07 e8    pop $r12, $r6
0x13ba:    04 00    ret

function set_random_seed
0x136c:    16 20    ???
0x136e:    04 00    ret

function get_random_value
0x136c:    17 20    ???
0x136e:    04 00    ret

flag: 6d72c3e2cf95549db6ac0384c3c23593c3d77ce2ddd4ac5e99c9a534de064e00
randval: 3d05dc31d18aaf2996facb1b01ece2f715706cf47ea19e0e01f9c24cbaa0a108
```

The pseudocode roughly looks like this.
```python
flag = "6d72c3e2cf95549db6ac0384c3c23593c3d77ce2ddd4ac5e99c9a534de064e00"
randval = "3d05dc31d18aaf2996facb1b01ece2f715706cf47ea19e0e01f9c24cbaa0a108"
def main():
  set_random_seed(0x92d68ca2)
  puts("...")
  puts(decode(flag, randval))

def decode(flag, randval):
  i = 0
  while flag[i]:
    flag[i] ^= randval[i] ^ get_random_value()
    i += 1
  return flag
```

Function `set_random_seed` and `get_random_value` are compiled with special instructions. From strings inside the binary, we know that:
```
SETRSEED: (Opcode:0x16)
	RegA -> SEED
GETRAND: (Opcode:0x17)
	xorshift32(SEED) -> SEED
	SEED -> RegA
```

We tried several `xorshift32` implementations (there are many variants in the internet), then we got the flag using this script.
```python
import numpy as np

state = np.uint32(0x92d68ca2)
def xorshift():
    global state
    state ^= np.uint32(state << 13);
    state ^= np.uint32(state >> 17);
    state ^= np.uint32(state << 15);
    return np.uint32(state);

flag = "6d72c3e2cf95549db6ac0384c3c23593c3d77ce2ddd4ac5e99c9a534de064e00".decode("hex")
r = "3d05dc31d18aaf2996facb1b01ece2f715706cf47ea19e0e01f9c24cbaa0a108".decode("hex")

s = ""
for i, c in enumerate(flag):
    if c == "\x00":
        break
    xorshift()
    s += chr((ord(c) ^ ord(r[i]) ^ state) & 0xff)
print s
```

Flag: `SECCON{MakeSpecialInstructions}`

## Bahasa Indonesia
Kami diberikan sebuah file ELF 32-bit dengan arsitektur yang tidak diketahui.
```sh
$ file runme_f3abe874e1d795ffb6a3eed7898ddcbcd929b7be
runme_f3abe874e1d795ffb6a3eed7898ddcbcd929b7be: ELF 32-bit MSB executable, *unknown arch 0xdf* version 1 (SYSV), statically linked, not stripped
```

Dengan menggunakan `strings`, kita mendapatkan bahwa arsitekturnya adalah `moxie`.
```sh
$ strings runme_f3abe874e1d795ffb6a3eed7898ddcbcd929b7be
,.U7
0123456789abcdef
This program uses special instructions.
SETRSEED: (Opcode:0x16)
	RegA -> SEED
GETRAND: (Opcode:0x17)
	xorshift32(SEED) -> SEED
	SEED -> RegA
GCC: (GNU) 4.9.4
moxie-elf.c
...
```

Kami tidak dapat melakukan disassemble dengan `objdump` atau `IDA`, sehingga kami memutuskan untuk membuat sendiri [disassembler-nya](disas_moxie.py) dengan membaca [dokumentasi ini](http://moxielogic.org/blog/pages/architecture.html).
```
$ python disas_moxie.py
function main
0x136c:    06 18    push $sp, $r6
0x136e:    91 18    dec $sp, 0x24
0x1370:    01 20    ldi.l $r0, 0x92d68ca2
0x1376:    03 00    jsra set_random_seed
0x137c:    01 80    ldi.l $r6, puts
0x1382:    01 20    ldi.l $r0, 0x1
0x1388:    01 30    ldi.l $r1, "This program uses special instructions.\n\n"
0x138e:    19 80    jsr $r6
0x1390:    01 20    ldi.l $r0, 0x1
0x1396:    01 30    ldi.l $r1, "SETRSEED: (Opcode:0x16)\n"
0x139c:    19 80    jsr $r6
0x139e:    01 20    ldi.l $r0, 0x1
0x13a4:    01 30    ldi.l $r1, "    RegA -> SEED\n\n"
0x13aa:    19 80    jsr $r6
0x13ac:    01 20    ldi.l $r0, 0x1
0x13b2:    01 30    ldi.l $r1, "GETRAND: (Opcode:0x17)\n"
0x13b8:    19 80    jsr $r6
0x13ba:    01 20    ldi.l $r0, 0x1
0x13c0:    01 30    ldi.l $r1, "    xorshift32(SEED) -> SEED\n"
0x13c6:    19 80    jsr $r6
0x13c8:    01 20    ldi.l $r0, 0x1
0x13ce:    01 30    ldi.l $r1, "    SEED -> RegA\n\n"
0x13d4:    19 80    jsr $r6
0x13d6:    01 20    ldi.l $r0, flag
0x13dc:    01 30    ldi.l $r1, randval
0x13e2:    03 00    jsra decode
0x13e8:    02 32    mov $r1, $r0
0x13ea:    01 20    ldi.l $r0, 0x1
0x13f0:    19 80    jsr $r6
0x13f2:    01 20    ldi.l $r0, 0x1
0x13f8:    01 30    ldi.l $r1, "\n"
0x13fe:    19 80    jsr $r6
0x1400:    2e 22    xor $r0, $r0
0x1402:    03 00    jsra exit

function decode
0x136c:    06 18    push $sp, $r6
0x136e:    06 19    push $sp, $r7
0x1370:    06 1a    push $sp, $r8
0x1372:    06 1b    push $sp, $r9
0x1374:    06 1c    push $sp, $r10
0x1376:    06 1d    push $sp, $r11
0x1378:    91 18    dec $sp, 0x24
0x137a:    02 d2    mov $r11, $r0
0x137c:    1c 42    ld.b $r2, ($r0)
0x137e:    2e 22    xor $r0, $r0
0x1380:    0e 42    cmp $r2, $r0
0x1382:    c0 12    beq 0x???
0x1384:    02 a3    mov $r8, $r1
0x1386:    02 9d    mov $r7, $r11
0x1388:    01 c0    ldi.l $r10, get_random_value
0x138e:    1c 8a    ld.b $r6, ($r8)
0x1390:    2e 22    xor $r0, $r0
0x1392:    19 c0    jsr $r10
0x1394:    2e 82    xor $r6, $r0
0x1396:    1c 29    ld.b $r0, ($r7)
0x1398:    2e 82    xor $r6, $r0
0x139a:    1e 98    st.b ($r7), $r6
0x139c:    89 01    inc $r7, 0x1
0x139e:    8a 01    inc $r8, 0x1
0x13a0:    1c 39    ld.b $r1, ($r7)
0x13a2:    2e 22    xor $r0, $r0
0x13a4:    0e 32    cmp $r1, $r0
0x13a6:    c7 f3    bne 0x???
0x13a8:    02 2d    mov $r0, $r11
0x13aa:    02 e0    mov $r12, $fp
0x13ac:    9e 18    dec $r12, 0x24
0x13ae:    07 ed    pop $r12, $r11
0x13b0:    07 ec    pop $r12, $r10
0x13b2:    07 eb    pop $r12, $r9
0x13b4:    07 ea    pop $r12, $r8
0x13b6:    07 e9    pop $r12, $r7
0x13b8:    07 e8    pop $r12, $r6
0x13ba:    04 00    ret

function set_random_seed
0x136c:    16 20    ???
0x136e:    04 00    ret

function get_random_value
0x136c:    17 20    ???
0x136e:    04 00    ret

flag: 6d72c3e2cf95549db6ac0384c3c23593c3d77ce2ddd4ac5e99c9a534de064e00
randval: 3d05dc31d18aaf2996facb1b01ece2f715706cf47ea19e0e01f9c24cbaa0a108
```

Pseudocode-nya kira-kira seperti ini.
```python
flag = "6d72c3e2cf95549db6ac0384c3c23593c3d77ce2ddd4ac5e99c9a534de064e00"
randval = "3d05dc31d18aaf2996facb1b01ece2f715706cf47ea19e0e01f9c24cbaa0a108"
def main():
  set_random_seed(0x92d68ca2)
  puts("...")
  puts(decode(flag, randval))

def decode(flag, randval):
  i = 0
  while flag[i]:
    flag[i] ^= randval[i] ^ get_random_value()
    i += 1
  return flag
```

Fungsi `set_random_seed` dan `get_random_value` dikompilasi dengan instruksi spesial. Dari string di dalam binary, kita mendapat hint bahwa:
```
SETRSEED: (Opcode:0x16)
	RegA -> SEED
GETRAND: (Opcode:0x17)
	xorshift32(SEED) -> SEED
	SEED -> RegA
```

Kami mencoba beberapa implementasi `xorshift32` (di internet ada beberapa varian fungsi tersebut), kemudian kami mendapat flag dengan script ini.
```python## English
TODO


## Bahasa Indonesia
TODO

import numpy as np

state = np.uint32(0x92d68ca2)
def xorshift():
    global state
    state ^= np.uint32(state << 13);
    state ^= np.uint32(state >> 17);
    state ^= np.uint32(state << 15);
    return np.uint32(state);

flag = "6d72c3e2cf95549db6ac0384c3c23593c3d77ce2ddd4ac5e99c9a534de064e00".decode("hex")
r = "3d05dc31d18aaf2996facb1b01ece2f715706cf47ea19e0e01f9c24cbaa0a108".decode("hex")

s = ""
for i, c in enumerate(flag):
    if c == "\x00":
        break
    xorshift()
    s += chr((ord(c) ^ ord(r[i]) ^ state) & 0xff)
print s
```

Flag: `SECCON{MakeSpecialInstructions}`