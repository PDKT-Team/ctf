# Cheat Console
---
**Points:** 329 | **Solves:** 25/1035 | **Category:** Reverse

Grandpa Bill told you that in his youth he loved playing arcade machines. He was a notorious cheater and rarely played fair. He told you that one day in his favorite arcade (Pacman) he played around with the known cheat codes, trying to discover something new. Contrary to his expectation one code that he tried did not make him invincible against all enemies but showed a prompt asking for a password. Sadly he never was able to figure out the password and discovered what is hidden behind the prompt. Eventually the arcade center shut down and he couldn't try anymore. Unwilling to give up he contacted the developers which gave him a small program and said that it's the part which he was shown back then and that if he discovers the password he'll know what was hidden behind that prompt. Be a good grandson/granddaughter and help him with your awesome reversing skills.

On a side note: You might wanna lie to him once you solved the challenge (and found the hidden message in the password). ;)

The flag is the password used for the program. This challenge does not use the standard flag format.

[Download](CheatConsole_4648d68145298cca67d3a6b97d6dbe50.zip)
---

[Bahasa Indonesia](#bahasa-indonesia)

## English

### TL;DR
- Patch the binary so we can decompile.
- Ensure `SIGTRAP` signal is sent and always cause `SIGFPE` to be sent if possible.
- Dynamic analysis with GDB to get the flag.
- Use Z3 (and guessing) to get the final part of the flag.

### Detailed Steps
We were given an ELF 32-bit binary. In this binary, there's a lot of functions that can't be decompiled by IDA because of `int3` instructions (opcode = `0xCC`).

```asm
.text:080486BB main:
...
.text:08048741           jnz     short loc_804872A
.text:08048743           mov     [ebp-68h], ecx
.text:08048743 ; ----------------------------------------------
.text:08048746           db 2 dup(0CCh)
.text:08048748 ; ----------------------------------------------
.text:08048748           cmp     dword ptr [ebp-68h], 32h
.text:0804874C           jnz     loc_8048890
```

We patched the binary and replaced the instructions to `nop` (opcode = `0x90`) with hex editor. After that, functions can be decompiled. Let's take a look at `main` function.

```c
int __cdecl main(int a1, char **a2) {
  int v2; // ecx
  unsigned int v3; // ebx
  int v4; // ST00_4
  int result; // eax
  char **v6; // [esp+0h] [ebp-7Ch]
  char v7; // [esp+18h] [ebp-64h]
  unsigned int v8; // [esp+60h] [ebp-1Ch]
  int *v9; // [esp+6Ch] [ebp-10h]

  v9 = &a1;
  v6 = a2;
  v8 = __readgsdword(0x14u);
  if ( a1 == 2 ) {
    ... // performs checking
  }
  else {
    puts("You might want to submit the password to gain access.");
    result = 1;
  }
  return result;
}
```

It takes an argument as a password then does some checking. Now take a look at function `sub_80488B2`.

```C
signed int __cdecl sub_80488B2(const char *a1)
{
  size_t v1; // eax
  signed int i; // [esp+18h] [ebp-A0h]
  char v4; // [esp+1Ch] [ebp-9Ch]
  char v5[32]; // [esp+8Ch] [ebp-2Ch]
  unsigned int v6; // [esp+ACh] [ebp-Ch]

  v6 = __readgsdword(0x14u);
  SHA256_Init(&v4);
  v1 = strlen(a1);
  SHA256_Update(&v4, a1, v1);
  SHA256_Final(v5, &v4);
  for ( i = 0; i <= 31; ++i )
  {
    if ( (v5[i] ^ 0x42) != *(i + 0x804B060) )
    {
      __asm { int     80h; LINUX - }
      return 0;
    }
  }
  return 1;
}
```

It calculates SHA-256 of our password, xored with `0x42`, and compared to `0x804B060` which will be translated into a string `Well done, but you were mislead.`. We took a note that there might be many misleading functions and fake flags in this binary.

We noticed that there's an `int 0x80` instruction (or `syscall`) in the function. Let's take a look at the disassembly.

```asm
.text:08048965                 movzx   eax, al
.text:08048968                 cmp     edx, eax
.text:0804896A                 jz      short loc_8048997
.text:0804896C                 movzx   edx, [ebp+var_A2]
.text:08048973                 mov     esi, offset sub_80489C6
.text:08048978                 xor     eax, eax
.text:0804897A                 mov     al, dl
.text:0804897C                 inc     eax
.text:0804897D                 push    8
.text:0804897F                 pop     ebx
.text:08048980                 push    0
.text:08048982                 push    0
.text:08048984                 push    0
.text:08048986                 push    esi
.text:08048987                 mov     ecx, esp
.text:08048989                 xor     edx, edx
.text:0804898B                 int     80h             ; LINUX -
.text:0804898D                 sub     esp, 10h
.text:08048990                 mov     eax, 0
.text:08048995                 jmp     short loc_80489AE
```

We learned that IDA can't decompile the function (and many other functions) completely. We decided to do dynamic analysis and set breakpoint at `0x0804898B` to know what `syscall` is made.

```
$ gdb public/challenge
...
gdb-peda$ b *0x0804898B
Breakpoint 1 at 0x804898b
gdb-peda$ r asd
[----------------------------------registers-----------------------------------]
EAX: 0x43 ('C')
EBX: 0x8
ECX: 0xffffcda0 --> 0x80489c6 (push   ebp)
EDX: 0x0
ESI: 0x80489c6 (push   ebp)
EDI: 0x0
EBP: 0xffffce68 --> 0xffffcf08 --> 0x0
ESP: 0xffffcda0 --> 0x80489c6 (push   ebp)
EIP: 0x804898b (int    0x80)
EFLAGS: 0x200246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
...
Breakpoint 1, 0x0804898b in ?? ()
gdb-peda$
```

The system call number (`EAX`) is `0x43` or `sys_sigaction`. In short, it registers a signal handler with signal number (`EBX`) `0x8` or `SIGFPE`, and to be handled by a function (`ECX`) in `0x80489c6`. `SIGFPE` is a floating point exception that will be occured in arithmetic operation error, such as division by zero.

Now let's take a look at function `0x80489c6`, we'll call this `handle_SIGFPE` from now on.

```c
int __cdecl handle_SIGFPE(int a1, int a2, int a3, int a4, int a5, int a6, int a7, int a8, int a9, int a10, int a11, unsigned __int8 *a12, int a13, int a14, int a15, int a16) {
  int v16; // eax
  int result; // eax

  if ( dword_804B084 == 'REGT' ) {
    v16 = sys_mprotect((main & 0xFFFFF000), 0x2000u, 7);
    result = a16 - 1;
    *result = 0x5B056A51;
    *(result + 4) = 0x8B58306A;
    *(result + 8) = 0x80CD944D;
    *(result + 12) = 89;
  }
  else {
    result = dword_804B084;
    if ( dword_804B084 != 'NOPP' ) {
      if ( dword_804B084 == 'FG03' ) {
        result = *a12;
      }
      else {
        result = dword_804B084;
        if ( dword_804B084 == 'FG41' )
          dword_804B084 = 'NOPP';
      }
    }
  }
  return result;
}
```

There's interesting code, if `dword_804B084 == 'REGT'` it will call `mprotect` and will modify address pointed by `a16 - 1`. We guessed it's modifying its code, so we used `pwntools` to disassembly the code.

```
>>> from pwn import *
>>> print disasm(p32(0x5B056A51)+p32(0x8B58306A)+p32(0x80CD944D)+chr(89))
   0:   51                      push   ecx
   1:   6a 05                   push   0x5
   3:   5b                      pop    ebx
   4:   6a 30                   push   0x30
   6:   58                      pop    eax
   7:   8b 4d 94                mov    ecx,DWORD PTR [ebp-0x6c]
   a:   cd 80                   int    0x80
   c:   59                      pop    ecx
```

Oh, another `int 0x80`! So to reach this code, we have to set `dword_804B084` to `'REGT'` and cause an arithmetic error so `SIGFPE` signal will be sent.

Now back to main function.

```c
int __cdecl main(int a1, char **a2) {
    ...
    dword_804B084 = 'REGT';
    if ( sub_80488B2(*a2) ) {
        if ( strlen(v6[1]) != 42 )
            exit(1);
    }
    else {
        v2 = 0;
        do
            v3 = v6[1][v2++];
        while ( 0x42424242 % v3 );
        if ( v2 == 50 ) {
            if ( sub_8048B14(v6[1] + 3) ) {
            if ( sub_8048D7D(v6, v6[1] + 16) ) {
        ...
    }
}
```

We will never satisfy function `sub_80488B2`, therefore we concluded that password length checking, `strlen(v6[1]) != 42`, is fake.

More checking will be done if `v2 == 50`. To satisfy this, simply set the 50th character of our password to `B` or `!` (they're divisible by `0x42424242`). But remember, we already had `SIGFPE` handler! So if the 50th character is null byte and there's no `!` and `B`, division by zero error will occur and cause `handle_SIGFPE` to be called. Also, `dword_804B084` is already set to `'REGT'` (to reach the modifying code). We concluded that our password length must be `49`.

We set breakpoint at `0x080489FC` where modifying code is executed inside `handle_SIGFPE` and run with 49 chars as password.

```
$ gdb public/challenge
gdb-peda$ b *0x080489FC
Breakpoint 1 at 0x80489fc
gdb-peda$ r 1234567890123456789012345678901234567890123456789
Stopped reason: SIGFPE
0x08048737 in ?? ()
gdb-peda$ c
Breakpoint 1, 0x080489fc in ?? ()
gdb-peda$ i r
eax            0x8048736	0x8048736
...
```

So it's modifying code at `0x8048736`, let's continue stepping in.

```
gdb-peda$ ni
0x08048a02 in ?? ()
...
gdb-peda$ ni
0x08048736 in ?? ()
gdb-peda$ x/15i $eip
=> 0x8048736:	push   ecx
   0x8048737:	push   0x5
   0x8048739:	pop    ebx
   0x804873a:	push   0x30
   0x804873c:	pop    eax
   0x804873d:	mov    ecx,DWORD PTR [ebp-0x6c]
   0x8048740:	int    0x80
   0x8048742:	pop    ecx
   0x8048743:	mov    DWORD PTR [ebp-0x68],ecx
   0x8048746:	int3
   0x8048747:	int3
   0x8048748:	cmp    DWORD PTR [ebp-0x68],0x32
   0x804874c:	jne    0x8048890
gdb-peda$ ni
...
0x08048740 in ?? ()
gdb-peda$ i r
eax            0x30	0x30
ecx            0x8048a7f	0x8048a7f
edx            0x0	0x0
ebx            0x5	0x5
```

In short, it registers signal `SIGTRAP` to be handled by function at `0x8048a7f`. We will call this function `handle_SIGTRAP`.

Now, if you observe disassembly of `handle_SIGFPE` and `handle_SIGTRAP`, there's a lot of code that is not decompiled into pseudocode. For example,

```
.text:08048A27      cmp     eax, 'FG03'
.text:08048A2C      jnz     short loc_8048A51
.text:08048A2E      mov     dword ptr [esp+38h], 0
.text:08048A36      mov     dword ptr [esp+34h], 64h
.text:08048A3E      mov     ecx, [esp+3Ch]
.text:08048A42      xor     eax, eax
.text:08048A44      mov     al, [ecx]
.text:08048A46      mov     [esp+40h], al
.text:08048A4A      add     dword ptr [esp+3Ch], 4
.text:08048A4F      jmp     short loc_8048A7B
```

only decompiled into

```c
...
      if ( dword_804B084 == 'FG03' ) {
        result = *a12;
      }
      else {
...
```
So, we decided to do full dynamic analysis from here. Unfortunately, `handle_SIGTRAP` and `handle_SIGFPE` modify memory and can't be ignored. Therefore, we send `SIGTRAP` signal manually if we encounter `int3` (we can do that by sending `signal SIGTRAP` command in GDB). For `SIGFPE`, we tried to cause division by zero error if possible. For example, in function `sub_8048B14`,
```c
signed int __cdecl sub_8048B14(unsigned __int8 *a1) {
  dword_804B084 = 'FG03';
  if ( (*a1 % (100 - *a1)) >= 1 )
    exit(4);
...
```
we made sure that `*a1` is `100` so it will cause `SIGFPE`. After a while doing dynamic analysis, we get the flag (without last checking part) `xxxdxx_Ob50l3te_and_UnS0lv4bl3_l3v3l_f0r_CH3AT3R5`.

Phew okay, now for the last checking part, function `sub_80490A0`.
```c
_BOOL4 __cdecl sub_80490A0(_BYTE *a1) {
  _BYTE *v2; // [esp+Ch] [ebp-4h]

  v2 = a1 + 4;
  return a1[4] & 4
      && *v2 & 0x40
      && *v2 & 1
      && ~a1[5] == 145
      && !((a1[1] & 0x20) + (*a1 & 0x20) + (a1[2] & 0x20))
      && *a1 & 8
      && a1[2] & 4
      && a1[1] != *a1;
}
```

Since it's a constraint checking function, we can solve this with Z3.

```python
from z3 import *

s = Solver()
xs = [BitVec('x%d' % i, 8) for i in xrange(6)]
for x in xs:
    s.add(Or(
        And(x >= ord('A'), x <= ord('Z')),
        And(x >= ord('a'), x <= ord('z')),
        And(x >= ord('0'), x <= ord('9')),
    ))

s.add(xs[4] & 4 != 0)
s.add(xs[4] & 0x40 != 0)
s.add(xs[4] & 1 != 0)
s.add(xs[5] == ord('n'))
s.add((xs[1] & 0x20) + (xs[0] & 0x20) + (xs[2] & 0x20) == 0)
s.add(xs[0] & 8 != 0)
s.add(xs[2] & 4 != 0)
s.add(xs[1] != xs[0])
s.add(xs[3] == ord('d'))

while s.check() == sat:
    m = s.model()
    print ''.join([chr(int(m[xs[i]].as_long())) for i in xrange(6)])
    s.add(Or([d() != m[d] for d in m]))
```
But there are more than one solutions that satisfy the constraints (CTF organizer had confirmed this). Since the 4th and 6th character is `d` and `n`, we guessed some possible words that make sense. We tried `HIDdEn_Ob50l3te_and_UnS0lv4bl3_l3v3l_f0r_CH3AT3R5` and got the flag!

## Bahasa Indonesia

### Rangkuman
- Patch binary sehingga bisa didekompilasi.
- Pastikan signal `SIGTRAP` terpanggil dan jika memungkinkan buat kondisi sehingga `SIGFPE` terpanggil.
- Lakukan dynamic analysis dengan GDB untuk mendapatkan flag.
- Gunakan Z3 (dan sedikit tebakan) untuk mendapatkan bagian flag terakhir.

### Langkah Detail
Diberikan sebuah binary ELF 32-bit. Banyak fungsi yang tidak bisa didekompilasi oleh IDA pada binary ini. Hal ini disebabkan oleh adanya instruksi `int3` dengan opcode `0xCC`.

```asm
.text:080486BB main:
...
.text:08048741           jnz     short loc_804872A
.text:08048743           mov     [ebp-68h], ecx
.text:08048743 ; ----------------------------------------------
.text:08048746           db 2 dup(0CCh)
.text:08048748 ; ----------------------------------------------
.text:08048748           cmp     dword ptr [ebp-68h], 32h
.text:0804874C           jnz     loc_8048890
```

Kami melakukan patch binary yaitu mengganti instruksinya menjadi `nop` dengan opcode `0x90` dengan hex editor. Setelah itu baru fungsi-fungsinya dapat didekompilasi oleh IDA. Sekarang kita lihat fungsi `main`.

```c
int __cdecl main(int a1, char **a2) {
  int v2; // ecx
  unsigned int v3; // ebx
  int v4; // ST00_4
  int result; // eax
  char **v6; // [esp+0h] [ebp-7Ch]
  char v7; // [esp+18h] [ebp-64h]
  unsigned int v8; // [esp+60h] [ebp-1Ch]
  int *v9; // [esp+6Ch] [ebp-10h]

  v9 = &a1;
  v6 = a2;
  v8 = __readgsdword(0x14u);
  if ( a1 == 2 ) {
    ... // performs checking
  }
  else {
    puts("You might want to submit the password to gain access.");
    result = 1;
  }
  return result;
}
```

Binary ini membutuhkan satu parameter sebagai password untuk dilakukan pengecekan. Sekarang kita lihat fungsi `sub_80488B2`.

```C
signed int __cdecl sub_80488B2(const char *a1) {
  size_t v1; // eax
  signed int i; // [esp+18h] [ebp-A0h]
  char v4; // [esp+1Ch] [ebp-9Ch]
  char v5[32]; // [esp+8Ch] [ebp-2Ch]
  unsigned int v6; // [esp+ACh] [ebp-Ch]

  v6 = __readgsdword(0x14u);
  SHA256_Init(&v4);
  v1 = strlen(a1);
  SHA256_Update(&v4, a1, v1);
  SHA256_Final(v5, &v4);
  for ( i = 0; i <= 31; ++i )
  {
    if ( (v5[i] ^ 0x42) != *(i + 0x804B060) )
    {
      __asm { int     80h; LINUX - }
      return 0;
    }
  }
  return 1;
}
```

Fungsi ini menghitung hash SHA-256 dari password, melakukan operasi xor dengan `0x42`, dan dicocokkan dengan `0x804B060` yang jika dihitung akan menghasilkan string `Well done, but you were mislead.`. Dari sini kami menduga bahwa banyak fungsi menjebak dan flag palsu pada binary.

Kami juga melihat ada instruksi `int 0x80` (semacam `syscall`) pada fungsi tersebut. Kita lihat disassembly-nya.

```asm
.text:08048965                 movzx   eax, al
.text:08048968                 cmp     edx, eax
.text:0804896A                 jz      short loc_8048997
.text:0804896C                 movzx   edx, [ebp+var_A2]
.text:08048973                 mov     esi, offset sub_80489C6
.text:08048978                 xor     eax, eax
.text:0804897A                 mov     al, dl
.text:0804897C                 inc     eax
.text:0804897D                 push    8
.text:0804897F                 pop     ebx
.text:08048980                 push    0
.text:08048982                 push    0
.text:08048984                 push    0
.text:08048986                 push    esi
.text:08048987                 mov     ecx, esp
.text:08048989                 xor     edx, edx
.text:0804898B                 int     80h             ; LINUX -
.text:0804898D                 sub     esp, 10h
.text:08048990                 mov     eax, 0
.text:08048995                 jmp     short loc_80489AE
```

Kami menyadari bahwa IDA tidak dapat melakukan dekompilasi fungsi ini (dan banyak fungsi lainnya) secara lengkap. Dari sini kami memutuskan untuk melakukan dynamic analysis dan memasang breakpoint pada `0x0804898B` untuk mengetahui `syscall` apa yang dipanggil.

```
$ gdb public/challenge
...
gdb-peda$ b *0x0804898B
Breakpoint 1 at 0x804898b
gdb-peda$ r asd
[----------------------------------registers-----------------------------------]
EAX: 0x43 ('C')
EBX: 0x8
ECX: 0xffffcda0 --> 0x80489c6 (push   ebp)
EDX: 0x0
ESI: 0x80489c6 (push   ebp)
EDI: 0x0
EBP: 0xffffce68 --> 0xffffcf08 --> 0x0
ESP: 0xffffcda0 --> 0x80489c6 (push   ebp)
EIP: 0x804898b (int    0x80)
EFLAGS: 0x200246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
...
Breakpoint 1, 0x0804898b in ?? ()
gdb-peda$
```
Nomor system call (`EAX`) adalah `0x43` yang merupakan `sys_sigaction`. Singkatnya, instruksi tersebut mendaftarkan signal handler dengan nomor signal (`EBX`) `0x8` yang merupakan `SIGFPE`, yang akan di-handle oleh fungsi (`ECX`) pada alamat `0x80489c6`. `SIGFPE` adalah *floating point exception* yang terjadi jika terdapat error pada operasi aritmatika, seperti pembagian dengan 0.

Kita lihat fungsi `0x80489c6`, yang akan kita sebut sebagai fungsi `handle_SIGFPE`.

```c
int __cdecl handle_SIGFPE(int a1, int a2, int a3, int a4, int a5, int a6, int a7, int a8, int a9, int a10, int a11, unsigned __int8 *a12, int a13, int a14, int a15, int a16) {
  int v16; // eax
  int result; // eax

  if ( dword_804B084 == 'REGT' ) {
    v16 = sys_mprotect((main & 0xFFFFF000), 0x2000u, 7);
    result = a16 - 1;
    *result = 0x5B056A51;
    *(result + 4) = 0x8B58306A;
    *(result + 8) = 0x80CD944D;
    *(result + 12) = 89;
  }
  else {
    result = dword_804B084;
    if ( dword_804B084 != 'NOPP' ) {
      if ( dword_804B084 == 'FG03' ) {
        result = *a12;
      }
      else {
        result = dword_804B084;
        if ( dword_804B084 == 'FG41' )
          dword_804B084 = 'NOPP';
      }
    }
  }
  return result;
}
```

Terdapat kode yang menarik, jika `dword_804B084 == 'REGT'` fungsi tersebut akan memanggil `mprotect` dan mengubah memory pada alamat yang ditunjuk oleh `a16 - 1`. Kami menduga fungsi tersebut mengubah kodenya sendiri, lalu kami menggunakan `pwntools` untuk melihat disassembly-nya.

```
>>> from pwn import *
>>> print disasm(p32(0x5B056A51)+p32(0x8B58306A)+p32(0x80CD944D)+chr(89))
   0:   51                      push   ecx
   1:   6a 05                   push   0x5
   3:   5b                      pop    ebx
   4:   6a 30                   push   0x30
   6:   58                      pop    eax
   7:   8b 4d 94                mov    ecx,DWORD PTR [ebp-0x6c]
   a:   cd 80                   int    0x80
   c:   59                      pop    ecx
```

Terdapat `int 0x80` lagi! Untuk mencapai kode ini, kita harus membuat `dword_804B084` bernilai `'REGT'` dan membuat error aritmatika sehingga signal `SIGFPE` akan terpanggil.

Sekarang kita kembali ke fungsi `main`.

```c
int __cdecl main(int a1, char **a2) {
    ...
    dword_804B084 = 'REGT';
    if ( sub_80488B2(*a2) ) {
        if ( strlen(v6[1]) != 42 )
            exit(1);
    }
    else {
        v2 = 0;
        do
            v3 = v6[1][v2++];
        while ( 0x42424242 % v3 );
        if ( v2 == 50 ) {
            if ( sub_8048B14(v6[1] + 3) ) {
            if ( sub_8048D7D(v6, v6[1] + 16) ) {
        ...
    }
}
```

Fungsi `sub_80488B2` tidak akan pernah bernilai `true`, dari sini kami menyimpulkan pengecekan panjang password, `strlen(v6[1]) != 42`, adalah palsu.

Pengecekan lebih lanjut jika `v2 == 50` terpenuhi. Untuk memenuhi ini, cara gampangnya adalah membuat karakter ke-50 password kita bernilai `B` or `!` (karena nilai tersebut habis membagi `0x42424242`). Akan tetapi ingat, kita telah mempunyai handler untuk `SIGFPE`! Sehingga jika karakter ke-50 password kita adalah null byte dan tidak ada karakter `B` dan `!`, error karena pembagian dengan 0 akan terjadi dan `handle_SIGFPE` terpanggil. Selain itu, `dword_804B084` juga telah bernilai `'REGT'` untuk mencapai kode aneh (yang mengubah kode lain). Kami menyimpulkan bahwa panjang password adalah `49`.

Kami memasang breakpoint pada `0x080489FC` di mana kode tersebut dieksekusi dan menjalankan binary tersebut dengan password sepanjang 49 karakter.

```
$ gdb public/challenge
gdb-peda$ b *0x080489FC
Breakpoint 1 at 0x80489fc
gdb-peda$ r 1234567890123456789012345678901234567890123456789
Stopped reason: SIGFPE
0x08048737 in ?? ()
gdb-peda$ c
Breakpoint 1, 0x080489fc in ?? ()
gdb-peda$ i r
eax            0x8048736	0x8048736
...
```

Kode tersebut mengubah kode pada `0x8048736`. Lalu lanjutkan analisisnya.

```
gdb-peda$ ni
0x08048a02 in ?? ()
...
gdb-peda$ ni
0x08048736 in ?? ()
gdb-peda$ x/15i $eip
=> 0x8048736:	push   ecx
   0x8048737:	push   0x5
   0x8048739:	pop    ebx
   0x804873a:	push   0x30
   0x804873c:	pop    eax
   0x804873d:	mov    ecx,DWORD PTR [ebp-0x6c]
   0x8048740:	int    0x80
   0x8048742:	pop    ecx
   0x8048743:	mov    DWORD PTR [ebp-0x68],ecx
   0x8048746:	int3
   0x8048747:	int3
   0x8048748:	cmp    DWORD PTR [ebp-0x68],0x32
   0x804874c:	jne    0x8048890
gdb-peda$ ni
...
0x08048740 in ?? ()
gdb-peda$ i r
eax            0x30	0x30
ecx            0x8048a7f	0x8048a7f
edx            0x0	0x0
ebx            0x5	0x5
```

Singkatnya, kode tersebut mendaftarkan signal `SIGTRAP` untuk di-handle oleh fungsi pada `0x8048a7f`. Kita akan menyebut fungsi itu sebagai `handle_SIGTRAP`.

Jika kita lihat disassembly dari fungsi `handle_SIGFPE` dan `handle_SIGTRAP`, banyak kode yang tidak berhasil didekompilasi oleh IDA menjadi pseudocode. Sebagai contoh,

```
.text:08048A27      cmp     eax, 'FG03'
.text:08048A2C      jnz     short loc_8048A51
.text:08048A2E      mov     dword ptr [esp+38h], 0
.text:08048A36      mov     dword ptr [esp+34h], 64h
.text:08048A3E      mov     ecx, [esp+3Ch]
.text:08048A42      xor     eax, eax
.text:08048A44      mov     al, [ecx]
.text:08048A46      mov     [esp+40h], al
.text:08048A4A      add     dword ptr [esp+3Ch], 4
.text:08048A4F      jmp     short loc_8048A7B
```

hanya berhasil didekompilasi menjadi

```c
      if ( dword_804B084 == 'FG03' ) {
        result = *a12;
      }
      else {
```

Dari sini kami memutuskan untuk melakukan dynamic analysis secara penuh. Sayangnya, `handle_SIGTRAP` dan `handle_SIGFPE` mengubah memory sehingga tidak dapat diabaikan begitu saja. Untuk itu, kami mengirim balik signal `SIGTRAP` secara manual jika kita mendapati instruksi `int3`. Hal ini dapat dilakukan dengan memberikan command `signal SIGTRAP` pada GDB. Untuk `SIGFPE`, kami mencoba untuk membuat error pembagian dengan 0 jika dimungkinkan. Contohnya, pada fungsi `sub_8048B14`,
```c
signed int __cdecl sub_8048B14(unsigned __int8 *a1) {
  dword_804B084 = 'FG03';
  if ( (*a1 % (100 - *a1)) >= 1 )
    exit(4);
...
```
kami membuat `*a1` bernilai `100` sehingga akan menyebabkan `SIGFPE`. Setelah beberapa saat dynamic analysis, kami mendapatkan potongan flag `xxxdxx_Ob50l3te_and_UnS0lv4bl3_l3v3l_f0r_CH3AT3R5`.

Huft oke, sekarang saatnya bagian pengecekan terakhir, fungsi `sub_80490A0`.
```c
_BOOL4 __cdecl sub_80490A0(_BYTE *a1) {
  _BYTE *v2; // [esp+Ch] [ebp-4h]

  v2 = a1 + 4;
  return a1[4] & 4
      && *v2 & 0x40
      && *v2 & 1
      && ~a1[5] == 145
      && !((a1[1] & 0x20) + (*a1 & 0x20) + (a1[2] & 0x20))
      && *a1 & 8
      && a1[2] & 4
      && a1[1] != *a1;
}
```

Karena fungsi tersebut adalah pengecekan constraint, kita dapat menyelesaikannya dengan Z3.

```python
from z3 import *

s = Solver()
xs = [BitVec('x%d' % i, 8) for i in xrange(6)]
for x in xs:
    s.add(Or(
        And(x >= ord('A'), x <= ord('Z')),
        And(x >= ord('a'), x <= ord('z')),
        And(x >= ord('0'), x <= ord('9')),
    ))

s.add(xs[4] & 4 != 0)
s.add(xs[4] & 0x40 != 0)
s.add(xs[4] & 1 != 0)
s.add(xs[5] == ord('n'))
s.add((xs[1] & 0x20) + (xs[0] & 0x20) + (xs[2] & 0x20) == 0)
s.add(xs[0] & 8 != 0)
s.add(xs[2] & 4 != 0)
s.add(xs[1] != xs[0])
s.add(xs[3] == ord('d'))

while s.check() == sat:
    m = s.model()
    print ''.join([chr(int(m[xs[i]].as_long())) for i in xrange(6)])
    s.add(Or([d() != m[d] for d in m]))
```
Akan tetapi, terdapat lebih dari solusi yang memenuhi constraint tersebut (pihak panitia juga telah mengonfirmasi hal ini). Karena karakter ke-4 dan ke-6 adalah huruf `d` and `n`, kami menebak beberapa kata yang masuk akal. Kami mencoba string `HIDdEn_Ob50l3te_and_UnS0lv4bl3_l3v3l_f0r_CH3AT3R5` dan ternyata mendapatkan poin untuk flag!