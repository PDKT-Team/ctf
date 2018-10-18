# Forgetful Commander
---
**Points:** 36 | **Solves:** 36/1035 | **Category:** Reverse

And you lost a key again. This time it's the key to your missiles command station. However, the command station got a silent password override. Even though your memory isn't that good, you don't remember the password either, your technical skills are!. You've already dumped the binary, which checks the password. Now you just have to reverse it!

[Download](ForgetfulCommander_85dcf6730d6936301904fc2218c77d6c.zip)
---

[Bahasa Indonesia](#bahasa-indonesia)

## English
The binary is `elf32-i386`. We have difficulty doing static analysis because the `.text` segment is not disassembled properly and it seems that the machine instructions are pretty random.

We decided to try to do dynamic analysis. The execution of the binary doesn't show clear behavior because there is no interaction whatsoever. Execution using strace shows that the program exited with code 1.

```
$ strace ./forgetful_commander
...
open("/proc/self/maps", O_RDONLY)       = 3
read(3, "5660d000-5660f000 r--p 00000000 "..., 16384) = 1528
close(3)                                = 0
exit_group(1)                           = ?
+++ exited with 1 ++
```

The binary is compiled as PIE (Independent Position-Executables). We try to use `gdb` and set `breakpoint` to the `.text` address in the hope that the correct instructions will be executed.

```
$ gdb ./forgetful_commander
...
gdb-peda$ b *0x0
Breakpoint 1 at 0x0
gdb-peda$ r
Starting program: /vagrant/forgetful_command
Warning:
Cannot insert breakpoint 1.
Cannot access memory at address 0x0

gdb-peda$ del 1
gdb-peda$ info files
Symbols from "/vagrant/forgetful_command".
Native process:
	Using the running image of child process 28513.
	While running this, GDB does not access memory from...
Local exec file:
	`/vagrant/forgetful_command', file type elf32-i386.
warning: Cannot find section for the entry point of /vagrant/forgetful_command.
	Entry point: 0xd000
	0x56556194 - 0x565561a7 is .interp
	0x565561a8 - 0x565561c8 is .note.ABI-tag
	0x565561c8 - 0x565561fc is .hash
	0x565561fc - 0x5655621c is .gnu.hash
	0x5655621c - 0x5655629c is .dynsym
	0x5655629c - 0x56556339 is .dynstr
	0x5655633a - 0x5655634a is .gnu.version
	0x5655634c - 0x5655637c is .gnu.version_r
	0x5655637c - 0x565563bc is .rel.dyn
	0x565563bc - 0x565563cc is .rel.plt
	0x56557000 - 0x56557020 is .init
	0x56557020 - 0x56557050 is .plt
	0x56557050 - 0x56557321 is .text
	0x56557324 - 0x56557338 is .fini
	0x56558000 - 0x5655842c is .rodata
	0x5655842c - 0x56558450 is .eh_frame_hdr
	0x56558450 - 0x565584f0 is .eh_frame
	0x56559eec - 0x56559ef0 is .init_array
	0x56559ef0 - 0x56559ef4 is .fini_array
	0x56559ef4 - 0x56559fec is .dynamic
	0x56559fec - 0x5655a000 is .got
	0x5655a000 - 0x5655a014 is .got.plt
	0x5655a014 - 0x5655a01c is .data
	0x5655a01c - 0x5655a020 is .bss
gdb-peda$ x/10i 0x56557050
   0x56557050:	cdq
   0x56557051:	addr16 int 0x30
   0x56557054:	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
   0x56557055:	add    bh,ah
   0x56557057:	add    ebp,ebx
   0x56557059:	xchg   ecx,eax
   0x5655705a:	into
   0x5655705b:	ins    DWORD PTR es:[edi],dx
   0x5655705c:	xor    al,0x2c
   0x5655705e:	daa
gdb-peda$ b *0x56557050
Breakpoint 2 at 0x56557050
gdb-peda$ c
Continuing.
...
Breakpoint 2, 0x56557050 in ?? ()
gdb-peda$ s
...
gdb-peda$ s

Program received signal SIGSEGV, Segmentation fault.
[----------------------------------registers-----------------------------------]
EAX: 0xf7ffd918 --> 0x56555000 --> 0x464c457f
EBX: 0xf7ffd000 --> 0x23f3c
ECX: 0xffffd694 --> 0xffffd7c3 ("/vagrant/forgetful_command")
EDX: 0xffffffff
ESI: 0xffffd69c --> 0xffffd7de ("XDG_SESSION_ID=221")
EDI: 0x56562000 --> 0x819c6050
EBP: 0x0
ESP: 0xffffd690 --> 0x1
EIP: 0x56557051 --> 0xb4895eed
EFLAGS: 0x10286 (carry PARITY adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x56557046:	push   0x8
   0x5655704b:	jmp    0x56557020
   0x56557050:	cdq
=> 0x56557051:	in     eax,dx
   0x56557052:	pop    esi
   0x56557053:	mov    DWORD PTR [ebx+eax*4+0x5405f0e4],esi
   0x5655705a:	push   edx
   0x5655705b:	call   0x565570d7
[------------------------------------stack-------------------------------------]
0000| 0xffffd690 --> 0x1
0004| 0xffffd694 --> 0xffffd7c3 ("/vagrant/forgetful_command")
0008| 0xffffd698 --> 0x0
0012| 0xffffd69c --> 0xffffd7de ("XDG_SESSION_ID=221")
0016| 0xffffd6a0 --> 0xffffd7f1 ("SHELL=/bin/bash")
0020| 0xffffd6a4 --> 0xffffd801 ("TERM=xterm-256color")
0024| 0xffffd6a8 --> 0xffffd815 ("SSH_CLIENT=10.0.2.2 56511 22")
0028| 0xffffd6ac --> 0xffffd832 ("SSH_TTY=/dev/pts/0")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x56557051 in ?? ()
```

As we can see, this looks strange because the execution of the random instructions still occurs and produces SIGSEGV. It seems like the program somehow use self-modifying code at one point.

Assuming that `__libc_start_main` will be called, we try to interrupt when call to `__libc_start_main` is occurs by hijacking the function using `LD_PRELOAD`. By raising `SIGINT`, `gdb` will capture the `signal` and we can check the `state` of the program at that time.

Here is the `hijack.c` code.

```C
#define _GNU_SOURCE

#include <dlfcn.h>
#include <signal.h>

int __libc_start_main(int (*main) (int,char **,char **),
                      int argc, char **ubp_av,
                      void (*init) (void),
                      void (*fini)(void),
                      void (*rtld_fini)(void),
                      void (*stack_end)) {

    int (*original__libc_start_main)(int (*main) (int,char **,char **),
                                     int argc, char **ubp_av,
                                     void (*init) (void),
                                     void (*fini)(void),
                                     void (*rtld_fini)(void),
                                     void (*stack_end));

    raise(SIGINT);

    original__libc_start_main = dlsym(RTLD_NEXT, "__libc_start_main");
    return original__libc_start_main(main, argc,ubp_av, init, fini,
                                     rtld_fini, stack_end);
}
```

Compile the code to `hijack.so` (32 bit).

```
gcc --shared -fPIC hijack.c -o hijack.so -ldl -m32
```

Use that library in the `gdb`.

```
$ gdb --args env LD_PRELOAD=/vagrant/hijack.so ./forgetful_command
...
gdb-peda$ r
Starting program: /usr/bin/env LD_PRELOAD=/vagrant/hijack.so ./forgetful_command
process 28754 is executing new program: /vagrant/forgetful_command

Program received signal SIGINT, Interrupt.
...
Stopped reason: SIGINT
0xf7fd8be9 in ?? ()
gdb-peda$ info files
...
0x56557050 - 0x56557321 is .text
...
gdb-peda$ x/10i 0x56557050
   0x56557050:	xor    ebp,ebp
   0x56557052:	pop    esi
   0x56557053:	mov    ecx,esp
   0x56557055:	and    esp,0xfffffff0
   0x56557058:	push   eax
   0x56557059:	push   esp
   0x5655705a:	push   edx
   0x5655705b:	call   0x56557082
   0x56557060:	add    ebx,0x2fa0
   0x56557066:	lea    eax,[ebx-0x2ce0]
```

It appears that the contents of the `.text` has changed and it seems like the instructions are correct. You can analyze the whole assembly. For easiness, you can also take the bytes from correct `.text` and override the `.text` in the binary file so that they can be decompiled by IDA to pseudo-code. Here, we try to figure out what the program is doing by just looking at the assembly.

By looking at the contents of the stack when the original `__libc_start_main` is called, we can know that `main` is located in `.text+320` or `0x56557190` in the case above.

Here are the first few instructions in the `main` function.

```asm
   0x56557190:	push   ebp
   0x56557191:	mov    ebp,esp
   0x56557193:	push   ebx
   0x56557194:	push   edi
   0x56557195:	push   esi
   0x56557196:	sub    esp,0x2c
   0x56557199:	call   0x5655719e
   0x5655719e:	pop    eax
   0x5655719f:	add    eax,0x2e62
   0x565571a5:	mov    ecx,DWORD PTR [ebp+0xc]
   0x565571a8:	mov    edx,DWORD PTR [ebp+0x8]
   0x565571ab:	mov    DWORD PTR [ebp-0x10],0x0
   0x565571b2:	cmp    DWORD PTR [ebp+0x8],0x2
   0x565571b6:	mov    DWORD PTR [ebp-0x28],eax
   0x565571b9:	mov    DWORD PTR [ebp-0x2c],ecx
   0x565571bc:	mov    DWORD PTR [ebp-0x30],edx
   0x565571bf:	je     0x565571d1
   0x565571c5:	mov    DWORD PTR [ebp-0x10],0x1
   0x565571cc:	jmp    0x565572a8
```

In the `cmp DWORD PTR [ebp + 0x8], 0x2` instruction, it will compare the contents of `[ebp+0x8]` where the number of arguments (argc) is located. So, the number of arguments must be two in order for the execution to go to `0x565571d1`. If not, the execution will continue to `0x565572a8` where the execution will go directly to `ret`.

The instructions after `0x565571d1` seem to be related to retrieving values in the argument, calling to `strlen`, and also checking the the argument. The following section looks interesting.


```asm
   0x5655723f:	movsx  eax,BYTE PTR [ebp-0x21]
   0x56557243:	mov    ecx,DWORD PTR [ebp-0x20]
   0x56557246:	mov    esi,DWORD PTR [ebp-0x28]
   0x56557249:	movsx  ecx,BYTE PTR [esi+ecx*1-0x1c0f]
   0x56557251:	mov    edi,DWORD PTR [ebp-0x18]
   0x56557254:	mov    ebx,DWORD PTR [ebp-0x20]
   0x56557257:	imul   ebx,DWORD PTR [ebp-0x1c]
   0x5655725b:	add    edi,ebx
   0x5655725d:	movsx  edi,BYTE PTR [esi+edi*1-0x1ff8]
   0x56557265:	xor    ecx,edi
   0x56557267:	cmp    eax,ecx
   0x56557269:	jne    0x56557278
```

When the program reaches `0x5655723f`, the value of `[ebp-0x21]` is the first letter of the argument and stored to `eax`. Then at the `0x56557267`, the value of `eax` is compared to `ecx` which is the value from a xor operation.

By setting the `breakpoint` in `0x56557267` (`cmp eax, ecx`), we can know the value of `ecx` when compared to the argument's characters. For reasons that we have not explored further, this `breakpoint` must be set while still in `__libc_start_main`. If it is set in the middle of execution on `.text`, there will be `SIGTRAP` continuously.

From observations on the value of 'ecx' in `0x56557267` one by one, we get the flag **flag {Just_type__Please__and_the_missles_will_be_launched.}**.

Execution with this flag as the argument will make the program exit with code 0.

```
$ strace ./forgetful_command flag{Just_type__Please__and_the_missles_will_be_launched.}
...
open("/proc/self/maps", O_RDONLY)       = 3
read(3, "56596000-56598000 r--p 00000000 "..., 16384) = 1594
close(3)                                = 0
exit_group(0)                           = ?
+++ exited with 0 +++
```


## Bahasa Indonesia
Binary yang diberikan adalah `elf32-i386`. Kami kesulitan untuk melakukan *static analysis* karena segmen `.text` tidak ter-*disassemble* dengan baik dan sepertinya bukan instruksi mesin yang akan dijalankan.

Kami memutuskan untuk mencoba melakukan *dynamic analysis*. Eksekusi pada binary tidak memperlihatkan perilaku yang jelas karena tidak ada interaksi apapun. Eksekusi menggunakan `strace` memperlihatkan bahwa program exit dengan kode 1.

```
$ strace ./forgetful_commander
...
open("/proc/self/maps", O_RDONLY)       = 3
read(3, "5660d000-5660f000 r--p 00000000 "..., 16384) = 1528
close(3)                                = 0
exit_group(1)                           = ?
+++ exited with 1 ++
```

Binary dikompilasi sebagai PIE (Position-Independent Executables). Kami mencoba untuk menggunakan `gdb` dan mengatur `breakpoint` pada alamat `.text`. Instruksi pada `.text` terlihat random tetapi mari coba untuk mengeksekusinya.	

```
$ gdb ./forgetful_commander
...
gdb-peda$ b *0x0
Breakpoint 1 at 0x0
gdb-peda$ r
Starting program: /vagrant/forgetful_command
Warning:
Cannot insert breakpoint 1.
Cannot access memory at address 0x0

gdb-peda$ del 1
gdb-peda$ info files
Symbols from "/vagrant/forgetful_command".
Native process:
	Using the running image of child process 28513.
	While running this, GDB does not access memory from...
Local exec file:
	`/vagrant/forgetful_command', file type elf32-i386.
warning: Cannot find section for the entry point of /vagrant/forgetful_command.
	Entry point: 0xd000
	0x56556194 - 0x565561a7 is .interp
	0x565561a8 - 0x565561c8 is .note.ABI-tag
	0x565561c8 - 0x565561fc is .hash
	0x565561fc - 0x5655621c is .gnu.hash
	0x5655621c - 0x5655629c is .dynsym
	0x5655629c - 0x56556339 is .dynstr
	0x5655633a - 0x5655634a is .gnu.version
	0x5655634c - 0x5655637c is .gnu.version_r
	0x5655637c - 0x565563bc is .rel.dyn
	0x565563bc - 0x565563cc is .rel.plt
	0x56557000 - 0x56557020 is .init
	0x56557020 - 0x56557050 is .plt
	0x56557050 - 0x56557321 is .text
	0x56557324 - 0x56557338 is .fini
	0x56558000 - 0x5655842c is .rodata
	0x5655842c - 0x56558450 is .eh_frame_hdr
	0x56558450 - 0x565584f0 is .eh_frame
	0x56559eec - 0x56559ef0 is .init_array
	0x56559ef0 - 0x56559ef4 is .fini_array
	0x56559ef4 - 0x56559fec is .dynamic
	0x56559fec - 0x5655a000 is .got
	0x5655a000 - 0x5655a014 is .got.plt
	0x5655a014 - 0x5655a01c is .data
	0x5655a01c - 0x5655a020 is .bss
gdb-peda$ x/10i 0x56557050
   0x56557050:	cdq
   0x56557051:	addr16 int 0x30
   0x56557054:	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
   0x56557055:	add    bh,ah
   0x56557057:	add    ebp,ebx
   0x56557059:	xchg   ecx,eax
   0x5655705a:	into
   0x5655705b:	ins    DWORD PTR es:[edi],dx
   0x5655705c:	xor    al,0x2c
   0x5655705e:	daa
gdb-peda$ b *0x56557050
Breakpoint 2 at 0x56557050
gdb-peda$ c
Continuing.
...
Breakpoint 2, 0x56557050 in ?? ()
gdb-peda$ s
...
gdb-peda$ s

Program received signal SIGSEGV, Segmentation fault.
[----------------------------------registers-----------------------------------]
EAX: 0xf7ffd918 --> 0x56555000 --> 0x464c457f
EBX: 0xf7ffd000 --> 0x23f3c
ECX: 0xffffd694 --> 0xffffd7c3 ("/vagrant/forgetful_command")
EDX: 0xffffffff
ESI: 0xffffd69c --> 0xffffd7de ("XDG_SESSION_ID=221")
EDI: 0x56562000 --> 0x819c6050
EBP: 0x0
ESP: 0xffffd690 --> 0x1
EIP: 0x56557051 --> 0xb4895eed
EFLAGS: 0x10286 (carry PARITY adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x56557046:	push   0x8
   0x5655704b:	jmp    0x56557020
   0x56557050:	cdq
=> 0x56557051:	in     eax,dx
   0x56557052:	pop    esi
   0x56557053:	mov    DWORD PTR [ebx+eax*4+0x5405f0e4],esi
   0x5655705a:	push   edx
   0x5655705b:	call   0x565570d7
[------------------------------------stack-------------------------------------]
0000| 0xffffd690 --> 0x1
0004| 0xffffd694 --> 0xffffd7c3 ("/vagrant/forgetful_command")
0008| 0xffffd698 --> 0x0
0012| 0xffffd69c --> 0xffffd7de ("XDG_SESSION_ID=221")
0016| 0xffffd6a0 --> 0xffffd7f1 ("SHELL=/bin/bash")
0020| 0xffffd6a4 --> 0xffffd801 ("TERM=xterm-256color")
0024| 0xffffd6a8 --> 0xffffd815 ("SSH_CLIENT=10.0.2.2 56511 22")
0028| 0xffffd6ac --> 0xffffd832 ("SSH_TTY=/dev/pts/0")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x56557051 in ?? ()
```

Seperti yang dapat kita lihat, ini terlihat aneh karena eksekusi pada instruksi random tersebut tetap terjadi dan menghasilkan SIGSEGV. Sepertinya program melakukan *self-modifying* pada satu titik dengan suatu cara.

Dengan asumsi bahwa `__libc_start_main` suatu saat terpanggil, kami mencoba untuk melakukan *interrupt* pada saat `__libc_start_main` dipanggil dengan melakukan *hijack* pada fungsi tersebut menggunakan `LD_PRELOAD`. Dengan memberikan `SIGINT`, maka `gdb` akan menangkap `signal` tersebut dan kita dapat memeriksa `state` program pada saat itu.

Berikut adalah kode `hijack.c`.

```C
#define _GNU_SOURCE

#include <dlfcn.h>
#include <signal.h>

int __libc_start_main(int (*main) (int,char **,char **),
                      int argc, char **ubp_av,
                      void (*init) (void),
                      void (*fini)(void),
                      void (*rtld_fini)(void),
                      void (*stack_end)) {

    int (*original__libc_start_main)(int (*main) (int,char **,char **),
                                     int argc, char **ubp_av,
                                     void (*init) (void),
                                     void (*fini)(void),
                                     void (*rtld_fini)(void),
                                     void (*stack_end));

    raise(SIGINT);

    original__libc_start_main = dlsym(RTLD_NEXT, "__libc_start_main");
    return original__libc_start_main(main, argc,ubp_av, init, fini,
                                     rtld_fini, stack_end);
}
```

Kompilasi kode menjadi `hijack.so` (32 bit).

```
gcc --shared -fPIC hijack.c -o hijack.so -ldl -m32
```

Gunakan `library` tersebut pada `gdb` dan jalankan.

```
$ gdb --args env LD_PRELOAD=/vagrant/hijack.so ./forgetful_command
...
gdb-peda$ r
Starting program: /usr/bin/env LD_PRELOAD=/vagrant/hijack.so ./forgetful_command
process 28754 is executing new program: /vagrant/forgetful_command

Program received signal SIGINT, Interrupt.
...
Stopped reason: SIGINT
0xf7fd8be9 in ?? ()
gdb-peda$ info files
...
0x56557050 - 0x56557321 is .text
...
gdb-peda$ x/10i 0x56557050
   0x56557050:	xor    ebp,ebp
   0x56557052:	pop    esi
   0x56557053:	mov    ecx,esp
   0x56557055:	and    esp,0xfffffff0
   0x56557058:	push   eax
   0x56557059:	push   esp
   0x5655705a:	push   edx
   0x5655705b:	call   0x56557082
   0x56557060:	add    ebx,0x2fa0
   0x56557066:	lea    eax,[ebx-0x2ce0]
```

Terlihat bahwa isi `.text` sudah berubah dan sepertinya instruksi yang benar. Anda dapat menganalis assembly-nya secara keseluruhan. Untuk mempermudah, Anda juga dapat mengambil nilai bytes dari `.text` yang sudah berubah dan menimpanya pada `.text` pada berkas binary sehingga dapat didekompilasi oleh IDA menjadi pseudo-code. Di sini, kami mencoba untuk mengira-ngira apa yang dilakukan oleh program dengan melihat assembly-nya saja.

Dengan melihat isi `stack` (parameter) pada saat `__libc_start_main` yang asli akan dipanggil, kita dapat mengetahui bahwa `main` terdapat pada alamat `.text+320` atau `0x56557190` pada kasus di atas. 

Berikut beberapa instruksi pertama pada fungsi `main`.

```asm
   0x56557190:	push   ebp
   0x56557191:	mov    ebp,esp
   0x56557193:	push   ebx
   0x56557194:	push   edi
   0x56557195:	push   esi
   0x56557196:	sub    esp,0x2c
   0x56557199:	call   0x5655719e
   0x5655719e:	pop    eax
   0x5655719f:	add    eax,0x2e62
   0x565571a5:	mov    ecx,DWORD PTR [ebp+0xc]
   0x565571a8:	mov    edx,DWORD PTR [ebp+0x8]
   0x565571ab:	mov    DWORD PTR [ebp-0x10],0x0
   0x565571b2:	cmp    DWORD PTR [ebp+0x8],0x2
   0x565571b6:	mov    DWORD PTR [ebp-0x28],eax
   0x565571b9:	mov    DWORD PTR [ebp-0x2c],ecx
   0x565571bc:	mov    DWORD PTR [ebp-0x30],edx
   0x565571bf:	je     0x565571d1
   0x565571c5:	mov    DWORD PTR [ebp-0x10],0x1
   0x565571cc:	jmp    0x565572a8
```

Instruksi `cmp DWORD PTR [ebp+0x8],0x2` akan membandingkan isi dari `[ebp+0x8]` di mana pada alamat tersebut tersimpan jumlah dari argumen (argc). Sehingga, jumlah argumen harus berjumlah dua agar program lanjut ke `0x565571d1`. Jika tidak, program akan lanjut ke `0x565572a8` yang mana program akan langsung menuju `ret`.

Instruksi-instruksi setelah `0x565571d1` sepertinya terkait dengan pengambilan nilai pada argumen, pemanggilan ke `strlen`, dan juga memeriksa isi argumen. Bagian pemeriksaan berikut terlihat menarik.

```asm
   0x5655723f:	movsx  eax,BYTE PTR [ebp-0x21]
   0x56557243:	mov    ecx,DWORD PTR [ebp-0x20]
   0x56557246:	mov    esi,DWORD PTR [ebp-0x28]
   0x56557249:	movsx  ecx,BYTE PTR [esi+ecx*1-0x1c0f]
   0x56557251:	mov    edi,DWORD PTR [ebp-0x18]
   0x56557254:	mov    ebx,DWORD PTR [ebp-0x20]
   0x56557257:	imul   ebx,DWORD PTR [ebp-0x1c]
   0x5655725b:	add    edi,ebx
   0x5655725d:	movsx  edi,BYTE PTR [esi+edi*1-0x1ff8]
   0x56557265:	xor    ecx,edi
   0x56557267:	cmp    eax,ecx
   0x56557269:	jne    0x56557278
```

Pada saat program mencapai `0x5655723f`, isi dari `[ebp-0x21]` adalah huruf pertama dari argumen dan disimpan ke `eax`. Kemudian pada alamat `0x56557267`, isi dari `eax` dibandingkan dengan `ecx` yang merupakan suatu nilai dari operasi xor.

Dengan mengatur `breakpoint` pada `0x56557267` pada instruksi `cmp eax,ecx`, kita dapat mengetahui nilai `ecx` yang dibandingkan dengan argumen karakter demi karakter. Karena alasan yang belum kami eksplorasi lebih lanjut, pemasangan `breakpoint` ini harus dilakukan ketika masih di `__libc_start_main`. Jika dilakukan di tengah-tengah eksekusi pada `.text`, terjadi `SIGTRAP` terus menerus.

Dari observasi pada nilai `ecx` pada `0x56557267` satu persatu, didapatkan flag **flag{Just_type__Please__and_the_missles_will_be_launched.}**.

Eksekusi dengan flag tersebut sebagai argumen akan membuat program exit dengan kode 0.

```
$ strace ./forgetful_command flag{Just_type__Please__and_the_missles_will_be_launched.}
...
open("/proc/self/maps", O_RDONLY)       = 3
read(3, "56596000-56598000 r--p 00000000 "..., 16384) = 1594
close(3)                                = 0
exit_group(0)                           = ?
+++ exited with 0 +++
```
