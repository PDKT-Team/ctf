# History
---
**Points:** 145 | **Solves:** 147/653 | **Category:** Forensics

History Check changed filename.
file:J.zip_4c7050d70c9077b8c94ce0d76effcb8676bed3ba

[Download](J.zip_4c7050d70c9077b8c94ce0d76effcb8676bed3ba)

---

[Bahasa Indonesia](#bahasa-indonesia)

## English
If we open the file `J` with hex editor, we will see a kind of UTF-16LE. We can read the string with `strings` utility with proper encoding (16 bit).

```
$ strings --encoding={b,l} J
"<ngen_service.lock
 <ngen_service.log
 <ngen_service.log
"<ngen_service.lock
&<ngenservicelock.dat
*<ngenrootstorelock.dat
"<ngen_service.lock
 <ngen_service.log
 <ngen_service.log
"<ngen_service.lock
"<ngen_service.lock
...
```

Judging from the pattern, looks like it's a file name history (like [USN Journal](https://en.wikipedia.org/wiki/USN_Journal)).

We found interesting history for txt files.

```
$ strings --encoding={b,l} J | grep txt
...
<logfile.txt.0
<logfile.txt.0
<SEC.txt
<SEC.txt
<SEC.txt
<SEC.txt
<CON{.txt
<CON{.txt
<CON{.txt
<F0r.txt
<F0r.txt
<tktksec.txt
<tktksec.txt
<tktksec.txt
<F0r.txt
<ensic.txt
<ensic.txt
<ensic.txt
<s.txt
<s.txt
<s.txt
<_usnjrnl.txt
<_usnjrnl.txt
<_usnjrnl.txt
<2018}.txt
<2018}.txt
<logfile.txt.0
```

It looks like the file name has been changed several times with name `SEC.txt`, `CON{.txt`, `F0r.txt`, `ensic.txt`, `s.txt`, `_usnjrnl.txt`, and `2018}.txt`.

Flag: `SECCON{F0rensics_usnjrnl2018}`

## Bahasa Indonesia
Jika kita membuka berkas `J` dengan hex editor, kita akan melihat sejenis UTF-16LE. Kita bisa membacanya dengan perkakas `strings` dengan encoding yang tepat (16 bit).

```
$ strings --encoding={b,l} J
"<ngen_service.lock
 <ngen_service.log
 <ngen_service.log
"<ngen_service.lock
&<ngenservicelock.dat
*<ngenrootstorelock.dat
"<ngen_service.lock
 <ngen_service.log
 <ngen_service.log
"<ngen_service.lock
"<ngen_service.lock
...
```

Dilihat dari polanya, sepertinya itu adalah history dari nama berkas (seperti [USN Journal](https://en.wikipedia.org/wiki/USN_Journal)).

Kami menemukan history menarik untuk berkas txt.

```
$ strings --encoding={b,l} J | grep txt
...
<logfile.txt.0
<logfile.txt.0
<SEC.txt
<SEC.txt
<SEC.txt
<SEC.txt
<CON{.txt
<CON{.txt
<CON{.txt
<F0r.txt
<F0r.txt
<tktksec.txt
<tktksec.txt
<tktksec.txt
<F0r.txt
<ensic.txt
<ensic.txt
<ensic.txt
<s.txt
<s.txt
<s.txt
<_usnjrnl.txt
<_usnjrnl.txt
<_usnjrnl.txt
<2018}.txt
<2018}.txt
<logfile.txt.0
```

Sepertinya nama berkas telah berubah beberapa kali dengan nama `SEC.txt`, `CON{.txt`, `F0r.txt`, `ensic.txt`, `s.txt`, `_usnjrnl.txt`, dan `2018}.txt`.

Flag: `SECCON{F0rensics_usnjrnl2018}`
