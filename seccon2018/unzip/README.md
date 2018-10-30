# Unzip
---
**Points:** 101 | **Solves:** 597/653 | **Category:** Forensics

Unzip flag.zip.

[Download](unzip.zip_26c0cb5b40e9f78641ae44229cda45529418183f)

---

[Bahasa Indonesia](#bahasa-indonesia)

## English
We got `flag.zip` and `makefile.sh`.

This is the content of `makefile.sh`.

```
echo 'SECCON{'`cat key`'}' > flag.txt
zip -e --password=`perl -e "print time()"` flag.zip flag.txt
```

We need to know the Unix time of date created of `flag.zip`.

By using `ls -l` we can know the file timestamp is `Fri, Oct 26 2018 15:10:41 UTC`. We can convert the timestamp to Unix time and use it to open `flag.zip`.

```sh
$ php -a
Interactive shell

php > echo strtotime('Fri, Oct 26 2018 15:10:41');
1540566641

$ unzip flag.zip
Archive:  flag.zip
[flag.zip] flag.txt password: 1540566641
  inflating: flag.txt

$ cat flag.txt
SECCON{We1c0me_2_SECCONCTF2o18}
```

Flag: `SECCON{We1c0me_2_SECCONCTF2o18}`

## Bahasa Indonesia
Kita dapat `flag.zip` dan `makefile.sh`.

Berikut adalah isi dari `makefile.sh`.

```
echo 'SECCON{'`cat key`'}' > flag.txt
zip -e --password=`perl -e "print time()"` flag.zip flag.txt
```

Kita harus mengetahui Unix time dari waktu `flag.zip` dibuat.

Dengan menggunakan `ls -l` kita dapat tahu timestamp dari file adalah `Fri, Oct 26 2018 15:10:41 UTC`. Kita dapat mengkonversikannya menjadi Unix time dan menggunakannya untuk membuka `flag.zip`.

```sh
$ php -a
Interactive shell

php > echo strtotime('Fri, Oct 26 2018 15:10:41');
1540566641

$ unzip flag.zip
Archive:  flag.zip
[flag.zip] flag.txt password: 1540566641
  inflating: flag.txt

$ cat flag.txt
SECCON{We1c0me_2_SECCONCTF2o18}
```

Flag: `SECCON{We1c0me_2_SECCONCTF2o18}`
