# ev3-basic
---
**Points:** 100 | **Solves:** 255/1789 | **Category:** Misc

Find the flag.

[Download](ev3basic-1e0165aa826649b7e3c5869a62faf8ba.tar.gz)

Author: Jeffxx

---

[Bahasa Indonesia](#bahasa-indonesia)

## English
In this challenge, given tar files contains image LEGO EV3 printing partial flag on screen and pklg files which contains data transmission on RFCOMM protocol. Use filter on wireshark to see what data send to LEGO EV3 device.

```
bluetooth.dst == 00:16:53:61:30:c1 && btrfcomm
```

After we apply filter, we can see much packet have packet length between 32 and 34. From this we analyze 2 packet data which have length between that.

```
0000   02 0c 20 1b 00 17 00 40 00 0b ef 27 11 00 2a 00  .. ....@...'..*.
0010   00 00 00 84 05 01 0a 81 28 84 68 00 84 00 80 9a  ........(.h.....

0000   02 0c 20 1b 00 17 00 40 00 0b ef 27 11 00 2a 00  .. ....@...'..*.
0010   00 00 00 84 05 01 14 81 28 84 69 00 84 00 80 9a  ........(.i.....
```

Between this 2 packet there is 2 byte different, on offset `0x16` and `0x1a`. On offset `0x1a` has value `h` and `i`, we suspect that is flag pieces. After we compare with given image, character `h` and `i` side by side. So, we concludes that offset `0x16` is `x coordinate` of screen LEGO EV3.

After we know that, we can extract x coordinate, y coordinate, and char printed from packet with length between 32 and 34. After that we just need to sort data.

The following is the script used.

```python

flagp = ["0a:28:68", "14:28:69", "1e:28:74", "1e:44:5f", "14:52:6f", "0a:36:5f",
        "1e:52:70", "14:36:63", "0a:44:6e", "14:44:64", "1e:36:6f", "0a:52:6c",
        "64:52:7d", "46:28:7b", "5a:28:31", "3c:28:6e", "28:28:63", "6e:28:64",
        "32:28:6f", "50:28:6d", "78:36:69", "28:52:65", "46:52:6b", "3c:44:72",
        "28:44:66", "5a:44:61", "3c:36:75", "64:36:61", "32:44:69", "78:28:35",
        "64:28:6e", "5a:52:74", "78:44:5f", "64:44:72", "46:36:6e", "50:52:69",
        "32:36:6d", "28:36:6d", "5a:36:63", "46:44:6d", "6e:36:74", "50:36:69",
        "3c:52:5f", "50:44:77", "32:52:72", "6e:44:65", "8c:44:65", "a0:36:61",
        "96:44:76", "82:44:64", "a0:44:65", "96:28:72", "82:36:6f", "a0:28:6d",
        "8c:28:30", "96:36:5f", "82:28:74", "8c:36:6e"]

flag = {}

def parse(sc):
    temp = sc.split(":")
    x = int(temp[0], 16)
    y = int(temp[1], 16)
    c = int(temp[2], 16)
    flag[y*16 + x] = chr(c)

for f in flagp:
    parse(f)

sflag = ""

for i in sorted(flag):
    sflag += flag[i]

print sflag
```

Flag: **hitcon{m1nd5t0rm_communication_and_firmware_developer_kit}**


## Bahasa Indonesia
Pada challenge ini diberikan sebuah file tar yang berisi sebuah gambar serta file pklg yang dapat dibuka dengan wireshark. File gambar berisi LEGO EV3 yang menampilkan potongan flag. Sedangkan file pklg ini berisi transmisi data pada protokol RFCOMM. Langsung lakukan filter pada wireshark untuk melihat apa yang dikirim ke device LEGO EV3.

```
bluetooth.dst == 00:16:53:61:30:c1 && btrfcomm
```

Setelah dilakukan filter dapat dilihat ada banyak packet yang memiliki panjang sekitar 32-34. Dari situ kita lakukan analisis pada 2 paket pertama yang memiliki panjang tersebut.

```
0000   02 0c 20 1b 00 17 00 40 00 0b ef 27 11 00 2a 00  .. ....@...'..*.
0010   00 00 00 84 05 01 0a 81 28 84 68 00 84 00 80 9a  ........(.h.....

0000   02 0c 20 1b 00 17 00 40 00 0b ef 27 11 00 2a 00  .. ....@...'..*.
0010   00 00 00 84 05 01 14 81 28 84 69 00 84 00 80 9a  ........(.i.....
```

Di antara kedua packet tersebut hanya terdapat 2 byte yang berbeda, yaitu pada offset `0x16` dan `0x1a`. Pada offset `0x1a` berisi huruf `h` dan `i`, kita mencurigai bahwa ini potongan flag. Setelah dihubungkan dengan gambar yang diberikan, letak huruf `h` dan `i` bersebelahan. Sehingga kita mengambil kesimpulan offset `0x16` adalah `koordinat x` dari layar LEGO EV3.

Setelah mengetahui hal tersebut, kita lakukan ekstraksi data yang memiliki panjang 32-34. Data yang kita ambil berupa koordinat x, koordinat y, serta huruf yang diprint. Kemudian sort data yang kita dapatkan.

Berikut adalah script yang digunakan.

```python

flagp = ["0a:28:68", "14:28:69", "1e:28:74", "1e:44:5f", "14:52:6f", "0a:36:5f",
        "1e:52:70", "14:36:63", "0a:44:6e", "14:44:64", "1e:36:6f", "0a:52:6c",
        "64:52:7d", "46:28:7b", "5a:28:31", "3c:28:6e", "28:28:63", "6e:28:64",
        "32:28:6f", "50:28:6d", "78:36:69", "28:52:65", "46:52:6b", "3c:44:72",
        "28:44:66", "5a:44:61", "3c:36:75", "64:36:61", "32:44:69", "78:28:35",
        "64:28:6e", "5a:52:74", "78:44:5f", "64:44:72", "46:36:6e", "50:52:69",
        "32:36:6d", "28:36:6d", "5a:36:63", "46:44:6d", "6e:36:74", "50:36:69",
        "3c:52:5f", "50:44:77", "32:52:72", "6e:44:65", "8c:44:65", "a0:36:61",
        "96:44:76", "82:44:64", "a0:44:65", "96:28:72", "82:36:6f", "a0:28:6d",
        "8c:28:30", "96:36:5f", "82:28:74", "8c:36:6e"]

flag = {}

def parse(sc):
    temp = sc.split(":")
    x = int(temp[0], 16)
    y = int(temp[1], 16)
    c = int(temp[2], 16)
    flag[y*16 + x] = chr(c)

for f in flagp:
    parse(f)

sflag = ""

for i in sorted(flag):
    sflag += flag[i]

print sflag
```

Flag: **hitcon{m1nd5t0rm_communication_and_firmware_developer_kit}**
