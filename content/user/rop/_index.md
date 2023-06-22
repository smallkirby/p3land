---
title: "ROP"
description: "Return Oriented ProgrammingとBuffer Overflowとlibc"
draft: false
weight: 2
---

## Challenge

[[Distribution File]](https://r2.p3land.smallkirby.com/rop-f1037e449116c920d8866c6cc5b20e4ac8efe42015e757e1aa5771d553d52d79.tar.gz)

```sh
nc sc.skb.pw 49401
```

{{< alert title="この章について" color="info" >}}
ROPについて調べたことがある人は、Exerciseまで飛ばしてしまってOKです。
詰まったら是非戻ってきてください。
{{< /alert >}}

## ROP: Return Oriented Programming

**ROP**とは、スタックフレーム中の**RA: Return Address**を書き換え、連鎖的に任意の命令を呼び出す攻撃手法です。

関数のスタックフレームは以下のようになっています:

```txt
↑ Lower Address
+-----------------+
 ...
+-----------------+
 ローカル変数
+-----------------+
 Canary
+-----------------+
 前のフレームのRSP    <= RBP
+-----------------+
 RA: Return Address
+-----------------+
↓ Higher Address
```

関数から帰るときには、`leave`命令で `mov rsp, rbp` と `pop rbp` を行い、スタックフレームを破棄します。

この時、スタック内でのオーバーフロー等で`RA`が`RA'`書き換えられていたと仮定します。
すると、`leave, ret`命令によって`RIP`を`RA'`に書き換えることができます。
プログラムの制御を奪えたことになります (RIPを取る、などと言います、言わないかも)。

更に発展させて、RIPを取るだけでなく命令Aを呼んだあとに命令Bを呼びたいと考えます。
この場合には、ターゲットのスタックフレーム内にあるRAを命令Aのアドレスに、その直下の8byteをBのアドレスに書き換えることができます:

```txt
+-----------------+
 Canary
+-----------------+
 前のフレームのRSP    <= RBP
+-----------------+
 &Inst A (overwritten)
+-----------------+
 &Inst B (overwritten)
+-----------------+
```

こうすると、`leave, ret`命令によって`RIP`を`&Inst A`に書き換え、`&Inst A`にある`ret`命令によって`RIP`を`&Inst B`に書き換えることができます。したがって、命令A,Bを順に実行することができます。
ROPでは、スタックフレーム内のRAを書き換えて`ret`命令によって任意の命令を次々に呼び出していきます。

なお、上記の説明にもあるように`Inst A`の最後は`ret`で終わる必要があります。
このような、ROPに利用することの出来る命令列を **Gadget** と呼びます。

{{< alert title="Note: ROPに使えるGadget" color="info" >}}
簡単のために`ret`で終わる必要があると書きましたが、実際は必ずしも`ret`で終わる必要はありません。
exploitの目的に沿うのであれば、`call`や`jmp`で終わることも可能です。
{{< /alert >}}

## Buffer Overflowとカナリア

ここからは[Challenge](https://r2.p3land.smallkirby.com/rop-f1037e449116c920d8866c6cc5b20e4ac8efe42015e757e1aa5771d553d52d79.tar.gz)を題材にして話を進めます。
Challengeのソースコードの抜粋は以下のとおりです:

```c
#define N_BUF 3
#define SIZE_BUF 0xD0
char notes[N_BUF][SIZE_BUF];

int main(int argc, char *argv[]) {
  char buf[0x50];
  long choice;

  for (int ix = 0; ix < N_BUF; ix++) {
    // Input
    puts("[INPUT]");
    printf("Note Index > ");
    scanf("%ld", &choice);
    printf("Note > ");
    readn(buf, 0xFF);

    if (choice >= 0 && choice < N_BUF && strlen(buf) < SIZE_BUF) {
      strcpy(notes[choice], buf);
    } else {
      puts("Invalid Note Index or Note Size!");
      exit(1);
    }

    // Output
    puts("[OUTPUT]");
    printf("Note Index > ");
    scanf("%ld", &choice);
    printf("Content: %s\n", notes[choice]);
  }

  return 0;
}
```

最初にスタックバッファ `buf` に入力を受け付けたあと、3つある `notes` のいずれかにコピーしています。
また、好きなノートを出力させることもできます。
この操作を3回繰り返すことができます。

このプログラムには、以下の2つの脆弱性があります。

### Vuln1: Buffer Overflow

`buf`に入力を受け付ける際に、`0xFF`文字だけ入力を許しています。
スタック上の`buf`のサイズは`0x50`であるため、`0xFF - 0x50 == 0xAF`文字だけオーバーフローが可能です。

ここで、`main`のスタックフレームを覗いてみます:

```gef
gef> tele $rsp 40
0x00007ffcc5afab70|+0x0000|000: 0x00007ffcc5afad08  ->  0x00007ffcc5afca81  ->  0x485300706f722f2e ('./rop'?)  <-  $rsp
0x00007ffcc5afab78|+0x0008|001: 0x0000000100000000
0x00007ffcc5afab80|+0x0010|002: 0x0000000000000003
0x00007ffcc5afab88|+0x0018|003: 0x0000000000000000
0x00007ffcc5afab90|+0x0020|004: 0x4141414141414141
0x00007ffcc5afab98|+0x0028|005: 0x4141414141414141
0x00007ffcc5afaba0|+0x0030|006: 0x4141414141414141
0x00007ffcc5afaba8|+0x0038|007: 0x4141414141414141
0x00007ffcc5afabb0|+0x0040|008: 0x4141414141414141
0x00007ffcc5afabb8|+0x0048|009: 0x4141414141414141
0x00007ffcc5afabc0|+0x0050|010: 0x4141414141414141
0x00007ffcc5afabc8|+0x0058|011: 0x00000000bfebfb41
0x00007ffcc5afabd0|+0x0060|012: 0x00007ffcc5afb159  ->  0x000034365f363878 ('x86_64'?)
0x00007ffcc5afabd8|+0x0068|013: 0x0000000000000064 ('d'?)
0x00007ffcc5afabe0|+0x0070|014: 0x0000000000001000
0x00007ffcc5afabe8|+0x0078|015: 0x39a1879339e1ed00  <-  canary
0x00007ffcc5afabf0|+0x0080|016: 0x0000000000000001  <-  $rbp
0x00007ffcc5afabf8|+0x0088|017: 0x00007fd47f429d90 <__libc_start_call_main+0x80>  ->  0xe80001b859e8c789
```

以下のような構造です:

- `+0x20` ~ `+0x70`: `buf`
- `+0x78`: カナリア
- `+0x80`: 前のRSP
- `+0x88`: RA (`__libc_start_call_main`)

`buf`に入力できるサイズが`0xFF`であることから、 **`+0x20` ~ `0x120`までの範囲を自由に上書きすることが可能** だと分かります。

### Vuln2: Out of Bound Read

`Input`においてはユーザから指定された`choice`が0から2の間であるかどうかをチェックしていますが、
`Output`においてはこのバウンドチェックを行っていません。
よって、`choice`として任意の値を入力することで`printf("Content: %s\n", notes[choice])`によって *ある程度任意の* アドレスにある値をleakすることができます。

*ある程度* と書いたのは、`notes[choice]`が指し示すアドレスの計算方法のためです。
この`printf`の第2引数に渡すアドレスの計算部分を見てみましょう:

```gef
gef> x/15i $rip-0x5
   0x5575f28094b8 <main+389>:   call   0x5575f2809140 <__isoc99_scanf@plt>
=> 0x5575f28094bd <main+394>:   mov    rdx,QWORD PTR [rbp-0x68] # <choice>
   0x5575f28094c1 <main+398>:   mov    rax,rdx
   0x5575f28094c4 <main+401>:   add    rax,rax
   0x5575f28094c7 <main+404>:   add    rax,rdx
   0x5575f28094ca <main+407>:   shl    rax,0x2
   0x5575f28094ce <main+411>:   add    rax,rdx
   0x5575f28094d1 <main+414>:   shl    rax,0x4
   0x5575f28094d5 <main+418>:   lea    rdx,[rip+0x2b84]        # 0x5575f280c060 <notes>
   0x5575f28094dc <main+425>:   add    rax,rdx
   0x5575f28094df <main+428>:   mov    rsi,rax
   0x5575f28094e2 <main+431>:   lea    rax,[rip+0xb5e]        # 0x5575f280a047
   0x5575f28094e9 <main+438>:   mov    rdi,rax
   0x5575f28094ec <main+441>:   mov    eax,0x0
   0x5575f28094f1 <main+446>:   call   0x5575f2809110 <printf@plt>
```

上のコードは`Output`で利用する`choice`を`scanf`で入力させた直後になります。
`+394`の`rdx`は`choice`のアドレスになります。
続く`+398` ~ `+414`では何やらめんどくさそうなことをしていますが、整理すると以下のような計算をしています
(なぜこうなるかどうか、一つ一つ命令を追って確認してみてください):

```txt
$rax = choice * (3 * 2^2 + 1) * 2^4
    (== choice * 0xD0)
```

`0xD0`という数字が出てきました。これは`SIZE_BUF`の値のことですね。
つまりこの一連の命令によって、`notes`から`choice * 0xD0`だけ進んだポインタを生成しています。
逆に言うと、 **leakのために指定するアドレスは`0xD0`単位でしか指定することができません** 。
これが *ある程度任意の* と書いた理由になります。

### カナリアを跨いだOverflow

ここまでの話をまとめると、以下のようなexploitの方針が立ちます:

1. `buf`のoverflowによってRAを書き換える
2. RAの下もどんどん書き換えて、ROPに持ち込む

しかし、1でoverflowをする時にはカナリアも巻き込んで書き換えてしまうことになります
(カナリアと線形WRITEについては [#FSBのコラム](/user/fsb/#fsaでのwrite) を参照してください)。

今回はノートのREAD機能もついているため、 **カナリアをleakしてOverflowの際にカナリアをカナリアの値で上書きすることにしましょう** 。具体的には、`buf`に対して0x50byteだけ入力することで`buf`内の文字列と`canary`が隣接します。その状態でノートを読むことで、`canary`をleakすることができます。

{{< alert title="Note: leakとNULL Termination" color="info" >}}
exploitにおいて何らかの値をREADする際には、文字列のNULL Terminationに注意が必要です。
例えば、`write(1, buf, 0x50)`のような出力であった場合には`buf`の中身がなんであったとしても`0x50`文字分は出力されます。
しかし、`printf("%s", buf)`のような出力ではNULL文字(`\x00`)があった時点で出力が終了してしまいます。

とりわけ今回、カナリアの下1byteはNULLになっていると思います。
そのため、実際に入力する文字数は`0x50`ではなく`0x51`文字入力してNULLを上書きしてやる必要があります。
(カナリアの下1byteがNULLになるのは隣接するバッファがNULL終端されていない場合に誤って出力されたりしないようにするためだと思いますが、自信ありません)
{{< /alert >}}

## libcbaseのleak

ここまででおおよその方針が立ったので具体的に何をするか考えましょう。

ROPには、libc内のgadgetを使います。これは、challengeバイナリ本体は比較的小さく十分な数のgadgetを含んでいないためです(FSBの章で使ったプログラムにあったような`win`関数も今回はありません)。

libc内のgadgetを使うには、まずlibcのアドレス( **libcbase** )をleakする必要があります。
libcがロードされるアドレスは実行時に決まりますが、シンボル同士の相対位置関係は同じlibcを使っている限り不変です。
そのため、まずは何かしらのlibcシンボルをleakできれば良いことになります。

今回は **GOT** からシンボルをleakすることにします。
`notes`はグローバル変数であり、GOTとの相対値が同じです。

```gef
gef> got
Name                        | PLT                | GOT                | GOT value
------------------------------------------------------------------------ .rela.plt ------------------------------------------------------------------------
strcpy                      | 0x000055d54b0fc0d0 | 0x000055d54b0fef90 | 0x00007f96cad9ee30 <__strcpy_avx2>
puts                        | 0x000055d54b0fc0e0 | 0x000055d54b0fef98 | 0x00007f96cac80ed0 <puts>
strlen                      | 0x000055d54b0fc0f0 | 0x000055d54b0fefa0 | 0x00007f96cad9d960 <__strlen_avx2>
__stack_chk_fail            | 0x000055d54b0fc100 | 0x000055d54b0fefa8 | 0x00007f96cad36720 <__stack_chk_fail>
printf                      | 0x000055d54b0fc110 | 0x000055d54b0fefb0 | 0x00007f96cac60770 <printf>
read                        | 0x000055d54b0fc120 | 0x000055d54b0fefb8 | 0x00007f96cad14980 <read>
setvbuf                     | 0x000055d54b0fc130 | 0x000055d54b0fefc0 | 0x00007f96cac81670 <setvbuf>
__isoc99_scanf              | 0x000055d54b0fc140 | 0x000055d54b0fefc8 | 0x00007f96cac62110 <__isoc99_scanf>
exit                        | 0x000055d54b0fc150 | 0x000055d54b0fefd0 | 0x00007f96cac455f0 <exit>

gef> p/x &notes
$16 = 0x55d54b0ff060

gef> p/x 0x55d54b0ff060 - 0x000055d54b0feff8 # got[exit]
$18 = 0x68
gef> p/x 0x55d54b0ff060 - 0x000055d54b0fef90 # got[strcpy]
$17 = 0xd0
```

`notes[choice]`がこのいずれかのGOTを指すようにすればGOTの値がleakできます。

但し、今回は問題の制約上任意のGOTをleakできるわけではありません。
`notes[choice]`のアドレス計算式を見て分かったとおり、`notes`から`0xD0`の倍数だけ離れたところしか指定できません。
`gef`の出力から、`notes`のアドレスと`GOT[exit]`のアドレス差分は`0x68`であることが分かります。また、`strcpy`は`0xD0`です。
よって、このGOTの中でleakに使えるのは`strcpy`だけであることが分かります。

以上より、`choice`として`-1`を入力してあげれば`GOT[strcpy]`の値をleakすることができます。
`strcpy`の値をleakしたら、あとはlibcのベースアドレスと`strcpy`の差分をleakした値から引いてあげるとlibcbaseが計算できます。

なお、「libcのベースアドレスと`strcpy`の差分」は`vmmap`コマンド等の出力を使って計算できます:

```gef
gef> vmmap
[ Legend:  Code | Heap | Stack | Writable | RWX]
Start              End                Size               Offset             Perm Path
0x000055d54b0fb000 0x000055d54b0fc000 0x0000000000001000 0x0000000000000000 r-- rop
0x000055d54b0fc000 0x000055d54b0fd000 0x0000000000001000 0x0000000000001000 r-x rop  <-  $rip, $r13
0x000055d54b0fd000 0x000055d54b0fe000 0x0000000000001000 0x0000000000002000 r-- rop
0x000055d54b0fe000 0x000055d54b0ff000 0x0000000000001000 0x0000000000002000 r-- rop  <-  $r14
0x000055d54b0ff000 0x000055d54b100000 0x0000000000001000 0x0000000000003000 rw- rop  <-  $rdx
0x00007f96cac00000 0x00007f96cac28000 0x0000000000028000 0x0000000000000000 r-- /usr/lib/x86_64-linux-gnu/libc.so.6
0x00007f96cac28000 0x00007f96cadbd000 0x0000000000195000 0x0000000000028000 r-x /usr/lib/x86_64-linux-gnu/libc.so.6
0x00007f96cadbd000 0x00007f96cae15000 0x0000000000058000 0x00000000001bd000 r-- /usr/lib/x86_64-linux-gnu/libc.so.6  <-  $r10, $r11
```

libcbaseのアドレスが`0x7f96cac00000`であり、`__strcpy_avx2`のアドレスが先程の`got`コマンドで見たように`0x7f96cad9ee30`であることから、libcbaseと`__strcpy_avx2`の差分は`0x7f96cad9ee30 - 0x7f96cac00000 == 0x9ee30`となります。

{{< alert title="libcの配布について" color="warning" >}}
ここまで進めて分かるとおり、このexploitではlibc固有の情報を使います。
そのため、利用するlibcのバージョンやビルド環境が異なるとexploitに使う値も異なってきます。

そのような場合には、配布ファイルに`libc.so`と`ld.so`が配布されています。
実行時には`LD_PRELOAD=$(realpath ./libc.so) ./ld.so ./challenge`のようにすることで
指定されたlibcをロードすることが可能になります。
個人的には`readelf`等のツールでELFヘッダ中のローダ情報を書き換えてしまうのが良いと思います。

Kernelの講義なので少しKernelの話をすると、PIEバイナリは実行時に以下のベースアドレスらへんにロードされます
([/arch/x86/include/asm/elf.h](https://elixir.bootlin.com/linux/latest/source/arch/x86/include/asm/elf.h#L237)):

```c
#define ELF_ET_DYN_BASE		(mmap_is_ia32() ? 0x000400000UL : \
						  (DEFAULT_MAP_WINDOW / 3 * 2))
```

計算すると、`0x555555554aaa`という見慣れた値になります。
実際にはこれにバイアスとしてアーキ固有の乱数が加算されます。
x64の場合には8bitの乱数をページ分だけシフトした値です([/mm/util.c](https://elixir.bootlin.com/linux/latest/source/mm/util.c#L379))
これが加算されて皆さんのもとにお届けされます。
農家の方には感謝しないといけないですね。

この辺のELFファイルのロードについては、[/fs/binfmt_elf.c](https://elixir.bootlin.com/linux/latest/source/fs/binfmt_elf.c#L823)らへんを中心に読んだり、[@smallkirbyが書いた概要](https://github.com/smallkirby/kernelpwn/blob/master/technique/modprobe_path.md#determine-binary-format)を読むと良いかもしれないです。
少し話が逸れましたが、こういう気になることはコードを読むと分かるので調べる癖をつけると世界が平和になります。
{{< /alert >}}

## libc内のgadgetを使ったROP

libcbaseのleakができれば、libc内の任意のシンボルのアドレスが分かったことになります。
これでlibc内の任意のgadgetを使ってROPをすることができますね。

今回のROPでは、`system("/bin/sh")`を呼び出すことを目的とします。
そのために必要なROP gadgetは以下のようになります:

1. RDIに`/bin/sh`という文字列のアドレスを入れる
2. `system`に飛ぶ

1に関して、`/bin/sh`という文字列は大抵libcの中に落ちています:

```gef
gef> search-pattern /bin/sh
[+] Searching '/bin/sh' in whole memory
[+] In '/usr/lib/x86_64-linux-gnu/libc.so.6' (0x7f96cadbd000-0x7f96cae15000 [r--])
  0x7f96cadd8698 - 0x7f96cadd869f  ->   "/bin/sh"
[+] Searching '/\x00b\x00i\x00n\x00/\x00s\x00h\x00' in whole memory
```

よって、1のROP-chainは以下のとおりになります:

```txt
+-----------------+
 &`pop rdi`
+-----------------+
 "/bin/sh"のアドレス
+-----------------+
```

2に関しては単純で、leakしたlibcのアドレスから`system`のアドレスを計算して1のchainの下に積んでおくだけでOKです。
なお、`pwntools`では`system`のlibcbaseからの相対アドレスを勝手に調べてくれる機能があります。
よって、この計算部分は以下のように書けます:

```py
libc = ELF("./libc.so")
system = libcbase + libc.symbols["system"]
```

さて、libc内のgadgetを探すには [rp++](https://github.com/0vercl0k/rp) というツールを使うのがおすすめです。
このツールは指定したELFファイルから指定した命令長のgadgetを列挙してくれます。
例えば今回使いたい`pop rdi` gadgetは以下のように探すことができます:

```sh
$ rp++ -f ./libc-2.35.so -r1 | grep "pop rdi" | head -n5
0x125bb1: pop rdi ; call rax ; (1 found)
0x2d549: pop rdi ; jmp rax ; (1 found)
0x2dc39: pop rdi ; jmp rax ; (1 found)
0x2e2f0: pop rdi ; jmp rax ; (1 found)
0x2eadb: pop rdi ; jmp rax ; (1 found)
```

{{< alert title="gadgetの選び方について" color="info" >}}
`rp++`は、同じ働きをするgadgetを全て見つけてくれるため、そこから1つを選んで利用することになります。
この時、 **gadgetの選び方はexploitの制約を満たすようにする必要** があります。

例えば今回のchallengeでは、`readn`関数は `\n` を読み込んだ時点で入力が終了するようになっています。
そのため、選んだgadgetのアドレスに`0x0A`が含まれないようなものを選択してやる必要があります。
{{< /alert >}}

{{< alert title="onegadget RCE" color="info" >}}
CTFでpwnを解いたことがある人は、 **onegadget** というgadgetを聞いたことがあるかもしれません。
onegadgetは、libcの中に存在するgadgetの内、ただ実行するだけでシェルが取れてしまうというものです。
libc内にonegadgetが存在する場合、ROPをする必要すらなくなります。

但し、onegadgetには実行開始時に満たすべき制約がいくつか付随しています(RDXが0である...etc)。
そのため、onegadgetが存在するからと行って必ず発火するとは限らず、単純にROPしたほうが早い場合もあります。
また、ROPによってonegadgetの制約を満たすように調整したあとでonegadgetに飛ぶという手法も考えられます。

onegadgetのアドレスとその制約を調べるには [OneGadget](https://github.com/david942j/one_gadget) というツールがおすすめです:

```sh
$ one_gadget ./libc-2.35.so | head -n8
0x50a37 posix_spawn(rsp+0x1c, "/bin/sh", 0, rbp, rsp+0x60, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL
  rbp == NULL || (u16)[rbp] == NULL

0xebcf1 execve("/bin/sh", r10, [rbp-0x70])
constraints:
```
{{< /alert >}}

------------------------------

以上でROPを使って本Challengeを解くことが出来るかと思います。
ぜひリモートサーバでflagを取得してみてください。

------------------------------

## Exercise

### 1. NOTE2ROP

[[Distribution File]](https://r2.p3land.smallkirby.com/fsb-fb761ab64511234bcc9db68c1606e60f6ce22266f8a661f4d02c20a991a087e3.tar.gz)

```sh
nc sc.skb.pw 49401
```
