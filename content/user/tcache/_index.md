---
title: "heap: tcache"
description: "Heapの基礎とtcache poisoning"
draft: false
weight: 3
---

## Challenge

[[Distribution File]](tcache-d5c0a4e85196bfd8132297ed0614d089559a605029d9bc3d31649b2498fa6b8c.tar.gz)

```sh
nc sc.skb.pw 49402
```

{{< alert title="この章について" color="info" >}}
卍heap master卍の人は、Exerciseまで飛ばしてしまってOKです。
{{< /alert >}}

## heapの概要

C/C++におけるheapはしばしばバグの原因となり、クリティカルな攻撃に繋がる可能性を大いに秘めています。
例えば2022年の[CWE Top 25 Most Dangerous Software Weakness](https://cwe.mitre.org/top25/archive/2022/2022_cwe_top25.html)では、前年に続いて **UAF: Use-After-Free** が7位になっています。
C/C++でこのようなUAF/*UAR(Use-After-Reallocation)* が起こる主な原因は、C/C++が *GC: Garbage Collection* を持たないためです。
ほとんどのメモリ管理がプログラマに一任されるため、heap objectの生存期間やサイズを正しく管理していないことに起因するバグが発生してしまいます。
もちろんこれらのメモリバグへの対処もいたるところで研究・開発されています(eg: [ChromeにおけるMiraclePtr](https://security.googleblog.com/2022/09/use-after-freedom-miracleptr.html))が、
未だにユニバーサルに利用することの出来る対策は知られていません。

heapはRealWorld/CTFの両方で、またuserland/kernelの両方で頻繁にexploitされます。
一方で、heapはライブラリやKernelの開発者によって頻繁にmitigationが実装される領域でもあります。
セキュリティと攻撃者のTHE・イタチごっこみたいな分野です。
したがって、heap exploitには「その仕組みに関する基礎的な理解」と「exploitの対策として実装し続けられるmitigation」の両方が必要となります。

本challengeではglibcで用いられるメモリアロケータである **ptmalloc** について扱います(厳密にはptmallocから「派生した」)。
最初から全ての機能を理解しようとすると日が暮れてしまうので、まずは **tcache** について考えます。
heapに触ったことがない人は、ぜひ実際に手を動かしつつ・メモリを読みつつ・GDBとお話しつつ読み進めてください。
たまにheap問題は難しそうで敬遠する人もいますが、個人的にはpwnの中でもパズル的面白さが分かりやすい有数の領域の一つだと思います。

## challenge概要

challengeのソースコードの概要は以下のとおりです:

```c
struct User {
  unsigned long id;
  unsigned long age;
  char name[0x30];
};
struct User *users[NUM_USER];

int main(int argc, char *argv[]) {
  int choice, index;
  printf("[DEBUG: puts=%p]\n\n", puts);

  while (1 == 1) {
    printf("Read(0) / Write(1) / Delete(2) > ");
    scanf("%d", &choice);

    if (choice < 0 || choice > 2) {
      puts("\nBye!");
      return 0;
    }

    printf("User Index > ");
    scanf("%d", &index);
    if (index < 0 || index >= NUM_USER) {
      puts("Invalid User Index");
      return 1;
    }

    switch (choice) {
      case 0:  // READ
        if (users[index] == NULL) {
          puts("User not found");
          break;
        } else {
          printf("ID: 0x%lx\n", users[index]->id);
          printf("Age: %ld\n", users[index]->age);
          printf("Name: %s\n", users[index]->name);
        }
        break;
      case 1:  // WRITE
        if (users[index] == NULL) {
          users[index] = (struct User *)malloc(sizeof(struct User));
        }
        printf("ID > ");
        scanf("%ld", &users[index]->id);
        printf("Age > ");
        scanf("%ld", &users[index]->age);
        printf("Name > ");
        readn(users[index]->name, sizeof(struct User));
        break;
      case 2:  // DELETE
        if (users[index] == NULL) {
          puts("User not found");
          break;
        } else {
          free(users[index]);
          users[index] = NULL;
        }
        break;
    }
  }
}
```

まず最初に`puts`関数のアドレスを自ら教えてくれています。
続いて、ループの中でいくつかの機能を実行しています:

- READ  : `users[index]` のユーザ情報を表示
- WRITE : `users[index]` のユーザ情報を入力
- DELETE: `users[index]` のユーザ情報を削除

`struct User`はユーザ情報としてID/年齢/名前を保持する構造体であり、`malloc()`によってheap上に確保されます。

{{< alert title="このプログラム何...?" color="info" >}}
最初っから変なプログラムですね。
CTFのchallengeプログラムには、「参加者に解かせたいコアの部分」と「シェルを取らせるために参加者が必要とする情報を与えるための部分」があります。
良い問題(というよりは大体の問題)は、後者の機能であってもいい感じにchallengeプログラムの趣旨に沿うようなシナリオを考えて実装します。

今回のような情報の提示方法は、大体作者の怠慢です。
おそらくどうやってシンプルさを保ったたまlibcbaseを提供するかを考えてたら、疲れちゃったんでしょうね。
{{< /alert >}}

heapはバージョンごとの差異が大きい領域であり、バージョンごとに使える攻撃が異なります。
バージョンが新しいほどexploitが難しくなる傾向にあり、今回は問題をシンプルにするために `glibc-2.31` を使っています。
そのため、今回の配布バイナリは単体ではおそらく実行できません。以下に示す方法でローダとライブラリを指定してください:

```sh
patchelf --set-interpreter $(realpath ./ld-2.31.so) ./tcache
patchelf --set-rpath $(realpath .) ./tcache
LD_PRELOAD=$(realpath ./libc-2.31.so) ./tcache
```

プログラムを実行すると、以下のようなユーザ管理コンソールが開きます:

```sh
$ LD_PRELOAD=$(realpath ../build/libc-2.31.so) ./tcache
## User Management System ##

[DEBUG: puts=0x7f6ec0873420]

Read(0) / Write(1) / Delete(2) > 1
User Index > 0
ID > 0
Age > 32
Name > Jogh Marks
Read(0) / Write(1) / Delete(2) > 0
User Index > 0
ID: 0x0
Age: 32
Name: Jogh Marks
Read(0) / Write(1) / Delete(2) >
```

ソースを読みつつ、ひとしきり操作をしてみてください。

## heapの大まかな構造

まずは何も考えずにしばらく実行して、heapがどうなっているかを見てみましょう。
以下では、WRITE操作のことを `WRITE(<ID>, <AGE>, <NAME>)` の用に表記します。
今回は `WRITE(i, i, ('A'+i) * 0x20)` という操作を5回ほどしたあとのheapを見てみます。

`gef`を使っている場合には、`heap`の一覧は `chunks` コマンドで見ることができます:

```gef
gef> chunks
Chunk(addr=0x55b9ddb6f000, size=0x290, flags=PREV_INUSE, fd=0x0, bk=0x0)
Chunk(addr=0x55b9ddb6f290, size=0x50, flags=PREV_INUSE, fd=0x0, bk=0x10)
Chunk(addr=0x55b9ddb6f2e0, size=0x50, flags=PREV_INUSE, fd=0x1, bk=0x10)
Chunk(addr=0x55b9ddb6f330, size=0x50, flags=PREV_INUSE, fd=0x2, bk=0x10)
Chunk(addr=0x55b9ddb6f380, size=0x50, flags=PREV_INUSE, fd=0x3, bk=0x10)
Chunk(addr=0x55b9ddb6f3d0, size=0x50, flags=PREV_INUSE, fd=0x4, bk=0x10)
Chunk(addr=0x55b9ddb6f420, size=0x20be0, flags=PREV_INUSE, fd=0x0, bk=0x0, fd_nextsize=0x0, bk_nextsize=0x0)  <-  top chunk
```

アドレス`0x55b9ddb6f290`から数バイトを表示してみましょう(`#####`は表示されません):

```gef
gef> x/54gx 0x55b9ddb6f290
##########################################################
0x55b9ddb6f290: 0x0000000000000000      0x0000000000000051
0x55b9ddb6f2a0: 0x0000000000000000      0x0000000000000010
0x55b9ddb6f2b0: 0x4141414141414141      0x4141414141414141
0x55b9ddb6f2c0: 0x4141414141414141      0x4141414141414141
0x55b9ddb6f2d0: 0x0000000000000000      0x0000000000000000
##########################################################
0x55b9ddb6f2e0: 0x0000000000000000      0x0000000000000051
0x55b9ddb6f2f0: 0x0000000000000001      0x0000000000000010
0x55b9ddb6f300: 0x4242424242424242      0x4242424242424242
0x55b9ddb6f310: 0x4242424242424242      0x4242424242424242
0x55b9ddb6f320: 0x0000000000000000      0x0000000000000000
##########################################################
0x55b9ddb6f330: 0x0000000000000000      0x0000000000000051
0x55b9ddb6f340: 0x0000000000000002      0x0000000000000010
0x55b9ddb6f350: 0x4343434343434343      0x4343434343434343
0x55b9ddb6f360: 0x4343434343434343      0x4343434343434343
0x55b9ddb6f370: 0x0000000000000000      0x0000000000000000
##########################################################
0x55b9ddb6f380: 0x0000000000000000      0x0000000000000051
0x55b9ddb6f390: 0x0000000000000003      0x0000000000000010
0x55b9ddb6f3a0: 0x4444444444444444      0x4444444444444444
0x55b9ddb6f3b0: 0x4444444444444444      0x4444444444444444
0x55b9ddb6f3c0: 0x0000000000000000      0x0000000000000000
##########################################################
0x55b9ddb6f3d0: 0x0000000000000000      0x0000000000000051
0x55b9ddb6f3e0: 0x0000000000000004      0x0000000000000010
0x55b9ddb6f3f0: 0x4545454545454545      0x4545454545454545
0x55b9ddb6f400: 0x4545454545454545      0x4545454545454545
0x55b9ddb6f410: 0x0000000000000000      0x0000000000000000
##########################################################
0x55b9ddb6f420: 0x0000000000000000      0x0000000000020be1
0x55b9ddb6f430: 0x0000000000000000      0x0000000000000000
```

この `########` で囲まれた部分のことを、 **Chunk** と呼ぶことにします。
現在見えているものは、大きさが`0x50`のchunkです。この`0x50`は、`sizeof(struct User)`から決定されます。
厳密には`sizeof(struct User) == 0x40`ですが、`malloc()`ではユーザにリクエストされたサイズに対してメタデータとしての0x10byteを加算します。

この文章で説明した内容をコードベースで追ってみましょう。対象のglibcはバージョン2.31です。

まず、chunkに該当する構造体は `struct malloc_chunk` ([/malloc/malloc.c](https://elixir.bootlin.com/glibc/glibc-2.31/source/malloc/malloc.c#L1048))です

```c
struct malloc_chunk {

  INTERNAL_SIZE_T      mchunk_prev_size;  /* Size of previous chunk (if free).  */
  INTERNAL_SIZE_T      mchunk_size;       /* Size in bytes, including overhead. */

  struct malloc_chunk* fd;         /* double links -- used only if free. */
  struct malloc_chunk* bk;

  /* Only used for large blocks: pointer to next larger size.  */
  struct malloc_chunk* fd_nextsize; /* double links -- used only if free. */
  struct malloc_chunk* bk_nextsize;
};
typedef struct malloc_chunk* mchunkptr;
```

`mchunk_size`(以下`size`)は、chunkの大きさを表します。
但し、chunkは必ず8byteアラインされるため、下3bitは必ず0になってしまいます。
それではもったいないため、下3bitはchunk管理用のフラグとして使われます(TBD)。
`fd`/`bk`と`fd_nextsize`/`bk_nextsize`もchunk管理用のフィールドですが、今は置いておきます。

これらのフィールドは基本的に`free()`されたchunkを管理するためのものであり、
`malloc()`されて利用中のchunkでは`prev_size`/`size`以外は使いません。
`malloc()`で返されたchunkでは、`prev_size`/`size`以外の領域を自由に使うことができます:

```txt
-------------------
prev_size | size
------------------- <= malloc()で返されるアドレス
User Data
...
...
...
-------------------
```

heapがめんどくさいのは、`free()`された後です。heapは`free()`するとキャッシングされます。
これは、プログラムが普遍的に持つ性質として「同じサイズのchunkをすぐに再度`malloc()`することが多い」ためです。

glibcのアロケータは`free()`されたchunkを **bins** と呼ばれるリストにキャッシュします。
binsには以下の種類があります
(以下のサイズには、メタデータ用の0x10byte分を含めています)
(`?`は自信ない・`-`は存在しないことを表します):

|  | min size | max size | granularity | max num | list |
|---|---|---|---|---|---|
| **smallbin** | 0x20 | 0x3F0 | 0x10 | ∞ | double-linked |
| **largebin** | 0x400 | ∞ | ★1 | ∞ | double-linked |
| **fastbin** | 0x20 | 0xB0? | 0x10 | ? | single-linked |
| **unsortedbin** | - | - | - | - | double-linked |
| **tcache** | 0x20 | 0x410 | 0x10 | 7 | single-linked |

{{< alert title="★1: largebinのbinごとのサイズ" color="info" >}}
smallbinやtcache等は、binごとに入るサイズが決まっています。
つまり、ある特定のサイズのchunkが欲しい場合にはそのbin内のどのchunkを取得してもメモリ性能は同じになります。
(もちろんメモリアクセスの空間局所性とかキャッシュラインとかを考えるとどれをとるかで差は出るでしょうが...)

largebinの場合は大きいchunkを扱うため、0x10byteごとにbinを分けてしまうと大量のbinが必要になります。
largebinは127個のbinを持っており、それぞれのbinは以下のサイズのchunkを扱います:

| largebin index | granularity | 個数 |
|---|---|---|
| 0   ~  63 | 0x08 | 64 |
| 64  ~  95 | 0x40 | 32 |
| 96  ~ 111 | 0x200 | 16 |
| 112 ~ 119 | 0x1000 | 8 |
| 120 ~ 123 | 0x80000 | 4 |
| 124 ~ 125 | 0x400000 | 2 |
| 126       | 残り全部 | 1 |

binの個数とサイズの区切りが指数関数的に増えたり減ったりしていますね。
大きいサイズのchunkほどリクエストされる機会が少ないためこのようになっています。
{{< /alert >}}

{{< alert title="tcacheの定義のソース" color="info" >}}
上に書いたtcacheのサイズとかの定義は以下のとおりです。

chunkのサイズ(`size`)をtcache binのインデックスに変換するマクロ
([/malloc/malloc.c](https://elixir.bootlin.com/glibc/glibc-2.31/source/malloc/malloc.c#L311)):
```c
// 注: `MINSIZE`は`0x20`, `MALLOC_ALIGNMENT`は`0x10`
# define csize2tidx(x) (((x) - MINSIZE + MALLOC_ALIGNMENT - 1) / MALLOC_ALIGNMENT)
```

tcacheを使うかどうか判断する部分
([/malloc/malloc.c](https://elixir.bootlin.com/glibc/glibc-2.31/source/malloc/malloc.c#L3656)):
```c
# define TCACHE_MAX_BINS		64
// _int_malloc()
if (tcache && tc_idx < mp_.tcache_bins) { /** tcacheからchunkを取得する処理 **/ }
```

他のbinsについても同様に`malloc.c`に定義が書いてあるので探してみてください。
色々とマクロがあって大変かもしれませんが、慣れると世界が平和になります。
{{< /alert >}}

各binはchunkをリスト構造で管理しています。
`malloc()`でchunkが要求されたときには、このリストから適切なものを選択してリストから外しユーザに提供します。
各キャッシュの用途と特徴を説明すると、以下のようになります:

- **tcache**: スレッドごとに用意されているため早い。binに入るchunkの個数上限が決まっている。
- **fastbin**: 隣接するchunkとマージ( *consolidate* )されることがない一匹狼。よって単純なLIFOでchunkを取得できて早い。
- **smallbin**: 他のchunkとマージされたりする。かと思えば、分割されてtcacheに入ったりもする。
- **largebin**: でかい。とにかくでかい。
- **unsortedbin**: tcacheかfastbinに入れられないchunkは取り敢えずこいつに入れておいて、あとでsmallbin/largebinに入れる。

{{< alert title="chunkのconsolidateとfastbinについて" color="info" >}}
基本的にfreeされたchunkは隣接するchunkとマージ(consolidate)されます。
これは、小さなchunkが散在(メモリフラグメンテーション)することを防ぐためです。
そのため、 **smallbin/largebinのchunk同士がメモリ上で隣接することはありません** (多分)。

しかし、fastbinのchunkはマージされません。
これは、fastbinのchhunkが`size`内の`AMP`bitsの内`P`(PREV_INUSE)を立てたままにしておくため、
アロケータから見るとfreeされていないように見せているためです。
{{< /alert >}}

定義の話ばかりになってしまったので、GDBで実際に確認してみましょう。

先程のheapの状態から、1番目と3番目のchunkを`free()`してみます。
binsの様子は`gef`の`bins`コマンドで確認できます:

```gef
gef> bins
---------------------------------------------------------- Tcachebins for arena '*0x7f70d8a91b80' ----------------------------------------------------------
[+] Tcachebins[idx=3, size=0x50, @0x55b9ddb6f0a8] count=2
 ->  Chunk(addr=0x55b9ddb6f380, size=0x50, flags=PREV_INUSE, fd=0x55b9ddb6f2f0, bk=0x55b9ddb6f010)
 ->  Chunk(addr=0x55b9ddb6f2e0, size=0x50, flags=PREV_INUSE, fd=0x0, bk=0x55b9ddb6f010)
[+] Found 2 chunks in tcache.
----------------------------------------------------------- Fastbins for arena '*0x7f70d8a91b80' -----------------------------------------------------------
[+] Found 0 chunks in fastbin.
--------------------------------------------------------- Unsorted Bin for arena '*0x7f70d8a91b80' ---------------------------------------------------------
[+] Found 0 chunks in unsorted bin.
---------------------------------------------------------- Small Bins for arena '*0x7f70d8a91b80' ----------------------------------------------------------
[+] Found 0 chunks in 0 small non-empty bins.
---------------------------------------------------------- Large Bins for arena '*0x7f70d8a91b80' ----------------------------------------------------------
[+] Found 0 chunks in 0 large non-empty bins.
```

どちらもtcacheに入りましたね。
これは、今回使っているchunkのサイズが`0x50`(< `0x410`)であるためです。
メモリをダンプしてみるとこんな感じです:

```gef
gef> x/100gx 0x55b9ddb6f290
##############################################################
0x55b9ddb6f290: 0x0000000000000000      0x0000000000000051
0x55b9ddb6f2a0: 0x0000000000000000      0x0000000000000010
0x55b9ddb6f2b0: 0x4141414141414141      0x4141414141414141
0x55b9ddb6f2c0: 0x4141414141414141      0x4141414141414141
0x55b9ddb6f2d0: 0x0000000000000000      0x0000000000000000
#### A: freeしたchunk #########################################
0x55b9ddb6f2e0: 0x0000000000000000      0x0000000000000051
0x55b9ddb6f2f0: 0x0000000000000000      0x000055b9ddb6f010
0x55b9ddb6f300: 0x4242424242424242      0x4242424242424242
0x55b9ddb6f310: 0x4242424242424242      0x4242424242424242
0x55b9ddb6f320: 0x0000000000000000      0x0000000000000000
##########################################################
0x55b9ddb6f330: 0x0000000000000000      0x0000000000000051
0x55b9ddb6f340: 0x0000000000000002      0x0000000000000010
0x55b9ddb6f350: 0x4343434343434343      0x4343434343434343
0x55b9ddb6f360: 0x4343434343434343      0x4343434343434343
0x55b9ddb6f370: 0x0000000000000000      0x0000000000000000
#### B: freeしたchunk #########################################
0x55b9ddb6f380: 0x0000000000000000      0x0000000000000051
0x55b9ddb6f390: 0x000055b9ddb6f2f0      0x000055b9ddb6f010
0x55b9ddb6f3a0: 0x4444444444444444      0x4444444444444444
0x55b9ddb6f3b0: 0x4444444444444444      0x4444444444444444
0x55b9ddb6f3c0: 0x0000000000000000      0x0000000000000000
##############################################################
0x55b9ddb6f3d0: 0x0000000000000000      0x0000000000000051
0x55b9ddb6f3e0: 0x0000000000000004      0x0000000000000010
0x55b9ddb6f3f0: 0x4545454545454545      0x4545454545454545
0x55b9ddb6f400: 0x4545454545454545      0x4545454545454545
0x55b9ddb6f410: 0x0000000000000000      0x0000000000000000
##############################################################
0x55b9ddb6f420: 0x0000000000000000      0x0000000000020be1
```

tcacheは`free()`したchunkをリストの根本に挿入します。
その際`chunk`の`fd`を、挿入前にリストの根本にあったchunkのアドレスに書き換えます。
今回は`1 -> 3`の順で`free`したため、`Chunk B`が根本に入っています。
確かに`Chunk B`の`fd`に該当する部分には、`Chunk A`のアドレス`0x000055b9ddb6f2f0`が書き込まれていますね:

```gef
#### B: freeしたchunk #########################################
0x55b9ddb6f380: 0x0000000000000000      0x0000000000000051
0x55b9ddb6f390: 0x000055b9ddb6f2f0 =fd  0x000055b9ddb6f010
0x55b9ddb6f3a0: 0x4444444444444444      0x4444444444444444
0x55b9ddb6f3b0: 0x4444444444444444      0x4444444444444444
0x55b9ddb6f3c0: 0x0000000000000000      0x0000000000000000
```

また、tcacheにchunkが繋がっている状態で同じサイズの`malloc()`が呼ばれると、
リストの根本からchunkを取り出してユーザに返します。
上記のheapの状態で新たなユーザを作ってみると以下のようになります:

```gef
gef> bins
---------------------------------------------------------- Tcachebins for arena '*0x7f70d8a91b80' ----------------------------------------------------------
[+] Tcachebins[idx=3, size=0x50, @0x55b9ddb6f0a8] count=1
 ->  Chunk(addr=0x55b9ddb6f2e0, size=0x50, flags=PREV_INUSE, fd=0x0, bk=0x55b9ddb6f010)
[+] Found 1 chunks in tcache.
```

`Chunk B`が根本から取り除かれ、`Chunk A`が根本になっていることが分かります。

## tcache poisoning

さて、tcacheを含めたbinsはリスト構造でchunkを管理しています。
これらのリストは`fd`/`bk`によって互いに繋がっています(single-linked listの場合は`fd`のみ)。

ということはfree済みchunkの`fd`を書き換えてしまうと、このリストは不正な場所に対して繋がってしまうはずです。
さらにその状態で`malloc()`をしてリストからchunkを取得すると、不正な場所に対してchunkが配置されユーザに提供されます。

このようなリストの書き換えをとりわけtcacheに行い、不正なアドレスにchunkを配置することを **tcache poisoning** と呼びます。
tcache poisoningでは、確保したオブジェクトを中身をユーザが読み書きできるかによって得られるプリミティブが変わります。
この問題のケースでは、ユーザがオブジェクト(`struct User`)の中身を自由に読み書きできるため、
tcache poisoningで配置した不正なオブジェクトによってRWプリミティブが得られます。

## tcache poisoningの手順

ここからは再びchallengeに沿って実際のtcache poisoningの手順を見ていきます。

まず、本challengeの脆弱性は2つあります。1つ目は`User.name`の入力にあります:

```c
        readn(users[index]->name, sizeof(struct User));
```

誤って`name`のサイズではなく`struct User`のサイズを指定しているため、
`name`以外のフィールドのサイズ分の0x10byteだけオーバーフローできます。
2つ目は`readn`の実装にあります。

```c
int readn(char *buf, int max) {
  int n = 0;
  char c;

  while (n++ < max) {
    read(0, &c, 1);
    if (c == '\n') break;
    *buf++ = c;
  }

  *buf = '\x00';
  return n;
}
```

`max`文字だけ入力された場合、1byte文だけ`\x00`(NULL文字)が溢れてしまいますね。
オーバーフローの中でも、このようなNULL Terminationに起因するものを **NULL-byte Overflow** と呼びます(呼ばないかも)。

例として、以下のようなheapの状態を考えます:

```gef
##############################################################
0x55b9ddb6f290: 0x0000000000000000      0x0000000000000051
0x55b9ddb6f2a0: 0x0000000000000000      0x0000000000000010
0x55b9ddb6f2b0: 0x4141414141414141      0x4141414141414141
0x55b9ddb6f2c0: 0x4141414141414141      0x4141414141414141
0x55b9ddb6f2d0: 0x4141414141414141      0x4141414141414141
##############################################################
0x55b9ddb6f2e0: 0x0000000000000000      0x0000000000000051 =size  <== ここまで自由にオーバーフローできる
0x55b9ddb6f2f0: 0x000055b9ddb6f3e0 =fd  0x000055b9ddb6f010 =bk
0x55b9ddb6f300: 0x4242424242424242      0x4242424242424242
0x55b9ddb6f310: 0x4242424242424242      0x4242424242424242
0x55b9ddb6f320: 0x0000000000000000      0x0000000000000000
```

この状態で、上にいるユーザの`name`を最大限オーバーフローすると、下にいるユーザの`size`までを自由に書き換えることができます。
また、NULL-byte overflowによって **`fd`の下1byteをNULLにすることができます** 。
たったの1byteで、かつNULLでしか書き換えられませんが、これはheap exploitにおいてとても大きいプリミティブになります。

現在tcacheが以下のようになっていると考えましょう:

```gef
(tcacheの根本) -> 0x55b9ddb6f2f0 -> 0x000055b9ddb6f3e0 -> some -> some
```

この場合、`fd`の下1byteをNULL-overflowすると以下のようになります:

```gef
(tcacheの根本) -> 0x55b9ddb6f2f0 -> 0x000055b9ddb6f300 -> ???
                                                    ^^
```

書き換えられたリストに繋がっている`0x000055b9ddb6f300`を見てみると、
これは **下のchunkの`name`部分を指すことになります** 。
つまり、 **`name`内に偽物のchunkを作ってやるとリストに任意のアドレスを繋げることができます** 。

上の図では下のchunkの`name`として`B`(0x42)を沢山入力してあります。
ここで、偽のchunkとして`name`に`p64(0) + p64(0x51) + p64(0xDEADBEEFCAFEBABE)`を入力します:

```gef
##############################################################
0x55b9ddb6f290: 0x0000000000000000      0x0000000000000051
0x55b9ddb6f2a0: 0x0000000000000000      0x0000000000000010
0x55b9ddb6f2b0: 0x4141414141414141      0x4141414141414141
0x55b9ddb6f2c0: 0x4141414141414141      0x4141414141414141
0x55b9ddb6f2d0: 0x4141414141414141      0x4141414141414141
##############################################################
0x55b9ddb6f2e0: 0x0000000000000000      0x0000000000000051 =size
0x55b9ddb6f2f0: 0x000055b9ddb6f3e0 =fd  0x000055b9ddb6f010 =bk
0x55b9ddb6f300: 0x0000000000000000      0x0000000000000051    -- fake chunk -----
0x55b9ddb6f310: 0xDEADBEEFCAFEBABE      0x4242424242424242    fake fd | fake bk |
0x55b9ddb6f320: 0x4242424242424242      0x4242424242424242                      |
0x55b9ddb6f330: 0x0000000000000000      0x0000000000000000                      |
0x55b9ddb6f340: 0x0000000000000000      0x0000000000000000    -------------------
```

先程新しくtcacheに繋げられた`0x000055b9ddb6f300`を見てみると、新しいfake chunkを作り上げることができています。
このfake chunkの`fd`は、先程適当に決めた`0xDEADBEEFCAFEBABE`になっています。
よってtcache listは以下のとおりです:

```gef
(tcacheの根本) -> 0x55b9ddb6f2f0 -> 0x000055b9ddb6f300 -> 0xDEADBEEFCAFEBABE
                                                    ^^    ^^^^^^^^^^^^^^^^^^
```

任意のアドレスがtcacheに繋がりました。
この状態で3回`malloc()`してやれば、`0xDEADBEEFCAFEBABE`というアドレスにchunkが配置されます。
あとはユーザの情報を好きに入力してやれば、任意のアドレスに任意の値を書き込めるようになります(AAW)。

## 今は亡き`__free_hook`

さて、AAWが実現できました。
あとは何を書き換えるかですが、今回は最もシンプルな方法を使います。

glibcのメモリアロケータは、`malloc()`や`free()`といった関数をフックできるように `__malloc_hook` / `__free_hook` という変数を用意しています([/malloc/malloc.c](https://elixir.bootlin.com/glibc/glibc-2.31/source/malloc/malloc.c#L1847)):

```c
void *weak_variable (*__malloc_hook)
  (size_t __size, const void *) = malloc_hook_ini;
```

この関数ポインタは、`_int_malloc()`や`_int_free()`の先頭で呼ばれます([/malloc/malloc.c](https://elixir.bootlin.com/glibc/glibc-2.31/source/malloc/malloc.c#L3030)):

```c
  void *(*hook) (size_t, const void *)
    = atomic_forced_read (__malloc_hook);
  if (__builtin_expect (hook != NULL, 0))
    return (*hook)(bytes, RETURN_ADDRESS (0));
```

よって、この変数を書き換えて任意のアドレスに設定することで、`malloc()`や`free()`の呼び出しをトリガーとして任意のアドレスにRIPを飛ばすことができます。

{{< alert title="今は亡き..." color="info" >}}
これらのhook関数は、最新のglibcでは消えてなくなっています。
まぁアンダースコアがついた名前なので内部的・開発目的でしか使わないものだったのでしょう。

消えたことが信じられない方は[glibc 2.35](https://elixir.bootlin.com/glibc/glibc-2.35/source/malloc/malloc.c)をgrepしてみてください。
{{< /alert >}}

------------------------------

以上でtcache poisoningを使って本Challengeを解くことが出来るかと思います。
ぜひリモートサーバでflagを取得してみてください。

------------------------------

## Exercise

### 1. tcache2hook

[[Distribution File]](tcache-d5c0a4e85196bfd8132297ed0614d089559a605029d9bc3d31649b2498fa6b8c.tar.gz)

```sh
nc sc.skb.pw 49402
```
