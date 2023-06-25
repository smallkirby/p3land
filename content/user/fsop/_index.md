---
title: "FSOP"
description: "FSOPと関数ポインタの書き換え"
draft: false
weight: 4
---

## Challenge

[[Distribution File]](https://r2.p3land.smallkirby.com/fsop-8d84f73ac2cb7479e0c12867f32a6f38040b86f6e6c3f02c549098b096b81de9.tar.gz)

```sh
nc sc.skb.pw 49403
```

## 既存の構造体の利用・関数ポインタの書き換え

exploitの基本的なプリミティブであるREAD/WRITEプリミティブには、いくつかのレベルがあります。
たとえば、どれだけ好きな値をWRITEできるかが考えられます。
アプリケーション上の制約によってはASCII文字列しか入力できないとか、あるいは30文字しか入力できないなどの文字数制限がある場合があります。
また、FSBの章にも書いたとおりOverflowなのかOoBなのかによってターゲット以外の余計なところも書き換えてしまうか否かが決まります。
それからREADできる値にも種類があり、libcbaseをleakできるもの・`.text`baseをleakできるもの・heap/stackをleakできるもの等があります。

exploitをする際には、得られるプリミティブとそれらの種類を考慮しながら最終的な目標(userlandならシェルを取る・kernelならrootを取る・もしくは他の方法でflagだけを読み出す)を達成する道筋を立てていきます。
これがしばしばpwnがパソコンを使ったパズルみたいだと言われる理由です。

{{< alert title="pwnとパズル" color="info" >}}
exploit/pwnはパズルみたいで面白いですが、これはたまたまプログラムというものがパズル的性質を持っているだけであり、
pwn以外でもpwn的面白さを持っているゲームは存在します。
パソコンは好きじゃないけどpwn的面白さが好きという人には、[Baba Is You](https://store.steampowered.com/app/736260/Baba_Is_You/?l=japanese) というゲームがおすすめだったりします。
{{< /alert >}}

本章では、RIPを取るための手法として **FSOP: File Structure Oriented Programming** を扱います。
これはglibcが標準的に利用する`stdin`や`stdout`などの`FILE`構造体を書き換える、とりわけその内部にある関数ポインタを書き換えることで、任意の関数を呼び出す手法です。
このような、既存の構造体を書き換えたり関数ポインタに細工をするという手法はuserlandだけではなくkernelのexploitにおいても頻繁に利用する手法です。
ぜひその感覚と考え方を手を動かしつつ体験してみてください。

## `struct FILE` / `struct _IO_FILE_plus`

`struct FILE`は、`stdin`や`stdout`・その他ユーザが開いたファイルの入出力処理やバッファリング・ストリーミング等を行うための構造体です([/libio/bits/types/struct_FILE.h](https://elixir.bootlin.com/glibc/glibc-2.35/source/libio/bits/types/struct_FILE.h#L49)):

```c
struct _IO_FILE
{
  int _flags;		/* High-order word is _IO_MAGIC; rest is flags. */
  /* The following pointers correspond to the C++ streambuf protocol. */
  char *_IO_read_ptr;	/* Current read pointer */
  char *_IO_read_end;	/* End of get area. */
  char *_IO_read_base;	/* Start of putback+get area. */
  char *_IO_write_base;	/* Start of put area. */
  char *_IO_write_ptr;	/* Current put pointer. */
  char *_IO_write_end;	/* End of put area. */
  char *_IO_buf_base;	/* Start of reserve area. */
  char *_IO_buf_end;	/* End of reserve area. */
  /* The following fields are used to support backing up and undo. */
  char *_IO_save_base; /* Pointer to start of non-current get area. */
  char *_IO_backup_base;  /* Pointer to first valid character of backup area */
  char *_IO_save_end; /* Pointer to end of non-current get area. */
  struct _IO_marker *_markers;
  struct _IO_FILE *_chain;
  int _fileno;
  int _flags2;
  __off_t _old_offset; /* This used to be _offset but it's too small.  */
  /* 1+column number of pbase(); 0 is unknown. */
  unsigned short _cur_column;
  signed char _vtable_offset;
  char _shortbuf[1];
  _IO_lock_t *_lock;
#ifdef _IO_USE_OLD_IO_FILE
};
```

`stdin`/`stdout`などは実際は`struct FILE`をラップする`struct _IO_FILE_plus`という構造体です([/libio/libioP.h](https://elixir.bootlin.com/glibc/glibc-2.35/source/libio/libioP.h#L324)):

```c
struct _IO_FILE_plus
{
  _IO_FILE file;
  const struct _IO_jump_t *vtable;
};
```

`_IO_FILE`の直後に`struct _IO_jump_t`型のポインタを持っていることが分かります。
これは、ファイルの入出力に利用する関数ポインタのリストです([/libio/libioP.h](https://elixir.bootlin.com/glibc/glibc-2.35/source/libio/libioP.h#L293)):

```c
struct _IO_jump_t
{
    JUMP_FIELD(size_t, __dummy);
    JUMP_FIELD(size_t, __dummy2);
    JUMP_FIELD(_IO_finish_t, __finish);
    JUMP_FIELD(_IO_overflow_t, __overflow);
    JUMP_FIELD(_IO_underflow_t, __underflow);
    JUMP_FIELD(_IO_underflow_t, __uflow);
    JUMP_FIELD(_IO_pbackfail_t, __pbackfail);
    /* showmany */
    JUMP_FIELD(_IO_xsputn_t, __xsputn);
    JUMP_FIELD(_IO_xsgetn_t, __xsgetn);
    JUMP_FIELD(_IO_seekoff_t, __seekoff);
    JUMP_FIELD(_IO_seekpos_t, __seekpos);
    JUMP_FIELD(_IO_setbuf_t, __setbuf);
    JUMP_FIELD(_IO_sync_t, __sync);
    JUMP_FIELD(_IO_doallocate_t, __doallocate);
    JUMP_FIELD(_IO_read_t, __read);
    JUMP_FIELD(_IO_write_t, __write);
    JUMP_FIELD(_IO_seek_t, __seek);
    JUMP_FIELD(_IO_close_t, __close);
    JUMP_FIELD(_IO_stat_t, __stat);
    JUMP_FIELD(_IO_showmanyc_t, __showmanyc);
    JUMP_FIELD(_IO_imbue_t, __imbue);
};
```

例として、`puts()`がglibcでどのように実装されているか見てみましょう([/libio/ioputs.c](https://elixir.bootlin.com/glibc/glibc-2.35/source/libio/ioputs.c#L31)):

```c
int
_IO_puts (const char *str)
{
  int result = EOF;
  size_t len = strlen (str);
  _IO_acquire_lock (stdout);

  if ((_IO_vtable_offset (stdout) != 0
       || _IO_fwide (stdout, -1) == -1)
      && _IO_sputn (stdout, str, len) == len
      && _IO_putc_unlocked ('\n', stdout) != EOF)
    result = MIN (INT_MAX, len + 1);

  _IO_release_lock (stdout);
  return result;
}
```

最初にロックを撮ったり諸々して、`if`の中ほどで`_IO_sputn()`を呼んでいます:

```c
#define _IO_sputn(__fp, __s, __n) _IO_XSPUTN (__fp, __s, __n)
#define _IO_XSPUTN(FP, DATA, N) JUMP2 (__xsputn, FP, DATA, N)
#define JUMP2(FUNC, THIS, X1, X2) (_IO_JUMPS_FUNC(THIS)->FUNC) (THIS, X1, X2)
# define _IO_JUMPS_FUNC(THIS) (IO_validate_vtable (_IO_JUMPS_FILE_plus (THIS)))
#define _IO_JUMPS_FILE_plus(THIS) \
  _IO_CAST_FIELD_ACCESS ((THIS), struct _IO_FILE_plus, vtable)
```

マクロはこのあとも続いていきますが、要は`struct _IO_FILE_plus`の`vtable`の中から該当するメンバ`__xsputn`を呼び出していることが分かります。この関数ポインタは、実際には以下の値が入っています:

```gef
gef> p _IO_2_1_stdout_->vtable->__xsputn
$18 = (_IO_xsputn_t) 0x7f6ab248b680 <_IO_new_file_xsputn>
```

最終的には`_IO_new_file_xsputn()`([/libio/fileops.c](https://elixir.bootlin.com/glibc/glibc-2.35/source/libio/fileops.c#L1195))が呼び出されています。このようにして、`FILE`は対応する関数を関数ポインタから呼び出すことでファイルの種類に応じて適切に振る舞いを変えながら入出力を行います。

## FSOP

関数ポインタと言われると、関数ポインタを書き換えてRIPを取りたくなると思います。
しかし、関数テーブル `_IO_file_jumps` がどこにマップされているかを見てみると以下のようになります:

```c
gef> p/x &_IO_file_jumps
$20 = 0x7f6ab2616600

gef> vmmap
[ Legend:  Code | Heap | Stack | Writable | RWX]
Start              End                Size               Offset             Perm Path
...
0x00007f6ab2400000 0x00007f6ab2428000 0x0000000000028000 0x0000000000000000 r-- /usr/lib/x86_64-linux-gnu/libc.so.6
0x00007f6ab2428000 0x00007f6ab25bd000 0x0000000000195000 0x0000000000028000 r-x /usr/lib/x86_64-linux-gnu/libc.so.6  <-  $rcx, $rip
0x00007f6ab25bd000 0x00007f6ab2615000 0x0000000000058000 0x00000000001bd000 r-- /usr/lib/x86_64-linux-gnu/libc.so.6
0x00007f6ab2615000 0x00007f6ab2619000 0x0000000000004000 0x0000000000214000 r-- /usr/lib/x86_64-linux-gnu/libc.so.6
0x00007f6ab2619000 0x00007f6ab261b000 0x0000000000002000 0x0000000000218000 rw- /usr/lib/x86_64-linux-gnu/libc.so.6
...
0xffffffffff600000 0xffffffffff601000 0x0000000000001000 0x0000000000000000 --x [vsyscall]
```

`_IO_file_jumps`のアドレスは`0x00007f6ab2615000 - 0x00007f6ab2615000`にマップされており、
この領域は`r--`でマップされていることが分かります。
それもそのはずで、このテーブルは`const`で定義されています([/libio/fileops.c](https://elixir.bootlin.com/glibc/glibc-2.35/source/libio/fileops.c#L1432))。
つまり、 **`_IO_file_jumps`内の関数ポインタを書き換えることはできません** 。

となると次に考えるのは、自前のフェイクvtableを用意したあと、`_IO_FILE_plus.vtable`を偽のvtableを指すように書き換えてしまうことです。
これだと確かにRWXプロットの制限には引っかかりません。
しかし、先程の`_IO_sputn()`の呼び出しマクロを辿ってみると以下の箇所に突き当たることが分かります:

```c
# define _IO_JUMPS_FUNC(THIS) (IO_validate_vtable (_IO_JUMPS_FILE_plus (THIS)))
```

`IO_validate_vtable`は以下のように定義されています([/libio/libioP.h](https://elixir.bootlin.com/glibc/glibc-2.35/source/libio/libioP.h#L935)):

```c
static inline const struct _IO_jump_t *
IO_validate_vtable (const struct _IO_jump_t *vtable)
{
  /* Fast path: The vtable pointer is within the __libc_IO_vtables
     section.  */
  uintptr_t section_length = __stop___libc_IO_vtables - __start___libc_IO_vtables;
  uintptr_t ptr = (uintptr_t) vtable;
  uintptr_t offset = ptr - (uintptr_t) __start___libc_IO_vtables;
  if (__glibc_unlikely (offset >= section_length))
    /* The vtable pointer is not in the expected section.  Use the
       slow path, which will terminate the process if necessary.  */
    _IO_vtable_check ();
  return vtable;
}
```

この関数は、指定された`vtable`が有効な領域内を指しているかどうかをチェックし、そうでない場合にはプロセスを終了させます。
この有効な領域内というのは以下に示すような範囲であり、先程の`vmmap`のこともわかるとおり全てRead Onlyでマップされています:

```gef
gef> p __start___libc_IO_vtables
$21 = 0x7f6ab2615a00 <_IO_helper_jumps> ""
gef> p __stop___libc_IO_vtables
$22 = 0x7f6ab2616768 ""
```

すなわち、この場合は`vtable`の指し示す先を書き換えて偽の`vtable`を用意することもできません。

{{< alert title="__start___libc_IO_vtables の定義" color="info" >}}
`IO_validate_vtable()`内で利用されている`__start___libc_IO_vtables`/`__stop___libc_IO_vtables`の定義ですが、
おそらくvtableの定義につけられたattribute `__libc_IO_vtables` によって生成されていると思われます。

```c
static const struct _IO_jump_t _IO_helper_jumps libio_vtable = ...
#define libio_vtable __attribute__ ((section ("__libc_IO_vtables")))
```

ただし、glibcのどこでこの属性をもとにして上記の定数を生成しているかについては調べていないため、
興味のある人は調べて教えてください。
{{< /alert >}}

詰んだ感じがしますが、2022年10月に[kylebot](https://twitter.com/ky1ebot)(kCTFやpwn2ownで荒稼ぎしてる人)が[ブログ](https://blog.kylebot.net/2022/10/22/angry-FSROP/)において[angr](https://angr.io/)を使ってジャンプテーブルのvalidationが存在しないパスを発見しています。

このパスでは`_IO_file_jumps`テーブルではなく、`_IO_wfile_jumps`テーブルを利用します([/libio/wfileops.c](https://elixir.bootlin.com/glibc/glibc-2.35/source/libio/wfileops.c#L1021)):

```c
const struct _IO_jump_t _IO_wfile_jumps libio_vtable =
{
  JUMP_INIT_DUMMY,
  JUMP_INIT(finish, _IO_new_file_finish),
  JUMP_INIT(overflow, (_IO_overflow_t) _IO_wfile_overflow),
  JUMP_INIT(underflow, (_IO_underflow_t) _IO_wfile_underflow),
  JUMP_INIT(uflow, (_IO_underflow_t) _IO_wdefault_uflow),
  JUMP_INIT(pbackfail, (_IO_pbackfail_t) _IO_wdefault_pbackfail),
  JUMP_INIT(xsputn, _IO_wfile_xsputn),
  JUMP_INIT(xsgetn, _IO_file_xsgetn),
  JUMP_INIT(seekoff, _IO_wfile_seekoff),
  JUMP_INIT(seekpos, _IO_default_seekpos),
  JUMP_INIT(setbuf, _IO_new_file_setbuf),
  JUMP_INIT(sync, (_IO_sync_t) _IO_wfile_sync),
  JUMP_INIT(doallocate, _IO_wfile_doallocate),
  JUMP_INIT(read, _IO_file_read),
  JUMP_INIT(write, _IO_new_file_write),
  JUMP_INIT(seek, _IO_file_seek),
  JUMP_INIT(close, _IO_file_close),
  JUMP_INIT(stat, _IO_file_stat),
  JUMP_INIT(showmanyc, _IO_default_showmanyc),
  JUMP_INIT(imbue, _IO_default_imbue)
};
```

注目すべきはこの中の`overflow`フィールドに入ってる `_IO_wfile_overflow()` です。
これは内部で`_IO_wdoallocbuf()`を呼びます:

```c
wint_t
_IO_wfile_overflow (FILE *f, wint_t wch)
{
  if (f->_flags & _IO_NO_WRITES) /* SET ERROR */
    {
      ...
      return WEOF;
    }
  /* If currently reading or no buffer allocated. */
  if ((f->_flags & _IO_CURRENTLY_PUTTING) == 0)
    {
      /* Allocate a buffer if needed. */
      if (f->_wide_data->_IO_write_base == 0)
	{
	  _IO_wdoallocbuf (f);
    ...
	}
      else
    }
  ...
}

void
_IO_wdoallocbuf (FILE *fp)
{
  if (fp->_wide_data->_IO_buf_base)
    return;
  if (!(fp->_flags & _IO_UNBUFFERED))
    if ((wint_t)_IO_WDOALLOCATE (fp) != WEOF)
      return;
  _IO_wsetb (fp, fp->_wide_data->_shortbuf,
		     fp->_wide_data->_shortbuf + 1, 0);
}

#define _IO_WDOALLOCATE(FP) WJUMP0 (__doallocate, FP)
#define WJUMP0(FUNC, THIS) (_IO_WIDE_JUMPS_FUNC(THIS)->FUNC) (THIS)
#define _IO_WIDE_JUMPS_FUNC(THIS) _IO_WIDE_JUMPS(THIS)
#define _IO_WIDE_JUMPS(THIS) \
  _IO_CAST_FIELD_ACCESS ((THIS), struct _IO_FILE, _wide_data)->_wide_vtable
```

`_IO_wdoallocbuf()`は`_IO_WDOALLOCATE`マクロを実行してジャンプテーブルにアクセスします。
このマクロを辿っていくと、 **`_IO_file_jumps`の場合と違って`vtable`の存在する範囲チェックが存在しないことが分かります** 。

つまり、`FILE._wide_data._wide_vtable`テーブルが指し示す先は自由に書き換えてしまえます。
以上を踏まえて、FSOPの手順をまとめると以下のようになります:

1. `FILE._wide_data._wide_vtable`を任意に書き込めるアドレスを指すように書き換える
2. 書き換えた先に偽の`vtable`を用意し、`doallocate`に当たる部分を実行したい命令のアドレスに書き換える
3. `FILE._vtable`を`_IO_file_jumps`から`_IO_wfile_jumps`に書き換える (この書き換え自体は、`_IO_wfile_jumps`が有効なアドレスにあるためOK)
4. `FILE._vtable.__overflow`(==`_IO_wfile_overflow`)を呼び出す
5. その内部で、上に見たように`doallocate`(任意の命令アドレス)にRIPが移る

4の`__overflow`の呼び出しについてですが、glibcではexit時に呼ばれる関数 `__libc_atexit` として `_IO_cleanup` が登録されています。
この関数は、内部で `_IO_flush_all_lockp()` を呼び出します:

```c

_IO_flush_all_lockp (int do_lock)
{
  int result = 0;
  FILE *fp;
...
  for (fp = (FILE *) _IO_list_all; fp != NULL; fp = fp->_chain)
    {
      ...
      if (((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base)
        || (_IO_vtable_offset (fp) == 0
          && fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr
              > fp->_wide_data->_IO_write_base))
        )
      && _IO_OVERFLOW (fp, EOF) == EOF)
        result = EOF;
 
    ...
    }
...
}
```

よって、`__overflow`の呼び出し時には単純に`exit`するパスを通ればよいということが分かります。

## FSOPの制約

ここまでで大まかなFSOPの手順が分かったと思います。
しかし、 **このような既存の構造体を利用するexploitには構造体が満たすべき制約がついてまわります** 。

例えば先程の`_IO_flush_all_lockp()`関数が`_IO_OVERFLOW`に到達するための制限だけ見ても以下のものが挙げられます:

- `fp->_mode <= 0`
- `fp->_IO_write_ptr > fp->_IO_write_base`

または

- `fp->_mode > 0`
- `fp->_wide_data->_IO_write_ptr > fp->_wide_data->_IO_write_base`

`overflow`が呼び出されたあとも、いくつか満たすべき制約が存在します(`Exercise 1`)。
とりわけOverflowのような線形WRITEでは、書き換えたいところだけを部分的に書き換えることは難しく、
必然的に`FILE`構造体を最初から最後まで書き換えてやる必要があります。
よってその際にはこれらの制約を全て満たし、目的のパスまで到達させてあげる必要があります。

## 本Challengeの概要

### 脆弱性

FSOP自体の説明は以上で終わりです。最後に少しだけ本challengeの概要を見てみます。
もう解けそうな人は`Exercise`に進んで良いと思います。

本challengeのプログラムは[base64](https://ja.wikipedia.org/wiki/Base64)のデコード・エンコードをしてくれます。実際のデコード・エンコードは[適当に見つけたMITライセンスで配布されてるライブラリ](https://github.com/joedf/base64.c)を使っています:

```c
struct Data {
  char *buf;
  size_t size;
};
struct Data *datas[MAX_DATA] = {0};

void encode(int index) {
  struct Data *data = datas[index];
  int size = get_size(index);
  if (data == NULL) {
    data = malloc(sizeof(struct Data));
    data->buf = malloc(size);
    data->buf[0] = ENCODE_TOKEN_CHAR;
    data->size = size;
    datas[index] = data;
  }

  print("Content > ");
  readn(data->buf, size);
  char *tmp = b64_encode(data->buf, strlen(data->buf));
  memcpy(data->buf + 1, tmp, strlen(tmp));

  put(data->buf + 1);
  free(tmp);
}
```

サイズを指定させて入力を受け付けた後、`b64_encode()`でエンコードしてバッファに格納しています。

脆弱性は、`memcpy(data->buf + 1, tmp, strlen(tmp))`でbase64エンコードした文字列を`buf`に格納する部分です。
base64では、エンコードした後のバイト数が30%程度増加します。
それにも関わらずエンコード前のサイズ分しか確保していないバッファに`memcpy`するのでオーバーフローが発生します。

ここで、2つほど適当に`encode`したあとのheapを見てみましょう:

```gef
gef> x/60gx 0x564cfc064290
#### Data A ######################################################
0x564cfc064290: 0x0000000000000000      0x0000000000000021
0x564cfc0642a0: 0x0000564cfc0642c0      0x0000000000000040
#### Buf  A ######################################################
0x564cfc0642b0: 0x0000000000000000      0x0000000000000051
0x564cfc0642c0: 0x0000003d3d515141      0x0000000000000000
0x564cfc0642d0: 0x0000000000000000      0x0000000000000000
0x564cfc0642e0: 0x0000000000000000      0x0000000000000000
0x564cfc0642f0: 0x0000000000000000      0x0000000000000000
#### Data B ######################################################
0x564cfc064300: 0x0000000000000000      0x0000000000000021
0x564cfc064310: 0x0000564cfc064330      0x0000000000000040
#### Buf  B ######################################################
0x564cfc064320: 0x0000000000000000      0x0000000000000051
0x564cfc064330: 0x0000003d3d515141      0x0000000000000000
0x564cfc064340: 0x0000000000000000      0x0000000000000000
0x564cfc064350: 0x0000000000000000      0x0000000000000000
0x564cfc064360: 0x0000000000000000      0x0000000000000000
#### TOP #########################################################
0x564cfc064370: 0x0000000000000000      0x0000000000020c91
```

`struct Data`とエンコードした後の文字列を格納するバッファがそれぞれ2つずつ生成されていますね。
とりわけ`Data`には対応するバッファのアドレスとサイズが格納されていることが分かります。

ここで、`Buf A`のエンコードされた文字列をオーバーフローさせると`Data B`を書き換えられそうだということが分かります。
**`Data B`の`buf`アドレスを書き換えると、次に`Data B`のバッファに対してエンコード・デコードを行う際に書き換えたアドレスに対して書き込みを行えそうですね** 。

例えば入力された文字列をエンコードした後の文字列が長さ`0x50`であり、かつ最後が`P`(`0x70`)で終わっていたとすると、
heapの状態は以下になります(なお、エンコードされた文字列は`buf + 1`からコピーされるようになっています):

```
#### Data A ######################################################
0x564cfc064290: 0x0000000000000000      0x0000000000000021
0x564cfc0642a0: 0x0000564cfc0642c0      0x0000000000000040
#### Buf  A ######################################################
0x564cfc0642b0: 0x0000000000000000      0x0000000000000051
0x564cfc0642c0: 0x4141414141414145      0x4141414141414141
0x564cfc0642d0: 0x4141414141414141      0x4141414141414141
0x564cfc0642e0: 0x4141414141414141      0x4141414141414141
0x564cfc0642f0: 0x4141414141414141      0x4141414141414141
#### Data B ######################################################
0x564cfc064300: 0x4141414141414141      0x4141414141414141
0x564cfc064310: 0x0000564cfc064370      0x0000000000000040         <== overflowで書き換えられる
#### Buf  B ######################################################
0x564cfc064320: 0x0000000000000000      0x0000000000000051
0x564cfc064330: 0x0000003d3d515141      0x0000000000000000
0x564cfc064340: 0x0000000000000000      0x0000000000000000
0x564cfc064350: 0x0000000000000000      0x0000000000000000
0x564cfc064360: 0x0000000000000000      0x0000000000000000
#### TOP #########################################################
0x564cfc064370: 0x0000000000000000      0x0000000000020c91          <== `Data B`のバッファが新たに指す場所
```

`Data B`のバッファがheap内の関係ないところを指すようになりました。
これで`Data B`から次にデータを読み書きする際に、heap内の関係ないところにアクセスできるようになりました。

このプリミティブを使うことで、AAR/AAWを実現することができます。
AAR/AAWを得るのは`Exercise 2`とします。

### libcbase leak

FSOPをするためにはlibcbaseをleakする必要があります。
今回は確保するバッファサイズをユーザが任意に指定し、かつ`free()`も任意のタイミングで行えるため **自由にunsorted chunkを生成することができます** 。

[heap](/user/tcache)の章でもやったとおり、unsortedbinはdouble-linked listでchunkを管理しており、
`fd`/`bk`にはそれぞれ前後のchunkのアドレスが格納されています。
また、リストの最初と最後のchunkでは`fd`/`bk`に対して`main_arena`内のアドレスが格納されています。
よって、生成したunsorted chunkの`fd`/`bk`を読み出すことで`main_arena`のアドレス及びlibcbaseをleakすることができます。

unsorted chunkの生成にはサイズが重要となります。
[heap](/user/tcache#heapの大まかな構造)の章のテーブルを参照すると、tcache/fastbinに入り切らないのは`0x420`以上のサイズであることが分かります。
よって、`0x420`以上のサイズのchunkを作った後Deleteを選択すると、`unsorted`に繋がります。

------------------------------

AAW/AARの実現とlibcbaseのleakができたらあとはFSOPをするだけです。
ぜひ実際に自分でexploitを書いてみてください。

------------------------------

## Exercise

### 1. 今回のFSOPで`FILE`が満たすべき条件

`_IO_flush_all_lockp()`の呼び出しから、`_IO_WDOALLOCATE`が呼び出されるまでに必要な`FILE`が満たすべき条件を、
ソースコードを追うことで列挙してみてください。

### 2. challengeでのAAW/AAR

challengeにおいてAAW/AARを実現してください。
challengeは`Exercise 3`と同じです。

### 3. b64fsop

[[Distribution File]](https://r2.p3land.smallkirby.com/fsop-8d84f73ac2cb7479e0c12867f32a6f38040b86f6e6c3f02c549098b096b81de9.tar.gz)

```sh
nc sc.skb.pw 49403
```
