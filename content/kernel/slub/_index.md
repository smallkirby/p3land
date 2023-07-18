---
title: "SLUBアロケータと構造体の利用"
description: "SLUBアロケータの概要と、kernelで使われる構造体を利用した攻撃"
draft: false
weight: 4
---

## Challenge

[[Distribution File]](https://r2.p3land.smallkirby.com/slub-585a7c9b1db0f6843ff37247218317fa81a479d405c42f3c00ef5c49b465f764.tar.gz)

[[vmlinux with debug symbols]](https://r2.p3land.smallkirby.com/vmlinux-slub.tar.gz)

```sh
nc sc skb.pw 49407
```

## Challenge概要と脆弱性

さっそく問題概要に入りましょう。
まずは起動オプションです:

```sh
  -cpu kvm64,+smep,-smap \
  -append "console=ttyS0 oops=panic panic=1 quiet" \
```

SMEP/KPTIが有効化されていますが、SMAPは無効化されています。
本当は有効化したかったんですが、exploitをシンプルにするために泣く泣く無効化した筆者の顔が浮かびますね。

LKMソースは以下の感じです:

```c
typedef struct {
  size_t size;
  /** Actual note follows immediately **/
} note;

#define NOTE_NOTE_BUF(note) ((char *)(note + 1))
note *notes[MAX_NUM_NOTE] = {0};
long slub_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) {
  ...

  switch (cmd) {
    case SLUB_IOCTL_CREATE:
      idx = find_empty_note();
      if (idx == -1) {
        ret = -ENOMEM;
        break;
      }
      if (req.size > MAX_SIZE_NOTE || req.size < sizeof(note)) {
        ret = -EINVAL;
        break;
      }
      if ((note = kzalloc(req.size, GFP_KERNEL)) == NULL) {
        ret = -ENOMEM;
        break;
      }
      if (copy_from_user(NOTE_NOTE_BUF(note), req.buf, req.size)) {
        ret = -EFAULT;
        break;
      }
      note->size = req.size;
      notes[idx] = note;
      ret = idx;
      break;
    case SLUB_IOCTL_DELETE:
      if (req.idx >= MAX_NUM_NOTE || (note = notes[req.idx]) == NULL) {
        ret = -EINVAL;
        break;
      }
      kfree(note);
      notes[req.idx] = NULL;
      break;
    case SLUB_IOCTL_READ:
      if (req.idx >= MAX_NUM_NOTE || (note = notes[req.idx]) == NULL) {
        ret = -EINVAL;
        break;
      }
      if (copy_to_user(req.buf, NOTE_NOTE_BUF(note), note->size)) {
        ret = -EFAULT;
        break;
      }
      break;
    default:
      ret = -EINVAL;
      break;
  }

out:
  mutex_unlock(&mtx);
  return ret;
}
```

シンプルなノートアロケータで、以下のことができます:

- CREATE: 任意サイズのノートを作成。好きな値を書き込める。
- DELETE: 指定したインデックスのノートを削除。
- READ  : 指定したインデックスのノートを取得。

ノートは`struct note`という構造体で表され、`size`フィールドにノートのサイズが格納されています。
ノートの実体は`NOTe_NOTE_BUF`マクロとコメントが示すように、`size`フィールドの直後に格納されます。
可変長構造体です。Cではたまに使われる方法で、`struct msg_msg`等がこんな感じになっています。

脆弱性は、`SLUB_IOCTL_CREATE`内にありますね。
`kzalloc`で取得するのはユーザが指定した`req.size`サイズだけですが、
`copy_from_user()`では`req.buf`からコピーを始めるので`sizeof(size)`だけオーバーフローが発生します。
kernel heap内におけるオーバーフローです。

## SLUB Allocator

heapでのオーバーフローに対する攻撃を行うため、ここでheapに対する知識が必要になります。
P3LANDでは [User - heap: tcache](/user/tcache) においてglibc heapに対する攻撃を扱っています。
対して、kernelのheapはいくらかシンプルです。
Linuxにおいては、メモリアロケータと呼べるものが2種類あります。

### Buddy Allocator

ページの確保と分配を行うアロケータを **Buddy Allocator** と呼びます。
Buddy Allocatorは、`alloc_pages()`([/mm/page_alloc.c]())等のAPIから呼び出され、ページ単位でメモリを確保します:

```c
static inline struct page *alloc_pages(gfp_t gfp_mask, unsigned int order)
```

`order`は確保するページの数の指数を表しています。
`0`なら`2^0 == 1`, `3`なら`2^3 == 8`ページを確保するといった感じです。
この指定方法からも察せられるとおり、Buddy Allocatorは内部で利用可能なページ一覧を2の累乗単位で確保しています。
Order-3のキューには連続した8ページの集まりが入っています。
Buddy Allocator自体も大切ですが、本セクションではほとんど意識する必要がないため、詳細は割愛します。

{{< alert title="Linuxのvirtual memory layout" color="info" >}}
Linuxでは仮想アドレスのレイアウトが決まっており、ユーザ空間がどこにマップされるか、
どこからどこまでがstraight mapされるか、GDTがどこにマップされるか等が決まっています。
レイアウトの詳細は[Linuxツリーのドキュメント](https://www.kernel.org/doc/Documentation/x86/x86_64/mm.txt)を参照してください。
{{< /alert >}}

### SLUB Allocator

Buddy Allocatorはページ単位のアロケータでしたが、より小さい粒度でオブジェクトを管理するアロケータもあります。
Linuxでは、一般的に **SLUB Allocator** と呼ばれるアロケータが使われます。

SLUB Allocatorは **SLUB** と呼ばれるページ単位の領域を管理し、その中に**同一サイズのオブジェクトを確保**します。
SLUBが司るオブジェクトのサイズは `8, 16, 32, 64, 96, 128, ..., 4k, 8k`まであり、
これらの情報は`/proc/slabinfo`から見ることができます:

```sh
/ # cat /proc/slabinfo
slabinfo - version: 2.1
# name            <active_objs> <num_objs> <objsize> <objperslab> <pagesperslab> : tunables <limit> <batchcou>
scsi_sense_cache      32     32    128   32    1 : tunables    0    0    0 : slabdata      1      1      0
virtio_scsi_cmd       84     84    192   21    1 : tunables    0    0    0 : slabdata      4      4      0
jbd2_transaction_s      0      0    256   16    1 : tunables    0    0    0 : slabdata      0      0      0
jbd2_journal_head      0      0    120   34    1 : tunables    0    0    0 : slabdata      0      0      0
jbd2_revoke_table_s      0      0     16  256    1 : tunables    0    0    0 : slabdata      0      0      0
ext4_fc_dentry_update      0      0     80   51    1 : tunables    0    0    0 : slabdata      0      0      0
...
kmalloc-8k             8      8   8192    4    8 : tunables    0    0    0 : slabdata      2      2      0
kmalloc-4k            32     32   4096    8    8 : tunables    0    0    0 : slabdata      4      4      0
kmalloc-2k           152    152   2048    8    4 : tunables    0    0    0 : slabdata     19     19      0
kmalloc-1k           760    760   1024    8    2 : tunables    0    0    0 : slabdata     95     95      0
kmalloc-512          176    176    512    8    1 : tunables    0    0    0 : slabdata     22     22      0
kmalloc-256          864    864    256   16    1 : tunables    0    0    0 : slabdata     54     54      0
kmalloc-192          189    189    192   21    1 : tunables    0    0    0 : slabdata      9      9      0
kmalloc-128          256    256    128   32    1 : tunables    0    0    0 : slabdata      8      8      0
kmalloc-96           336    336     96   42    1 : tunables    0    0    0 : slabdata      8      8      0
kmalloc-64           704    704     64   64    1 : tunables    0    0    0 : slabdata     11     11      0
kmalloc-32           512    512     32  128    1 : tunables    0    0    0 : slabdata      4      4      0
kmalloc-16           768    768     16  256    1 : tunables    0    0    0 : slabdata      3      3      0
kmalloc-8           3072   3072      8  512    1 : tunables    0    0    0 : slabdata      6      6      0
```

`<objsize>`がオブジェクトのサイズ、`<objperslab>`が1SLUBあたりに入れることの出来るオブジェクトの数です。
`kmalloc-128`を見てみると、サイズが`128`・1SLUBあたりに`32`個のオブジェクトを入れることができることがわかります。
また、`<pagesperslab>`は1SLUBのために確保されるページ数を表しています。
`kmalloc-128`では`1`となっており、1ページ(`4096 bytes`)の中にサイズが`128`のオブジェクトが入るため、
`4096 / 128 == 32`個のオブジェクトを入れることができます。`<objperslab>`と一致していますね。

SLUB Allocatorは、`kmalloc()`や`kzalloc()`等のAPIでメモリを要求された場合、
要求サイズに対応するSLUBからオブジェクトを確保してユーザに返します。
また、これらのSLUBページ自体はBuddy Allocatorに対してページを要求しています。

{{< alert title="vmalloc / kmalloc" color="info" >}}
kernelのメモリ取得APIには`kmalloc`の他に`vmalloc`というものもあります。
`kmalloc`との違いとして、`vmalloc`はSLUB Allocatorを利用せずページ単位でメモリを確保します。
また、`kmalloc()`で取得した領域は物理的に連続することが保証されています(Buddy AllocatorからSLUBを確保するため)が、
`vmalloc`で取得した領域は物理的に連続することが保証されていないという特徴があります(もちろん仮想アドレス的には連続しています)。
{{< /alert >}}

少しだけ実装に立ち入ってみましょう。
各SLUBは、`struct kmem_cache`([]())という構造体によって管理されます:

```c
struct kmem_cache {
	struct kmem_cache_cpu __percpu *cpu_slab;
	slab_flags_t flags;
	unsigned long min_partial;
	unsigned int size;	/* The size of an object including metadata */
	unsigned int object_size;/* The size of an object without metadata */
	struct reciprocal_value reciprocal_size;
	unsigned int offset;	/* Free pointer offset */
  ...
	const char *name;	/* Name (only for display!) */
	struct list_head list;	/* List of slab caches */
	unsigned int useroffset;	/* Usercopy region offset */
	unsigned int usersize;		/* Usercopy region size */

	struct kmem_cache_node *node[MAX_NUMNODES];
};
```

`name`には`kmalloc-32`とかの名前が入ります。
大事なフィールドは`struct kmem_cache_cpu cpu_slab`と`struct kmem_cache_node node[]`です。
今回は話をシンプルにするため`cpu_slab`だけ見てみます:

```c
struct kmem_cache_cpu {
	void **freelist;	/* Pointer to next available object */
	unsigned long tid;	/* Globally unique transaction id */
	struct slab *slab;	/* The slab from which we are allocating */
	struct slab *partial;	/* Partially allocated frozen slabs */
	local_lock_t lock;	/* Protects the fields above */
};

struct slab {
	unsigned long __page_flags;
	union {
		struct list_head slab_list;
		struct rcu_head rcu_head;
	};
	struct kmem_cache *slab_cache;
	/* Double-word boundary */
	void *freelist;		/* first free object */
	union {
		unsigned long counters;
		struct {
			unsigned inuse:16;
			unsigned objects:15;
			unsigned frozen:1;
		};
	};
	unsigned int __unused;
	atomic_t __page_refcount;
};
```

ここで、SLUBの構造を簡単に図示してみましょう:

![slub](./img/slub.png)

単純のためにあまり正確ではないですが、ざっくりしたイメージとしては図のようになります。
`kmem_cache_cpu`は、最も最近freeされたオブジェクトのアドレスを`freelist`に保持しています。
また、SLUB内のfreeされたオブジェクトはglibcと同様に次の空きオブジェクトを指すポインタをオブジェクト内部に保持しています。
これによって、そのSLUB内の保持されたオブジェクトを`freelist`を辿ることで全列挙できます。

また、`partial`では残りのSLUBが管理されています。
図のSLUB A内のfreeオブジェクトが全て確保されてしまうと`partial`のSLUBから
`slab`に引っ張ってきます。

{{< alert title="Dedicated Cache" color="info" >}}
`/proc/slabinfo`の中には`kmalloc-XX`という名前ではないキャッシュがあることに気づいたでしょうか。
実は、kernelの中でもいくつかの構造体は`kmalloc-XX`のようなサイズによってのみ決まるSLUBではなく、
専用のキャッシュ・SLUBを保持している場合があります。
例えば、ユーザ情報を司る`struct cred`は`cred_jar`という名前の専用のキャッシュを持っています
([/kernel/cred.c]())。

```c
static struct kmem_cache *cred_jar;
```

また、`CONFIG_MEMCG_KMEM`が有効になっている場合には`kmalloc-cg-XX`という名前の汎用キャッシュも作られることになります。
(ちょっと筆者は詳しく調べていないんですが、)これを有効化するとcgroupに関連するような構造体が`SLAB_ACCOUNT`フラグを指定することで`kmalloc-cg-XX`キャッシュを使うようになります。
つまり、汎用キャッシュも以前に比べると幾分か専用化されてきているということですね。

```c
#ifdef CONFIG_MEMCG_KMEM
#define KMALLOC_CGROUP_NAME(sz)	.name[KMALLOC_CGROUP] = "kmalloc-cg-" #sz,
#else
#define KMALLOC_CGROUP_NAME(sz)
#endif

void __init seq_file_init(void)
{
	seq_file_cache = KMEM_CACHE(seq_file, SLAB_ACCOUNT|SLAB_PANIC);
}
```
{{< /alert >}}

## heap overflowによる同一SLUB内構造体の書き換え

さて、少し駆け足ですがSLUB Allocatorについて触れました。
SLUB Allocatorでは、(基本的に)オブジェクトサイズに応じてどのキャッシュ・SLUBを利用するかが決まります。
この性質と **Challenge LKMのheap overflowを利用することで、`note`と同じSLUBに確保されるkernel構造体を
書き換えたり読み込んだりすることができます**。
