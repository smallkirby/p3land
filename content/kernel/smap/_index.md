---
title: "syscallとSMAP/KPTI"
description: "syscallの原理とページテーブルに関するセキュリティ機構とROPを使ったbypass"
draft: false
weight: 3
---

## Challenge

[[Distribution File]](https://r2.p3land.smallkirby.com/smap-21a99c107721eb80b4d9e763d401ceeeb32c8798cf0badd9cda9c7f137205c7b.tar.gz)

[[vmlinux with debug symbols]](https://r2.p3land.smallkirby.com/vmlinux-smap.tar.gz)

```sh
nc sc skb.pw 49405
```

## Address Translation

以下では、前提知識としてx64アーキテクチャの64bit mode(4-level paging)におけるページング機構について軽く触れます。

x64において、アドレスは**Logical Address**・**Linear Address**・**Physical Address**の3つがあります。
Logical Addressはいわゆる仮想アドレスに対応するもので、Linear->Physicalへと変換されていきます。
これらのアドレスの用語はx64固有のもので、他のアーキだと*Effective Address(EA)*と言ったり、
そもそもLinearがなかったりします。

### Logical to Linear

Logical->Linear変換は**GDT/LDT**と呼ばれる構造体が司ります[^1]。

![segment](img/segment.png)

画像のように、アドレスの上位16bitがGDT内の**Segment Descriptor**のインデックスとして使われます。
このdescriptorは、Linear Addressの **Base** / **Limit** / **Access Rights** 等を保持しています。
Logical Addressのオフセットを、descriptorのBaseに加算することでLinear Addressが得られます。
また、`Seg. Selector`は **RPL (Requested Protection Level)** と呼ばれる値も保持しており、
アクセスする際の希望Ring Levelを表します。
Descriptorも同様に **DPL (Descriptor Privilege Level)** と呼ばれる値を保持しており、
これ以下のRing Levelからのアクセスを許可します。
Descriptorの値を使ってLinear Addressに変換する際には、`max(RPL, CPL) <= DPL`である必要があります。

### Linear to Physical

Linear->Physical変換は、**Page Table**と呼ばれる構造体を使って**MMU**が司ります。

![paging](img/paging.png)

Linear Address中の値をもとにして4段階でアドレス解決をしていきます。
上の画像に置いて、アドレス解決に使われる構造を左から **PGD** / **PMD** / **PTE** と呼びます。
なお、これはLinuxにおける呼び名でありIntelはまた別の命名をしているのでご注意を。
Linear Address中の`Dir`によってPGD内のエントリを指定します。
そのエントリがPMDのアドレスを保持していて、Linear Address内の`Table`と組み合わせてPMD内のエントリを取得します。
ということを繰り返して、最終的にPhysical Addressのベースアドレスが取得できるため、
これをLinear Address内の`Offset`と加算して完了です。

### GDTのキャッシング

いちいちGDTを参照するのは嫌なので、x64はSegment Descriptorの値をキャッシュしておくためのレジスタを保持しています。
**CS**(code) / **DS**(data) / **SS**(stack) / **ES**(general) / **FS**(general) / **GS**(general) と呼ばれるレジスタたちです。
GDTから対応するエントリをこれらのレジスタにロードすることで、以降はこのレジスタの値を使ってアドレス解決を行うことができます。

{{< alert title="Hidden Part..." color="info" >}}
これらのセグメントレジスタにGDTの値をロードするときは、
Segment Selectorのみを指定してロードします。
すると、CPU側で勝手にDescriptorの値を引っ張ってきてレジスタに入れておいてくれます。
このDescriptorからとってきた部分のことを、セグメントレジスタの*Hidden Part*(*Shadow Part*)と呼びます。
{{< /alert >}}

### x64におけるセグメント

せっかく説明しましたが、x64においてセグメント機構はあまり使われていません。
というのも、64bitモードに置いてはCS/DS/SS/ESの`Base`値を常に0として扱うようになっています。
`Limit`チェックもされません(一応アドレス解決の結果がCanonicalかどうかくらいは見てくれるらしいです)。
よって、大抵の場合において `Logical Address == Linear Address` になります。

例外はFSとGSです。
FSはglibcにおいて**TLS (Thread Local Storage)** を指すために利用されたりします。
GSはLinux KernelにおいてCPU固有のデータ(**Per-CPU Variable**)を指すために利用されたりします。
なお、x64においてFSとGSは`Base`解決のために利用されます。
そして、FSとGSレジスタは **MSR (Model Specific Register)** というレジスタに物理的にマッピングされています。
それぞれ**IA32_FS_BASE** / **IA32_GS_BASE**というMSRです。
そのためFS/GSを参照しようとすると、これらのMSRを見に行くことになります。
GSはkernellandで重要なため、のちほどまた詳しく見ていきます。

## syscallについて

### entry point ~ do_syscall_64

一昔前は、`int 0x80`命令によってsyscallを呼び出していました。
`int`命令は割り込みを発生させる命令で、[IDTR](https://wiki.osdev.org/Interrupt_Descriptor_Table)によって指される割り込みテーブルに登録されたハンドラに処理が移ります。
`0x80`番がsyscallのエントリポイントということですね。
また、32bitでは[sysenter](https://www.felixcloutier.com/x86/sysenter)命令が使われていました。
しかし、最近の64bitアーキでは`int 0x80`はほとんど使われず、より高速な[syscall](https://www.felixcloutier.com/x86/syscall.html)命令が使われます。

`syscall`は**IA32_LSTAR_MSR**レジスタによって指されるエントリポイントに処理を移します。
`MSR_LSTAR`は`syscall_init()`([/arch/x86/kernel/cpu/common.c]())で初期化され、`entry_SYSCALL_64`を指すことになります:

```c
void syscall_init(void)
{
	wrmsr(MSR_STAR, 0, (__USER32_CS << 16) | __KERNEL_CS);
	wrmsrl(MSR_LSTAR, (unsigned long)entry_SYSCALL_64);

	wrmsrl(MSR_CSTAR, (unsigned long)ignore_sysret);
	wrmsrl_safe(MSR_IA32_SYSENTER_CS, (u64)GDT_ENTRY_INVALID_SEG);
	wrmsrl_safe(MSR_IA32_SYSENTER_ESP, 0ULL);
	wrmsrl_safe(MSR_IA32_SYSENTER_EIP, 0ULL);

	/* Flags to clear on syscall */
	wrmsrl(MSR_SYSCALL_MASK,
	       X86_EFLAGS_TF|X86_EFLAGS_DF|X86_EFLAGS_IF|
	       X86_EFLAGS_IOPL|X86_EFLAGS_AC|X86_EFLAGS_NT);
}
```

`entry_SYSCALL_64`([(/arch/x86/entry/entry_64.S]())の前半部分は以下のように定義されます:

```c
SYM_CODE_START(entry_SYSCALL_64)
	UNWIND_HINT_ENTRY
	ENDBR

	swapgs
	/* tss.sp2 is scratch space. */
	movq	%rsp, PER_CPU_VAR(cpu_tss_rw + TSS_sp2)
	SWITCH_TO_KERNEL_CR3 scratch_reg=%rsp
	movq	PER_CPU_VAR(cpu_current_top_of_stack), %rsp

SYM_INNER_LABEL(entry_SYSCALL_64_safe_stack, SYM_L_GLOBAL)
	ANNOTATE_NOENDBR

	/* Construct struct pt_regs on stack */
	pushq	$__USER_DS				/* pt_regs->ss */
	pushq	PER_CPU_VAR(cpu_tss_rw + TSS_sp2)	/* pt_regs->sp */
	pushq	%r11					/* pt_regs->flags */
	pushq	$__USER_CS				/* pt_regs->cs */
	pushq	%rcx					/* pt_regs->ip */
SYM_INNER_LABEL(entry_SYSCALL_64_after_hwframe, SYM_L_GLOBAL)
	pushq	%rax					/* pt_regs->orig_ax */

	PUSH_AND_CLEAR_REGS rax=$-ENOSYS

	/* IRQs are off. */
	movq	%rsp, %rdi
	/* Sign extend the lower 32bit as syscall numbers are treated as int */
	movslq	%eax, %rsi

	/* clobbers %rax, make sure it is after saving the syscall nr */
	IBRS_ENTER
	UNTRAIN_RET

	call	do_syscall_64		/* returns with IRQs disabled */```
```

L2はよく分かりませんが、この時点でstackを持っていないことを表現しているらしいです。

L3の`ENDBR`は新しいCPUに搭載されたIndirect Branch Tracking用の命令です。
詳しくは[この辺の記事](https://smallkirby.hatenablog.com/entry/2020/09/10/230629)を見てみてください。

L5の**swapgs**はとても大切です。
kernelについた直後はスタックがありません。寂しいです。
そのため、まず[swapgs](https://www.felixcloutier.com/x86/swapgs)命令によって **IA32_KERNEL_GS_BASE** からkernel用のGSを取り出してきています。
この命令は現在のGSとMSRに入っている値を交換します。

取り出したGSは、**PER_CPU_VAR**の計算に使われます[(arch/x86/include/asm/percpu.h)]():

```c
#define __percpu_seg		gs
#define PER_CPU_VAR(var)	%__percpu_seg:var
```

確かにGSレジスタを使ってアドレスを計算していることが分かりますね。
みなさんもぜひお手元のGDBと`vmlinux`をつかって`entry_SYSCALL_64`にbpを貼ってみてください。
`swapgs`の直前のレジスタや`MSR_GS_BASE`の値は以下のようになります:

```sh
gef> registers
$rax   : 0x0
$rbx   : 0x0
$rcx   : 0x00000000004a91de  ->  0x5a77fffff0003d48 ('H='?)
$rdx   : 0x1
$rsp   : 0x00007fff60392318  ->  0x000000000050c168  ->  0x7d83411179c08548
$rbp   : 0x00007fff60392469  ->  0xa800000000005637 ('7V'?)
$rsi   : 0x00007fff60392469  ->  0xa800000000005637 ('7V'?)
$rdi   : 0x0
$rip   : 0xffffffff81800000 <entry_SYSCALL_64>  ->  0x2524894865f8010f
$r8    : 0x0000000000663338  ->  0x0000000000000000 <fixed_percpu_data>
$r9    : 0x0
$r10   : 0x8
$r11   : 0x246
$r12   : 0x1
$r13   : 0x0000000000660320  ->  0x0000000000000000 <fixed_percpu_data>
$r14   : 0x0
$r15   : 0x00007fff60392469  ->  0xa800000000005637 ('7V'?)
$eflags: 0x2 [ident align vx86 resume nested overflow direction interrupt trap sign zero adjust parity carry] [Ring=0]
$cs: 0x10 $ss: 0x18 $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00

gef> msr MSR_GS_BASE
MSR_GS_BASE (0xc0000101): 0x0 (=0b)
```

確かにRSP等はまだuserlandのものを指していることが分かります。
また、`GS_BASE`は0になっています。userlandでは使わないので妥当ですね。

これが、`swapgs`をした後には以下のようになります:

```sh
gef> msr MSR_GS_BASE
MSR_GS_BASE (0xc0000101): 0xffff88800f600000 (=0b1111_1111_1111_1111_1000_1000_1000_0000_0000_1111_0110_0000_0000_0000_0000_0000)
```

`0xffff88800f600000`を指すようになっています。
これが、このCPUの`PER_CPU_VAR`領域となります。

続くL7で、この`PER_CPU_VAR`を使って`RSP`の値を退避させています。
x64では**TSS (Task State Segment)**と呼ばれる領域にタスク情報を格納することになっており、
該当領域は以下のように`cpu_tss_rw`変数として定義されています:

![tss](img/tss.png)

```c
// /include/generated/asm-offsets.h
#define TSS_sp2 20 /* offsetof(struct tss_struct, x86_tss.sp2) */

// /arch/x86/include/asm/processor.h
struct tss_struct {
	struct x86_hw_tss	x86_tss;
	struct x86_io_bitmap	io_bitmap;
} __aligned(PAGE_SIZE);
DECLARE_PER_CPU_PAGE_ALIGNED(struct tss_struct, cpu_tss_rw);
```

L7の`TSS_sp2`は、TSSの中でたまたま使われていない領域のため、せっかくだからuser RSPを保存するのにこの領域を使おうということらしいです。

L8では何か大切そうなことをしています([/arch/x86/entry/calling.h]()):

```h
#define PTI_USER_PGTABLE_AND_PCID_MASK  (PTI_USER_PCID_MASK | PTI_USER_PGTABLE_MASK)

.macro ADJUST_KERNEL_CR3 reg:req
	ALTERNATIVE "", "SET_NOFLUSH_BIT \reg", X86_FEATURE_PCID
	/* Clear PCID and "PAGE_TABLE_ISOLATION bit", point CR3 at kernel pagetables: */
	andq    $(~PTI_USER_PGTABLE_AND_PCID_MASK), \reg
.endm

.macro SWITCH_TO_KERNEL_CR3 scratch_reg:req
	ALTERNATIVE "jmp .Lend_\@", "", X86_FEATURE_PTI
	mov	%cr3, \scratch_reg
	ADJUST_KERNEL_CR3 \scratch_reg
	mov	\scratch_reg, %cr3
.Lend_\@:
.endm
```

どうやら`scratch_reg`で指定したレジスタを仲介として、
**CR3**レジスタの11/12-th bit (0-origin)を下ろしているようです。
CR3レジスタはPGDの物理アドレスを保持します:

![cr3](img/cr3.png)

このビット演算が何を意味するかは非常に重要なのですが、
今のところはとりあえずkernel空間のページにアクセスできるようになるという認識で大丈夫です。
本ページで必要になったら説明します。

L9では、`PER_CPU_VAR(cpu_current_top_of_stack)`を使って`RSP`を更新しています。
どうやらこの領域にはこのCPU用のstackアドレスがおいてあるらしいです。
これでやっとkernelくんはstackをゲットしました、やったね。

続くL15-L21ではひたすらにユーザレジスタをstackに積みまくっています。
これは、のちほど関数に引数として渡す必要がある`struct pt_regs`([/arch/x86/include/asm/ptrace.h]())を構築しています。
確かにアセンブリ中で積んでいる順番と一致しますね:

```c
struct pt_regs {
	unsigned long r15;
	unsigned long r14;
	unsigned long r13;
	unsigned long r12;
	unsigned long bp;
	unsigned long bx;
	unsigned long r11;
	unsigned long r10;
	unsigned long r9;
	unsigned long r8;
	unsigned long ax;
	unsigned long cx;
	unsigned long dx;
	unsigned long si;
	unsigned long di;
	unsigned long orig_ax;
	unsigned long ip;
	unsigned long cs;
	unsigned long flags;
	unsigned long sp;
	unsigned long ss;
};j
```

あとはL26,28で`RDI`/`RSI`に引数を入れて、`do_syscall_64`([/arch/x86/entry/common.c]())を呼んでいるだけです。
この中身についてはここでは触れないため、興味のある人は見てみてください。

### do_syscall_64 ~ userlandへの帰還

ここからは`do_syscall_64`を終えてuserlandに帰還するまでの部分です。
帰還方法には`sysret`と`iret`があります。
基本的にはそれぞれsyscall / 割り込みから帰るようですが、後者のほうが簡単なため後者を見ていくことにします。


```S
	movq	RCX(%rsp), %rcx
	movq	RIP(%rsp), %r11
	cmpq	%rcx, %r11	/* SYSRET requires RCX == RIP */
	jne	swapgs_restore_regs_and_return_to_usermode
  ...

SYM_CODE_START_LOCAL(common_interrupt_return)
SYM_INNER_LABEL(swapgs_restore_regs_and_return_to_usermode, SYM_L_GLOBAL)
	IBRS_EXIT

	POP_REGS pop_rdi=0

	/*
	 * The stack is now user RDI, orig_ax, RIP, CS, EFLAGS, RSP, SS.
	 * Save old stack pointer and switch to trampoline stack.
	 */
	movq	%rsp, %rdi
	movq	PER_CPU_VAR(cpu_tss_rw + TSS_sp0), %rsp
	UNWIND_HINT_EMPTY

	/* Copy the IRET frame to the trampoline stack. */
	pushq	6*8(%rdi)	/* SS */
	pushq	5*8(%rdi)	/* RSP */
	pushq	4*8(%rdi)	/* EFLAGS */
	pushq	3*8(%rdi)	/* CS */
	pushq	2*8(%rdi)	/* RIP */

	/* Push user RDI on the trampoline stack. */
	pushq	(%rdi)

	/*
	 * We are on the trampoline stack.  All regs except RDI are live.
	 * We can do future final exit work right here.
	 */
	STACKLEAK_ERASE_NOCLOBBER

	SWITCH_TO_USER_CR3_STACK scratch_reg=%rdi

	/* Restore RDI. */
	popq	%rdi
	swapgs
	jmp	.Lnative_iret
```

L1-4は`sysret`を使えるかどうかのチェックです。
無理な場合には`swapgs_restore_regs_and_return_to_usermode`に飛びます。

L11で`RDI`を除いてPOPしています。
先程stackには`struct pt_regs`を積んでいたので、それを取り出しています。

L18では`RSP`を退避させています。
ここでも`PER_CPU_VAR(cpu_tss_rw + TSS_sp0)`を使うことで、次にkernelに来た時にこの値を使って`RSP`を復元することができます。

L21-26では、`iretq`で必要となるユーザレジスタの値を積んでいます。

L37は、CR3をuserlandのものに戻しています。さっきの逆ですね。

そして最終的にもう一度`swapgs`をしてGSをユーザのもの(0)に戻して、めでたく`iretq`で帰還しています。

[^1]: 画像は[Intel Architectures Software Developer Manuals (SDM)](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html)からの引用です。以下、特に断らない限り画像はSDMからの出典です。
