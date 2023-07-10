---
title: "Preparation"
description: "Kernelのソースコードを読める・デバッグできる環境を作る"
draft: false
weight: 1
---

## はじめに

このページでは、Kernelのソースコードを読んだり、実際にデバッグビルドしてGDBで動かすための環境を作っていきます。

## Source Code

Kernelのソースコードが出来る環境を作ります。
ソースコードはexploitを書いたり、kernelの処理の内容を調べたりするのに頻繁に必要になります。
コードリーディングに使う環境は正直なんでも良いですが、一般的には以下ができることが望ましいです:

- Go To Definitionできる
- XREFが見れる
- シンボルが検索できる
- 特定のアーキテクチャのシンボルが探せる
- 容易にバージョンをswitchできる

以下ではこれらを満たす環境として、VSCode + Clangdを使う方法を紹介します。
これ以外の方法としては、[bootlin Elixir Cross Referencer](https://elixir.bootlin.com/linux/latest/source)もオンライン上で気軽に使えるのでおすすめです。

### Linuxソースツリーのクローン

`git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git` あたりからソースコードをcloneしてきましょう。

cloneには異常時間かかります。コーヒーブレイクをしながら気軽に待ちましょう。

### `compile_commands.json`の生成

cloneしたら、適当なタグにcheckoutします。
バージョンは何でも良いですが、特に断らない限りはUbuntu 22.04 LTSで使われている5.19.XX系を使うことにします。
あんまり古すぎてもリアリティがなくなりますし、
あんまり新しすぎてもexploitに使いやすいattack surfaceが消されていることがあるので、
そこだけ注意してください。

```sh
git checkout v5.19.2
```

そのあと、configを設定します。Linuxのコンフィグは`make menuconfig`によって設定できます。
しかし今回は取り敢えずビルドできればいいので、`make alldefconfig`で適当に設定してしまってもいいでしょう。

```sh
make alldefconfig
```

{{< alert title="menuconfig" color="info" >}}
`menuconfig`では、以下のような操作を覚えておくと少し扱いやすいかもしれないです:

- `?`: ヘルプを表示
- `/`: 設定を検索。検索結果画面で該当する数字を押すと、そのコンフィグまでジャンプできる
- `<alphabet>`: アルファベットを一文字押すと、現在のページ内にあるそのアルファベットから始まる最初のコンフィグにジャンプできます
- `Esc`: 前の画面に戻る
{{< /alert >}}

続いてkernelをビルドします:

```sh
make -j$(nproc)
```

このビルドもマシンスペックによっては少し時間がかかります。
ビルドが終わったら、続いてclangdに食べさせる用の`compile_commands.json`を生成します:

```sh
python3 ./scripts/clang-tools/gen_compile_commands.py
```

これによって、ソースツリーのルートに`compile_commands.json`が生成されます。

### clangd

必要に応じてLLVM/[clangd](https://clangd.llvm.org/)をインストールしてください。
また、VSCode拡張の[vscode-clangd](https://marketplace.visualstudio.com/items?itemName=llvm-vs-code-extensions.vscode-clangd)をインストールしてください。
その後、`/vscode/c_cpp_properties.json`を以下のように設定します:

```json
{
"configurations": [
    {
        "name": "Linux",
        "includePath": [
            "${workspaceFolder}/include/**",
            "${workspaceFolder}/arch/x86/**",
            "${default}"
        ],
        "defines": [
            "__GNUC__",
            "__KERNEL__"
        ],
        "compilerPath": "/bin/clang-15",
        "cStandard": "c17",
        "cppStandard": "c++14",
        "intelliSenseMode": "linux-clang-x64",
        "compileCommands": "${workspaceFolder}/compile_commands.json"
    }
],
"version": 4
}
```

この状態でclangdを起動すると、`compile_commands.json`に従ってソースコードをindexingしてくれるはずです。

試しにVSCodeを開いて、シンボルの検索やGo To Definition等ができるかどうかを確かめてみてください。
また、アーキ依存のシンボルに関してはx86用のシンボルが表示されることを確かめてください。

## Build

ソースコードを動かせたので次は任意のバージョンのカーネルをビルドしてみます。
先程のLinuxソースツリーを使ってもいいですが、
折角なので今回は[buildroot](https://buildroot.org/)を使ってみましょう。

まずは[buildrootをダウンロード](https://buildroot.org/download.html)します。
展開後、ソースのルートディレクトリにて`make menuconfig`を実行することで設定ができます。
ここで、**buildrootの設定とLinuxの設定は別ものであることに注意**してください。
今回はただビルドするだけなのでとりわけ追加で設定する必要はありませんが、
簡単のため以下のコンフィグだけ設定してください:

- `BR2_LINUX_KERNEL_CUSTOM_VERSION_VALUE`: 任意のカーネルバージョン
- `BR2_TARGET_ROOTFS_CPIO`: `y`を選択
- `BR2_TARGET_ROOTFS_EXT2`: `y`を選択

buildrootはあらかじめいくつかのビルドターゲット用の設定を用意してくれています。
その一覧は`make list-defconfigs`で確認することができます。
今回はQEMU上で動かす用のx64ビルドをしたいため、以下のコマンドでコンフィグをしてください。

```sh
make qemu_x86_64_defconfig
```

あとはビルドするのみです。
もともとbuildrootはクロスビルドにも対応したツールのため、ホストツールも含めて全てダウンロード・ビルドします。
そのため先程のkernelのビルドよりも時間がかかりますが、
これは初回だけなので気長に待ちましょう。

```sh
make -j$(nproc)
```

{{< alert title="ドメイン切れ...?" color="info" >}}
`buildroot-2023.02.2`の時点でビルドを行うと、
依存のダウンロードの際にサーバに接続できずに失敗する可能性があります。
これはおそらく`pkgconf`のダウンロード元である`distfiles[dot]dereferenced[dot]org`が
ドメイン切れしているためと考えられます。
この[サーバの管理人であると思われる人物](https://twitter.com/ariadneconill/status/1675575196936466432)が
ドメインを移行したと思われる旨のツイートをしているため、
新しいドメインを指定すると解決する可能性があります。

ダウンロード元を変える際には、
`/package/pkgconf/pkgconf.mk`内の
`https://distfiles[dot]dereferenced[dot]org/pkgconf`となっている部分を
`https://distfiles[dot]ariadne[dot]space`に置き換えてください。

なお、このサーバがmaliciousで無いことは断言できないためご自身で検証してください。
{{< /alert >}}

ビルドが終わると、`/output/images`以下に以下のファイルが生成されます:

- `bzImage`: ビルドしたカーネルのバイナリ
- `rootfs.cpio`: ビルドしたカーネルのルートファイルシステムのバイナリ(rootfs)
- `rootfs.ext2`: ビルドしたカーネルのルートファイルシステムのバイナリ(EXT2)

あとはQEMU上で動かすだけです。
buildrootは`/output/images/start_qemu.sh`にQEMUを起動するスクリプトを生成してくれているので、
これを動かせばOKです。

```sh
./output/images/start_qemu.sh
```

kernelが起動してネットワーク設定等諸々したあとにログインプロンプトが出るかと思います。
configからルートログイン設定をすることもできますが、めんどくさいので今回は`inittab`を修正することで
勝手にルートログインしてくれるようにしましょう。

まず`/output/images/rootfs.ext2`をマウントして`/etc/inittab`を修正します:

```sh
sudo mkdir /mnt/hoge
sudo mount ./output/images/rootfs.ext2 /mnt/hoge
vim /mnt/hoge/etc/inittab
```

`inittab`中の以下の部分を修正してください

```inittab
tty1::respawn:/sbin/getty -L  tty1 0 vt100 # QEMU graphical window
(fix)=>
::respawn:-/bin/sh
```

`rootfs.ext2`をアンマウントして、再度QEMUを起動してください。
今度は勝手にルートとしてシェルが起動するはずです。

------------------------------

## Exercise

### 1. ソースコードが便利に読める状態にする

[Source Code](#source-code)の章を参考にして、ソースコードが読める状態にしてください。
なお、Web上のクロスリファレンサーを使うのも全く問題ありません。

### 2. 任意のバージョンのカーネルをビルドする

[Build](#build)の章を参考にして、任意のバージョンのカーネルをビルドして動かしてみてください。
