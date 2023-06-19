---
title: "セットアップ"
description: "pwn環境のセットアップ"
draft: false
weight: 10
---

本ページではpwn環境のセットアップをしていきます。

## Prerequisites

以下のソフトウェアをインストールしてください:

### GDB

デバッグに利用します。

M1 MacではbrewからGDBをインストールすることはできません。LLDBでも良いかもしれませんが、いずれにせよx64環境は必要となるためQEMU/UTM等でx64 Ubuntu環境を用意するのが良いかもしれません。

userlandのデバッグをする際には、いい感じの拡張を入れておくと便利です:

- [pwndbg](https://github.com/pwndbg/pwndbg)
- [gef](https://github.com/hugsy/gef)
- [gef by bata24](https://github.com/bata24/gef)

### pwntools / ptrlib

Pythonでexploitを書く際の良い感じライブラリです。

- [pwntools](https://github.com/Gallopsled/pwntools)
- [ptrlib](https://github.com/ptr-yudai/ptrlib)

### Ghidra

バイナリをデコンパイルします。本講義ではあまり使いません。

- [Ghidra](https://ghidra-sre.org/)

### QEMU

kernel challengeで仮想環境を用意するのに必要です。`qemu-system-x86_64`をインストールしてください。

### Docker

基本的には使いませんが、あると便利です。Dockerに慣れていない人はDocker Desktopを入れておくと良いかも。
