---
title: "P3LAND"
draft: false
linkTitle: Home

cascade:
  - type: "docs"
    _target:
      path: "/**"

menu:
  main:
    weight: 5
    pre: <i class='fa-solid fa-book'></i>
---

## 👀 About This Site

このサイトは[セキュリティキャンプ全国大会2023](https://www.ipa.go.jp/jinzai/security-camp/2023/zenkoku/index.html)の[C2 手を動かして理解するLinux Kernel Exploit](https://www.ipa.go.jp/jinzai/security-camp/2023/zenkoku/program_list_cd.html)の事前学習で利用されます。

本講義は、4時間1コマでCTF-likeな問題を通してLinux Kernel Exploitを手を動かしながら学習します。
とはいっても4時間だけでExploitまで辿り着くのは難しく、それなりの事前学習を必要とします。
本講義では、このサイトにおける必須知識の座学・例題 / Discordにおける講師・チューターへの質問・議論を通して事前学習を行います。

{{< alert title="Note: 事前学習に注ぐエネルギー" color="info" >}}
Cトラックは複数の講義からなるオムニバス形式です。
皆さんの興味関心・技術的背景も多様だと思います。
どれだけ本講義の事前学習にエネルギーを注ぐかはお任せするので、自分の興味関心に合わせて調整してください。
{{< /alert >}}

本サイトでは、以下の内容を扱います:

- userland pwnの基礎と典型的な脆弱性
- kernelland pwnの基礎と典型的な脆弱性
- 講義で扱うテーマに関する事前知識(TBD)

## 🏃 Way to Proceed

基本的には自分のペースで進めてください。
前半はuserlandに関する話題のため、既に知識・経験がある場合には飛ばしてOKです。

最初に前提知識について本サイトで学習してください。
その後、各ページの最後にある*Excercise*を解いてみてください。
各問題は実際にリモートサーバ上で動作しており、Flagが奪取できれば正解です。

わからないことがあれば、セキュリティキャンプのDiscordチャンネル `#c2-kernel-exp` で `@smallkirby` をメンションしてください。
質問はその難易度や内容に関わらず歓迎します。どんなに初歩的と思われる質問でも構いません。
逆に@smallkirbyが即座に答えられない質問には、他の参加者の人が答えてくれるかもしれません。

## 📚 Disclaimer / Contribute

本サイトの内容には誤りがある可能性があります。

誤りを見つけた場合には、以下のいずれかのチャネルで報告してくれると嬉しいです:

- [P3LANDのGitHubページ](https://github.com/smallkirby/p3land)
- セキュリティキャンプ参加者向けDiscord
- [@smallkirbyのTwitter](https://twitter.com/smallkirby)

## 📝 Note

- 講義に利用した資料は以下のリポジトリで公開しています: [smallkirby/seccamp23c2-assets](https://github.com/smallkirby/seccamp23c2-assets)
