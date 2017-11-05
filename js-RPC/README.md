/**** Web3.pyはうまく動かない！！jsを使おう！ ****/
[Javascript実行方法]
node sample.js で実行できる
Terminalに文字をconole.log("DEBUG")と打てば表示できる 
https://qiita.com/ukiuni@github/items/d077e2d450c79829a67f

[**** 重要 **** Web3.jsを使ってJavaScriptからEthereumのスマートコントラクトを制御する]
https://qiita.com/oggata/items/53f533503481edde6da4

[Web3.jsを使わず、Gethに接続せずに署名を作成する]
ライブラリの紹介をしている
https://ethereum.stackexchange.com/questions/6368/using-web3-to-sign-a-transaction-without-connecting-to-geth

[solidity-sha3の使い方]
var sha3 = require('solidity-sha3').sha3withsize;
sha3(1, 32) // 0x00000001をsha3の入力とする

[SolidityのSha3を扱う場合に文字列リテラルが重要]
sha3("0xa1", "0xa2")を入力とした場合,,,
sha3("0xa1a2")とならずに、sha3("0xa10xa2")となってしまう
つまり
sha3("0xa1", "a2")とする必要がある
sha3("0xa1a2")と一致する

[JavaScriptでWeb上のJSONデータの読み込みを行う]
// うまくいかない, 結果的にnpm install requestが一番簡単
http://uxmilk.jp/46993