/*** 外部ライブラリの読み込み ***/
// 関数呼び出し用
var BigNumber = require('bignumber.js'); // npm install bignumber, https://www.npmjs.com/package/bignumber.js
var leftPad = require('left-pad'); // npm install left-pad, https://www.npmjs.com/package/left-padのサイトとかにある
var web3utils = require('web3-utils'); // npm install web3-utils, https://www.npmjs.com/package/web3-utilsなど
// Web3のインスタンスの作成
var Web3 = require('web3');
var web3 = new Web3();
web3.setProvider(new web3.providers.HttpProvider('http://localhost:8545'));
web3.eth.defaultAccount = web3.eth.accounts[1];

// コントラクトのインスタンスを作成
var contract_json = require('../build/contracts/BulkedGIIAM.json');
var addr = contract_json.networks[1].address;
var abi = contract_json.abi;
var test = web3.eth.contract(abi).at(addr);

var result;
// テストを実行
console.log("--- incrementTLDcのテスト ---");
result = test.incrementTLDc.call();
console.log("result: " + result);
console.log();
console.log("--- updateDiffTargetのテスト ---");
result = test.updateDiffTarget.call('0x197fffff');
console.log("result: " + result);
console.log();
console.log("--- stringのテスト ---");
// result = test.testStr.sendTransaction("prismoid.webcrow.jpprismoid.webcrow.jpprismoid.webcrow.jpprismoid.webcrow.jpprismoid.webcrow.jpprismoid.webcrow.jpprismoid.webcrow.jpprismoid.webcrow.jpprismoid.webcrow.jpprismoid.webcrow.jpprismoid.webcrow.jpprismoid.webcrow.jpprismoid.webcrow.jpaaaaaa");
// result = test.testStr.call("prismoid.webcrow.jpprismoid.webcrow.jpprismoid.webcrow.jpprismoid.webcrow.jpprismoid.webcrow.jpprismoid.webcrow.jpprismoid.webcrow.jpprismoid.webcrow.jpprismoid.webcrow.jpprismoid.webcrow.jpprismoid.webcrow.jpprismoid.webcrow.jpprismoid.webcrow.jpaaaaaab");
console.log("result: " + result);
console.log();

// ID空間発行テスト
console.log("ID空間発行テスト");
var keyIDSpace = "0x1001000000001e";
var nonce = 1;
var blockH = 2500;
result = test.regIDSpace64.call(keyIDSpace, blockH, nonce);
console.log("result: " + result);
if (result) {
    result = test.regIDSpace64.sendTransaction(keyIDSpace, blockH, nonce, {gas: 4700000});
    console.log("result: " + result);
}
console.log();

// ID空間譲渡テスト
console.log("ID空間譲渡テスト");
var x1 = new BigNumber('0x2710'); // 10000ブロックまで有効
var keyIDSpaceAndRange = keyIDSpace + "00000000ffffffff";
var validateBlockHeight = "0x" + leftPad(web3.toHex(x1).slice(2).toString(16), 16, 0); // 16*4=64bit
var hash = web3utils.soliditySha3({t: 'uint120', v: keyIDSpaceAndRange}, {t: 'uint64', v: validateBlockHeight});
var sig = web3.eth.sign(web3.eth.accounts[2], web3utils.soliditySha3({t: 'uint120', v: keyIDSpaceAndRange}, {t: 'uint64', v: validateBlockHeight}));
// r, s, vを各々定義する
var v = Number(sig.slice(130,132)) + 27; // これだけ数値型
var r = sig.slice(0,66);
var s = '0x' + sig.slice(66,130);
result = test.assignRight64.call(keyIDSpaceAndRange, validateBlockHeight, web3.eth.accounts[2], v, r, s);
console.log("result: " + result);
if (result) {
    result = test.assignRight64.sendTransaction(keyIDSpaceAndRange, validateBlockHeight, web3.eth.accounts[2], v, r, s, {gas: 4700000});
    console.log("result: " + result);
}
console.log();

// ドメイン登録テスト
console.log("ドメイン登録テスト");



// お金がどれだけ減ったか
var prev_balance = new BigNumber("100974499240000000000", 10);
var div = new BigNumber("20000000000", 10);
var balance = web3.eth.getBalance(web3.eth.accounts[1]);
console.log("balance: " + balance);
console.log("gas: " + (prev_balance - balance) / div);
/*
if (result) {
    result = test.regIDSpace64.sendTransaction(keyIDSpaceAndRange, validateBlockHeight, web3.eth.accounts[2], v, r, s);
    console.log("result: " + result);
}
*/

/*** ディジタル署名の実行 ***/
// string型で作成した場合(Solidity側でもStringで受ける必要がある)
/*
var x1 = new BigNumber('0x2710'); // 10000ブロックまで有効
var _keyIDSpaceAndRange = '0x000000001e0000ffff';
var _validateBlockHeight = "0x" + leftPad(web3.toHex(x1).slice(2).toString(16), 32, 0); // 32*4=128bit
var _middleOfRange = ["0x3fff", "0x7fff"]; // 1/4, 1/4, 1/2の分け方
var _toPlace = ["0x00", "0x01"];
var _ownerPlace = ["0x02"];
var _to = [web3.eth.accounts[1], web3.eth.accounts[2]];
var _v = new Array(0);
var _r = new Array(0);
var _s = new Array(0);
*/

// ！！！！デバック完了！！！！
// https://github.com/ethereumjs/ethereumjs-abi/issues/27!!!に記述あり！下記のコードはうまく動く
/*
console.log("--- 署名するメッセージのテストを行う ---");
var hash = web3utils.soliditySha3({t: 'uint72', v: _keyIDSpaceAndRange}, {t: 'uint128', v: _validateBlockHeight}, 
				  {t: 'uint256[]', v: _middleOfRange}, {t: 'uint256[]', v: _toPlace},
				  {t: 'uint256[]', v: _ownerPlace}, {t: 'uint256[]', v: _to}); // uint256[]で入ることに注意する！！！
var hash_remote = test.getTransHash.call(_keyIDSpaceAndRange, _validateBlockHeight, _middleOfRange, _toPlace, _ownerPlace, _to);
*/
/*
var hash = web3utils.soliditySha3({t: 'uint72', v: _keyIDSpaceAndRange}, {t: 'uint128', v: _validateBlockHeight}, 
				  {t: 'uint16[]', v: _middleOfRange}, {t: 'uint8[]', v: _toPlace});
var hash_remote = test.getTransHash.call(_keyIDSpaceAndRange, _validateBlockHeight, _middleOfRange, _toPlace, [], []);
*/
/*
console.log("署名するメッセージ(ローカル): " + hash);
console.log("署名するメッセージ(リモート): " + hash_remote);
console.log();

console.log("--- String Digital Sign ---");
// 署名一つ目
console.log(web3.eth.accounts[1] + " による署名 ");
var sig1 = web3.eth.sign(web3.eth.accounts[1], web3utils.soliditySha3({t: 'uint72', v: _keyIDSpaceAndRange}, {t: 'uint128', v: _validateBlockHeight}, 
								      {t: 'uint256[]', v: _middleOfRange}, {t: 'uint256[]', v: _toPlace},
								      {t: 'uint256[]', v: _ownerPlace}, {t: 'uint256[]', v: _to}));
console.log("sig1: " + sig1);
// r, s, vを各々定義する
var v1 = Number(sig1.slice(130,132)) + 27; // これだけ数値型
var r1 = sig1.slice(0,66);
var s1 = '0x' + sig1.slice(66,130);

// 署名二つ目
var sig2 = web3.eth.sign(web3.eth.accounts[2], web3utils.soliditySha3({t: 'uint72', v: _keyIDSpaceAndRange}, {t: 'uint128', v: _validateBlockHeight}, 
								      {t: 'uint256[]', v: _middleOfRange}, {t: 'uint256[]', v: _toPlace},
								      {t: 'uint256[]', v: _ownerPlace}, {t: 'uint256[]', v: _to}));
console.log("sig2: " + sig2);
// r, s, vを各々定義する
var v2 = Number(sig2.slice(130,132)) + 27; // これだけ数値型
var r2 = sig2.slice(0,66);
var s2 = '0x' + sig2.slice(66,130);

_v = [v1, v2];
_r = [r1, r2];
_s = [s1, s2];
console.log(_v);
console.log(_r);
console.log(_s);

// decision = test.transferIDSpace64.call(_keyIDSpaceAndRange, _validateBlockHeight, _middleOfRange, _toPlace, _ownerPlace, _to, _v, _r, _s);
var decision = test.transferIDSpace64.sendTransaction(_keyIDSpaceAndRange, _validateBlockHeight, _middleOfRange, _toPlace, _ownerPlace, _to, _v, _r, _s, {gas: 4000000});
console.log(decision);
*/
