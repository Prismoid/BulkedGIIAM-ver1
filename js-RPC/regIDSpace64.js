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

// ID空間発行テスト
console.log("ID空間発行テスト");
var keyIDSpace = "0x1001000000001e";
var nonce = 1;
var blockH = 1900;

var wrongKeyIDSpace1 = "0x10000000000020";
var wrongKeyIDSpace2 = "0x20000000000020";
result = test.regIDSpace64.call(wrongKeyIDSpace1, blockH, nonce);
console.log("result(false): " + result);
result = test.regIDSpace64.call(wrongKeyIDSpace2, blockH, nonce);
console.log("result(false): " + result);

// e.g. マイニング1931ブロック
// ハッシュが取れるブロック: 1674-1929(256個), 直近のブロックの情報は得られない
result = test.regIDSpace64.call(keyIDSpace, blockH, nonce);
console.log("result(true): " + result);
if (result) {
    result = test.regIDSpace64.sendTransaction(keyIDSpace, blockH, nonce);
    console.log("result: " + result);
}
// var prev_balance = new BigNumber("100974499240000000000", 10);
// var div = new BigNumber("20000000000", 10); // 20GWei / gas とする
var balance = web3.eth.getBalance(web3.eth.accounts[1]);
console.log("balance: " + balance);
// console.log("gas: " + (prev_balance - balance) / div);
