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

// ID空間譲渡テスト
console.log("ID空間譲渡テスト");
var keyIDSpace = "0x1001000000001e";
var x1 = new BigNumber('0x271000'); // 2560000ブロックまで有効
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
    result = test.assignRight64.sendTransaction(keyIDSpaceAndRange, validateBlockHeight, web3.eth.accounts[2], v, r, s);
    console.log("result: " + result);
}
console.log();

// var prev_balance = new BigNumber("100974499240000000000", 10);
// var div = new BigNumber("20000000000", 10); // 20GWei / gas とする
var balance = web3.eth.getBalance(web3.eth.accounts[1]);
console.log("balance: " + balance);
// console.log("gas: " + (prev_balance - balance) / div);
