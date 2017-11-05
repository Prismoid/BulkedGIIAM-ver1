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

// ID空間Getテスト
console.log("ID空間所有者確認テスト");
var keyIDSpace = "0x1001000000001e";
var keyIDSpaceAndRange = keyIDSpace + "00000000ffffffff";
                                                                     
result = test.getAddr64.call(keyIDSpaceAndRange);
console.log("result: " + result);
