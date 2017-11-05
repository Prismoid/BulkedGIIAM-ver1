/*** require the external Liblary ***/
// employed as the function
var BigNumber = require('bignumber.js'); // npm install bignumber, https://www.npmjs.com/package/bignumber.js
var leftPad = require('left-pad'); // npm install left-pad, https://www.npmjs.com/package/left-pad
var web3utils = require('web3-utils'); // npm install web3-utils, https://www.npmjs.com/package/web3-utils
// making a Web3 instance
var Web3 = require('web3');
var web3 = new Web3();
console.log("TEST");
// web3.setProvider(new web3.providers.HttpProvider('http://localhost:8545'));
web3.setProvider(new web3.providers.HttpProvider('http://172.26.16.6:8545'));
web3.eth.defaultAccount = web3.eth.accounts[0];
console.log(web3.eth.blockNumber);



// making a contract instance (Sha3AndSign)
// var contract_json = require('../build/contracts/Sha3AndSign.json');
// var addr = contract_json.networks[1].address;
// var abi = contract_json.abi;
// var contract = web3.eth.contract(abi).at(addr);

console.log(web3.eth.accounts[0]);
