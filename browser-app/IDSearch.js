// npm外部ライブラリ
var BigNumber = require('bignumber.js');
var leftPad = require('left-pad');
var request = require('sync-request'); // 同期処理用のrequest

// 使ってないライブラリ
// var request = require('request'); // JSONリクエストの定義 クロスドメイン問題になる？
// var axios = require('axios'); // Promiseに対応 (非同期は除く)

// web3インスタンスを作成
var Web3 = require('web3');
var web3 = new Web3();
web3.setProvider(new web3.providers.HttpProvider('http://localhost:8545'));
web3.eth.defaultAccount=web3.eth.accounts[0];

// コントラクトのインスタンスを作成
// var addr = '0x7bc49432896bcaf37a0fd2f6e572a6c1a6d9cf36';
var contract_json = require('../build/contracts/BulkedGIIAM.json');
var addr = contract_json.networks[1].address;
var abi = contract_json.abi;
// console.log(addr); 空白
console.log(addr);

var test = web3.eth.contract(abi).at(addr); // Web3@0.16.0までこの方式1.0.0betaは非対応

// ID空間獲得ウェブアプリ
var targetID;
var targetIDStr;
var decision = 0; // 判断に使う
// JSONデータを取得できたフラグが立った場合に
var json; // jsonの獲得
var jsonFlag = 0;
// ブロックチェーンデータ
var IDSpace;
var owner;
var domain;

function response(req, res) {
    // ローカル変数の宣言
    var data = "";
    var obj;    
    
    function makeHTML() {
	var template = fs.readFileSync("./html/IDSearch.ejs", "utf-8");
	var html = ejs.render(template, {targetIDStr: targetIDStr, decision: decision, json: json, jsonFlag: jsonFlag,
					 IDSpace: IDSpace, owner: owner, domain: domain}); // 名前を決定
	res.writeHead(200, {"Content-type": "text/html"});
	res.write(html);
	res.end();
    }
    
    function getData(chunk) {
      data += chunk;
	// console.log(chunk);
    }
    
    function getDataEnd() {
	obj = qs.parse(data);
	console.log(obj);
	targetID = obj;
	checkInput(targetID);
	makeHTML();
    }
    
    function checkInput(_targetID) {
	console.log("DEBUG");
	if (_targetID.name == '') {
	    console.log("DEBUG1");
	    decision = -1;
	    targetIDStr = _targetID.name;
	} else if (isNaN(_targetID.name)) {
	    console.log("DEBUG2");
	    decision = -2;
	    targetIDStr = _targetID.name;
	} else {
	    console.log("DEBUG3");
	    decision = 1;
	    console.log(_targetID.name);
	    var num = new BigNumber(_targetID.name);
	    // console.log(num);
	    targetIDStr = "0x" + leftPad(num.toString(16), 32, 0); // 16 Byte = 128bit (=32*4)
	    IDSpace = test.getIDS.call();
	    console.log("DEBUGXXXX");
	    test.getAddr64.call("0x000000001e0000ffff");
	    console.log("HHHHEHYE");
	    owner = test.getAddr64.call("0x000000001e0000ffff");
	    // owner = test.getAddr64.call("0x000000001e0000ffff", function(error, value) { }); // 非同期処理
	    domain = test.getDomain64.call("0x000000001e0000ffff");
	    // domain = test.getIDS.call();
	    // console.log(IDSpace);
	}
	
    }
    
    if (req.method == "POST") {
	decision = 0; // 判定フラグリセット
	jsonFlag = 0;
	req.on('data', getData);
	req.on('end', getDataEnd);
    } else if (req.method == "GET") {
	// 非同期処理
	/*
	request("http://prismoid.webcrow.jp/json/11110000ffff0001.json", function (error, response, body) {
	    console.log('error:', error); // Print the error if one occurred
	    console.log('statusCode:', response && response.statusCode); // Print the response status code if a response was received
	    console.log('body:', body); // Print the HTML for the Google homepage.
	    json = body;
	    jsonFlag = 1;
	});
	*/
	// 同期処理
	response = request('GET', 'http://prismoid.webcrow.jp/json/11110000ffff0001.json');
	json = response.body; // JSON化するときはJSON.parse, JSON.stringfyは文字列化
	jsonFlag = 1;
	makeHTML();
    } else {
	jsonFlag = 0;
	makeHTML(); // 通常にHTMLを表示
    }

}
 
var http = require("http");
var fs = require("fs");
var ejs = require("ejs");
var qs = require('querystring');
var server = http.createServer();
server.on("request", response);
server.listen(1234);
console.log("server started.");
