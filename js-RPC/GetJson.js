// JSONの呼び出し方
var request = require('request');
var json;
// 非同期処理
request('http://prismoid.webcrow.jp/json/11110000ffff0001.json', function (error, response, body) {
    console.log('error:', error); // Print the error if one occurred
    console.log('statusCode:', response && response.statusCode); // Print the response status code if a response was received
    console.log('body:', body); // Print the HTML for the Google homepage.
    json = body;
});

console.log(json);
console.log("DTETE");
/*
var options = {
  host: 'www.google.com',
  port: 80,
  path: '/index.html'
};

http.get(options, function(res) {
  var body = '';
  res.on('data', function(chunk) {
    body += chunk;
  });
  res.on('end', function() {
    console.log(body);
  });
}).on('error', function(e) {
  console.log("Got error: " + e.message);
}); 


var OpenURL = require("openurl");
var XMLHttpRequest = require("xmlhttprequest").XMLHttpRequest;
var xmlHttpRequest = new XMLHttpRequest();

var json = OpenURL.open("http://prismoid.webcrow.jp/json/11110000ffff0001.json");
console.log(json);

xmlHttpRequest.onreadystatechange = function()
{
    if( this.readyState == 4 && this.status == 200 )
    {
	console.log("TEST")
        if( this.response )
        {
            console.log(this.response);
            // 読み込んだ後処理したい内容をかく

        }
	console.log(this.response)
    }
}

xmlHttpRequest.open( 'GET', 'http://uedayou.net/loa/東京都千代田区千代田1.json', false );
// xmlHttpRequest.open( 'GET', 'http://prismoid.webcrow.jp/json/11110000ffff0001.json', false );
xmlHttpRequest.responseType = 'json';
xmlHttpRequest.send();
var obj = eval('(' + xmlHttpRequest.response + ')');
console.log(obj);
*/
