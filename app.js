/*jshint esversion: 6 */
const express = require("express");
const app = express();
const decompress = require("decompress");
const https = require("https");
const fs = require("fs");
const readline = require("readline");
const path = require("path");
const { Console } = require("console");
const { toUnicode } = require("punycode");
var stringSimilarity = require("string-similarity");
var bodyParser = require("body-parser");
const axios = require('axios');
const request = require('request');
const { json } = require("body-parser");

const fetch = require('node-fetch');
const url = require('url');
const async = require("async");
const getreq = require("async-get-file");
const { resolve } = require("path");

app.set('views',path.join(__dirname, 'views'));
app.set('view engine','ejs');
global.fileDataArray = [];
let filedata = [];

const Domainurl =
  "https://www.whoisds.com//whois-database/newly-registered-domains/MjAyMS0xMi0xOS56aXA=/nrd?fbclid=IwAR0D-rrILqUUh2RIMXkh4AzmaqwzNF7gchl0ZXdAqJlaZV_OCOYwdta_JjY&h=AT18cj3redIE0dTPFdQoVyUpnyJit20b25KjWT_jQh2dfygIzM0iuWvjTOk3uCEnT49B1zJ23vzejloucu2wt0A6agIb1s5zPwNFO4czxhaIOfkfWaLXPe0gyeSpj8qBPuUnstSoU3w";
https.get(Domainurl, function (res) {
  const fileStream = fs.createWriteStream("domain.zip");
  res.pipe(fileStream);
  fileStream.on("finish", function () {
    fileStream.close();
    console.log("Done Downloading zip file");
    console.log("Unzipping file");
    decompress("domain.zip", "dist", function () {});
    console.log("Done Unzipping the file");

    //fs.readFileSync("/dist/domain-names.txt","utf8",function(err, data){

    //    console.log(data);
    //   console.log("Transeerfing data");
    //        });
    //    const filecontent = fs.readFileSync(__dirname + '/dist/domain-names.txt', (err, data) =>{
    //    if(err) throw err;
    //console.log(data.toString());
    //    filedata = data.toString();
    //});
  });
});
// Code To read from Domain names file line by line
const file = readline.createInterface({
  input: fs.createReadStream(__dirname + "/dist/domain-names.txt"),
  output: process.stdout,
  terminal: false,
});
let i = 0;
file.on("line", (line) => {
  //console.log(line.toString());

  fileDataArray[i] = line.toString();
  //console.log(fileDataArray[i]);
  filedata = fileDataArray;
  i++;
});
// Async Function fetchDomainApi domainwhois
async function fetchAPI(domainName) {
  let bufstr =  await Buffer.from(domainName,'utf8');
  let domainHex = await bufstr.toString('hex');
  let url = await `https://dnstwister.report/api/whois/${domainHex}`;
  const response = await fetch(url);
  const body = await response.json();
  const whoisText = await body.whois_text;
   //console.log(whoisText);

  return whoisText;

}
// Async Function fetchDomainApi Domain Fuzzing
async function fetchAPIDnsTwist(domainName) {
  let bufstr =  await Buffer.from(domainName,'utf8');
  let domainHex = await bufstr.toString('hex');
  let DnsTwistUrlFuzzer = `https://dnstwister.report/api/fuzz/${domainHex}`;
  const response = await fetch(DnsTwistUrlFuzzer);
  const body = await response.json();
  const domains = await body.fuzzy_domains;
   //console.log(whoisText);
  var dataTable = [];
  for(var i =0; i< domains.length;i++){
       dataTable[i] = domains[i].domain;
   }
  return dataTable;

}



function checkIfExists(domaine) {
  
  var check = false;
  var i = 0;
  var fileDataArrayLength = fileDataArray.length;
  console.log(fileDataArrayLength);
  while (i < fileDataArrayLength || check == true) {
    if (fileDataArray[i] == domaine) {
      check = true;
      break;
    }
    i++;
  }

  return check;
}

function similarityCheck(domain) {
  let i = 0;
  var fileDataArrayLength = fileDataArray.length;
  var dict = {};
  while (i < fileDataArrayLength) {
    //console.log("Checking " + fileDataArray[i]);
    var similarity = stringSimilarity.compareTwoStrings(
      fileDataArray[i],
      domain
    ); 
    //console.log(fileDataArray[i]);
    var nameDomane = fileDataArray[i].toString();
    //console.log(typeof(nameDomane));
    // Similarity value to be added by the user
    if(similarity > 0.6){
      dict[nameDomane.toString()] = similarity;
    }
    
    //console.log(similarity);
    i++;
  }
  return dict;
}

function DnsTwistSimilarity(domainsList, DomainNameSim) {
  let i = 0;
  var arrayLength = domainsList.length;
  console.log(arrayLength);
  var dict = {};
  while(i < arrayLength){

    var similarity = stringSimilarity.compareTwoStrings(
      domainsList[i].toString(),
      DomainNameSim.toString()
    );
    console.log(similarity);
    //console.log(similarity);
    var nameDomaine = domainsList[i].toString();
    dict[nameDomaine.toString()] = similarity;
    i++;
  }
  return dict;
}

app.use(
  "/css",
  express.static(path.join(__dirname, "node_modules/bootstrap/dist/css"))
);
app.use(
  "/js",
  express.static(path.join(__dirname, "node_modules/bootstrap/dist/js"))
);
app.use(
  "/js",
  express.static(path.join(__dirname, "node_modules/jquery/dist"))
);


// Render main page
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname,"/views/index.html"));
});
// create application/json parser
var jsonParser = bodyParser.json();

// create application/x-www-form-urlencoded parser
var urlencodedParser = bodyParser.urlencoded({ extended: false });
// Render Daily Domains
app.post("/domainsearch", urlencodedParser, (req, res) => {
  var reqDomainName = req.body.doms.toString(); 
  var resReqDomainName = {} ;
  resReqDomainName = similarityCheck(reqDomainName);
/*  for(const [key, value] of Object.entries(resReqDomainName)){
    console.log(resReqDomainName[key]);
    console.log(resReqDomainName[value]);
}*/
var numberDailyDomains = fileDataArray.length;
let trimedList = [];
for (let k in resReqDomainName) {
    trimedList.push(k + ' : ' + resReqDomainName[k])
}

res.render('index',{resReqDomainName: resReqDomainName, numberDailyDomains: numberDailyDomains});
 // res.sendFile(__dirname + "/views/index.html" , resReqDomainName);
});
// Fulfills the promise and send the data to html response domain whois
app.post('/dnstwistsearch', urlencodedParser, (req,res) => {
  var reqDomainName = req.body.doms.toString();
  console.log(reqDomainName);
  let urlfetch = fetchAPIDnsTwist(reqDomainName);
  urlfetch.then(RertiveData);
  function RertiveData(data){
      var resReqDomainName = {};
      resReqDomainName = DnsTwistSimilarity(data,reqDomainName);
      console.log(data);
      let trimedList = [];
      for (let k in resReqDomainName) {
        trimedList.push(k + ' : ' + resReqDomainName[k]);
      }
      res.render('dns.ejs',{resReqDomainName: resReqDomainName});
  }
  console.log(urlfetch);
  
});
// Fulfills the promise and send the data to html response domain Fuzzing
app.get('/views/domainwhois.ejs', urlencodedParser ,(req,res) => {
  var reqDomainNamebtn = req.query.id.toString();
  let urlfetch = fetchAPI(reqDomainNamebtn);
  urlfetch.then(RertiveData);
  function RertiveData(data){
      console.log(data);
      res.render('domainwhois.ejs',{dataWhoisLookup: data});
  }
  console.log(urlfetch);
  
});
app.listen(3000);