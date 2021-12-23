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


// It works but needs to refresh the page few times until the file is downloaded
 function DnsTwistApi(domainName) {
  let bufstr = Buffer.from(domainName,'utf8');
  let domainHex = bufstr.toString('hex');
  console.log(domainHex);
  var DnsTwistUrl = `https://dnstwister.report/search/${domainHex}/json`;
  let DnsTwistUrlFuzzer = `https://dnstwister.report/api/fuzz/${domainHex}`;
  let whoisurl = `https://dnstwister.report/api/whois/${domainHex}`;
  https.get(DnsTwistUrlFuzzer, function(res){
  const  fileStreamDns =  fs.createWriteStream(path.join(__dirname, "/dist/DnsTiwsitRes.json"));
    res.pipe(fileStreamDns);
    fileStreamDns.on("finish", function () {
       fileStreamDns.close();
       console.log("Done Downloading json file");
     });
  });
   
  var data =  require(path.join(__dirname, "/dist/DnsTiwsitRes.json"));
  console.log(typeof(data));
  var dataLight = data.fuzzy_domains;
  var dataTable = [];
  for(var i =0; i< dataLight.length;i++){
      dataTable[i] = dataLight[i].domain;
  }
 
  return  dataTable;

}

// Whois Lookup for a domain
 function WhoisLookupDns(domainName) {
  let bufstr = Buffer.from(domainName,'utf8');
  let domainHex = bufstr.toString('hex');
  let url = `https://dnstwister.report/api/whois/${domainHex}`;
    https.get(url, function(res){
      const  streamfile =  fs.createWriteStream(path.join(__dirname, `/dist/domainwhois.json`));
        res.pipe(streamfile);
        streamfile.on("finish", function () {
           streamfile.close();
           console.log("Done Downloading json file");
         });
      });
    var data =  require(path.join(__dirname, `/dist/domainwhois.json`));
    console.log(typeof(data));
    return data.whois_text;
}

//let dataWhoisLookup = WhoisLookupDns("google.com");

//console.log(dataWhoisLookup);

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
/*let datarr = [""];
fileDataArray.forEach(line){
    dataarr
}*/

function checkIfExists(domaine) {
  
  var check = false;
  var i = 0;
  var fileDataArrayLength = fileDataArray.length;
  console.log(fileDataArrayLength);
  /*   do {
        //console.log("checking " + fileDataArray[i]);
        console.log(i);
        if(fileDataArray[i] == domaine){
            check = true;
            console.log(i + check );
        }
        i++;
    } while (i < fileDataArrayLength || check == true);*/
  //console.log(typeof(fileDataArray[2] == "0001011.com" ));
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
    if(similarity > 0.7){
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

//console.log(chars);
//var similarity = stringSimilarity.compareTwoStrings(chars, "sealed");
//console.log(similarity);
//similarityCheck("google.com");
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
  //res.send(distance) ;
  //res.send("Hello " + checkIfExists("zzy913.com") );
  //res.send(similarityCheck("google.com"));
  //res.sendFile(__dirname + "/views/index.html");
  res.sendFile(path.join(__dirname,"/views/index.html"));
 //res.send(dataWhoisLookup);
  //console.log(typeof(resp));
  /*
var DomaineNameTest = 'google.com';
let resp = DnsTwistApi(DomaineNameTest);
console.log(resp);
let SimilarDomsTwist = DnsTwistSimilarity(resp,DomaineNameTest);
console.log(SimilarDomsTwist);*/
});
// create application/json parser
var jsonParser = bodyParser.json();

// create application/x-www-form-urlencoded parser
var urlencodedParser = bodyParser.urlencoded({ extended: false });
app.post("/domainsearch", urlencodedParser, (req, res) => {
  //console.log(req.body.doms.toString());
  var reqDomainName = req.body.doms.toString();
  //console.log(reqDomainName);
  var resReqDomainName = {} ;
  resReqDomainName = similarityCheck(reqDomainName);
/*  for(const [key, value] of Object.entries(resReqDomainName)){
    console.log(resReqDomainName[key]);
    console.log(resReqDomainName[value]);
}*/
let trimedList = [];
for (let k in resReqDomainName) {
    trimedList.push(k + ' : ' + resReqDomainName[k])
}

res.render('index',{resReqDomainName: resReqDomainName});
 // res.sendFile(__dirname + "/views/index.html" , resReqDomainName);
});
// DnsTwistPage
app.post("/dnstwistsearch",urlencodedParser,(req,res) =>{
  var reqDomainName = req.body.doms.toString();
  console.log(reqDomainName);
  var resReqDomainName = {};
  let resp = DnsTwistApi(reqDomainName);
  //console.log(resp);
  resReqDomainName = DnsTwistSimilarity(resp,reqDomainName);
  let trimedList = [];
  for (let k in resReqDomainName) {
    trimedList.push(k + ' : ' + resReqDomainName[k]);
  }
  res.render('dns.ejs',{resReqDomainName: resReqDomainName});
});
// Render DomainWhois page
app.get("/views/domainwhois.ejs",urlencodedParser , (req,res) =>{
  var reqDomainNamebtn = req.query.id.toString();
  //var dom = reqDomainNamebtn.
  console.log(reqDomainNamebtn);
  var dataWhoisLookup =  WhoisLookupDns(reqDomainNamebtn);
  res.render('domainwhois.ejs',{dataWhoisLookup: dataWhoisLookup});
});

app.listen(3000);