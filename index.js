"use strict";
const request = require('request');                             //for NVD API calls
const rp = require('request-promise');                          //wrap request with promises for easir flow control
const fs = require('fs');                                       //for reading the JSON file
const userAgent = `Node ${process.version}`;                    //the user agent we set to talk to github
const unzipper = require('unzipper');
const util = require('util');                                   //for using child-process-promise
const exec = require('child-process-promise').exec;
const config = require('./config');
//simple script to get recent NVD JSON data from their CDN in a zip format
//unzip it and do some stuff using past project's code

//Notes:
//Looks like request is corrupting the ZIP file,using CURL instead

//TODO:
//Allow for vulerability severity configuration based on the config.js file
///get the XML too eventually to allow for both URLs to be used?

//script starts here
Promise.resolve()                                               //start the promise chain as resolved to avoid issues
    .then(() => {
        console.log(`\nNVD Recent Vulnerability Script Started on ${new Date().toISOString()}`);
    })
    .then(() => {
        //Get the RECENT json that is in .zip format
        return new Promise((resolve, reject) => {
            exec(`curl "${config.NVDURL}" >>test.zip`)
                .then(function (result) {
                    var stdout = result.stdout;
                    var stderr = result.stderr;
                    console.log('stderr: ', stderr);            //debugging
                    return resolve(stdout);
                });
        });
    })
    .then((zippedJSON) => {
        //unzip the JSON and write to file
        return fs.createReadStream('test.zip')
            .pipe(unzipper.Extract({ path: config.NVDPath }));
    })
    .then(() => {
        //read file contents to memory
        var NVDJSON = fs.readFileSync(`${config.NVDPath}/${config.NVDJSONFileName}`, 'utf-8');
        return NVDJSON;
    })
    .then((NVDJSONData) => {
        //for now just to get things working, list data about ALL recents
        console.log(NVDJSONData.length);
    })
    .then(() => {
        console.log(`\nSuccessfully ended on ${new Date().toISOString()}`);
    })
    .catch((err) => {
        console.log(`Ended with error at ${new Date().toISOString()}:
        ${err}`);
    });