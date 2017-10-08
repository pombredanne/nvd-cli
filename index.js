"use strict";
const request = require('request');                             //for NVD API calls
const rp = require('request-promise');                          //wrap request with promises for easir flow control
const fs = require('fs');                                       //for reading the JSON file
const userAgent = `Node ${process.version}`;                    //the user agent we set to talk to github
var extract = require('extract-zip');
const util = require('util');                                   //for using child-process
const exec = require('child-process-promise').exec;
const config = require('./config');                             //confiog file for script
//this is long, redo!
const swChecklist = JSON.parse(fs.readFileSync(config.checklistName, 'utf-8'));

//simple script to get recent NVD JSON data from their CDN in a zip format
//unzip it and check against a set of manufacturers to track vulnerabilites
//for

//Notes:
//Looks like request is corrupting the ZIP file,using CURL instead

//TODO:
//Allow for vulerability severity configuration based on the config.js file
///get the XML too eventually to allow for both URLs to be used?

//script starts here
console.log(`\nNVD Recent Vulnerability Script Started on ${new Date().toISOString()}`);
Promise.resolve()                                               //start the promise chain as resolved to avoid issues
    .then(() => {
        //Get the RECENT json that is in .zip format
        return new Promise((resolve, reject) => {
            exec(`curl "${config.NVDURL}" > test.zip`)
                .then(function (result) {
                    var stdout = result.stdout;
                    var stderr = result.stderr;
                    console.log('stderr: ', stderr);            //debugging
                    return resolve(stdout);
                });
        });
    })
    .then(() => {
        //unzip the JSON and write to file
        //looks like this module only allows cwd extracts
        return extract('test.zip', { dir: process.cwd() }, function (err) {
            // extraction is complete. make sure to handle the err 
            //looks like this package also whines about an undefined error
            console.log(err)
        })
    })
    .then(() => {
        //read file contents to memory
        let NVDJSON = fs.readFileSync(config.NVDJSONFileName, 'utf-8');
        return NVDJSON;
    })
    .then((NVDJSONData) => {
        //for now just to get things working, list data about ALL recents
        console.log(NVDJSONData.length);                        //debugging
        let parsedNVDData = JSON.parse(NVDJSONData);
        return parsedNVDData;
    })
    .then((NVDObj) => {
        console.log(`CVE data version: ${NVDObj.CVE_data_version}`);
        console.log(`CVE count: ${NVDObj.CVE_data_numberOfCVEs}`);
        console.log(`Last Updated: ${NVDObj.CVE_data_timestamp}`);
        NVDObj.CVE_Items.forEach((entry, index) => {
            //console.log(entry.cve.affects.vendor.vendor_data);
            //console.log(entry.cve.description.description_data[0].value)
            entry.cve.affects.vendor.vendor_data.forEach((entryV, indexV) => {
                //check against the list of vendors to check for vulnerabilities
                if (entryV.vendor_name.toLowerCase() == swChecklist[0].manufacturerName.toLowerCase()) {
                    console.log("\nVendor name: " + entryV.vendor_name);
                    console.log("Product name: " + entryV.product.product_data[0].product_name);
                    console.log("Vulnerability description:\n" + entry.cve.description.description_data[0].value);
                    //log all of the versions affected:
                    entryV.product.product_data[0].version.version_data.forEach((version) => {
                        console.log("Affected version: " + version.version_value);
                    })
                }

            })
        })
    })
    .then(() => {
        console.log(`\nSuccessfully ended on ${new Date().toISOString()}`);
    })
    .catch((err) => {
        console.log(`Ended with error at ${new Date().toISOString()}:${err}`);
    });