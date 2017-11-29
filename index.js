"use strict";
const fs = require('fs');                                       // for reading the JSON file
const userAgent = `Node ${process.version}`;                    // the user agent we set to talk to github
var extract = require('extract-zip');
const util = require('util');                                   // for using child-process
const PDFDocument = require('pdfkit');
const exec = require('child-process-promise').exec;
const config = require('./config');                             // confiog file for script
const swChecklist = JSON.parse(fs.readFileSync(config.checklistName, 'utf-8'));
/*
simple script to get recent NVD JSON data from their CDN in a zip format
unzip it and check against a set of manufacturers & software products to track vulnerabilites

TODO: Allow for vulerability severity configuration based on the config.js file
TODO: get the XML too eventually to allow for both URLs to be used?
TODO: better format the data
TODO: allow argument flag for getting RECENT or ALL year 20XX vulnerabilities
TODO: figure out what the hell this was intended to do with the data
TODO: Do something with the date on NVD entries
TODO: allow for a -r (recent) or -f (full-check) arg
TODO: create a CLI search functionality
*/

//script starts here
console.log(`\nNVD RECENT Vulnerability Script Started on ${new Date().toISOString()}\n`);
Promise.resolve()                                               // start the promise chain as resolved to avoid issues
    .then(() => {                                               // Get the RECENT json that is in .zip format
        return new Promise((resolve, reject) => {
            exec(`curl "${config.NVDURL}" > test.zip`)
                .then(function (result) {
                    var stdout = result.stdout;
                    var stderr = result.stderr;
                    console.log('stderr: ', stderr);            // debugging
                    return resolve(stdout);
                });
        });
    })
    .then(() => {
        // unzip the JSON and write to file, looks like this module only allows cwd extracts
        return extract('test.zip', { dir: process.cwd() }, function (err) {
            //return console.log(err);                                               // extraction is complete,  make sure to handle the err 
        });
    })
    .then(() => {
        // read file contents to memory
        let NVDJSON = fs.readFileSync(config.NVDJSONFileName, 'utf-8');
        let parsedNVDData = JSON.parse(NVDJSON);
        return parsedNVDData;
    })
    .then((NVDObj) => {
        console.log(`CVE data version: ${NVDObj.CVE_data_version}`);
        console.log(`CVE count: ${NVDObj.CVE_data_numberOfCVEs}`);
        console.log(`Last Updated: ${NVDObj.CVE_data_timestamp}`);
        var affectedItems = [];
        NVDObj.CVE_Items.forEach((entry, index) => {
            var affectedItem = {};
            entry.cve.affects.vendor.vendor_data.forEach((entryV, indexV) => {
                // check against the list of vendors to check for vulnerabilities
                swChecklist.forEach((item, itemIndex) => {
                    if (entryV.vendor_name.toLowerCase() == item.manufacturerName.toLowerCase() && entryV.product.product_data[0].product_name == item.softwareName.toLowerCase()) {
                        console.log(`\nVendor name:  ${entryV.vendor_name}`);
                        console.log(`Product name: ${entryV.product.product_data[0].product_name}`);
                        console.log(`Published Date: ${entry.publishedDate}`);
                        console.log(`Last modified: ${entry.lastModifiedDate}`);
                        console.log(`Vulnerability description:\n ${entry.cve.description.description_data[0].value}`);
                        // log all of the versions affected:
                        var versionsAffected = [];
                        entryV.product.product_data[0].version.version_data.forEach((version) => {
                            versionsAffected.push(version.version_value);
                        });
                        console.log(`\nVersions Affected: ${versionsAffected.join('    ')}`);
                        // log impact score here v3 and v2
                        console.log(`Attack vector: ${entry.impact.baseMetricV3.cvssV3.attackVector}`);
                        console.log(`V3 Severity: ${entry.impact.baseMetricV3.cvssV3.baseSeverity} (${entry.impact.baseMetricV3.cvssV3.baseScore})`);
                        console.log(`V2 Severity: ${entry.impact.baseMetricV2.severity} (${entry.impact.baseMetricV2.cvssV2.baseScore})`);
                        // push all of the data to an the affectedItem Obj
                        affectedItem.vendorName = entryV.vendor_name;
                        affectedItem.productName = entryV.product.product_data[0].product_name;
                        affectedItem.publishedDate = entry.publishedDate;
                        affectedItem.lastModifiedDate = entry.lastModifiedDate;
                        affectedItem.vulnerabilityDescription
                        affectedItem.versionsAffected = versionsAffected;
                        affectedItem.attackVector = entry.impact.baseMetricV3.cvssV3.attackVector
                        affectedItem.v3SeverityScore = {
                            severity: entry.impact.baseMetricV3.cvssV3.baseSeverity,
                            scoreString: entry.impact.baseMetricV3.cvssV3.baseScore
                        }
                        affectedItem.v2SeverityScore = {
                            severity: entry.impact.baseMetricV2.severity,
                            scoreString: entry.impact.baseMetricV2.cvssV2.baseScore
                        }
                        // push the affected item to the array
                        affectedItems.push(affectedItem)
                    }
                });
            });
        });
        return affectedItems;
    })
    .then((affectedItemsArray) => {
        // write the report (to JSON for now!)
       affectedItemsArray.forEach((entry, index) => {
           console.log(entry);
           var doc = new PDFDocument;
           
       })
    })
    .then(() => {
        console.log(`\nSuccessfully ended on ${new Date().toISOString()}`);
    })
    .catch((err) => {
        console.log(`Ended with error at ${new Date().toISOString()}:${err}`);
    });