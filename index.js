"use strict";
const fs = require('fs');                                       // for reading the JSON file
const userAgent = `Node ${process.version}`;                    // the user agent we set to talk to github
var extract = require('extract-zip');
const util = require('util');                                   // for using child-process
const PDFDocument = require('pdfkit');
const exec = require('child-process-promise').exec;
const config = require('./config');                             // confiog file for script
const swChecklist = JSON.parse(fs.readFileSync(config.checklistName, 'utf-8'));
var globalNVDJSON;
var defaultArg = '-r';
/*
simple script to get recent NVD JSON data from their CDN in a zip format
unzip it and check against a set of manufacturers & software products to track vulnerabilites

Notes: the PDF way to get bold text is 'stroke' not bold

TODO: Allow for vulerability severity configuration based on the config.js file
TODO: allow argument flag for getting RECENT or ALL year 20XX vulnerabilities
TODO: figure out what the hell this was intended to do with the data
TODO: Do something with the date on NVD entries
TODO: allow for a -r (recent) or -f (full-check) arg
TODO: create a CLI search functionality
TODO: when done, work on README
*/

function capitalizeFirstLetter(string) {                    //used to clean up some WF data 
    return string.charAt(0).toUpperCase() + string.slice(1);
}

function getNVDZipFile() {
    return new Promise((resolve, reject) => {
        exec(`curl "${config.NVDURL}" > ${config.zipFileName}`)
            .then(function (result) {
                var stdout = result.stdout;
                var stderr = result.stderr;
                console.log('stderr: ', stderr);            // debugging
                return resolve(stdout);
            });
    });
}

function extractZipFile(fileNameToExtract) {
    // unzip the JSON and write to file, looks like this module only allows cwd extracts
    return extract(fileNameToExtract, { dir: process.cwd() }, function (err) {
        if (err) { return console.log(err); }                                              // extraction is complete,  make sure to handle the err 
    });
}

function parseNVDData(NVDObjArray) {
    console.log(`CVE data version: ${NVDObjArray.CVE_data_version}`);
    console.log(`CVE count: ${NVDObjArray.CVE_data_numberOfCVEs}`);
    console.log(`Last Updated: ${NVDObjArray.CVE_data_timestamp}`);
    var affectedItems = [];
    NVDObjArray.CVE_Items.forEach((entry, index) => {
        var affectedItem = {};
        entry.cve.affects.vendor.vendor_data.forEach((entryV, indexV) => {
            // check against the list of vendors to check for vulnerabilities
            swChecklist.forEach((item, itemIndex) => {
                if (entryV.vendor_name.toLowerCase() == item.manufacturerName.toLowerCase()) {
                    entryV.product.product_data.forEach((product, productIndex) => {
                        if (product.product_name == item.softwareName.toLowerCase()) {
                            var versionsAffected = [];
                            entryV.product.product_data[0].version.version_data.forEach((version) => {
                                versionsAffected.push(version.version_value);
                            });
                            // push all of the data to an the affectedItem Obj
                            affectedItem.ID = entry.cve.CVE_data_meta.ID;
                            affectedItem.vendorName = entryV.vendor_name;
                            affectedItem.productName = entryV.product.product_data[0].product_name;
                            affectedItem.publishedDate = entry.publishedDate;
                            affectedItem.lastModifiedDate = entry.lastModifiedDate;
                            affectedItem.vulnerabilityDescription = entry.cve.description.description_data[0].value;
                            affectedItem.versionsAffected = versionsAffected;
                            // validate that v3 exists
                            if (entry.impact.hasOwnProperty('baseMetricV3')) {
                                affectedItem.v3SeverityScore = {
                                    severity: entry.impact.baseMetricV3.cvssV3.baseSeverity,
                                    scoreString: entry.impact.baseMetricV3.cvssV3.baseScore
                                }
                                affectedItem.attackVector = entry.impact.baseMetricV3.cvssV3.attackVector;
                            } else {
                                affectedItem.v3SeverityScore = {
                                    severity: 'NONE',
                                    scoreString: 'NONE'
                                }
                            }
                            // Do the same for v2
                            if (entry.impact.hasOwnProperty('baseMetricV2')) {
                                affectedItem.v2SeverityScore = {
                                    severity: entry.impact.baseMetricV2.severity,
                                    scoreString: entry.impact.baseMetricV2.cvssV2.baseScore
                                }
                            } else {
                                affectedItem.v2SeverityScore = {
                                    severity: 'NONE',
                                    scoreString: 'NONE'
                                }
                            }
                            // push the affected item to the array to return
                            affectedItems.push(affectedItem);
                        }
                    });
                }
            });
        });
    });
    console.log(`Number of mathces found: ${affectedItems.length}`);
    return affectedItems;
}

function writePDFReport(affectedItemsArray) {
    var doc = new PDFDocument;
    doc.pipe(fs.createWriteStream('output.pdf'));
    doc.fontSize(16);
    doc.font(config.defaultFontLocation);
    doc.text(`NVD RECENT Vulnerability Check Report ${new Date().toDateString()}`, { align: 'center', stroke: true });
    doc.fontSize(12);
    doc.moveDown();
    doc.moveDown();
    doc.text(`CVE data version: ${globalNVDJSON.CVE_data_version}`);
    doc.text(`CVE count: ${globalNVDJSON.CVE_data_numberOfCVEs}`);
    doc.text(`Last Updated: ${globalNVDJSON.CVE_data_timestamp}`);
    doc.moveDown();
    doc.fontSize(14);
    doc.text(`RECENT vulnerabilites matched using config file: ${config.checklistName}`, { align: 'center' });
    doc.moveDown();
    // get each affected item's data and format it
    affectedItemsArray.forEach((entry, index) => {
        doc.text(`\n${capitalizeFirstLetter(entry.vendorName)} ${capitalizeFirstLetter(entry.productName)} (${entry.ID})`, { stroke: true });
        doc.text(`Versions Affected: ${entry.versionsAffected.join(', ')}`);
        doc.text(`Attack Vector: ${entry.attackVector}`);
        doc.text(`\nDescription: ${entry.vulnerabilityDescription}`);
        doc.text(`\nV3 Score: ${entry.v3SeverityScore.severity} (${entry.v3SeverityScore.scoreString})`);
        doc.text(`V2 Score: ${entry.v2SeverityScore.severity} (${entry.v2SeverityScore.scoreString})`);
        doc.text(`\nPublished: ${entry.publishedDate}    Modified: ${entry.lastModifiedDate}`)
    });
    doc.text('\n\nEnd of File');
    doc.end();

}

// script starts here
// args will eventually be processed here
console.log(`\nNVD Vulnerability Check Script Started on ${new Date().toISOString()}\n`);
if (process.argv[2] == '-r' || process.argv[2] == '--recent') {
    Promise.resolve()                                               // start the promise chain as resolved to avoid issues
        .then(() => getNVDZipFile())                                // Get the RECENT json that is in .zip format
        .then(() => extractZipFile(config.zipFileName))
        .then(() => {
            let NVDJSON = fs.readFileSync(config.NVDJSONFileName, 'utf-8');
            let parsedNVDData = JSON.parse(NVDJSON);
            globalNVDJSON = parsedNVDData;                              // used to allow the PDF file acess to certain data
            return parsedNVDData;
        })
        .then((NVDData) => parseNVDData(NVDData))
        .then((affectedItemsArray) => writePDFReport(affectedItemsArray))
        .then(() => {
            console.log(`\nSuccessfully ended on ${new Date().toISOString()}`);
        })
        .catch((err) => {
            console.log(`Ended with error at ${new Date().toISOString()}: ${err}`);
        })
} else if (process.argv[2] == '-f') {
console.log('AAAAAAA')
} else {
    //display help file
}
