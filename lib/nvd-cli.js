#!/usr/bin/env node
"use strict";
const fs = require('fs');                                       // for reading the JSON file
var extract = require('extract-zip');
const util = require('util');                                   // for using child-process
const PDFDocument = require('pdfkit');
const exec = require('child-process-promise').exec;
var argv = require('minimist')(process.argv.slice(2));          // for parsing args
const config = require('./config.js');                          // config file for script
const NVDClass = require('./NVDJSONClass.js');                  // helper for getting at NVD Data for specific years
const bright = '\x1b[1m';
const reset = '\x1b[0m';
const debug = config.debug;                                     // used to allow/disallow verbose logging
const ver = '0.5.0';                                            // arbitrary version number, should match NPM version

var globalNVDJSON;
/*
Script scope: To provide a command line utility for generating NVD vulnerability
check reports based on a checklist of products

Note: Searching by vendor and product name seem to return the same results (kind of?)

TODO: Allow for vulerability severity arg (IE Ignore 'LOW' scoring entries that match)
TODO: for recents, ensure that the CVE review is FINAL?
TODO: add params for every function that needs them
TODO: fix the global JSON data issue that really shouldn't be there
TODO: make this usable as an NPM command line util! (kind of like node-mailer CLI)
TODO: allow for better help args handling
TODO: make the NVDCheckFull/Recent one funtion (it's doable!)
TODO: add more of the NVD data to the objects in parseNVDData
TODO: combine the long and shorthand for each command/arg/flag type
TODO: validate checklist type passed to script is .json
TODO: allow for a recent search
*/

function capitalizeFirstLetter(string) {                            // used to clean up some of the NVD names for products
    return string.charAt(0).toUpperCase() + string.slice(1);
}

function getNVDZipFile(url, fileLocation) {
    return new Promise((resolve, reject) => {
        exec(`curl "${url}" > ${fileLocation}`)
            .then(function (result) {
                var stdout = result.stdout;
                var stderr = result.stderr;
                if (debug) { console.log('stderr: ', stderr); }
                return resolve(stdout);
            });
    });
}

// this is a hacky solution.
function extractZipFile(fileNameToExtract) {
    return new Promise((resolve, reject) => {
        return extract(fileNameToExtract, { dir: process.cwd() }, function (err) {
            return resolve(err);
        });
    });
}

function parseNVDData(NVDObjArray, checklist) {
    console.log(`CVE data version: ${NVDObjArray.CVE_data_version}`);
    console.log(`CVE count: ${NVDObjArray.CVE_data_numberOfCVEs}`);
    console.log(`Last Updated: ${NVDObjArray.CVE_data_timestamp}`);
    var affectedItems = [];
    let swChecklist = JSON.parse(fs.readFileSync(checklist, 'utf-8'));
    NVDObjArray.CVE_Items.forEach((entry, index) => {
        var affectedItem = {};
        entry.cve.affects.vendor.vendor_data.forEach((entryV, indexV) => {
            // check against the list of vendors to check for vulnerabilities
            swChecklist.forEach((item, itemIndex) => {
                if (entryV.vendor_name.toLowerCase() == item.manufacturerName.toLowerCase()) {
                    entryV.product.product_data.forEach((product, productIndex) => {
                        if (product.product_name == item.softwareName.toLowerCase()) {
                            if (debug) { console.log(entry); }
                            var versionsAffected = [];
                            var referenceURLs = [];
                            entryV.product.product_data[0].version.version_data.forEach((version) => {
                                versionsAffected.push(version.version_value);
                            });
                            if (entry.cve.hasOwnProperty('references')) {
                                entry.cve.references.reference_data.forEach((ref, refIndex) => {
                                    referenceURLs.push(ref.url);
                                });
                            }
                            // push all of the data to an the affectedItem Obj
                            affectedItem.ID = entry.cve.CVE_data_meta.ID;
                            affectedItem.vendorName = entryV.vendor_name;
                            affectedItem.productName = entryV.product.product_data[0].product_name;
                            affectedItem.publishedDate = entry.publishedDate;
                            affectedItem.lastModifiedDate = entry.lastModifiedDate;
                            affectedItem.vulnerabilityDescription = entry.cve.description.description_data[0].value;
                            affectedItem.versionsAffected = versionsAffected;
                            affectedItem.referenceURLs = referenceURLs
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
                            affectedItems.push(affectedItem);       // push the affected item to the array to return
                        }
                    });
                }
            });
        });
    });
    console.log(`Number of matches found: ${affectedItems.length}`);
    return affectedItems;
}

function searchNVDProducts(NVDObjArray, productSearchQuery) {
    console.log(`CVE data version: ${NVDObjArray.CVE_data_version}`);
    console.log(`CVE count: ${NVDObjArray.CVE_data_numberOfCVEs}`);
    console.log(`Last Updated: ${NVDObjArray.CVE_data_timestamp}`);
    var matches = [];
    NVDObjArray.CVE_Items.forEach((entry, index) => {
        var affectedItem = {};
        entry.cve.affects.vendor.vendor_data.forEach((entryV, indexV) => {
            // check against the list of products to match
            entryV.product.product_data.forEach((product, productIndex) => {
                if (product.product_name == productSearchQuery.toLowerCase() || product.product_name.includes(productSearchQuery.toLowerCase())) {
                    if (debug) { console.log(entry); }
                    var versionsAffected = [];
                    var referenceURLs = [];
                    entryV.product.product_data[0].version.version_data.forEach((version) => {
                        versionsAffected.push(version.version_value);
                    });
                    if (entry.cve.hasOwnProperty('references')) {
                        entry.cve.references.reference_data.forEach((ref, refIndex) => {
                            referenceURLs.push(ref.url);
                        });
                    }
                    // push all of the data to an the affectedItem Obj
                    affectedItem.ID = entry.cve.CVE_data_meta.ID;
                    affectedItem.vendorName = entryV.vendor_name;
                    affectedItem.productName = entryV.product.product_data[0].product_name;
                    affectedItem.publishedDate = entry.publishedDate;
                    affectedItem.lastModifiedDate = entry.lastModifiedDate;
                    affectedItem.vulnerabilityDescription = entry.cve.description.description_data[0].value;
                    affectedItem.versionsAffected = versionsAffected;
                    affectedItem.referenceURLs = referenceURLs
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
                    matches.push(affectedItem);                     // push the affected item to the array to return
                }
            });
        });
    });
    console.log(`Number of matches found for '${productSearchQuery}': ${matches.length}`);
    return matches;
}

function searchNVDVendors(NVDObjArray, vendorSearchQuery) {
    console.log(`CVE data version: ${NVDObjArray.CVE_data_version}`);
    console.log(`CVE count: ${NVDObjArray.CVE_data_numberOfCVEs}`);
    console.log(`Last Updated: ${NVDObjArray.CVE_data_timestamp}`);
    var matches = [];
    let swChecklist = JSON.parse(fs.readFileSync(checklist, 'utf-8'));
    NVDObjArray.CVE_Items.forEach((entry, index) => {
        var affectedItem = {};
        entry.cve.affects.vendor.vendor_data.forEach((entryV, indexV) => {
            // check against the list of vendors to check for vulnerabilities
            if (entryV.vendor_name.toLowerCase() == vendorSearchQuery.toLowerCase()) {
                entryV.product.product_data.forEach((product, productIndex) => {
                    if (debug) { console.log(entry); }
                    var versionsAffected = [];
                    var referenceURLs = [];
                    entryV.product.product_data[0].version.version_data.forEach((version) => {
                        versionsAffected.push(version.version_value);
                    });
                    if (entry.cve.hasOwnProperty('references')) {
                        entry.cve.references.reference_data.forEach((ref, refIndex) => {
                            referenceURLs.push(ref.url);
                        });
                    }
                    // push all of the data to an the affectedItem Obj
                    affectedItem.ID = entry.cve.CVE_data_meta.ID;
                    affectedItem.vendorName = entryV.vendor_name;
                    affectedItem.productName = entryV.product.product_data[0].product_name;
                    affectedItem.publishedDate = entry.publishedDate;
                    affectedItem.lastModifiedDate = entry.lastModifiedDate;
                    affectedItem.vulnerabilityDescription = entry.cve.description.description_data[0].value;
                    affectedItem.versionsAffected = versionsAffected;
                    affectedItem.referenceURLs = referenceURLs
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
                    matches.push(affectedItem);       // push the affected item to the array to return
                });
            }
        });
    });
    console.log(`Number of matches found for '${vendorSearchQuery}': ${matches.length}`);
    return matches;
}

function writePDFReport(affectedItemsArray, timeArg, outputArg) {
    var doc = new PDFDocument;
    doc.pipe(fs.createWriteStream(`${outputArg}.pdf`));
    doc.fontSize(16);
    doc.text(`NVD ${timeArg} Vulnerability Check Report ${new Date().toDateString()}`, { align: 'center', stroke: true });
    doc.fontSize(12);
    doc.text(`\n\nCVE data version: ${globalNVDJSON.CVE_data_version}`);
    doc.text(`CVE count: ${globalNVDJSON.CVE_data_numberOfCVEs}`);
    doc.text(`Last Updated: ${globalNVDJSON.CVE_data_timestamp}`);
    doc.text(`Checklist File: ${config.checklistName}`);
    doc.text(`Number of Vulnerabilites Matched: ${affectedItemsArray.length}`);
    doc.fontSize(14);
    doc.moveDown();
    // get each affected item's data and format it
    affectedItemsArray.forEach((entry, index) => {
        doc.text(`\n${capitalizeFirstLetter(entry.vendorName)} ${capitalizeFirstLetter(entry.productName)} (${entry.ID})`, { stroke: true });
        doc.text(`Published: ${entry.publishedDate}    Modified: ${entry.lastModifiedDate}`);
        doc.text(`Versions Affected: ${entry.versionsAffected.join(', ')}`);
        doc.text(`Attack Vector: ${entry.attackVector}`);
        doc.text(`\nDescription: ${entry.vulnerabilityDescription}`);
        doc.text(`\nV3 Score: ${entry.v3SeverityScore.severity} (${entry.v3SeverityScore.scoreString})`);
        doc.text(`V2 Score: ${entry.v2SeverityScore.severity} (${entry.v2SeverityScore.scoreString})`);
        doc.text(`\nReferences:`);
        doc.fillColor('blue');                                      // color ref URLs blue
        doc.text(`${entry.referenceURLs.join('\n')}`);
        doc.fillColor('black');                                     // reset the color
        doc.moveDown();                                             // Allow for some whitespace in between entries
    });
    doc.text('\n\nEnd of File');
    doc.end();
    console.log(`Wrote report as ${outputArg}.pdf`);
}

function writeTextReport(affectedItemsArray, timeArg, outputArg) {
    var textData = '';
    textData = textData + `NVD ${timeArg} Vulnerability Check Report ${new Date().toDateString()}`;
    textData = textData + `\n\nCVE data version: ${globalNVDJSON.CVE_data_version}`;
    textData = textData + `\nCVE count: ${globalNVDJSON.CVE_data_numberOfCVEs}`;
    textData = textData + `\nLast Updated: ${globalNVDJSON.CVE_data_timestamp}`;
    textData = textData + `\nChecklist File: ${config.checklistName}`;
    textData = textData + `\nNumber of Vulnerabilites Matched: ${affectedItemsArray.length}`;
    textData = textData + `\n\n`;                                   // Extra spacing before iterating through the array
    // get each affected item's data and format it
    affectedItemsArray.forEach((entry, index) => {
        textData = textData + `\n${capitalizeFirstLetter(entry.vendorName)} ${capitalizeFirstLetter(entry.productName)} (${entry.ID})`;
        textData = textData + `\nPublished: ${entry.publishedDate}    Modified: ${entry.lastModifiedDate}`;
        textData = textData + `\nVersions Affected: ${entry.versionsAffected.join(', ')}`;
        textData = textData + `\nAttack Vector: ${entry.attackVector}`;
        textData = textData + `\nDescription: ${entry.vulnerabilityDescription}`;
        textData = textData + `\nV3 Score: ${entry.v3SeverityScore.severity} (${entry.v3SeverityScore.scoreString})`;
        textData = textData + `\nV2 Score: ${entry.v2SeverityScore.severity} (${entry.v2SeverityScore.scoreString})`;
        textData = textData + `\nReferences:\n`;
        textData = textData + `${entry.referenceURLs.join('\n')}`;
        textData = textData + `\n`;                             // Allow for some whitespace in between entries
    });
    textData = textData + `\n\n\nEnd of File`;                  // Make sure the entire array was iterated through

    fs.writeFileSync(`${outputArg}.txt`, textData);
    console.log(`Wrote report as ${outputArg}.txt`);
}

function NVDCheckFull(yearToSearch, outputLocation, outputFormat, checklistLocation, outputName) {
    let NVDFileData = new NVDClass(yearToSearch);                   // generate the new NVDData references to work with
    console.log(`Getting NVD FULL data to compare against ${checklistLocation}`);
    return Promise.resolve()                                        // start the promise chain as resolved to avoid issues
        .then(() => getNVDZipFile(NVDFileData.NVDURL, NVDFileData.zipFileLocation))
        .then(() => extractZipFile(NVDFileData.zipFileLocation))
        .then(() => {
            let NVDJSON = fs.readFileSync(NVDFileData.NVDJSONFileName, 'utf-8');
            let parsedNVDData = JSON.parse(NVDJSON);
            globalNVDJSON = parsedNVDData;                          // used to allow the PDF file acess to certain data
            return parsedNVDData;
        })
        .then((NVDData) => parseNVDData(NVDData, checklistLocation))                   // sort through the entire data list and parse for matches
        .then((affectedItemsArray) => {
            if (outputFormat == '.pdf') {
                writePDFReport(affectedItemsArray, yearToSearch, outputName);
            } else if (outputFormat == '.txt') {
                writeTextReport(affectedItemsArray, yearToSearch, outputName);
            } else {
                throw new Error('Error: Unknown output format was passed to function NVDCheckRecent');
            }
        })
        .then(() => {
            if (debug) { console.log(`\nSuccessfully ended on ${new Date().toISOString()}`); }
        })
        .catch((err) => {
            console.log(`Ended with error at ${new Date().toISOString()}: ${err}`);
        })
}

function NVDCheckRecent(outputLocation, outputFormat, checklistLocation, outputName) {
    console.log(`Getting NVD recent data to compare against ${checklistLocation}`);
    Promise.resolve()                                               // start the promise chain as resolved to avoid issues
        .then(() => getNVDZipFile(config.NVDURLRecent, config.zipFileNameRecent))        // Get the RECENT json that is in .zip format
        .then(() => extractZipFile(config.zipFileNameRecent))
        .then(() => {
            let NVDJSON = fs.readFileSync(config.NVDJSONFileNameRecent, 'utf-8');
            let parsedNVDData = JSON.parse(NVDJSON);
            globalNVDJSON = parsedNVDData;                          // used to allow the PDF file acess to certain data
            return parsedNVDData;
        })
        .then((NVDData) => parseNVDData(NVDData, checklistLocation))
        .then((affectedItemsArray) => {
            if (outputFormat == '.pdf') {
                writePDFReport(affectedItemsArray, 'RECENT', outputName);
            } else if (outputFormat == '.txt') {
                writeTextReport(affectedItemsArray, 'RECENT', outputName);
            } else {
                throw new Error('Error: Unknown output format was passed to function NVDCheckRecent');
            }
        })
        .then(() => {
            if (debug) { console.log(`\nSuccessfully ended on ${new Date().toISOString()}`); }
        })
        .catch((err) => {
            console.log(`Ended with error at ${new Date().toISOString()}: ${err}`);
        })
}

function helpInfo() {                                               // NOTE: this list is incomplete
    console.log(`
    About: This script is designed to help you get information from the\n    NVD and/or generate a report based on a checklist file`);
    console.log(`
    Usage: nvd-cli <primary flag> <primary flag arg> [optional flags]
    
    -f, --full            Conduct a full search against the default or provided 
                          checklist for a given <year> arg
    
    -r, --recent, recent  Search for vulnerabilaties in the NVD recent category using default 
                          or provided checklist
    
    -s, --search          Specifically search for an NVD vulnerability matching the providded 
                          <product> or <vendor> string and optional <year> arg
    
    - OPTIONAL PARAMETERS -
    
    -o, --output          Change the nvd-cli output file name and/or location
    
    -c, --checklist       Change the nvd-cli checklist file name and/or location

    -t, --type            Change the output type for the NVD report (.pdf or .txt)
    
    - MISC PARAMETERS -
    
    -h, --help, help      Display this help text or try -h <command>
    
    -v, --version         Get the version of nvd-cli you are currently running


    For more help on a specific command/arg type help <command> without the '-' or '--'
    `);
}

function helpCommandHandler(helpArg) {
    switch (helpArg) {
        case 'r':
        case 'recent':
            console.log(`
    Usage: -r, --recent, recent, [optional parameters]
            
    Description:        Get RECENT NVD data matching the default or provided
                        checklist and write the report to a file
            `);
            break;
        case 'f':
        case 'full':
            console.log(`
    Usage: -f, --full, <year to fully search> [optional parameters]
            
    Description:        Get FULL NVD data for a given year matching the 
                        default or provided checklist and write the report to a file
                `);
            break;
        case 's':
        case 'search':
            console.log(`
    Usage: -s, --search, <year to search> --product=<product_name> OR --vendor=<vendor_name> [optional parameters]
            
    Description:        Get NVD data for a given year that matches the 
                        <product_name> or <vendor_name> string
                    `);
            break;
        case 'c':
        case 'checklist':
            console.log(`
    Usage: <primary flag> -c, --checklist=<checklist_file_location>
            
    Description:        Specify a custom checklist other than the
                        default './checklist.json'
                        `);
            break;
        case 'o':
        case 'output':
            console.log(`
    Usage: <primary flag> -o, --output=<custom_output_dir/file_name>
            
    Description:        Specify a report location and file name other
                        than the default './report.pdf'
                            `);
            break;
        case 't':
        case 'type':
            console.log(`
    Usage: <primary flag> -t, --type=<file_type_to_generate ('.txt') ('.pdf')>
            
    Description:        Change the report type to be either .txt or .pdf
                                `);
            break;
        default:
            console.log(`${helpArg} isn't recognized as a command, option or flag`);
            break;
    }
}

function productSearchHandler(yearToSearch, productSearchQuery, outputLocation, outputFormat, outputName) {
    if (typeof (productSearchQuery) !== 'string') {
        return console.log('Error: Product search term must be a string');
    } else if (productSearchQuery.length < 3) {
        console.log(`Error: please give a product name with at least 3 characters`);
        process.exit(0);
    } else {
        console.log(`Searching NVD year ${yearToSearch} for ${productSearchQuery}`);
        let NVDFileData = new NVDClass(yearToSearch);                   // generate the new NVDData references to work with
        return Promise.resolve()                                               // start the promise chain as resolved to avoid issues
            .then(() => getNVDZipFile(NVDFileData.NVDURL, NVDFileData.zipFileLocation))
            .then(() => extractZipFile(NVDFileData.zipFileLocation))
            .then(() => {
                let NVDJSON = fs.readFileSync(NVDFileData.NVDJSONFileName, 'utf-8');
                let parsedNVDData = JSON.parse(NVDJSON);
                globalNVDJSON = parsedNVDData;                          // used to allow the PDF file acess to certain data
                return parsedNVDData;
            })
            .then((NVDData) => searchNVDProducts(NVDData, productSearchQuery))
            .then((affectedItemsArray) => {
                if (outputFormat == '.pdf') {
                    writePDFReport(affectedItemsArray, `SEARCH '${productSearchQuery}' ${yearToSearch}`, outputName);
                } else if (outputFormat == '.txt') {
                    writeTextReport(affectedItemsArray, `SEARCH '${productSearchQuery}' ${yearToSearch}`, outputName)
                } else {
                    throw new Error('Error: Unknown output format was passed to function NVDCheckRecent');
                }
            })
            .then(() => {
                if (debug) { console.log(`\nSuccessfully ended on ${new Date().toISOString()}`); }
            })
            .catch((err) => {
                console.log(`Ended with error at ${new Date().toISOString()}: ${err}`);
            })
    }
}

function vendorSearchHanlder(yearToSearch, vendorSearchQuery, outputLocation, outputFormat, outputName) {
    if (typeof (vendorSearchQuery) !== 'string') {
        return console.log('Error: Product search term must be a string');
    } else if (vendorSearchQuery.length < 3) {
        console.log(`Error: please give a product name with at least 3 characters`);
        process.exit(0);
    } else {
        console.log(`Searching NVD year ${yearToSearch} for ${vendorSearchQuery}`);
        let NVDFileData = new NVDClass(yearToSearch);                   // generate the new NVDData references to work with
        return Promise.resolve()                                               // start the promise chain as resolved to avoid issues
            .then(() => getNVDZipFile(NVDFileData.NVDURL, NVDFileData.zipFileLocation))
            .then(() => extractZipFile(NVDFileData.zipFileLocation))
            .then(() => {
                let NVDJSON = fs.readFileSync(NVDFileData.NVDJSONFileName, 'utf-8');
                let parsedNVDData = JSON.parse(NVDJSON);
                globalNVDJSON = parsedNVDData;                          // used to allow the PDF file acess to certain data
                return parsedNVDData;
            })
            .then((NVDData) => searchNVDProducts(NVDData, vendorSearchQuery))
            .then((affectedItemsArray) => {
                if (outputFormat == '.pdf') {
                    writePDFReport(affectedItemsArray, `SEARCH '${vendorSearchQuery}' ${yearToSearch}`, outputName);
                } else if (outputFormat == '.txt') {
                    writeTextReport(affectedItemsArray, `SEARCH '${vendorSearchQuery}' ${yearToSearch}`, outputName);
                } else {
                    throw new Error('Error: Unknown output format was passed to function NVDCheckRecent');
                }
            })
            .then(() => {
                if (debug) { console.log(`\nSuccessfully ended on ${new Date().toISOString()}`); }
            })
            .catch((err) => {
                console.log(`Ended with error at ${new Date().toISOString()}: ${err}`);
            })
    }
}

function NVDYearValidator(yearToValidate) {
    if (typeof (yearToValidate) !== 'number') {
        return false;
    } else {
        if (isNaN(yearToValidate) || yearToValidate.toString().charAt(0) !== '2' || yearToValidate.toString().charAt(1) !== '0' || yearToValidate.length < 4 || yearToValidate.length > 4 || yearToValidate < 2003) {
            return false;
        }
        return true;
    }
}

// script starts here
function main() {
    if (debug) { console.log(argv); }
    if (debug) { console.log(`\nNVD Vulnerability Check Script Started on ${new Date().toISOString()}\n`); }
    // vars to hold arg values and their defaults
    var defaultOutputLocation = process.cwd();
    var defaultOutputFormat = '.pdf';
    var defaultOutputName = './report';
    var defaultChecklistLoc = config.checklistName;
    var defaultYearArg = '2017';
    // check through the args passed to decide what to do and arg values to reassign
    if (argv.h || argv.help) {
        return helpInfo();
    }
    // help <commad> handler 
    if (argv._.indexOf('help') !== -1) {
        // determine which command was passed
        if (argv._.length > 1) {
            return helpCommandHandler(argv._[1].trim());
        }
        return console.log(`Error: Please provide a command to get help with (Ex: help <command> or help [arg flag]\n\nMake sure you don't include the '-' or '--' prefix with to commands and flags`);
    }
    if (argv.c) {
        // check for a checklist valid file path
        if (typeof (argv.c) !== 'string') {                         // validate the arg first
            return console.log('Error: Please provide a string for the checklist file location (EX: ./checklist.json)');
        } else {
            if (fs.existsSync(argv.c)) {
                defaultChecklistLoc = argv.c;
            } else {
                return console.log(`Error: ${argv.c} is not a valid location`);
            }
        }
    }
    if (argv.checklist) {
        // check for a checklist valid file path
        if (typeof (argv.checklist) !== 'string') {                         // validate the arg first            
            return console.log('Error: Please provide a string for the checklist file location (EX: ./checlist.json)');
        } else {
            if (fs.existsSync(argv.checklist)) {
                defaultChecklistLoc = argv.checklist;
            } else {
                return console.log(`Error: ${argv.checklist} is not a valid location`);
            }
        }
    }
    if (argv.c && argv.checklist) {
        return console.log('Error: Please only use -c or --checklist, not both!');
    }
    if (argv.o) {
        if (typeof (argv.o) !== 'string') {                         // validate the arg first
            return console.log('Error: Please provide a string for the output file name');
        }
        defaultOutputName = argv.o;                             // assign the file output name/location to the passed arg somce it is valid
    }
    if (argv.output) {
        if (typeof (argv.output) !== 'string') {
            return console.log('Error: Please provide a string for the output file name');
        }
        defaultOutputName = argv.output;
    }
    if (argv.o && argv.output) {
        return console.log('Error: Please only use -o or --output, not both!');
    }
    if (argv.t) {
        if (argv.t == '.txt') {
            defaultOutputFormat = argv.t;
        } else if (argv.t == '.pdf') {
            defaultOutputFormat = argv.t;
        } else {
            return console.log(`Error: Please provide a valid -t arg: .txt OR .pdf`);
        }
    }
    if (argv.type) {
        if (argv.type == '.txt') {
            defaultOutputFormat = argv.type;
        } else if (argv.type == '.pdf') {
            defaultOutputFormat = argv.type;
        } else {
            return console.log(`Error: Please provide a valid -type arg: .txt OR .pdf`);
        }
    }
    if (argv.t && argv.type) {
        return console.log('Error: Please only use -t or --type, not both!');
    }
    // recent needs no extra arg checking
    if (argv.r || argv.recent || argv._.indexOf('recent') !== -1) {
        if (!argv.c && !argv.checklist && fs.existsSync(config.checklistName) !== true) {
            return console.log(`Error: No checklist arg given and no default '${config.checklistName}' was found in ${process.cwd()}`)
        }
        return NVDCheckRecent(defaultOutputLocation, defaultOutputFormat, defaultChecklistLoc, defaultOutputName);
    }
    if (argv.f) {
        // ensure a valid year was passed
        if (!NVDYearValidator(argv.f)) {
            return console.log(`Error: ${argv.f} is not a valid year to search by`);
        }
        if (!argv.c && !argv.checklist && fs.existsSync(config.checklistName) !== true) {
            return console.log(`Error: No checklist arg given and no default '${config.checklistName}' was found in ${process.cwd()}`)
        }
        return NVDCheckFull(argv.f, defaultOutputLocation, defaultOutputFormat, defaultChecklistLoc, defaultOutputName);
    }
    if (argv.full) {
        // ensure a valid year was passed
        if (!NVDYearValidator(argv.full)) {
            return console.log(`Error: ${argv.full} is not a valid year to search by`);
        } else {
            if (!argv.c && !argv.checklist && fs.existsSync(config.checklistName) !== true) {
                return console.log(`Error: No checklist arg given and no default '${config.checklistName}' was found in ${process.cwd()}`)
            }
            return NVDCheckFull(argv.full, defaultOutputLocation, defaultOutputFormat, defaultChecklistLoc, defaultOutputName);
        }
    }
    if (argv.s) {
        // ensure a valid year was passed
        if (!NVDYearValidator(argv.s)) {
            console.log(`No year given for -s, default is ${defaultYearArg}`);
        } else {
            defaultYearArg = argv.s;
        }
        if (argv.product) {
            return productSearchHandler(defaultYearArg, argv.product, defaultOutputLocation, defaultOutputFormat, defaultOutputName);
        } else if (argv.vendor) {
            return vendorSearchHanlder(defaultYearArg, argv.vendor, defaultOutputLocation, defaultOutputFormat, defaultOutputName);
        } else {
            console.log(`Unsupported or no search type given. Product must be specified like so: --product=product_name`);
        }
    }
    if (argv.search) {
        // ensure a valid year was passed
        if (!NVDYearValidator(argv.search)) {
            console.log(`No year given for --search, default is ${defaultYearArg}`);
        } else {
            defaultYearArg = argv.search;
        }
        if (argv.product) {
            return productSearchHandler(defaultYearArg, argv.product, defaultOutputLocation, defaultOutputFormat, defaultOutputName);
        } else if (argv.vendor) {
            return vendorSearchHanlder(defaultYearArg, argv.vendor, defaultOutputLocation, defaultOutputFormat, defaultOutputName);
        } else {
            console.log(`Unsupported or no search type given. Product must be specified like so: --product=product_name`);
        }
    }
    if (argv.v || argv.version) {
        return console.log(`nvd-cli version: ${ver}`);
    }
    // if no cammand arg is given, display the help section
    if (!argv.r && !argv.recent && !argv.f && !argv.full && !argv.s && !argv.search && !argv.v && !argv.version && argv._.indexOf('help') == -1) {
        console.log('Error: Please provide a task arg (-r, (--recent), -f (--full), -s (--search)');
        return helpInfo();
    }
}

main();                                                             // script starts here, args are processed before anything is done