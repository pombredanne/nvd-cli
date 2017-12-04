"use strict";
const fs = require('fs');                                       // for reading the JSON file
var extract = require('extract-zip');
const util = require('util');                                   // for using child-process
const PDFDocument = require('pdfkit');
const exec = require('child-process-promise').exec;
var argv = require('minimist')(process.argv.slice(2));          // for parsing args
console.log(argv);
// custom requires
const config = require('./config');                             // confiog file for script
const NVDClass = require('./lib/NVDJSONClass');                 // helper for getting at NVD Data for specific years

const swChecklist = JSON.parse(fs.readFileSync(config.checklistName, 'utf-8'));
const bright = '\x1b[1m';
const reset = '\x1b[0m';
const debug = config.debug;
const ver = '0.2.0';                                            // arbitrary version number, should match NPM version

var globalNVDJSON;
/*
simple script to get recent NVD JSON data from their CDN in a zip format
unzip it and check against a set of manufacturers & software products to track vulnerabilites

Notes: 
- the PDFkit way to get bold text is 'stroke' not bold
- for PDFKit, doc.moveDown and \n being in the string do the same thing

TODO: Allow for vulerability severity arg (IE Ignore 'LOW' scoring entries that match)
TODO: create a CLI search functionality (search for a product vulnerability or vendor list)
TODO: when done, work on README
TODO: add filename handler for the PDF/TXT and the type of file to generate
TODO: update project scope description
TODO: for recents, ensure that the CVE review is FINAL?
TODO: add params for every function that needs them
TODO: fix the global JSON data issue that really shouldn't be there
TODO: allow for a checklist file arg to be passed
TODO: allow for output location
TODO: make this usable as an NPM command line util? (kind of like node-mailer CLI)
TODO: create a more sacalable arg system
TODO: create defaults for all arg types
TODO: REAAAAAAALLLLLLLLLLY work on getting a way to redirect the output location AND the name
not just the name!
*/

function capitalizeFirstLetter(string) {                            //used to clean up some WF data 
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
                            // push the affected item to the array to return
                            affectedItems.push(affectedItem);
                        }
                    });
                }
            });
        });
    });
    console.log(`Number of matches found: ${affectedItems.length}`);
    return affectedItems;
}

function writePDFReport(affectedItemsArray, timeArg, outputArg) {
    var doc = new PDFDocument;
    doc.pipe(fs.createWriteStream(`${outputArg}.pdf`));
    doc.fontSize(16);
    doc.font(config.defaultFontLocation);
    doc.text(`NVD ${timeArg} Vulnerability Check Report ${new Date().toDateString()}`, { align: 'center', stroke: true });
    doc.fontSize(12);
    doc.moveDown();
    doc.moveDown();
    doc.text(`CVE data version: ${globalNVDJSON.CVE_data_version}`);
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

function NVDCheckFull(yearToSearch) {
    // yearToSearch should already be validated
    let NVDFileData = new NVDClass(yearToSearch);                   // generate the new NVDData references to work with
    console.log(`Getting NVD FULL data to compare against ${config.checklistName}`);
    return Promise.resolve()                                        // start the promise chain as resolved to avoid issues
        .then(() => getNVDZipFile(NVDFileData.NVDURL, NVDFileData.zipFileLocation))
        .then(() => extractZipFile(NVDFileData.zipFileLocation))
        .then(() => {
            let NVDJSON = fs.readFileSync(NVDFileData.NVDJSONFileName, 'utf-8');
            let parsedNVDData = JSON.parse(NVDJSON);
            globalNVDJSON = parsedNVDData;                          // used to allow the PDF file acess to certain data
            return parsedNVDData;
        })
        .then((NVDData) => parseNVDData(NVDData))                   // sort through the entire data list and parse for matches
        .then((affectedItemsArray) => writePDFReport(affectedItemsArray, yearToSearch))
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
        .then((NVDData) => parseNVDData(NVDData))
        .then((affectedItemsArray) => {
            if (outputFormat == '.pdf') {
                writePDFReport(affectedItemsArray, 'RECENT', outputName);
            } else if (outputFormat == '.txt') {
                console.log('.txt output not yet supported');
            } else {
                throw new Error('No output format was passed to function NVDCheckRecent');
            }
        })
        .then(() => {
            if (debug) { console.log(`\nSuccessfully ended on ${new Date().toISOString()}`); }
        })
        .catch((err) => {
            console.log(`Ended with error at ${new Date().toISOString()}: ${err}`);
        })
}

function helpInfo() {
    // NOTE: this list is incomplete
    console.log('\nAbout: \nThis script is designed to help you get information from the\nNVD and/or generate a report based on a checklist file');
    console.log('\n\nUsage: nvd-cli <command> OR nvd-cli -arg');
    console.log(`\nnvd-cli -r OR --recent\t\t\tGenerate a report based on a checklist file for RECENT 
                                        vulnerabilities that match the checklist`);
    console.log(`\nnvd-cli -f <year> OR --full <year>\tGenerate a report based on a checklist file for 
                                        vulnerabilities found in the <year> arg passed`);
}

function handleOutPutArg() {

}

// script will eventually start here
function main() {
    if (debug) { console.log(`\nNVD Vulnerability Check Script Started on ${new Date().toISOString()}\n`); }
    // vars to hold arg values and their defaults
    var defaultOutputLocation = process.cwd();
    var defaultOutPutFormat = '.pdf';
    var defaultOutputName = 'report';
    var defaultChecklistLoc = config.checklistName;
    // check through the args passed to decide what to do and arg values to reassign

    // if argv has help arg, return help, if help <command> is passed, return better helpmsg
    if (argv.h || argv.help || argv._.indexOf('help') !== -1) {
        return helpInfo();
    }
    if (argv.c) {
        // check for a checklist valid file path
        // validate the arg first
        if (typeof (argv.c) !== 'string') {
            console.log('Error: Please provide a string for the output file name');
            process.exit(0);
        } else {
            if (fs.existsSync(argv.c)) {
                defaultChecklistLoc = argv.c;
            } else {
                console.log(`Error: ${argv.c} is not a valid location`);
                process.exit(0);
            }
        }
    }
    if (argv.checklist) {
        // check for a checklist valid file path
        // validate the arg first
        if (typeof (argv.c) !== 'string') {
            console.log('Error: Please provide a string for the output file name');
            process.exit(0);
        } else {
            if (fs.existsSync(argv.checklist)) {
                defaultChecklistLoc = argv.checklist;
            } else {
                console.log(`Error: ${argv.checklist} is not a valid location`);
                process.exit(0);
            }
        }
    }
    if (argv.c && argv.checklist) {
        console.log('Error: Please only use -c or --checklist, not both!');
        process.exit(0);
    }
    //TODO: clean the file name output renames to not have invalid chars
    if (argv.o) {
        // change the output name
        // validate the arg first
        if (typeof (argv.o) !== 'string') {
            console.log('Please provide a string for the output file name');
        } else {
            defaultOutputName = argv.o;
        }
    }
    if (argv.output) {
        if (typeof (argv.o) !== 'string') {
            console.log('Please provide a string for the output file name');
        } else {
            defaultOutputName = argv.output;
        }
    }
    if (argv.o && argv.output) {
        console.log('Please only use -o or --output, not both!');
        process.exit(0);
    }
    // recent needs no extra arg checking
    if (argv.r || argv.recent || argv._.indexOf('recent') !== -1) {
        return NVDCheckRecent(defaultOutputLocation, '.pdf', defaultChecklistLoc, defaultOutputName);
    }

    if (!argv.r && !argv.recent && !argv.f && !argv.full && !argv.s && !argv.search) {
        console.log('Please provide a task arg (-r, --recent, -f --full, -s --search');
        return helpInfo();
    }
    // if arg is -f, get FULL data for a year that was passed
    // if arg is -s, search for a the string in the year arg passed
    // if no arg, display help file

}

// script starts here, args are processed before anything is done

main();
if (debug) { console.log(`\nNVD Vulnerability Check Script Started on ${new Date().toISOString()}\n`); }
else if (process.argv[2] == '-f' || process.argv[2] == '--full') {
    // check for a year arg as well, allow for up to 10 years ago
    var yearArg = '2017';
    if (process.argv[3]) {
        yearArg = process.argv[3];
        // verify the arg is a valid year (catch a lot of exceptions)
        if (isNaN(yearArg) || yearArg.charAt(0) !== '2' || yearArg.charAt(1) !== '0' || yearArg.length < 4 || yearArg.length > 4) {
            console.log(bright, `\n${yearArg} is not a valid year, the year arg should look something like this: 2017`);
            console.log('\nExiting...');
            console.log(reset, '');                                      // Reset the console color
            process.exit(0);
        } else {
            return NVDCheckFull(yearArg);
        }
    } else {
        console.log(bright, `\nNo year argument for full search, default is ${yearArg}`);
        console.log(reset, '');                                      // Reset the console color
        return NVDCheckFull(yearArg);
    }
} else if (argv.h || process.argv[2] == '--help' || process.argv[2] == 'help') {
    return helpInfo();
} else {
    // return helpInfo();                                              // Display help information since nothing was passed
}
