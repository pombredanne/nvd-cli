'use strict';
const request = require('request');                             //for NVD API calls
const rp = require('request-promise');                          //wrap request with promises for easir flow control
const fs = require('fs');                                       //for reading the JSON file

//simple script to get recent NVD JSON data from their CDN in a zip format
//unzip it and do some stuff using past project's code

//TODO:
//Allow for vulerability severity configuration based on the config.js file

//script starts here
Promise.resolve()                                               //start the promise chain as resolved to avoid issues
.then(() => {
    console.log(`\nNVD Recent Vulnerability Script Started on ${new Date().toISOString()}`);
})
.then(() => {
    //Get the RECENT json that is in .zip format
})
.then(() => {
    //unzip the JSON and write to file
})
.then(() => {
    //for now just to get things working, list data about ALL recents
})