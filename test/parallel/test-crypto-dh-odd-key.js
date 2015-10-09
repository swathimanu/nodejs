'use strict';
var common = require('../common');
var assert = require('assert');

if (!common.hasCrypto) {
  console.log('1..0 # Skipped: missing crypto');
  return;
}
/* This test was added specifically to test abnormally small prime lengths. FIPS requires a length of at least 1024 
 * See: https://github.com/nodejs/node-v0.x-archive/commit/20247064b63b7937d5374368e236bcf4b184888a */
if (common.hasFipsCrypto) {
  console.log('1..0 # Skipped: small prime length not supported in FIPS mode');
  return;
}
var crypto = require('crypto');

var odd = new Buffer(39);
odd.fill('A');

var c = crypto.createDiffieHellman(32);
c.setPrivateKey(odd);
c.generateKeys();
