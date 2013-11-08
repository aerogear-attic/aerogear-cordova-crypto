/* AeroGear JavaScript Library
 * https://github.com/aerogear/aerogear-js
 * JBoss, Home of Professional Open Source
 * Copyright Red Hat, Inc., and individual contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
var exec = require('cordova/exec');

var AeroGear = AeroGear || {};
AeroGear.crypto = {};

// Method to provide key derivation with PBKDF2
/**
 Returns the value of the key
 @status Experimental
 @param {String} password - master password
 @param success {String} - The encrypted data represented by hex values encoded as String
 @param failure {String} error - the error message
 @example
 //Password encryption:
 AeroGear.crypto.deriveKey( function(encrypted) { console.log(encrypted) }, errorHandler, 'mypassword' );
 */
AeroGear.crypto.deriveKey = function( success, failure, password ) {
    return exec( success, failure, 'crypto', 'deriveKey', [{password: password}] );
};
// Method to provide symmetric encryption with GCM by default
/**
 Encrypts in GCM mode
 @status Experimental
 @param {Object} options - includes IV (Initialization Vector), AAD
 (Additional Authenticated Data), key (private key for encryption),
 plainText (data to be encrypted)
 @param success {String} - The encrypted data represented by hex values encoded as String
 @example
 //Data encryption:
 var options = {
        IV: myIV,
        AAD: myAAD,
        key: mySecretKey,
        data: message
    };
 AeroGear.crypto.encrypt( function(result) {}, options );
 */
AeroGear.crypto.encrypt = function( success, options ) {
    return exec( success, null, 'crypto', 'encrypt', [options] );
};

// Method to provide symmetric decryption with GCM by default
/**
 Decrypts in GCM mode
 @status Experimental
 @param {Object} options - includes IV (Initialization Vector), AAD
 (Additional Authenticated Data), key (private key for encryption),
 ciphertext (data to be decrypted)
 @param success {String} - The result
 @example
 //Data decryption:
 var options = {
        IV: myIV,
        AAD: myAAD,
        key: mySecretKey,
        data: ciphertext
    };
 AeroGear.crypto.decrypt( function(result) {}, options );
 */
AeroGear.crypto.decrypt = function( success, options ) {
    return exec( success, null, 'crypto', 'decrypt', [options] );
};

AeroGear.crypto.KeyPair = function( privateKey, publicKey ) {

    if (typeof privateKey == "function")  {
        exec(privateKey, null, 'crypto', 'generateKeyPair', []);
    } else if ( privateKey && publicKey ) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }
};

module.exports = AeroGear.crypto;