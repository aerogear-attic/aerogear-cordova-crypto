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
/**
 AeroGear.Crypto is used to provide various crypto methods
 @status Experimental
 @class
 @augments AeroGear.Core
 @returns {object} agCrypto - The created Crypto Object
 @example
 // Create a AeroGear.Crypto Object

 var agCrypto = AeroGear.Crypto();
 */
AeroGear.Crypto = function() {

    // Allow instantiation without using new
    if ( !( this instanceof AeroGear.Crypto ) ) {
        return new AeroGear.Crypto();
    }

    // Local Variables
    var privateKey, publicKey, IV, salt;

    /**
     Returns the value of the salt var
     @private
     @augments Crypto
     @returns {Object}
     */
    this.getSalt = function() {
        return salt;
    };
    /**
     Returns the value of the IV var
     @private
     @augments Crypto
     @returns {Object}
     */
    this.getIV = function() {
        return IV;
    };
    /**
     Returns the value of the private key var
     @private
     @augments Crypto
     @returns {Object}
     */
    this.getPrivateKey = function() {
        return privateKey;
    };

    /**
     Returns the value of the public key var
     @private
     @augments Crypto
     @returns {Object}
     */
    this.getPublicKey = function() {
        return publicKey;
    };

    // Method to retrieve random values
    /**
     Returns the random value
     @status Experimental
     @return {Number} - the random value
     @example
     //Random number generator:
     AeroGear.Crypto().getRandomValue();
     */
    this.getRandomValue = function() {
        var random = new Uint32Array( 1 );
        crypto.getRandomValues( random );
        return random[ 0 ];
    };
    // Method to provide key derivation with PBKDF2
    /**
     Returns the value of the key
     @status Experimental
     @param {String} password - master password
     @param {Number} providedSalt - salt provided to recreate the key
     @return {bitArray} - the derived key
     @example
     //Password encryption:
     AeroGear.Crypto().deriveKey( 'mypassword', 42 );
     */
    this.deriveKey = function( success, failure, password, providedSalt ) {
        return exec( success, failure, 'crypto', 'deriveKey', [{password: password, providedSalt: providedSalt}] );
    };

    // Method to provide symmetric encryption with GCM by default
    /**
     Encrypts in GCM mode
     @status Experimental
     @param {Object} options - includes IV (Initialization Vector), AAD
     (Additional Authenticated Data), key (private key for encryption),
     plainText (data to be encrypted)
     @return {bitArray} - The encrypted data represented by an array of bytes
     @example
     //Data encryption:
     var options = {
            IV: myIV,
            AAD: myAAD,
            key: mySecretKey,
            data: message
        };
     AeroGear.Crypto().encrypt( options );
     */
    this.encrypt = function( success, options ) {
        return exec( success, null, 'crypto', 'encrypt', [options] );
    };

    // Method to provide symmetric decryption with GCM by default
    /**
     Decrypts in GCM mode
     @status Experimental
     @param {Object} options - includes IV (Initialization Vector), AAD
     (Additional Authenticated Data), key (private key for encryption),
     ciphertext (data to be decrypted)
     @return {bitArray} - The decrypted data
     @example
     //Data decryption:
     var options = {
            IV: myIV,
            AAD: myAAD,
            key: mySecretKey,
            data: ciphertext
        };
     AeroGear.Crypto().decrypt( options );
     */
    this.decrypt = function( success, options ) {
        return exec( success, null, 'crypto', 'decrypt', [options] );
    };

    this.KeyPair = function( privateKey, publicKey ) {

        if (typeof privateKey == "function")  {
            exec(privateKey, null, 'crypto', 'generateKeyPair', []);
        } else if ( privateKey && publicKey ) {
            this.privateKey = privateKey;
            this.publicKey = publicKey;
        }
    };
};

module.exports = AeroGear.crypto;