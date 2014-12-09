/* AeroGear JavaScript Library
 * https://github.com/aerogear/aerogear-crypto-cordova
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
 @returns {object} agCrypto - The created Crypto Object
 @example
 // Create a AeroGear.Crypto Object

 var agCrypto = AeroGear.Crypto();
 */
AeroGear.Crypto = function () {

  // Allow instantiation without using new
  if (!(this instanceof AeroGear.Crypto)) {
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
  this.getSalt = function () {
    return salt;
  };
  /**
     Returns the value of the IV var
     @private
     @augments Crypto
     @returns {Object}
     */
  this.getIV = function () {
    return IV;
  };
  /**
     Returns the value of the private key var
     @private
     @augments Crypto
     @returns {Object}
     */
  this.getPrivateKey = function () {
    return privateKey;
  };

  /**
     Returns the value of the public key var
     @private
     @augments Crypto
     @returns {Object}
     */
  this.getPublicKey = function () {
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
  this.getRandomValue = function (param) {
    return new Promise(function (resolve, reject) {
      var success;
      param = param || {};

      success = function (result) {
        resolve(result, "success", param.success);
      };

      exec(success, null, 'crypto', 'getRandomValue', []);
    });
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
  this.deriveKey = function (password, providedSalt, param) {
    param = param || {};
    return new Promise(function (resolve, reject) {
      var success, error,
        options = {
          password: password
        };

      error = function (error) {
        reject(error);
      };

      success = function (result) {
        salt = result.salt;
        resolve(result.password);
      };

      if (providedSalt) {
        options.providedSalt = providedSalt;
      }

      exec(success, error, 'crypto', 'deriveKey', [options]);

    }).then(param.success, param.error);
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
  this.encrypt = function (options, param) {
    param = param || {};
    return new Promise(function (resolve, reject) {
      var success = function (result) {
        resolve(result);
      };

      exec(success, null, 'crypto', 'encrypt', [options]);

    }).then(param.success);
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
  this.decrypt = function (options, param) {
    param = param || {};
    return new Promise(function (resolve, reject) {

      var success = function (result) {
        resolve(result);
      };

      exec(success, null, 'crypto', 'decrypt', [options]);

    }).then(param.success);
  };

  /**
     KeyPair is used to hold public and private key
     @status Experimental
     @class
     @param {String|Function} privateKey - the private key
     @param {String} [publicKey] - the private key
     @returns {object} keyPair - the holder
     @example
         // Create a AeroGear.KeyPair Object
         var agCrypto = AeroGear.Crypto();
         var keyPair = new agCrypto.KeyPair(privateKey, publicKey);

         //or generate a keyPair
         agCrypto.KeyPair(function(result) { ... });
     */
  this.KeyPair = function (privateKey, publicKey) {

    if (privateKey === undefined || typeof privateKey == "function") {
      return new Promise(function (resolve, reject) {
        var success = function (result) {
          resolve(result);
        };

        exec(success, null, 'crypto', 'generateKeyPair', []);
      }).then(privateKey);
    } else if (privateKey && publicKey) {
      this.privateKey = privateKey;
      this.publicKey = publicKey;
    }
  };
};

module.exports = AeroGear;