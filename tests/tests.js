/*
 * JBoss, Home of Professional Open Source.
 * Copyright Red Hat, Inc., and individual contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

exports.defineAutoTests = function () {
  var PASSWORD = "Bacon ipsum dolor sit amet prosciutto ground round short ribs" +
               "short loin tri-tip meatball jowl frankfurter turducken pork belly";
  var ENCRYPTED_PASSWORD = "269a804bf4584bbda65c72143aa86b73449618aeb7fa636ec2fa05d1146f2379";

  var PLAIN_TEXT = "My Bonnie lies over the ocean, my Bonnie lies over the sea";
  var BOB_SECRET_KEY = "f3a9375ec8746cc6e78e4b02d7e748988e10c74525e5c0a41d63fe5d21f84224";
  var BOB_AAD = "feedfacedeadbeeffeedfacedeadbeefabaddad2";
  var BOB_IV = "69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37";

  var MESSAGE = "be075fc53c81f2d5cf141316ebeb0c7b5228c52a4c62cbd44b66849b64244ffc" +
            "e5ecbaaf33bd751a1ac728d45e6c61296cdc3c01233561f41db66cce314adb31" +
            "0e3be8250c46f06dceea3a7fa1348057e2f6556ad6b1318a024a838f21af1fde" +
            "048977eb48f59ffd4924ca1c60902e52f0a089bc76897040e082f93776384864" +
            "5e0705";

  describe('Plugin should be installed', function () {
    it("crypto plugin should exist", function () {
      expect(AeroGear.Crypto).toBeDefined();
      expect(typeof AeroGear.Crypto == 'function').toBe(true);
    });

    it("should contain a encrypt function", function () {
      expect(AeroGear.Crypto().encrypt).toBeDefined();
      expect(typeof AeroGear.Crypto().encrypt == 'function').toBe(true);
    });

    it("should contain a decrypt function", function () {
      expect(AeroGear.Crypto().decrypt).toBeDefined();
      expect(typeof AeroGear.Crypto().decrypt == 'function').toBe(true);
    });
  });

  describe('Password based key derivation support', function () {
    it("Password validation with random salt provided", function () {
      AeroGear.Crypto().deriveKey(function (rawPassword) {
        expect(rawPassword).toEqual(ENCRYPTED_PASSWORD);
      }, errorHandler, PASSWORD);
    });
  });

  describe('Password based encrytion with GCM', function () {
    it("Encrypt/Decrypt password", function () {
      AeroGear.Crypto().deriveKey(function (rawPassword) {
        var options = {
          IV: BOB_IV,
          AAD: BOB_AAD,
          key: rawPassword,
          data: PLAIN_TEXT
        };
        AeroGear.Crypto().encrypt(function (cipherText) {
          options.data = cipherText;
          AeroGear.Crypto().decrypt(function (plainText) {
            expect(plainText).toEqual(PLAIN_TEXT);
          }, options);
        }, options);
      }, errorHandler, PASSWORD);
    });
  });

  describe('Symmetric encrytion with GCM', function () {
    it("Encrypt/Decrypt", function () {
      var options = {
        IV: BOB_IV,
        AAD: BOB_AAD,
        key: BOB_SECRET_KEY,
        data: MESSAGE
      },
        agCrypto = new AeroGear.Crypto();
      agCrypto.encrypt(function (cipherText) {
        options.data = cipherText;
        agCrypto.decrypt(function (plainText) {
          expect(plainText).toEqual(MESSAGE);
        }, options);
      }, options);
    });
  });

  describe('Digital signatures', function () {
    it("Encrypt/Decrypt", function () {
      var agCrypto = new AeroGear.Crypto();
      agCrypto.KeyPair(function (keyPair) {
        agCrypto.KeyPair(function (keyPairPandora) {
          var options = {
            IV: BOB_IV,
            AAD: BOB_AAD,
            key: new agCrypto.KeyPair(keyPair.privateKey, keyPairPandora.publicKey),
            data: PLAIN_TEXT
          };
          agCrypto.encrypt(function (cipherText) {
            options.key = new agCrypto.KeyPair(keyPairPandora.privateKey, keyPair.publicKey);
            options.data = cipherText;
            agCrypto.decrypt(function (plainText) {
              expect(plainText).toEqual(PLAIN_TEXT);
            }, options);
          }, options);
        });
      });
    });
  });

  describe('Promise test', function () {
    it("Encrypt/Decrypt", function () {
      var agCrypto = new AeroGear.Crypto();
      Promise.all([agCrypto.deriveKey('my password'), agCrypto.getRandomValue()])
        .then(function (rawPassword, IV) {
          var options = {
            IV: IV[0],
            key: rawPassword[0],
            data: "My Bonnie lies over the ocean, my Bonnie lies over the sea"
          };
          agCrypto.encrypt(options).then(function (cipherText) {
            console.log(cipherText);
          });
        },
          function (error) {
            console.log('error ' + error);
          });
    });
  });

  function errorHandler(message) {
    throw new Error('test failed ' + message);
  }
}