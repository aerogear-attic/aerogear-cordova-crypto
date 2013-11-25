AeroGear Crypto Plugin
======================

This plugin allows you to use the native aerogear crypto libs for your cordova apps. While staying close to the aerogear-js api.

* Password based key derivation support (PBKDF2)

```js
var agCrypto = new AeroGear.Crypto();
agCrypto.deriveKey('my password', null, {
    success: function (rawPassword) {
        console.log(rawPassword);
    }
});
```

* Symmetric encryption support (GCM)

    * Encryption:

```js
$.when(agCrypto.deriveKey('my password'), agCrypto.getRandomValue())
    .then(function (rawPassword, IV) {
            var options = {
                IV: IV[0],
                key: rawPassword[0],
                data: "My Bonnie lies over the ocean, my Bonnie lies over the sea"
            };
            agCrypto.encrypt(options).then(function (cipherText) {
                    console.log(cipherText);
                }
            });
        },
        function (error) {
            console.log('error ' + error);
        });
        
// or with regular callbacks

agCrypto.deriveKey('my password', null, {
    success: function (rawPassword) {
        agCrypto.getRandomValue({
            success: function (generatedIV) {
                var options = {
                    IV: generatedIV,
                    key: rawPassword,
                    data: "My Bonnie lies over the ocean, my Bonnie lies over the sea"
                };
                agCrypto.encrypt(options {
                    success: function (cipherText) {
                        console.log(cipherText);
                    }
                });
            }
        });
    }
});
```

    * Decryption:

```js
var options = {
    IV: "69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37",
    AAD: "feedfacedeadbeeffeedfacedeadbeefabaddad2",
    key: rawPassword,
    data: cipherText
};
AeroGear.Crypto().decrypt(options, {
    success: function (text) {
        console.log(text);
    }
});
```

* Asymmetric encryption support (ECC) / iOS not supported

```js
$.when(agCrypto.KeyPair(), agCrypto.KeyPair(), agCrypto.getRandomValue())
    .then(function (keyPair, keyPairPandora, IV) {
        var options = {
            IV: IV[0],
            key: new agCrypto.KeyPair(keyPair[0].privateKey, keyPairPandora[0].publicKey),
            data: "My bonnie lies over the ocean"
        };
        agCrypto.encrypt(options).then(function (cipherText) {
            options.key = new agCrypto.KeyPair(keyPairPandora[0].privateKey, keyPair[0].publicKey);
            options.data = cipherText;
            agCrypto.decrypt(options).then(function (plainText) {
                console.log('plainText ' + plainText);
            });
        });

    });

```

## Installing

```
cordova create <PATH> [ID] [NAME]
cd <PATH>
# only ios and android are supported
cordova platform add <PLATFORM>
cordova plugin install https://github.com/edewit/aerogear-crypto-cordova

# after adding the plugin for ios you'll have to run:
cd platforms/ios
pod install

```