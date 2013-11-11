AeroGear Crypto Plugin
======================

This plugin allows you to use the native aerogear crypto libs for your cordova apps. While staying close to the aerogear-js api.

* Password based key derivation support (PBKDF2)

```js
AeroGear.crypto.deriveKey( function(password) {
    console.log(password);    
}, errorHandler, PASSWORD );        
```

* Symmetric encryption support (GCM)

    * Encryption:

```js
AeroGear.crypto.deriveKey( function(rawPassword) {
    var options = {
            IV: BOB_IV,
            AAD: BOB_AAD,
            key: rawPassword,
            data: "My Bonnie lies over the ocean, my Bonnie lies over the sea"
        };
    AeroGear.crypto.encrypt( function(cipherText) {
        console.log(cipherText)
    }, options ); 
}, errorHandler, 'myPassword' );

```

    * Decryption:

```js
var options = {
        IV: BOB_IV,
        AAD: BOB_AAD,
        key: rawPassword,
        data: cipherText
    };
AeroGear.crypto.decrypt( function(text) {
    console.log(text)
}, options ); 
```

* Asymmetric encryption support (ECC) / iOS not supported

```js
AeroGear.crypto.KeyPair(function(keyPair) {
    AeroGear.crypto.KeyPair(function(keyPairPandora) {
        var options = {
            IV: BOB_IV,
            AAD: BOB_AAD,
            key: new AeroGear.crypto.KeyPair(keyPair.privateKey, keyPairPandora.publicKey),
            data: "My bonnie lies over the ocean"
        };
        AeroGear.crypto.encrypt(function (cipherText) {
            options.key = new AeroGear.crypto.KeyPair(keyPairPandora.privateKey, keyPair.publicKey);
            options.data = cipherText;
            AeroGear.crypto.decrypt(function (plainText) {
                console.log(plainText);
            }, options);
        }, options);
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