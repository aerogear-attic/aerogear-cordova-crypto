AeroGear Crypto Plugin
======================

This plugin allows you to use the native aerogear crypto libs for your cordova apps. While staying close to the aerogear-js api.

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
