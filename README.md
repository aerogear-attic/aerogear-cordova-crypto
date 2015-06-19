AeroGear Crypto Plugin
======================

|                 | Project Info  |
| --------------- | ------------- |
| License:        | Apache License, Version 2.0  |
| Build:          | Cordova Plugin  |
| Documentation:  | https://aerogear.org/docs/specs/aerogear-cordova/  |
| Issue tracker:  | https://issues.jboss.org/browse/AGCORDOVA  |
| Mailing lists:  | [aerogear-users](http://aerogear-users.1116366.n5.nabble.com/) ([subscribe](https://lists.jboss.org/mailman/listinfo/aerogear-users))  |
|                 | [aerogear-dev](http://aerogear-dev.1069024.n5.nabble.com/) ([subscribe](https://lists.jboss.org/mailman/listinfo/aerogear-dev))  |

This plugin allows you to use the native aerogear crypto libs for your cordova apps. While staying close to the aerogear-js api.

* Password based key derivation support

```js
var agCrypto = new AeroGear.Crypto();
agCrypto.deriveKey('my password', null, {
    success: function (rawPassword) {
        console.log(rawPassword);
    }
});
```

* Symmetric encryption support

    * Encryption:

```js
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
                agCrypto.encrypt(options, {
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

* Asymmetric encryption support / iOS not supported

```js
Promise.all([agCrypto.KeyPair(), agCrypto.KeyPair(), agCrypto.getRandomValue()])
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

## Documentation

For more details about the current release, please consult [our documentation](https://aerogear.org/docs/specs/aerogear-cordova/).

## Development

If you would like to help develop AeroGear you can join our [developer's mailing list](https://lists.jboss.org/mailman/listinfo/aerogear-dev), join #aerogear on Freenode, or shout at us on Twitter @aerogears.

Also takes some time and skim the [contributor guide](http://aerogear.org/docs/guides/Contributing/)

## Questions?

Join our [user mailing list](https://lists.jboss.org/mailman/listinfo/aerogear-users) for any questions or help! We really hope you enjoy app development with AeroGear!

## Found a bug?

If you found a bug please create a ticket for us on [Jira](https://issues.jboss.org/browse/AGCORDOVA) with some steps to reproduce it.
