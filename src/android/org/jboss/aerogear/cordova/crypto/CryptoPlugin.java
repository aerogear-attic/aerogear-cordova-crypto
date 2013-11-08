/**
 * JBoss, Home of Professional Open Source
 * Copyright Red Hat, Inc., and individual contributors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jboss.aerogear.cordova.crypto;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaPlugin;
import org.jboss.aerogear.AeroGearCrypto;
import org.jboss.aerogear.crypto.CryptoBox;
import org.jboss.aerogear.crypto.keys.KeyPair;
import org.jboss.aerogear.crypto.keys.PrivateKey;
import org.jboss.aerogear.crypto.password.Pbkdf2;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import static org.jboss.aerogear.crypto.encoders.Encoder.HEX;

/**
 * Plugin that delegates the crypto functions to aerogear crypto libs for android.
 * @author edewit
 */
public class CryptoPlugin extends CordovaPlugin {
  @Override
  public boolean execute(final String action, JSONArray args, final CallbackContext callbackContext) throws JSONException {
    if ("deriveKey".equals(action)) {
      JSONObject params = parseParameters(args);
      final String password = (String) params.get("password");

      cordova.getThreadPool().execute(new Runnable() {
        public void run() {
          Pbkdf2 pbkdf2 = new Pbkdf2();
          try {
            byte[] rawPassword = pbkdf2.encrypt(password);
            callbackContext.success(HEX.encode(rawPassword));
          } catch (InvalidKeySpecException e) {
            callbackContext.error(e.getMessage());
          }
        }
      });
    }

    if ("decrypt".equals(action) || "encrypt".equals(action)) {
      JSONObject params = parseParameters(args);
      final Object key = params.get("key");
      final byte[] iv = HEX.decode((String) params.get("IV"));
      final String data = (String) params.get("data");

      cordova.getThreadPool().execute(new Runnable() {
        public void run() {
          final CryptoBox cryptoBox;
          if (key instanceof JSONObject) {
            final java.security.KeyPair keyPair = parseKeyPairFromJson((JSONObject) key);
            cryptoBox = new CryptoBox(keyPair.getPrivate(), keyPair.getPublic());
          } else {
            cryptoBox = new CryptoBox(new PrivateKey((String) key));
          }

          String result = null;
          if ("encrypt".equals(action)) {
            result = HEX.encode(cryptoBox.encrypt(iv, data.getBytes()));
          }

          if ("decrypt".equals(action)) {
            result = new String(cryptoBox.decrypt(iv, HEX.decode(data)));
          }

          callbackContext.success(result);
        }
      });
    }

    if ("generateKeyPair".equals(action)) {
      cordova.getThreadPool().execute(new Runnable() {
        public void run() {
          KeyPair keyPair = new KeyPair();
          final JSONObject object = new JSONObject();
          try {
            object.put("privateKey", HEX.encode(keyPair.getPrivateKey().getEncoded()));
            object.put("publicKey", HEX.encode(keyPair.getPublicKey().getEncoded()));
          } catch (JSONException e) {
            throw new RuntimeException("could not construct key pair object");
          }
          callbackContext.success(object);
        }
      });
    }

    return true;
  }

  private java.security.KeyPair parseKeyPairFromJson(JSONObject key) {
    try {
      final String publicKey = (String) key.get("publicKey");
      final String privateKey = (String) key.get("privateKey");
      return parseKeyPairFromJson(HEX.decode(publicKey), HEX.decode(privateKey));
    } catch (JSONException e) {
      throw new RuntimeException("could not reconstruct key pair from json!", e);
    }
  }

  private java.security.KeyPair parseKeyPairFromJson(byte[] encodedPublicKey, byte[] encodedPrivateKey) {
    try {
      KeyFactory fact = KeyFactory.getInstance("ECDH", AeroGearCrypto.PROVIDER);
      PublicKey publicKey2 = fact.generatePublic(new X509EncodedKeySpec(encodedPublicKey));
      java.security.PrivateKey privateKey2 = fact.generatePrivate(new PKCS8EncodedKeySpec(encodedPrivateKey));
      return new java.security.KeyPair(publicKey2, privateKey2);
    } catch (InvalidKeySpecException e) {
      throw new RuntimeException("could not reconstruct key pair from json!", e);
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException("could not reconstruct key pair from json!", e);
    } catch (NoSuchProviderException e) {
      throw new RuntimeException("could not reconstruct key pair from json!", e);
    }
  }

  private JSONObject parseParameters(JSONArray data) throws JSONException {
    if (data.length() == 1 && !data.isNull(0)) {
      return (JSONObject) data.get(0);
    } else {
      throw new IllegalArgumentException("Invalid arguments specified!");
    }
  }
}
