// Android Expo SecureStore Decrypter

Java.perform(() => {
    // Common Java Classes
    const Base64 = Java.use('android.util.Base64');
    const GCMParameterSpec = Java.use('javax.crypto.spec.GCMParameterSpec');
    const Cipher = Java.use('javax.crypto.Cipher');
    const String = Java.use('java.lang.String');
      
    // Expo Classes
    const SecureStoreModule = Java.use('expo.modules.securestore.SecureStoreModule');
    const AESEncrypter = Java.use('expo.modules.securestore.SecureStoreModule$AESEncrypter');

    // Hook the function 'getItemImpl' to get the encrypted value
    SecureStoreModule.getItemImpl.implementation = function (key, options, promise) {
      let prefs = this.getSharedPreferences();

      if (!prefs.contains(key)) {        
        console.log("[+] getItemImpl called. Key: " + key + " No value found.");
        return this.getItemImpl(key, options, promise);
      }

      // Get encrypted value from the JSON
      let encryptedItemString = prefs.getString(key, null);
      console.log("[+] getItemImpl called. Key: " + key + " Value: " + encryptedItemString);

      return this.getItemImpl(key, options, promise);
    };

    // Hook AESEncrypter.decryptItem to decrypt the value
    AESEncrypter.decryptItem.overload('expo.modules.core.Promise', 'org.json.JSONObject', 'java.security.KeyStore$SecretKeyEntry', 'expo.modules.core.arguments.ReadableArguments', 'expo.modules.securestore.AuthenticationCallback').implementation = function (promise, encryptedJson, secretKeyEntry, options, callback) {
      let encodedContent = encryptedJson.getString("ct");
      let iv = encryptedJson.getString("iv");
      let tlen = encryptedJson.getInt("tlen");

      let decodedContent = Base64.decode(encodedContent, 0);

      let parameterSpec = GCMParameterSpec.$new(tlen, Base64.decode(iv, 0));
      let cipher = Cipher.getInstance("AES/GCM/NoPadding");

      cipher.init(2, secretKeyEntry.getSecretKey(), parameterSpec);

      let decrypted = cipher.doFinal(decodedContent);

      let decryptedString = String.$new(decrypted, "UTF-8");

      console.log("[+] AESEncrypter.decryptItem called. Decrypted: " + decryptedString);

      return this.decryptItem(promise, encryptedJson, secretKeyEntry, options, callback);
    };
  });