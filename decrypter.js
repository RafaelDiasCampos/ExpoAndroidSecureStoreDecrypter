// Android Expo SecureStore Decrypter

Java.perform(() => {
    // Common Java Classes
    const JSONObject = Java.use('org.json.JSONObject');
    
    // Expo Crypto Classes
    const AESEncrypter = Java.use('expo.modules.securestore.SecureStoreModule$AESEncrypter');
    const HybridAESEncrypter = Java.use('expo.modules.securestore.SecureStoreModule$HybridAESEncrypter');
    
    // Java KeyStore Classes
    const SecretKeyEntry = Java.use('java.security.KeyStore$SecretKeyEntry')
    const PrivateKeyEntry = Java.use('java.security.KeyStore$PrivateKeyEntry')

    // Expo SecureStore Moduke
    const SecureStoreModule = Java.use('expo.modules.securestore.SecureStoreModule');

    // Get function we want to hook
    const getItemImpl = SecureStoreModule.getItemImpl;

    // Hook the function
    getItemImpl.implementation = function (key, options, promise) {
      const prefs = this.getSharedPreferences();

      if (!prefs.contains(key)) {        
        console.log("[-] getItemImpl called. Key: " + key + " No value found.");
        return this.getItemImpl(key, options, promise);
      }

      // Get encrypted value from the JSON
      const encryptedItemString = prefs.getString(key, null);
      console.log("[-] getItemImpl called. Key: " + key + " Value: " + encryptedItemString);

      // Parse the JSON and extract the scheme
      const encryptedItem = JSONObject.$new(encryptedItemString);
      const scheme = encryptedItem.optString('scheme');

      if (scheme == null) {
        console.log("[!] Error: Scheme is null.");
        return this.getItemImpl(key, options, promise);
      }

      // Decrypt the value based on the scheme
      switch (scheme) {
        case AESEncrypter.NAME.value: 
            const secretKeyEntry = this.getKeyEntry(SecretKeyEntry.class, this.mAESEncrypter.value, options);
            var value = this.mAESEncrypter.value.decryptItem(encryptedItem, secretKeyEntry);
            console.log("[+] Decrypted value with AESEncrypter. Key: " + key + " Value: " + value);
            break;
        case HybridAESEncrypter.NAME.value:
            const privateKeyEntry = this.getKeyEntry(PrivateKeyEntry.class, this.mHybridAESEncrypter.value, options);
            var value = this.mHybridAESEncrypter.decryptItem(encryptedItem, privateKeyEntry);
            console.log("[+] Decrypted value with HybridAESEncrypter. Key: " + key + " Value: " + hybridValue);
            break;
        default:
            console.log("[!] Error: Unknown scheme. Scheme: " + scheme);        
      }

      return this.getItemImpl(key, options, promise);
    };
  });