# Expo Android SecureStore Decrypter

Decrypter for Expo SecureStore on Android using Frida.

## Requirements

* A rooted Android device
* Frida
* An app that uses Expo SecureStorage

## Usage

```console
git clone https://github.com/RafaelDiasCampos/ExpoAndroidSecureStoreDecrypter && cd ExpoAndroidSecureStoreDecrypter
frida -U -f 'com.company.app' -l decrypter.js
```

The decrypted values should be printed as the app calls for them.