  /*  THIS IS Core JS
    Browser-side prototype for:
    - user creation
    - device registration
    - password/recovery unlock
    - note creation
    - secure sharing to other users/devices
    - revocation via key rotation
    - soft fingerprint/IP context checks

    Notes:
    - This is still a prototype. Storage is localStorage for now.
    - Public IP cannot be read reliably from browser JS alone.
    - Pass ipHint from your backend later if you want that signal.
  */

  const SecureVault = (() => {
    const DB_KEY = "secure_notes_v5";
    const te = new TextEncoder();
    const td = new TextDecoder();

    // ---------- Utilities ----------

    const bufToB64 = (buf) => {
      const bytes = new Uint8Array(buf);
      let bin = "";
      for (const b of bytes) bin += String.fromCharCode(b);
      return btoa(bin);
    };

    const b64ToBuf = (b64) => {
      const bin = atob(b64);
      const bytes = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
      return bytes.buffer;
    };

    const b64ToBytes = (b64) => new Uint8Array(b64ToBuf(b64));
    const bytesToB64 = (bytes) =>
      bufToB64(bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength));

    const randomBytes = (len) => {
      const out = new Uint8Array(len);
      crypto.getRandomValues(out);
      return out;
    };

    const randomId = (prefix = "") => {
      const a = crypto.getRandomValues(new Uint32Array(2));
      return `${prefix}${a[0].toString(16)}${a[1].toString(16)}`;
    };

    async function sha256Bytes(dataBytes) {
      return new Uint8Array(await crypto.subtle.digest("SHA-256", dataBytes));
    }

    async function sha256String(str) {
      return bytesToB64(await sha256Bytes(te.encode(str)));
    }

    async function fingerprintHash(extra = "") {
      const basis = [
        navigator.userAgent,
        navigator.language,
        navigator.platform,
        String(navigator.hardwareConcurrency || ""),
        String(navigator.deviceMemory || ""),
        String(screen.width || ""),
        String(screen.height || ""),
        String(screen.colorDepth || ""),
        String(new Date().getTimezoneOffset()),
        String(!!navigator.cookieEnabled),
        String("ontouchstart" in window),
        extra || ""
      ].join("||");

      return sha256String(basis);
    }



    function assert(condition, msg) {
      if (!condition) throw new Error(msg);
    }

    // ---------- Crypto primitives ----------

    async function deriveAesKeyFromSecret(secret, saltBytes, iterations = 250000) {
      const baseKey = await crypto.subtle.importKey(
        "raw",
        te.encode(secret),
        "PBKDF2",
        false,
        ["deriveKey"]
      );

      return crypto.subtle.deriveKey(
        {
          name: "PBKDF2",
          salt: saltBytes,
          iterations,
          hash: "SHA-256"
        },
        baseKey,
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
      );
    }

    async function aesGcmEncryptBytes(aesKey, plaintextBytes, ivBytes = randomBytes(12)) {
      const ciphertext = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: ivBytes },
        aesKey,
        plaintextBytes
      );

      return {
        ivB64: bytesToB64(ivBytes),
        dataB64: bytesToB64(new Uint8Array(ciphertext))
      };
    }

    async function aesGcmDecryptBytes(aesKey, payload) {
      const ivBytes = b64ToBytes(payload.ivB64);
      const dataBytes = b64ToBytes(payload.dataB64);
      const plaintext = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: ivBytes },
        aesKey,
        dataBytes
      );
      return new Uint8Array(plaintext);
    }

    async function generateRsaKeyPair() {
      return crypto.subtle.generateKey(
        {
          name: "RSA-OAEP",
          modulusLength: 2048,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: "SHA-256"
        },
        true,
        ["encrypt", "decrypt"]
      );
    }

    async function exportPublicKeyJwk(publicKey) {
      return crypto.subtle.exportKey("jwk", publicKey);
    }

    async function importPublicKeyJwk(jwk) {
      return crypto.subtle.importKey(
        "jwk",
        jwk,
        { name: "RSA-OAEP", hash: "SHA-256" },
        true,
        ["encrypt"]
      );
    }

    async function exportPrivateKeyPkcs8(privateKey) {
      return new Uint8Array(await crypto.subtle.exportKey("pkcs8", privateKey));
    }

    async function importPrivateKeyPkcs8(pkcs8Bytes) {
      return crypto.subtle.importKey(
        "pkcs8",
        pkcs8Bytes,
        { name: "RSA-OAEP", hash: "SHA-256" },
        true,
        ["decrypt"]
      );
    }

    async function exportAesRawKey(aesKey) {
      return new Uint8Array(await crypto.subtle.exportKey("raw", aesKey));
    }

    async function importAesRawKey(rawBytes) {
      return crypto.subtle.importKey(
        "raw",
        rawBytes,
        { name: "AES-GCM" },
        false,
        ["encrypt", "decrypt"]
      );
    }

    function generateRecoveryPhrase(wordCount = 12) {
      const words = [
        "apple","anchor","amber","arc","aster","bloom","brisk","cabin","candle","cipher",
        "comet","crystal","delta","ember","falcon","forest","frost","galaxy","harbor","ivory",
        "jungle","kinetic","lunar","maple","mystic","nebula","ocean","onyx","panda","quartz",
        "raven","ridge","saffron","shadow","signal","silver","solstice","spark","starlight","summit",
        "temple","thorn","tiger","trident","velvet","violet","wander","whisper","willow","zephyr"
      ];
      const rand = new Uint32Array(wordCount);
      crypto.getRandomValues(rand);
      const out = [];
      for (let i = 0; i < wordCount; i++) out.push(words[rand[i] % words.length]);
      return out.join(" ");
    }
    async function generateAuthVerifier(secretAesKey) {
      const rawBytes = await exportAesRawKey(secretAesKey);
      const staticSalt = te.encode("_SERVER_VERIFY_V1");
      const authBase = new Uint8Array(rawBytes.length + staticSalt.length);
      authBase.set(rawBytes, 0);
      authBase.set(staticSalt, rawBytes.length);
      return bytesToB64(await sha256Bytes(authBase));
    }
    async function makeSecretKey(secret, saltBytes) {
      return deriveAesKeyFromSecret(secret, saltBytes);
    }

    async function encryptPrivateKeyWithSecret(privateKey, secretAesKey) {
      const pkcs8Bytes = await exportPrivateKeyPkcs8(privateKey);
      return aesGcmEncryptBytes(secretAesKey, pkcs8Bytes);
    }

    async function decryptPrivateKeyWithSecret(payload, secretAesKey) {
      const pkcs8Bytes = await aesGcmDecryptBytes(secretAesKey, payload);
      return importPrivateKeyPkcs8(pkcs8Bytes);
    }

    async function wrapMasterKeyForPublicKey(masterKeyRawBytes, recipientPublicKeyJwk) {
      const recipientPub = await importPublicKeyJwk(recipientPublicKeyJwk);
      const encrypted = await crypto.subtle.encrypt(
        { name: "RSA-OAEP" },
        recipientPub,
        masterKeyRawBytes
      );
      return bytesToB64(new Uint8Array(encrypted));
    }

    async function unwrapMasterKeyWithPrivateKey(wrappedMasterKeyB64, privateKey) {
      const wrappedBytes = b64ToBytes(wrappedMasterKeyB64);
      const raw = await crypto.subtle.decrypt(
        { name: "RSA-OAEP" },
        privateKey,
        wrappedBytes
      );
      return new Uint8Array(raw);
    }

    

  // ---------- Context checks (Lenient Mode) ----------

    async function assessContext(deviceRecord, currentFingerprintHashB64 = "", currentIpHint = "") {

      return {
        ok: true,
        warnings: []
      };
    }

    async function enforceContext(deviceRecord, opts = {}) {

      return { ok: true, warnings: [] };
    }


    async function decryptMasterKeyForDevice(devicePrivateKey, wrappedMasterKeyB64) {
      const raw = await unwrapMasterKeyWithPrivateKey(wrappedMasterKeyB64, devicePrivateKey);
      return importAesRawKey(raw);
    }

    async function encryptNoteWithMasterKey(noteText, masterKeyAes) {
      return aesGcmEncryptBytes(masterKeyAes, te.encode(noteText));
    }

    async function decryptNoteWithMasterKey(encryptedNotePayload, masterKeyAes) {
      const plainBytes = await aesGcmDecryptBytes(masterKeyAes, encryptedNotePayload);
      return td.decode(plainBytes);
    }

    // ---------- Public API ----------

  // ---------- Public API ----------

    async function createUser({
      username,
      password,
      deviceName = "Primary device",
      recoveryHint = "",
      ipHint = ""
    }) {
      assert(username && password, "Username and password are required.");

      // 1. Generate all the keys in the browser (Zero-Knowledge)
      const pwSalt = randomBytes(16);
      const recoverySalt = randomBytes(16);
      const currentFingerprintHashB64 = await fingerprintHash();
      const recoveryPhrase = generateRecoveryPhrase(12);

      const passwordKey = await makeSecretKey(password, pwSalt);
      const recoveryKey = await makeSecretKey(recoveryPhrase, recoverySalt);

      const authVerifierB64 = await generateAuthVerifier(passwordKey);

      const deviceKeys = await generateRsaKeyPair();
      const encPrivateByPassword = await encryptPrivateKeyWithSecret(deviceKeys.privateKey, passwordKey);
      const encPrivateByRecovery = await encryptPrivateKeyWithSecret(deviceKeys.privateKey, recoveryKey);
      const publicKeyJwk = await exportPublicKeyJwk(deviceKeys.publicKey);

      const deviceId = randomId("dev_");

      // 2. Pack the data up into a JSON object
      const payload = {
        username,
        pwSaltB64: bytesToB64(pwSalt),
        recoverySaltB64: bytesToB64(recoverySalt),
        authVerifierB64,
        device: {
          deviceId,
          deviceName,
          fingerprintHashB64: currentFingerprintHashB64,
          ipHintHashB64: ipHint ? await sha256String(ipHint) : "",
          publicKeyJwk,
          encPrivateKeyByPassword: encPrivateByPassword,
          encPrivateKeyByRecovery: encPrivateByRecovery
        }
      };

      // 3. Shoot it over to the Express Server
      const response = await fetch('http://localhost:3000/api/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || "Failed to register user on the server.");
      }

      return {
        username,
        deviceId,
        recoveryPhrase,
        authVerifierB64 
      };
    }

  async function validateLogin(username, password, deviceId) {
      // 1. Ask the server for the user's specific Salt
      const saltRes = await fetch(`http://localhost:3000/api/salt/${username}`);
      if (!saltRes.ok) throw new Error("Could not fetch salt.");
      const { pwSaltB64 } = await saltRes.json();

      // 2. Re-create the Password Key and the Auth Verifier
      const passwordKey = await makeSecretKey(password, b64ToBytes(pwSaltB64));
      const authVerifierB64 = await generateAuthVerifier(passwordKey);

      // 3. Send the proof (AuthVerifier) to the server to actually log in
      const loginRes = await fetch('http://localhost:3000/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username,
          authVerifierB64,
          deviceId
        })
      });

      if (!loginRes.ok) {
        const errorData = await loginRes.json();
        throw new Error(errorData.error || "Login failed.");
      }

      const sessionData = await loginRes.json();
      
      // 4. (Locally) Unlock the device's private key using the password key we just generated
      const privateKey = await decryptPrivateKeyWithSecret(sessionData.encPrivateKeyByPassword, passwordKey);

      return { 
        username, 
        deviceId, 
        token: sessionData.token,
        privateKey,
        publicKeyJwk: sessionData.publicKeyJwk
      };
    }
    
async function addDevice({ username, password, deviceName = "New device" }) {
    // 1. Get Salt to prove identity
    const saltRes = await fetch(`http://localhost:3000/api/salt/${username}`);
    const { pwSaltB64 } = await saltRes.json();

    const passwordKey = await makeSecretKey(password, b64ToBytes(pwSaltB64));
    const authVerifierB64 = await generateAuthVerifier(passwordKey);

    // 2. Generate new device keys
    const deviceKeys = await generateRsaKeyPair();
    const encPrivateByPassword = await encryptPrivateKeyWithSecret(deviceKeys.privateKey, passwordKey);
    const publicKeyJwk = await exportPublicKeyJwk(deviceKeys.publicKey);
    const deviceId = randomId("dev_");

    // 3. Upload to server
    const res = await fetch('http://localhost:3000/api/devices', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
         username, 
         authVerifierB64, 
         deviceId, 
         deviceName,
         publicKeyJwk, 
         encPrivateKeyByPassword
      })
    });

    if (!res.ok) throw new Error("Failed to register new device.");
    return { deviceId, publicKeyJwk };
  }

  async function updateNote({ noteId, title, noteText, publicKeyJwk, token }) {
    // 1. Create a NEW Master Key (Best practice: Key Rotation)
    const masterRaw = randomBytes(32);
    const masterAes = await importAesRawKey(masterRaw);

    // 2. Encrypt the new content
    const encryptedNote = await encryptNoteWithMasterKey(noteText, masterAes);
    
    // 3. Re-wrap the key
    const wrappedMasterKeyB64 = await wrapMasterKeyForPublicKey(masterRaw, publicKeyJwk);

    const response = await fetch(`http://localhost:3000/api/notes/${noteId}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
      body: JSON.stringify({ title, encryptedNote, wrappedMasterKeyB64 })
    });

    if (!response.ok) throw new Error("Failed to update note on server.");
    return { success: true };
  }

  async function deleteNote({ noteId, token }) {
    const response = await fetch(`http://localhost:3000/api/notes/${noteId}`, {
      method: 'DELETE',
      headers: { 'Authorization': `Bearer ${token}` }
    });

    if (!response.ok) throw new Error("Failed to delete note.");
    return { success: true };
  }

async function recoverAccount({ username, recoveryPhrase, newPassword }) {
    // 1. Fetch ALL recovery data from the specific recovery endpoint
    const devRes = await fetch(`http://localhost:3000/api/devices/recovery/${username}`);
    if (!devRes.ok) throw new Error("Could not find recovery data.");
    
    // Extract the salt from HERE, not from the /api/salt endpoint!
    let { deviceId, encPrivateKeyByRecovery, recoverySaltB64 } = await devRes.json();

    // Safety net: Force it into an object if MySQL sent it as a string
    if (typeof encPrivateKeyByRecovery === 'string') {
        try { encPrivateKeyByRecovery = JSON.parse(encPrivateKeyByRecovery); } catch(e) {}
    }

    // 2. Unlock Private Key using the 12-word phrase and the correct salt
    const recoveryKey = await makeSecretKey(recoveryPhrase, b64ToBytes(recoverySaltB64));
    const privateKey = await decryptPrivateKeyWithSecret(encPrivateKeyByRecovery, recoveryKey);

    // 3. Create a brand new password and re-encrypt the private key
    const newPwSalt = randomBytes(16);
    const newPasswordKey = await makeSecretKey(newPassword, newPwSalt);
    const newAuthVerifierB64 = await generateAuthVerifier(newPasswordKey);
    const newEncPrivateByPassword = await encryptPrivateKeyWithSecret(privateKey, newPasswordKey);

    // 4. Send updated credentials to server
    const recRes = await fetch(`http://localhost:3000/api/users/recovery/update-auth`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
         username, 
         deviceId,
         newPwSaltB64: bytesToB64(newPwSalt),
         newAuthVerifierB64,
         newEncPrivateKeyPassword: newEncPrivateByPassword // Make sure this matches your server.js variable!
      })
    });

    if (!recRes.ok) throw new Error("Account recovery failed on server side.");
    return { success: true };
}
  async function createNote({
      title = "Untitled",
      noteText,
      publicKeyJwk, // Passed in from your app.js state
      token,        // Passed in from your app.js state
      ipHint = ""
    }) {
      assert(publicKeyJwk && token, "Public Key and Auth Token are required to create a note.");

      // 1. Generate a random AES Master Key just for this specific note
      const masterRaw = randomBytes(32);
      const masterAes = await importAesRawKey(masterRaw);

      // 2. Encrypt the note text with the AES key
      const encryptedNote = await encryptNoteWithMasterKey(noteText, masterAes);
      
      // 3. Lock the AES key inside your RSA Public Key
      const wrappedMasterKeyB64 = await wrapMasterKeyForPublicKey(masterRaw, publicKeyJwk);
      const currentFingerprintHashB64 = await fingerprintHash();

      const noteId = randomId("note_");

      // 4. Send the completely encrypted blobs to the Server
      const payload = {
        noteId,
        title,
        encryptedNote,
        wrappedMasterKeyB64,
        fingerprintHashB64: currentFingerprintHashB64,
        ipHintHashB64: ipHint ? await sha256String(ipHint) : ""
      };

      const response = await fetch('http://localhost:3000/api/notes', {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}` // This passes the bouncer!
        },
        body: JSON.stringify(payload)
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || "Failed to save note to server.");
      }

      return { noteId, title };
    }
    async function unlockNote({ noteId, privateKey, token }) {
    assert(privateKey && token, "Private Key and Token are required.");

    // 1. Fetch the encrypted note and your specific wrapped key from the server
    const response = await fetch(`http://localhost:3000/api/notes/${noteId}`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    if (!response.ok) throw new Error("Failed to fetch note from server.");
    
    const noteData = await response.json();

    // 2. Local Zero-Knowledge Decryption
    const masterKeyAes = await decryptMasterKeyForDevice(privateKey, noteData.wrappedMasterKeyB64);
    const noteText = await decryptNoteWithMasterKey(noteData.encryptedNote, masterKeyAes);

    return {
      noteId,
      title: noteData.title,
      noteText,
      role: noteData.role
    };
  }



async function shareNote({ noteId, recipientUsername, ownerPrivateKey, token }) {
    assert(ownerPrivateKey && token, "Private key and token required to share.");

    // 1. Fetch the note's current wrapped key
    const noteRes = await fetch(`http://localhost:3000/api/notes/${noteId}`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    const noteData = await noteRes.json();

    // 2. Fetch the recipient's Public RSA Key
    const userRes = await fetch(`http://localhost:3000/api/users/${recipientUsername}/key`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    if (!userRes.ok) throw new Error("Recipient not found.");
    const userData = await userRes.json();

    // 3. Math: Unwrap with your private key, re-wrap with their public key
    const masterKeyAes = await decryptMasterKeyForDevice(ownerPrivateKey, noteData.wrappedMasterKeyB64);
    const masterRaw = await exportAesRawKey(masterKeyAes);
    const newWrappedKeyB64 = await wrapMasterKeyForPublicKey(masterRaw, userData.publicKeyJwk);

    // 4. Send the new lock to the server
    const shareRes = await fetch(`http://localhost:3000/api/notes/${noteId}/share`, {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}` 
      },
      body: JSON.stringify({ 
        recipientUsername, 
        wrappedMasterKeyB64: newWrappedKeyB64 
      })
    });

    if (!shareRes.ok) throw new Error("Failed to share note on server.");
    return { noteId, sharedWith: recipientUsername };
  }

async function revokeAccess({ noteId, revokedUsername, ownerPrivateKey, token }) {
    // 1. Fetch the note and ALL users who currently have access (with their public keys)
    const fullNoteRes = await fetch(`http://localhost:3000/api/notes/${noteId}/full`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    const fullNote = await fullNoteRes.json();

    // 2. Decrypt the current note locally
    const oldMasterAes = await decryptMasterKeyForDevice(ownerPrivateKey, fullNote.myWrappedKey);
    const plaintext = await decryptNoteWithMasterKey(fullNote.encryptedNote, oldMasterAes);

    // 3. Generate a NEW Master Key & Re-encrypt the note
    const newRawMaster = randomBytes(32);
    const newMasterAes = await importAesRawKey(newRawMaster);
    const newEncryptedNote = await encryptNoteWithMasterKey(plaintext, newMasterAes);

    // 4. Wrap the new key for everyone EXCEPT the revoked user
    const newAccessList = [];
    for (const access of fullNote.accessList) {
      if (access.username === revokedUsername) continue;
      
      const wrapped = await wrapMasterKeyForPublicKey(newRawMaster, access.publicKeyJwk);
      newAccessList.push({ 
        deviceId: access.deviceId, 
        wrappedMasterKeyB64: wrapped 
      });
    }

    // 5. Upload the rotated keys and the newly encrypted note blob
    const rotateRes = await fetch(`http://localhost:3000/api/notes/${noteId}/rotate`, {
      method: 'PUT',
      headers: { 
        'Content-Type': 'application/json', 
        'Authorization': `Bearer ${token}` 
      },
      body: JSON.stringify({ 
        newEncryptedNote, 
        newAccessList 
      })
    });

    if (!rotateRes.ok) throw new Error("Failed to rotate keys on server.");
    return { noteId, revokedUsername, rotated: true };
  }

    async function listUserNotes(token) {
    const response = await fetch('http://localhost:3000/api/notes/owned', {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    if (!response.ok) throw new Error("Failed to fetch your notes.");
    return await response.json();
  }

  async function listAccessibleNotes(token) {
    const response = await fetch('http://localhost:3000/api/notes/shared', {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    if (!response.ok) throw new Error("Failed to fetch shared notes.");
    return await response.json();
  }

  async function deactivateDevice({ deviceId, token }) {
     const res = await fetch(`http://localhost:3000/api/devices/${deviceId}`, {
       method: 'DELETE',
       headers: { 'Authorization': `Bearer ${token}` }
     });
     if (!res.ok) throw new Error("Failed to deactivate device.");
     return { deactivated: true };
  }
    async function debugDump() {
    }

    return {
      createUser,
      addDevice,
      createNote,
      unlockNote,
      shareNote,
      revokeAccess,
      listUserNotes,
      listAccessibleNotes,
      deactivateDevice,
      debugDump,
      validateLogin,
      recoverAccount,
      updateNote,
      deleteNote
    };
  })();

  window.SecureVault = SecureVault;

  if (typeof module !== "undefined" && module.exports) {
    module.exports = SecureVault;
  }