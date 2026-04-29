const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const pool = require('./db');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json({ limit: '15mb' }));

// ==========================================
// 🟢 REGISTER ENDPOINT
// ==========================================
app.post('/api/register', async (req, res) => {
  const { 
    username, 
    pwSaltB64, 
    recoverySaltB64, 
    authVerifierB64, 
    device 
  } = req.body;

  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();

    // 1. Insert User
    await connection.query(
      `INSERT INTO users (username, pw_salt_b64, recovery_salt_b64, auth_verifier_b64) 
       VALUES (?, ?, ?, ?)`,
      [username, pwSaltB64, recoverySaltB64, authVerifierB64]
    );

    // 2. Insert Device
    await connection.query(
      `INSERT INTO devices 
      (id, username, device_name, fingerprint_hash_b64, ip_hint_hash_b64, public_key_jwk, enc_private_key_password, enc_private_key_recovery) 
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        device.deviceId, 
        username, 
        device.deviceName, 
        device.fingerprintHashB64 || null, 
        device.ipHintHashB64 || null,
        JSON.stringify(device.publicKeyJwk), 
        JSON.stringify(device.encPrivateKeyByPassword), 
        JSON.stringify(device.encPrivateKeyByRecovery)
      ]
    );

    await connection.commit();
    res.status(201).json({ message: "Vault secured and device registered." });

  } catch (error) {
    await connection.rollback();
    if (error.code === 'ER_DUP_ENTRY') {
      return res.status(400).json({ error: "Username is already taken." });
    }
    console.error("Registration Error:", error);
    res.status(500).json({ error: "Internal Server Error" });
  } finally {
    connection.release();
  }
});

// ==========================================
// 🟡 GET SALT ENDPOINT (Step 1 of Login)
// ==========================================
app.get('/api/salt/:username', async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT pw_salt_b64 FROM users WHERE username = ?`, 
      [req.params.username]
    );

    if (rows.length === 0) {
      // Return a fake salt if user doesn't exist to prevent username enumeration attacks
      return res.json({ pwSaltB64: "fake_salt_to_fool_hackers==" }); 
    }

    res.json({ pwSaltB64: rows[0].pw_salt_b64 });
  } catch (error) {
    res.status(500).json({ error: "Internal Server Error" });
  }
});
// ==========================================
// 🔵 LOGIN ENDPOINT
// ==========================================
app.post('/api/login', async (req, res) => {
  const { username, authVerifierB64, deviceId } = req.body;

  try {
    const [userRows] = await pool.query(
      `SELECT auth_verifier_b64, pw_salt_b64, recovery_salt_b64 FROM users WHERE username = ?`, 
      [username]
    );

    if (userRows.length === 0) return res.status(401).json({ error: "Invalid credentials." });

    const user = userRows[0];
    if (user.auth_verifier_b64 !== authVerifierB64) return res.status(401).json({ error: "Invalid credentials." });

    const [deviceRows] = await pool.query(
      `SELECT enc_private_key_password, public_key_jwk FROM devices WHERE id = ? AND username = ? AND active = TRUE`,
      [deviceId, username]
    );

    if (deviceRows.length === 0) return res.status(403).json({ error: "Device not recognized." });

    const token = jwt.sign({ username, deviceId }, process.env.JWT_SECRET, { expiresIn: '2h' });

    // --- CRITICAL FIX START ---
    // Instead of a separate helper, we handle it inline for absolute safety
    let encKey = deviceRows[0].enc_private_key_password;
    let pubKey = deviceRows[0].public_key_jwk;

    // If they are strings, parse them. If they are already objects, leave them alone.
    if (typeof encKey === 'string') encKey = JSON.parse(encKey);
    if (typeof pubKey === 'string') pubKey = JSON.parse(pubKey);
    // --- CRITICAL FIX END ---

    res.json({
      token,
      pwSaltB64: user.pw_salt_b64,
      recoverySaltB64: user.recovery_salt_b64,
      encPrivateKeyByPassword: encKey,
      publicKeyJwk: pubKey
    });

  } catch (error) {
    console.error("Login Error Details:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// ==========================================
// 📝 CREATE NOTE ENDPOINT
// ==========================================
app.post('/api/notes', async (req, res) => {
  // 1. Verify the JWT Token (The "Guard looking at the King's Seal")
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: "Missing token" });
  
  const token = authHeader.split(' ')[1];
  let decoded;
  try {
    decoded = jwt.verify(token, process.env.JWT_SECRET);
  } catch (err) {
    return res.status(401).json({ error: "Invalid or expired token" });
  }

  const { noteId, title, encryptedNote, wrappedMasterKeyB64, fingerprintHashB64, ipHintHashB64 } = req.body;
  const username = decoded.username;
  const deviceId = decoded.deviceId;

  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();

    // 2. Insert the locked note
    await connection.query(
      `INSERT INTO notes (id, owner_username, title, encrypted_note) 
       VALUES (?, ?, ?, ?)`,
      [noteId, username, title, JSON.stringify(encryptedNote)]
    );

    // 3. Insert the lock (wrapped key) for this specific device
    await connection.query(
      `INSERT INTO note_access (note_id, device_id, wrapped_master_key_b64, role, fingerprint_hash_b64, ip_hint_hash_b64) 
       VALUES (?, ?, ?, 'owner', ?, ?)`,
      [noteId, deviceId, wrappedMasterKeyB64, fingerprintHashB64, ipHintHashB64]
    );

    await connection.commit();
    res.status(201).json({ message: "Note secured in vault." });
  } catch (error) {
    await connection.rollback();
    console.error("Note Creation Error:", error);
    res.status(500).json({ error: "Internal Server Error" });
  } finally {
    connection.release();
  }
});

// ==========================================
// 📜 LIST OWNED NOTES
// ==========================================
app.get('/api/notes/owned', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: "Missing token" });

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const username = decoded.username;

    // We only send the metadata (ID, Title, Dates) for the list
    const [notes] = await pool.query(
      `SELECT id as noteId, title, created_at as createdAt, updated_at as updatedAt 
       FROM notes WHERE owner_username = ? ORDER BY created_at DESC`,
      [username]
    );

    res.json(notes);
  } catch (err) {
    res.status(401).json({ error: "Invalid session" });
  }
});

// ==========================================
// 🔓 FETCH ENCRYPTED NOTE FOR DECRYPTION
// ==========================================
app.get('/api/notes/:noteId', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: "Missing token" });

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const { noteId } = req.params;
    const { deviceId } = decoded;

    // Join notes with note_access to get the specific "lock" for THIS device
    const [rows] = await pool.query(
      `SELECT n.title, n.encrypted_note as encryptedNote, a.wrapped_master_key_b64 as wrappedMasterKeyB64, a.role
       FROM notes n
       JOIN note_access a ON n.id = a.note_id
       WHERE n.id = ? AND a.device_id = ?`,
      [noteId, deviceId]
    );

    if (rows.length === 0) return res.status(404).json({ error: "Note not found or access denied." });

    const note = rows[0];
    
    // Safety check for JSON parsing
    let encNote = note.encryptedNote;
    if (typeof encNote === 'string') {
      try { encNote = JSON.parse(encNote); } catch(e) {}
    }

    res.json({
      title: note.title,
      encryptedNote: encNote,
      wrappedMasterKeyB64: note.wrappedMasterKeyB64,
      role: note.role
    });
  } catch (err) {
    res.status(401).json({ error: "Invalid session" });
  }
});

// ==========================================
// ✏️ UPDATE NOTE (Re-Encrypt & Save)
// ========================================== 
app.put('/api/notes/:noteId', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: "Missing token" });

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const { noteId } = req.params;
    const { title, encryptedNote, wrappedMasterKeyB64 } = req.body;
    const username = decoded.username;
    const deviceId = decoded.deviceId;

    const connection = await pool.getConnection();
    try {
      await connection.beginTransaction();

      // 1. Update the note title and blob
      const [result] = await connection.query(
        `UPDATE notes SET title = ?, encrypted_note = ? WHERE id = ? AND owner_username = ?`,
        [title, JSON.stringify(encryptedNote), noteId, username]
      );

      if (result.affectedRows === 0) throw new Error("Update failed: Ownership mismatch.");

      // 2. Update the specific key for this device
      await connection.query(
        `UPDATE note_access SET wrapped_master_key_b64 = ? WHERE note_id = ? AND device_id = ?`,
        [wrappedMasterKeyB64, noteId, deviceId]
      );

      await connection.commit();
      res.json({ message: "Note updated and re-secured." });
    } catch (err) {
      await connection.rollback();
      throw err;
    } finally {
      connection.release();
    }
  } catch (err) {
    res.status(401).json({ error: "Unauthorized or update failed." });
  }
});

// ==========================================
// 🗑️ DELETE NOTE
// ==========================================
app.delete('/api/notes/:noteId', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: "Missing token" });

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const { noteId } = req.params;
    const username = decoded.username;

    // Delete the note (note_access should have ON DELETE CASCADE, but we'll be safe)
    await pool.query(`DELETE FROM notes WHERE id = ? AND owner_username = ?`, [noteId, username]);
    await pool.query(`DELETE FROM note_access WHERE note_id = ?`, [noteId]);

    res.json({ message: "Note purged from vault." });
  } catch (err) {
    res.status(401).json({ error: "Unauthorized or delete failed." });
  }
});

  // ==========================================
// 🩹 RECOVERY DATA FETCH
// ==========================================
app.get('/api/devices/recovery/:username', async (req, res) => {
  try {
    const { username } = req.params;

    // Fetch the recovery salt from 'users' and the recovery-encrypted key from 'devices'
    const [rows] = await pool.query(
      `SELECT u.recovery_salt_b64, d.enc_private_key_recovery, d.id as deviceId
       FROM users u
       JOIN devices d ON u.username = d.username
       WHERE u.username = ? AND d.active = TRUE LIMIT 1`,
      [username]
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: "Recovery data not found." });
    }

    const data = rows[0];

    // Smart Parsing logic to avoid [object Object] crashes
    let encKeyRecovery = data.enc_private_key_recovery;
    if (typeof encKeyRecovery === 'string') {
      try { encKeyRecovery = JSON.parse(encKeyRecovery); } catch (e) {}
    }

    res.json({
      recoverySaltB64: data.recovery_salt_b64,
      encPrivateKeyByRecovery: encKeyRecovery,
      deviceId: data.deviceId
    });

  } catch (error) {
    console.error("Recovery Data Fetch Error:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// ==========================================
// 🔑 UPDATE AUTH AFTER RECOVERY (Password Reset)
// ==========================================
app.post('/api/users/recovery/update-auth', async (req, res) => {
  const { username, deviceId, newAuthVerifierB64, newPwSaltB64, newEncPrivateKeyPassword } = req.body;

  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();

    // 1. Update user's main password salt and auth verifier
    await connection.query(
      `UPDATE users SET auth_verifier_b64 = ?, pw_salt_b64 = ? WHERE username = ?`,
      [newAuthVerifierB64, newPwSaltB64, username]
    );

    // 2. Update the device's private key (now encrypted with the NEW password)
    await connection.query(
      `UPDATE devices SET enc_private_key_password = ? WHERE id = ? AND username = ?`,
      [JSON.stringify(newEncPrivateKeyPassword), deviceId, username]
    );

    await connection.commit();
    res.json({ message: "Security credentials updated successfully." });

  } catch (error) {
    await connection.rollback();
    console.error("Auth Update Error:", error);
    res.status(500).json({ error: "Internal Server Error" });
  } finally {
    connection.release();
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🛡️  Secure Vault Backend listening on http://localhost:${PORT}`);
});