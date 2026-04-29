/**
 * app.js - Full-Stack Zero-Knowledge UI Controller
 */

// 🔴 THE SECURE RAM VAULT (Wiped when tab closes or locks)
let sessionState = {
  username: null,
  deviceId: null,
  token: null,
  privateKey: null,
  publicKeyJwk: null
};

// DOM Elements
let allNotes = [];
let currentNoteId = null; 
const recoveryPanel = document.getElementById("recoveryPanel");
const ackRecoveryBtn = document.getElementById("ackRecoveryBtn");
const authDiv = document.getElementById("auth");
const dashboardDiv = document.getElementById("dashboard");
const viewerDiv = document.getElementById("viewer");
const usernameInput = document.getElementById("username");
const passwordInput = document.getElementById("password");
const loginBtn = document.getElementById("loginBtn");
const signupBtn = document.getElementById("signupBtn");
const logoutBtn = document.getElementById("logoutBtn");
const recoveryDisplay = document.getElementById("recoveryDisplay");
const noteTitle = document.getElementById("noteTitle");
const noteContent = document.getElementById("noteContent");
const createNoteBtn = document.getElementById("createNoteBtn");
const notesList = document.getElementById("notesList");
const viewTitle = document.getElementById("viewTitle");
const viewContent = document.getElementById("viewContent");
const closeViewer = document.getElementById("closeViewer");
const forgotBtn = document.getElementById("forgotBtn");
const forgotPanel = document.getElementById("forgotPanel");
const fpUsername = document.getElementById("fpUsername");
const fpRecovery = document.getElementById("fpRecovery");
const fpNewPassword = document.getElementById("fpNewPassword");
const recoverBtn = document.getElementById("recoverBtn");
const cancelRecover = document.getElementById("cancelRecover"); 
// Add these to the bottom of app.js
document.getElementById("updateBtn").onclick = handleUpdateNote;
document.getElementById("deleteBtn").onclick = handleDeleteNote;

// --- Navigation Helpers ---
function showDashboard() {
  authDiv.classList.add("hidden");
  forgotPanel.classList.add("hidden");
  dashboardDiv.classList.remove("hidden");
}

function showAuth() {
  dashboardDiv.classList.add("hidden");
  viewerDiv.classList.add("hidden");
  recoveryPanel.classList.add("hidden");
  forgotPanel.classList.add("hidden");
  authDiv.classList.remove("hidden");
}

function showViewer() { viewerDiv.classList.remove("hidden"); }
function hideViewer() { viewerDiv.classList.add("hidden"); }

// ==========================================
// 1. REGISTRATION
// ==========================================
signupBtn.onclick = async () => {
  try {
    const username = usernameInput.value.trim();
    const password = passwordInput.value.trim();

    if (!username || !password) return alert("Enter username and password");

    const res = await SecureVault.createUser({ username, password });

    // Save Device ID to browser so the server recognizes us at login
    localStorage.setItem("deviceId", res.deviceId);

    recoveryDisplay.textContent = "⚠️ SAVE THIS RECOVERY PHRASE:\n\n" + res.recoveryPhrase;

    authDiv.classList.add("hidden");
    recoveryPanel.classList.remove("hidden");

  } catch (err) {
    alert("Registration Failed: " + err.message);
  }
};

// Force login after acknowledging recovery phrase
ackRecoveryBtn.onclick = () => {
  recoveryPanel.classList.add("hidden");
  alert("Registration complete. Please log in now.");
  showAuth(); 
};

// ==========================================
// 2. LOGIN (DOUBLE-HASH AUTH)
// ==========================================
loginBtn.onclick = async () => {
  try {
    const username = usernameInput.value.trim();
    const password = passwordInput.value.trim();
    const deviceId = localStorage.getItem("deviceId");

    if (!username || !password) return alert("Enter username and password");
    if (!deviceId) return alert("Unrecognized device. You must create an account on this browser first.");

    const res = await SecureVault.validateLogin(username, password, deviceId);

    // LOAD THE UNLOCKED KEYS INTO RAM
    sessionState.username = res.username;
    sessionState.deviceId = res.deviceId;
    sessionState.token = res.token;
    sessionState.privateKey = res.privateKey;
    sessionState.publicKeyJwk = res.publicKeyJwk;

    const name = sessionState.username;
    const formatted = name.endsWith("s") ? `${name}' Vault` : `${name}'s Vault`;
    document.getElementById("vaultTitle").textContent = formatted;

    recoveryPanel.classList.add("hidden"); 
    await loadNotes();
    showDashboard();

  } catch (err) {
     alert("Login Failed: " + err.message);
  }
};

// ==========================================
// 3. CREATE NOTE
// ==========================================
createNoteBtn.onclick = async () => {
  try {
    const title = noteTitle.value.trim();
    const content = noteContent.value.trim();

    if (!content) return alert("Write something first");
    if (!sessionState.token) return alert("Fatal Error: Not logged in.");

const result = await SecureVault.createNote({
      title,
      noteText: content,
      publicKeyJwk: sessionState.publicKeyJwk,
      token: sessionState.token
    });
    console.log("Created note:", result.noteId); // Good for debugging

    noteTitle.value = "";
    noteContent.value = "";

    await loadNotes();
  } catch (err) {
    alert("Encryption Failed: " + err.message);
  }
};

// ==========================================
// 4. LOAD NOTES
// ==========================================
async function loadNotes() {
  try {
    const notes = await SecureVault.listUserNotes(sessionState.token);
    allNotes = notes || []; // Save them locally!
    renderNotes(allNotes); // Call a new helper function to draw the UI
  } catch (err) {
    console.error("Failed to load notes:", err.message);
  }
}

// 🎨 Helper to draw the notes on screen
function renderNotes(notesToDisplay, searchQuery = "") {
  notesList.innerHTML = "";
  
  if (notesToDisplay.length === 0) {
    notesList.innerHTML = "<p>No notes found.</p>";
    return;
  }

  notesToDisplay.forEach(note => {
    const div = document.createElement("div");
    div.className = "note";
    
    // Use your SearchModule.highlight feature here!
    const displayTitle = SearchModule.highlight(note.title || "Untitled", searchQuery);
    div.innerHTML = DOMPurify.sanitize(displayTitle); 
    
    div.onclick = () => openNote(note.noteId);
    notesList.appendChild(div);
  });
}

// ==========================================
// 5. UNLOCK & VIEW NOTE
// ==========================================
async function openNote(noteId) {
  currentNoteId = noteId;
  try {
    const res = await SecureVault.unlockNote({
      noteId,
      privateKey: sessionState.privateKey,
      token: sessionState.token
    });

    viewTitle.textContent = res.title;
    viewContent.value = res.noteText;

    trackSecret(viewContent);
    showViewer();
  } catch (err) {
    alert("Decryption Failed: " + err.message);
  }
}

// ==========================================
// 6. RECOVERY
// ==========================================
forgotBtn.onclick = () => {
  authDiv.classList.add("hidden");
  forgotPanel.classList.remove("hidden");
};

cancelRecover.onclick = () => {
  forgotPanel.classList.add("hidden");
  showAuth();
};

// HANDLER: UPDATE
async function handleUpdateNote() {
  try {
    const title = viewTitle.textContent; // Or make title editable in the viewer
    const content = viewContent.value;

    await SecureVault.updateNote({
      noteId: currentNoteId,
      title,
      noteText: content,
      publicKeyJwk: sessionState.publicKeyJwk,
      token: sessionState.token
    });

    alert("Changes encrypted and saved!");
    await loadNotes(); // Refresh list
  } catch (err) {
    alert("Update failed: " + err.message);
  }
}

// HANDLER: DELETE
async function handleDeleteNote() {
  if (!confirm("Are you sure? This note will be gone forever. Even the server can't recover it.")) return;

  try {
    await SecureVault.deleteNote({
      noteId: currentNoteId,
      token: sessionState.token
    });

    hideViewer();
    await loadNotes();
    alert("Note purged.");
  } catch (err) {
    alert("Delete failed: " + err.message);
  }
}

recoverBtn.onclick = async () => {
  try {
    const u = fpUsername.value.trim();
    const phrase = fpRecovery.value.trim();
    const newPw = fpNewPassword.value.trim();

    if(!u || !phrase || !newPw) return alert("Fill out all fields.");

    await SecureVault.recoverAccount({
       username: u, 
       recoveryPhrase: phrase, 
       newPassword: newPw 
    });

    alert("Account recovered! Your private key has been re-encrypted with your new password. Please log in.");
    forgotPanel.classList.add("hidden");
    showAuth();
  } catch (err) {
    alert("Recovery Failed: " + err.message);
  }
};

// ==========================================
// 7. SECURITY PURGES
// ==========================================
logoutBtn.onclick = () => {
  wipeSecrets();
  sessionState = { username: null, deviceId: null, token: null, privateKey: null, publicKeyJwk: null };
  showAuth();
};

closeViewer.onclick = () => {
  wipeSecrets();
  hideViewer();
};

let trackedSecrets = [];
function trackSecret(ref) { trackedSecrets.push(ref); }

function wipeSecrets() {
  trackedSecrets.forEach(el => {
    if (el && "value" in el) el.value = "";
  });
  trackedSecrets = [];
}

const searchInput = document.getElementById("searchInput");

SearchModule.attachSearch(searchInput, (query) => {
  const filtered = SearchModule.filterNotes(allNotes, query);
  renderNotes(filtered, query); // Re-render the list with the filtered results
});
// Anti-Shoulder-Surfing / Sandbox Leaks
document.addEventListener("visibilitychange", () => {
  if (document.hidden) { wipeSecrets(); hideViewer(); }
});

window.addEventListener("blur", () => {
  wipeSecrets(); hideViewer();
});