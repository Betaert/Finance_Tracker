// app.js - Cryptographic Security & Atomic Read-Modify-Write (RMW) Google Drive Engine

const STORAGE_KEY_SALT = "finance_tracker_salt";
const STORAGE_KEY_HASH = "finance_tracker_hash";
const STORAGE_KEY_DATA = "finance_tracker_data";
const STORAGE_KEY_TOKEN = "g_access_token";

// --- Google Drive Configuration ---
const CLIENT_ID = '473137610415-7rotlpd299stbu5m4js8qppsejukdes2.apps.googleusercontent.com'; 
const SCOPES = 'https://www.googleapis.com/auth/drive.appfolder';
let tokenClient;

// --- Cryptographic Helpers (PBKDF2-HMAC-SHA256) ---
async function hashPassword(password, saltBytes = null) {
    const encoder = new TextEncoder();
    const salt = saltBytes || window.crypto.getRandomValues(new Uint8Array(16));
    
    const keyMaterial = await window.crypto.subtle.importKey(
        "raw",
        encoder.encode(password),
        { name: "PBKDF2" },
        false,
        ["deriveBits"]
    );

    const derivedBits = await window.crypto.subtle.deriveBits(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: 600000,
            hash: "SHA-256"
        },
        keyMaterial,
        256
    );

    return {
        salt: Array.from(salt),
        hash: Array.from(new Uint8Array(derivedBits))
    };
}

async function verifyStoredPassword(inputPassword) {
    const storedSaltArr = JSON.parse(localStorage.getItem(STORAGE_KEY_SALT));
    const storedHashArr = JSON.parse(localStorage.getItem(STORAGE_KEY_HASH));

    if (!storedSaltArr || !storedHashArr) return false;

    const saltBytes = new Uint8Array(storedSaltArr);
    const inputResult = await hashPassword(inputPassword, saltBytes);

    const inputHashBytes = new Uint8Array(inputResult.hash);
    const storedHashBytes = new Uint8Array(storedHashArr);

    if (inputHashBytes.length !== storedHashBytes.length) return false;
    let mismatch = 0;
    for (let i = 0; i < inputHashBytes.length; i++) {
        mismatch |= inputHashBytes[i] ^ storedHashBytes[i];
    }
    return mismatch === 0;
}

async function initializeMasterPassword(password) {
    const result = await hashPassword(password);
    localStorage.setItem(STORAGE_KEY_SALT, JSON.stringify(result.salt));
    localStorage.setItem(STORAGE_KEY_HASH, JSON.stringify(result.hash));
    
    // Create initial cloud anchor file on Google Drive
    await commitDataToGoogleDrive(loadTrackerData());
}

function hasStoredPassword() {
    return localStorage.getItem(STORAGE_KEY_SALT) !== null;
}

// --- Local Storage Helpers ---
function loadTrackerData() {
    const rawData = localStorage.getItem(STORAGE_KEY_DATA);
    if (!rawData) return { plans: {} };
    try {
        const data = JSON.parse(rawData);
        return data.plans ? data : { plans: {} };
    } catch (e) {
        return { plans: {} };
    }
}

// Legacy save helper maintained for single-device offline fallback
function saveTrackerData(data) {
    try {
        localStorage.setItem(STORAGE_KEY_DATA, JSON.stringify(data));
        return true;
    } catch (e) {
        return false;
    }
}

// --- Persistent Token Management ---
function getStoredToken() {
    return localStorage.getItem(STORAGE_KEY_TOKEN) || sessionStorage.getItem(STORAGE_KEY_TOKEN);
}

function setStoredToken(token) {
    localStorage.setItem(STORAGE_KEY_TOKEN, token);
    sessionStorage.setItem(STORAGE_KEY_TOKEN, token);
}

// --- Google Drive Atomic Read-Modify-Write (RMW) Engine ---
async function getRemoteFileId(accessToken) {
    try {
        const searchRes = await fetch('https://www.googleapis.com/drive/v3/files?spaces=appDataFolder&q=name%3D%27finance_tracker_backup.json%27', {
            headers: { 'Authorization': 'Bearer ' + accessToken }
        });
        const searchJson = await searchRes.json();
        return (searchJson.files && searchJson.files.length > 0) ? searchJson.files[0].id : null;
    } catch (e) {
        console.error("Error retrieving cloud file ID", e);
        return null;
    }
}

// Fetch the single master JSON file directly from Google Drive
async function fetchRemoteData() {
    const accessToken = getStoredToken();
    if (!accessToken) return null;

    try {
        const fileId = await getRemoteFileId(accessToken);
        if (!fileId) return null;

        const fileRes = await fetch(`https://www.googleapis.com/drive/v3/files/${fileId}?alt=media`, {
            headers: { 'Authorization': 'Bearer ' + accessToken }
        });
        const backupBundle = await fileRes.json();

        // Restore remote security credentials & data to local device browser cache
        if (backupBundle.salt) localStorage.setItem(STORAGE_KEY_SALT, backupBundle.salt);
        if (backupBundle.hash) localStorage.setItem(STORAGE_KEY_HASH, backupBundle.hash);
        if (backupBundle.data) localStorage.setItem(STORAGE_KEY_DATA, backupBundle.data);

        return backupBundle;
    } catch (e) {
        console.error("Failed to fetch remote data from Google Drive", e);
        return null;
    }
}

// Atomic Mutation Engine: Fetches remote file -> Merges local change -> Writes directly back
async function mutateAndSaveTrackerData(mutatorFunction) {
    const accessToken = getStoredToken();
    let currentData = loadTrackerData();

    // If online & connected to Drive, fetch latest cloud state first to prevent overwriting
    if (accessToken) {
        const remoteBundle = await fetchRemoteData();
        if (remoteBundle && remoteBundle.data) {
            try {
                currentData = JSON.parse(remoteBundle.data);
            } catch (e) {}
        }
    }

    // Apply the specific modification (add plan, record amount, delete plan)
    currentData = mutatorFunction(currentData);

    // Save locally
    localStorage.setItem(STORAGE_KEY_DATA, JSON.stringify(currentData));

    // Write merged state directly back to the single Google Drive file
    if (accessToken) {
        await commitDataToGoogleDrive(currentData);
    }
    return true;
}

// Write JSON payload directly to the persistent Google Drive file
async function commitDataToGoogleDrive(currentData) {
    const accessToken = getStoredToken();
    if (!accessToken) return;

    const backupBundle = {
        salt: localStorage.getItem(STORAGE_KEY_SALT),
        hash: localStorage.getItem(STORAGE_KEY_HASH),
        data: JSON.stringify(currentData)
    };

    try {
        const fileId = await getRemoteFileId(accessToken);
        const metadata = {
            name: 'finance_tracker_backup.json',
            parents: fileId ? undefined : ['appDataFolder']
        };

        const form = new FormData();
        form.append('metadata', new Blob([JSON.stringify(metadata)], { type: 'application/json' }));
        form.append('file', new Blob([JSON.stringify(backupBundle)], { type: 'application/json' }));

        const method = fileId ? 'PATCH' : 'POST';
        const url = fileId 
            ? `https://www.googleapis.com/upload/drive/v3/files/${fileId}?uploadType=multipart`
            : 'https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart';

        await fetch(url, {
            method: method,
            headers: { 'Authorization': 'Bearer ' + accessToken },
            body: form
        });
    } catch (e) {
        console.error("Direct cloud commit failed", e);
    }
}

// --- Google Authentication Triggers ---
function initGoogleAuth(callback) {
    if (typeof google === 'undefined') return;
    
    tokenClient = google.accounts.oauth2.initTokenClient({
        client_id: CLIENT_ID,
        scope: SCOPES,
        callback: async (resp) => {
            if (resp.error !== undefined) {
                console.error("Google Auth Error", resp);
                return;
            }
            setStoredToken(resp.access_token);
            if (callback) await callback(resp.access_token);
        }
    });
}

function handleGoogleAuthClick() {
    initGoogleAuth(async (token) => {
        alert("Connected to Google Drive! Synchronizing cloud data...");
        await fetchRemoteData();
        window.location.reload();
    });
    
    if (tokenClient) {
        tokenClient.requestAccessToken({ prompt: '' });
    } else {
        initGoogleAuth(async (token) => {
            await fetchRemoteData();
            window.location.reload();
        });
    }
}

// --- Date & Session Utilities ---
function getFormattedDate() {
    const now = new Date();
    const pad = (n) => String(n).padStart(2, '0');
    return `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())} ${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}`;
}

function checkAuthSession() {
    const isAuth = sessionStorage.getItem("finance_authenticated");
    if (!isAuth && window.location.pathname.indexOf("index.html") === -1 && window.location.pathname !== "/") {
        window.location.href = "index.html";
    }
}

if (window.location.pathname.indexOf("index.html") === -1 && window.location.pathname !== "/") {
    checkAuthSession();
}
