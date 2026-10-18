// app.js - Complete Cryptographic Security & Local Storage Engine

const STORAGE_KEY_SALT = "finance_tracker_salt";
const STORAGE_KEY_HASH = "finance_tracker_hash";
const STORAGE_KEY_DATA = "finance_tracker_data";

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
        256 // 32 bytes key length
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
}

function hasStoredPassword() {
    return localStorage.getItem(STORAGE_KEY_SALT) !== null;
}

// --- Data Helpers ---
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

function saveTrackerData(data) {
    try {
        localStorage.setItem(STORAGE_KEY_DATA, JSON.stringify(data));
        return true;
    } catch (e) {
        return false;
    }
}

// --- Utility: Get Current Formatted Date ---
function getFormattedDate() {
    const now = new Date();
    const pad = (n) => String(n).padStart(2, '0');
    return `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())} ${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}`;
}

// --- Session Check for Protected Pages ---
function checkAuthSession() {
    const isAuth = sessionStorage.getItem("finance_authenticated");
    if (!isAuth && window.location.pathname.indexOf("index.html") === -1 && window.location.pathname !== "/") {
        window.location.href = "index.html";
    }
}

if (window.location.pathname.indexOf("index.html") === -1 && window.location.pathname !== "/") {
    checkAuthSession();
}