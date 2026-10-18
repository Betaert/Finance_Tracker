// app.js - Extended with Cloud Sync Helpers (Google Drive API Example)

// Configuration for Google API (Requires a free Google Cloud Console Client ID)
const CLIENT_ID = 'YOUR_GOOGLE_CLIENT_ID.apps.googleusercontent.com';
const SCOPES = 'https://www.googleapis.com/auth/drive.appfolder';

let tokenClient;
let gapiInited = false;
let gisInited = false;

// Initialize Google Identity Services
function initGoogleAuth(callback) {
    if (typeof google === 'undefined') return;
    
    tokenClient = google.accounts.oauth2.initTokenClient({
        client_id: CLIENT_ID,
        scope: SCOPES,
        callback: async (resp) => {
            if (resp.error !== undefined) {
                throw(resp);
            }
            sessionStorage.setItem("g_access_token", resp.access_token);
            if (callback) callback(resp.access_token);
        }
    });
}

// Automatically sync local data up to Google Drive
async function syncDataToCloud(encryptedDataBlob) {
    const accessToken = sessionStorage.getItem("g_access_token");
    if (!accessToken) return false;

    // Upload encrypted blob to Google Drive AppData folder
    const metadata = {
        name: 'finance_tracker_backup.json',
        parents: ['appDataFolder']
    };

    const form = new FormData();
    form.append('metadata', new Blob([JSON.stringify(metadata)], { type: 'application/json' }));
    form.append('file', new Blob([encryptedDataBlob], { type: 'application/json' }));

    const response = await fetch('https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart', {
        method: 'POST',
        headers: new Headers({ 'Authorization': 'Bearer ' + accessToken }),
        body: form
    });

    return response.ok;
}