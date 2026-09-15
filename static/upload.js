"use strict";

// ── DOM Elements ──────────────────────────────────────────────────────────────
const form = document.getElementById("uploadForm");
const controls = document.getElementById("uploadControls");
const fileInput = document.getElementById("fileInput");
const textInput = document.getElementById("textInput");
const fileLabel = document.getElementById("fileInputLabel");
const fileInputText = document.getElementById("fileInputText");
const status = document.getElementById("uploadStatus");
const progress = document.getElementById("uploadProgress");
const cancel = document.getElementById("cancelUpload");
const result = document.getElementById("result");
const expireSelect = document.getElementById("expire");
const storageProviderInput = document.getElementById("storageProvider");
const storageNote = document.getElementById("storageNote");
const fileInputContainer = document.getElementById("fileInputContainer");
const textInputContainer = document.getElementById("textInputContainer");
const selectedFiles = document.getElementById("selectedFiles");
const cancelNotice = document.getElementById("cancelNotice");
const bannedExts = JSON.parse(document.getElementById("bannedExtensions").textContent);
const maxBytes = Number(form.dataset.maxBytes);
const litterboxMaxBytes = Number(form.dataset.litterboxMaxBytes);
const maxTextLength = Number(form.dataset.maxTextLength);

// ── State ─────────────────────────────────────────────────────────────────────
let busy = false;
let cancelled = false;
let activeRequest = null;
const LITTERBOX_PROXY_URL = "https://alienxfile-proxy.fly.dev";

// ══════════════════════════════════════════════════════════════════════════════
// FEATURE 4: Dark mode toggle
// ══════════════════════════════════════════════════════════════════════════════
(function initDarkMode() {
    let toggle = document.getElementById("darkToggle");
    if (!toggle) {
        toggle = document.createElement("button");
        toggle.type = "button";
        toggle.id = "darkToggle";
        toggle.textContent = "\u263E";
        toggle.title = "Toggle dark mode";
        toggle.setAttribute("aria-label", "Toggle dark mode");
        toggle.className = "dark-toggle";
        const card = document.querySelector(".card");
        if (card) card.prepend(toggle);
    }

    const saved = localStorage.getItem("alienxfile_dark");
    if (saved === "true") document.body.classList.add("dark");
    else if (saved === null && window.matchMedia("(prefers-color-scheme: dark)").matches) document.body.classList.add("dark");
    toggle.textContent = document.body.classList.contains("dark") ? "\u2600" : "\u263E";

    toggle.addEventListener("click", () => {
        document.body.classList.toggle("dark");
        const isDark = document.body.classList.contains("dark");
        toggle.textContent = isDark ? "\u2600" : "\u263E";
        try { localStorage.setItem("alienxfile_dark", String(isDark)); } catch {}
    });
})();

// ══════════════════════════════════════════════════════════════════════════════
// FEATURE 9: Expiry selector presets
// ══════════════════════════════════════════════════════════════════════════════
(function initExpiryPresets() {
    const btns = document.querySelectorAll(".preset-btn");
    if (!btns.length) return;
    for (const btn of btns) {
        btn.addEventListener("click", () => {
            expireSelect.value = btn.dataset.expire;
            for (const b of btns) {
                b.classList.toggle("active", b === btn);
                b.setAttribute("aria-checked", String(b === btn));
            }
        });
    }
})();

// ══════════════════════════════════════════════════════════════════════════════
// FEATURE 12: Custom codes input (uses existing #customCode from HTML)
// ══════════════════════════════════════════════════════════════════════════════
const customKeyInput = document.getElementById("customCode");

// ══════════════════════════════════════════════════════════════════════════════
// FEATURE 6: Password-protected shares (uses existing #sharePassword from HTML)
// ══════════════════════════════════════════════════════════════════════════════
const passwordInput = document.getElementById("sharePassword");

const hasCrypto = typeof crypto !== "undefined" && crypto.subtle;

function bufToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = "";
    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
}

function base64ToBuf(b64) {
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
}

async function deriveKeyFromPassword(password, salt) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
        { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );
}

async function encryptContent(password, plaintext) {
    const enc = new TextEncoder();
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveKeyFromPassword(password, salt);
    const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(plaintext));
    return { salt: bufToBase64(salt), iv: bufToBase64(iv), data: bufToBase64(encrypted) };
}

async function decryptContent(password, saltB64, ivB64, dataB64) {
    const key = await deriveKeyFromPassword(password, base64ToBuf(saltB64));
    const dec = new TextDecoder();
    const decrypted = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: new Uint8Array(base64ToBuf(ivB64)) },
        key,
        base64ToBuf(dataB64)
    );
    return dec.decode(decrypted);
}

async function encryptFileContent(password, file) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveKeyFromPassword(password, salt);
    const arrayBuf = await file.arrayBuffer();
    const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, arrayBuf);
    const encryptedBlob = new Blob([encrypted], { type: "application/octet-stream" });
    return { encryptedBlob, salt: bufToBase64(salt), iv: bufToBase64(iv) };
}

// ══════════════════════════════════════════════════════════════════════════════
// FEATURE 1: Paste image from clipboard
// ══════════════════════════════════════════════════════════════════════════════
document.addEventListener("paste", (e) => {
    if (busy) return;
    if (form.elements.mode.value !== "file" || fileInput.disabled) return;
    const items = e.clipboardData?.items;
    if (!items) return;
    const imageFiles = [];
    for (const item of items) {
        if (item.type.startsWith("image/")) {
            const file = item.getAsFile();
            if (file) imageFiles.push(file);
        }
    }
    if (!imageFiles.length) return;
    e.preventDefault();
    const dt = new DataTransfer();
    for (const f of imageFiles) dt.items.add(f);
    const existing = Array.from(fileInput.files);
    for (const f of existing) dt.items.add(f);
    fileInput.files = dt.files;
    updateFiles();
    status.textContent = `Image pasted from clipboard.${imageFiles.length > 1 ? ` (${imageFiles.length} images)` : ""}`;
});

// ══════════════════════════════════════════════════════════════════════════════
// FEATURE 3: Drag & drop visual feedback
// ══════════════════════════════════════════════════════════════════════════════
let dragCounter = 0;

fileLabel.addEventListener("dragenter", (e) => {
    e.preventDefault();
    dragCounter++;
    if (busy || fileInput.disabled) return;
    const files = e.dataTransfer?.files;
    if (files && files.length) {
        const count = files.length;
        const size = Array.from(files).reduce((s, f) => s + f.size, 0);
        fileInputText.textContent = `Drop ${count} file${count !== 1 ? "s" : ""} (${formatSize(size)})`;
    }
    fileLabel.classList.add("dragover");
});

fileLabel.addEventListener("dragover", (e) => {
    e.preventDefault();
    if (!busy) fileLabel.classList.add("dragover");
});

fileLabel.addEventListener("dragleave", (e) => {
    e.preventDefault();
    dragCounter--;
    if (dragCounter <= 0) {
        dragCounter = 0;
        fileLabel.classList.remove("dragover");
        fileInputText.textContent = fileInput.files.length
            ? `${fileInput.files.length} file(s) selected. Choose again to replace.`
            : "Drop files here or click to browse";
    }
});

fileLabel.addEventListener("drop", (e) => {
    e.preventDefault();
    dragCounter = 0;
    fileLabel.classList.remove("dragover");
    fileInputText.textContent = "Drop files here or click to browse";
    if (busy || fileInput.disabled) return;
    fileInput.files = e.dataTransfer.files;
    updateFiles();
});

// ══════════════════════════════════════════════════════════════════════════════
// FEATURE 13: URL metadata fetch (uses existing #urlPreview from HTML)
// ══════════════════════════════════════════════════════════════════════════════
const urlPreviewEl = document.getElementById("urlPreview");
const urlPreviewTitle = document.getElementById("urlPreviewTitle");
const urlPreviewDesc = document.getElementById("urlPreviewDesc");

async function fetchUrlMeta(url) {
    if (!urlPreviewEl || !url.match(/^https?:\/\//i)) return;
    urlPreviewEl.hidden = true;
    if (!url.match(/^https?:\/\//i)) return;
    try {
        const resp = await fetch("/api/url-meta", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url }),
        });
        if (!resp.ok) return;
        const meta = await resp.json();
        if (!meta || (!meta.title && !meta.description)) return;
        if (urlPreviewTitle) urlPreviewTitle.textContent = meta.title || "";
        if (urlPreviewDesc) urlPreviewDesc.textContent = meta.description ? (meta.description.length > 200 ? meta.description.slice(0, 200) + "\u2026" : meta.description) : "";
        urlPreviewEl.hidden = false;
    } catch {}
}

// ══════════════════════════════════════════════════════════════════════════════
// FEATURE 8: Share via URL paste (detect in textarea)
// ══════════════════════════════════════════════════════════════════════════════
let urlDebounce = null;
textInput.addEventListener("input", () => {
    clearTimeout(urlDebounce);
    if (urlPreviewEl) urlPreviewEl.hidden = true;
    const val = textInput.value.trim();
    if (!val.match(/^https?:\/\//i)) return;
    urlDebounce = setTimeout(() => fetchUrlMeta(val), 600);
});

// ══════════════════════════════════════════════════════════════════════════════
// Core: Mode switching, file validation, file list update
// ══════════════════════════════════════════════════════════════════════════════
function switchMode() {
    const mode = form.elements.mode.value;
    const isFile = mode === "file" || mode === "folder";
    fileInputContainer.hidden = !isFile;
    textInputContainer.hidden = isFile;
    fileInput.disabled = !isFile;
    fileInput.required = isFile;
    textInput.disabled = isFile;
    textInput.required = !isFile;
    if (mode === "folder") {
        fileInput.setAttribute("webkitdirectory", "");
        fileInput.removeAttribute("directory");
        fileInputText.textContent = "Select a folder to upload";
    } else {
        fileInput.removeAttribute("webkitdirectory");
        fileInputText.textContent = "Drop files here or click to browse";
    }
}

function fileError(file, storageProvider) {
    if (storageProvider === "litterbox") {
        if (file.size > litterboxMaxBytes) return "This file exceeds the 1 GB per-file limit.";
    } else if (file.size > maxBytes) {
        return `This file exceeds the ${form.dataset.limitLabel} limit.`;
    }
    if (bannedExts.some(ext => file.name.toLowerCase().endsWith(ext))) return "This file extension is blocked.";
    return "";
}

function formatSize(bytes) {
    if (bytes < 1024) return bytes + " B";
    if (bytes < 1048576) return (bytes / 1024).toFixed(1) + " KB";
    return (bytes / 1048576).toFixed(1) + " MB";
}

function getStorageProvider(file) {
    if (file && file.size > maxBytes) return "litterbox";
    return "vercel";
}

function updateFiles() {
    const isFileMode = form.elements.mode.value === "file";
    let needsLitterbox = false;
    if (isFileMode && fileInput.files.length) {
        for (const file of fileInput.files) {
            if (file.size > maxBytes) { needsLitterbox = true; break; }
        }
    }
    storageProviderInput.value = needsLitterbox ? "litterbox" : "vercel";
    if (storageNote) storageNote.hidden = !needsLitterbox;
    document.getElementById("fileLimits").textContent = needsLitterbox
        ? `Large file detected. Using temporary third-party storage (~1 GB limit).`
        : `Up to ${form.dataset.limitLabel} per file.`;
    selectedFiles.replaceChildren();
    for (const file of fileInput.files) {
        const item = document.createElement("li");
        const sp = getStorageProvider(file);
        const error = fileError(file, sp);
        item.textContent = `${file.name} (${formatSize(file.size)})${error ? ` - ${error}` : ""}`;
        selectedFiles.append(item);
    }
    fileInputText.textContent = fileInput.files.length
        ? `${fileInput.files.length} file(s) selected. Choose again to replace.`
        : "Drop files here or click to browse";
}

form.querySelectorAll('input[name="mode"]').forEach(radio => radio.addEventListener("change", () => {
    switchMode();
    fileInput.value = "";
    updateFiles();
}));
form.addEventListener("reset", () => requestAnimationFrame(() => {
    switchMode();
    fileInput.value = "";
    updateFiles();
}));
fileInput.addEventListener("change", updateFiles);

// ══════════════════════════════════════════════════════════════════════════════
// FEATURE 10: File type icons in results
// ══════════════════════════════════════════════════════════════════════════════
const FILE_ICONS = {
    image: { exts: ["png","jpg","jpeg","gif","svg","webp","bmp","ico"], svg: '<svg viewBox="0 0 24 24" width="16" height="16"><path fill="currentColor" d="M21 19V5c0-1.1-.9-2-2-2H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2zM8.5 13.5l2.5 3.01L14.5 12l4.5 6H5l3.5-4.5z"/></svg>' },
    code:   { exts: ["js","py","html","css","json","ts","jsx","tsx","java","c","cpp","h","go","rs","rb","php","swift","kt","rs","sh","bash","yaml","yml","toml","xml"], svg: '<svg viewBox="0 0 24 24" width="16" height="16"><path fill="currentColor" d="M9.4 16.6L4.8 12l4.6-4.6L8 6l-6 6 6 6 1.4-1.4zm5.2 0l4.6-4.6-4.6-4.6L16 6l6 6-6 6-1.4-1.4z"/></svg>' },
    doc:    { exts: ["txt","md","pdf","doc","docx","rtf","odt","xls","xlsx","ppt","pptx","csv"], svg: '<svg viewBox="0 0 24 24" width="16" height="16"><path fill="currentColor" d="M14 2H6c-1.1 0-2 .9-2 2v16c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V8l-6-6zm-1 7V3.5L18.5 9H13zM6 20V4h5v7h7v9H6z"/></svg>' },
    archive:{ exts: ["zip","tar","gz","rar","7z","bz2","xz","tgz"], svg: '<svg viewBox="0 0 24 24" width="16" height="16"><path fill="currentColor" d="M20 6h-8l-2-2H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2zm-6 10h-2v-2h2v2zm0-4h-2V8h2v4z"/></svg>' },
    audio:  { exts: ["mp3","wav","ogg","flac","aac","m4a","wma"], svg: '<svg viewBox="0 0 24 24" width="16" height="16"><path fill="currentColor" d="M12 3v10.55c-.59-.34-1.27-.55-2-.55-2.21 0-4 1.79-4 4s1.79 4 4 4 4-1.79 4-4V7h4V3h-6z"/></svg>' },
    video:  { exts: ["mp4","webm","mkv","avi","mov","flv","wmv"], svg: '<svg viewBox="0 0 24 24" width="16" height="16"><path fill="currentColor" d="M17 10.5V7c0-.55-.45-1-1-1H4c-.55 0-1 .45-1 1v10c0 .55.45 1 1 1h12c.55 0 1-.45 1-1v-3.5l4 4v-11l-4 4z"/></svg>' },
};
const DEFAULT_ICON = '<svg viewBox="0 0 24 24" width="16" height="16"><path fill="currentColor" d="M14 2H6c-1.1 0-2 .9-2 2v16c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V8l-6-6zm-1 7V3.5L18.5 9H13zM6 20V4h5v7h7v9H6z"/></svg>';

function getFileIcon(filename) {
    const ext = filename.split(".").pop()?.toLowerCase() || "";
    for (const [, cfg] of Object.entries(FILE_ICONS)) {
        if (cfg.exts.includes(ext)) return cfg.svg;
    }
    return DEFAULT_ICON;
}

// ══════════════════════════════════════════════════════════════════════════════
// FEATURE 2: Upload history (localStorage)
// ══════════════════════════════════════════════════════════════════════════════
const HISTORY_KEY = "alienxfile_history";
const HISTORY_MAX = 20;

function getHistory() {
    try { return JSON.parse(localStorage.getItem(HISTORY_KEY)) || []; }
    catch { return []; }
}

function saveHistory(entry) {
    const history = getHistory();
    history.unshift(entry);
    if (history.length > HISTORY_MAX) history.length = HISTORY_MAX;
    try { localStorage.setItem(HISTORY_KEY, JSON.stringify(history)); } catch {}
}

function timeAgo(ts) {
    const diff = Date.now() - ts;
    const mins = Math.floor(diff / 60000);
    if (mins < 1) return "just now";
    if (mins < 60) return `${mins}m ago`;
    const hrs = Math.floor(mins / 60);
    if (hrs < 24) return `${hrs}h ago`;
    const days = Math.floor(hrs / 24);
    return `${days}d ago`;
}

function renderHistory() {
    const section = document.getElementById("uploadHistory");
    const list = document.getElementById("historyList");
    const clearBtn = document.getElementById("historyClear");
    if (!section || !list) return;
    const history = getHistory();
    list.replaceChildren();
    if (!history.length) {
        section.hidden = true;
        return;
    }
    section.hidden = false;
    for (const entry of history.slice(0, 10)) {
        const li = document.createElement("li");
        li.className = "history-item";
        const nameSpan = document.createElement("span");
        nameSpan.className = "history-name";
        nameSpan.textContent = entry.name;
        const codeBtn = document.createElement("button");
        codeBtn.type = "button";
        codeBtn.className = "copy-btn history-key";
        codeBtn.textContent = entry.key;
        codeBtn.title = "Click to copy code";
        codeBtn.addEventListener("click", async () => {
            try {
                await navigator.clipboard.writeText(entry.key);
                status.textContent = `Code ${entry.key} copied.`;
            } catch {
                status.textContent = "Clipboard unavailable.";
            }
        });
        const timeSpan = document.createElement("span");
        timeSpan.className = "history-time";
        timeSpan.textContent = timeAgo(entry.timestamp);
        li.append(nameSpan, codeBtn, timeSpan);
        list.append(li);
    }
    if (clearBtn) {
        clearBtn.hidden = false;
        clearBtn.onclick = () => {
            try { localStorage.removeItem(HISTORY_KEY); } catch {}
            section.hidden = true;
            status.textContent = "History cleared.";
        };
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// FEATURE 7: Bulk download
// ══════════════════════════════════════════════════════════════════════════════
function showBulkDownloadButton(keys) {
    if (keys.length < 2) return;
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "bulk-download-btn";
    btn.textContent = `Download All as ZIP (${keys.length} files)`;
    btn.addEventListener("click", async () => {
        btn.disabled = true;
        btn.textContent = "Preparing ZIP\u2026";
        try {
            const resp = await fetch("/bulk-download", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ keys }),
            });
            if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
            const blob = await resp.blob();
            const url = URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = `alienxfile-batch-${Date.now()}.zip`;
            a.click();
            setTimeout(() => URL.revokeObjectURL(url), 30000);
            btn.textContent = "ZIP Downloaded";
        } catch (err) {
            btn.textContent = "Download failed. Try again.";
            btn.disabled = false;
            status.textContent = `Bulk download failed: ${err.message}`;
        }
    });
    result.append(btn);
}

// ══════════════════════════════════════════════════════════════════════════════
// renderUpload — enhanced with file type icons (Feature 10)
// ══════════════════════════════════════════════════════════════════════════════
function renderUpload(upload, batch) {
    const pageURL = new URL(upload.page_url);
    const directURL = new URL(upload.link);
    const expires = new Date(upload.expires);
    if (![pageURL, directURL].every(url => ["https:", "http:"].includes(url.protocol)) ||
        !/^[A-Za-z0-9]{3,20}$/.test(upload.key) || !Number.isFinite(expires.getTime())) {
        throw new Error("The server returned invalid share details.");
    }
    const item = document.createElement("article");
    item.className = "upload-item";
    const name = document.createElement("b");
    name.className = "upload-item-name";
    if (upload.name) {
        const iconSpan = document.createElement("span");
        iconSpan.className = "file-type-icon";
        iconSpan.innerHTML = getFileIcon(upload.name);
        iconSpan.setAttribute("aria-hidden", "true");
        name.append(iconSpan, upload.name);
    } else {
        name.textContent = "Shared Text";
    }
    const codeLine = document.createElement("p");
    codeLine.className = "key-line";
    codeLine.textContent = `Code: ${upload.key}`;
    const links = document.createElement("div");
    links.className = "result-links";
    for (const [label, value] of [["Copy Code", String(upload.key)], ["Copy Link", pageURL.href]]) {
        const button = document.createElement("button");
        button.type = "button";
        button.className = "copy-btn";
        button.textContent = label;
        button.addEventListener("click", async () => {
            try {
                await navigator.clipboard.writeText(value);
                status.textContent = `${label === "Copy Code" ? "Code" : "Details link"} copied.`;
            } catch {
                status.textContent = "Clipboard unavailable. Select and copy the code or link below.";
                let fallback = item.querySelector(".copy-fallback");
                if (!fallback) {
                    fallback = document.createElement("input");
                    fallback.className = "copy-fallback";
                    fallback.readOnly = true;
                    fallback.setAttribute("aria-label", "Select and copy share value");
                    item.append(fallback);
                }
                fallback.value = value;
                fallback.focus();
                fallback.select();
            }
        });
        codeLine.append(button);
    }
    for (const [label, url] of [["Details Page", pageURL], ["Direct Link", directURL]]) {
        const link = document.createElement("a");
        link.textContent = label;
        link.href = url.href;
        link.target = "_blank";
        link.rel = "noopener noreferrer";
        links.append(link);
    }
    const qrDetails = document.createElement("details");
    qrDetails.className = "qr-details";
    const qrSummary = document.createElement("summary");
    qrSummary.textContent = "Show QR Code";
    const qrImg = document.createElement("img");
    qrImg.src = `/qr/${upload.key}`;
    qrImg.alt = `QR code for ${upload.key}`;
    qrImg.loading = "lazy";
    qrImg.width = 200;
    qrImg.height = 200;
    qrImg.className = "qr-inline";
    qrDetails.append(qrSummary, qrImg);
    links.append(qrDetails);
    const expiryLine = document.createElement("p");
    const time = document.createElement("time");
    time.dateTime = expires.toISOString();
    time.textContent = expires.toLocaleString(undefined, {
        year: "numeric", month: "long", day: "numeric", hour: "numeric",
        minute: "2-digit", second: "2-digit", timeZoneName: "short"
    });
    expiryLine.append("Expires (your local time): ", time);
    item.append(name, codeLine, expiryLine, links);
    batch.append(item);
}

// ══════════════════════════════════════════════════════════════════════════════
// FEATURE 5: Upload progress with ETA
// ══════════════════════════════════════════════════════════════════════════════
function formatETA(seconds) {
    if (seconds < 60) return `${Math.ceil(seconds)}s`;
    const m = Math.floor(seconds / 60);
    const s = Math.ceil(seconds % 60);
    return `${m}m ${s}s`;
}

// ══════════════════════════════════════════════════════════════════════════════
// uploadRequest with ETA tracking
// ══════════════════════════════════════════════════════════════════════════════
function uploadRequest(data, label, url, headers) {
    return new Promise((resolve, reject) => {
        const xhr = new XMLHttpRequest();
        activeRequest = xhr;
        xhr.open("POST", url || form.action);
        xhr.timeout = 30 * 60 * 1000;
        if (headers) for (const [k, v] of Object.entries(headers)) xhr.setRequestHeader(k, v);
        let uploadStart = performance.now();
        let lastLoaded = 0;
        let lastTime = uploadStart;
        let smoothedSpeed = 0;
        xhr.upload.onprogress = event => {
            if (!event.lengthComputable) {
                progress.removeAttribute("value");
                status.textContent = `${label}: uploading; percentage unavailable.`;
                return;
            }
            const now = performance.now();
            const elapsed = (now - uploadStart) / 1000;
            const percent = Math.floor(event.loaded / event.total * 100);
            progress.value = percent;

            let etaText = "";
            if (elapsed > 0.5) {
                const dt = (now - lastTime) / 1000;
                if (dt > 0.1) {
                    const instantSpeed = (event.loaded - lastLoaded) / dt;
                    smoothedSpeed = smoothedSpeed ? smoothedSpeed * 0.7 + instantSpeed * 0.3 : instantSpeed;
                    lastLoaded = event.loaded;
                    lastTime = now;
                }
                if (smoothedSpeed > 0) {
                    const remaining = (event.total - event.loaded) / smoothedSpeed;
                    etaText = ` | ETA: ${formatETA(remaining)}`;
                }
            }

            if (percent === 100) {
                status.textContent = `${label}: 100% uploaded. Waiting for storage provider / server confirmation.`;
            } else {
                const speedText = smoothedSpeed > 0 ? ` (${formatSize(Math.round(smoothedSpeed))}/s)` : "";
                status.textContent = `${label}: ${percent}% uploaded${speedText}${etaText}.`;
            }
        };
        xhr.upload.onload = () => {
            progress.value = 100;
            status.textContent = `${label}: 100% uploaded. Waiting for storage provider / server confirmation.`;
        };
        xhr.onload = () => resolve(xhr);
        xhr.onerror = () => reject(new Error("Network error. Check your connection. The server may already have stored this item; verify before retrying."));
        xhr.ontimeout = () => reject(new Error("Upload timed out. The server may still finish; verify before retrying."));
        xhr.onabort = () => reject(new Error("Cancelled. The server might already finish storing this item; cancellation does not delete it."));
        xhr.send(data);
    });
}

// ══════════════════════════════════════════════════════════════════════════════
// Cancel button
// ══════════════════════════════════════════════════════════════════════════════
cancel.addEventListener("click", () => {
    cancelled = true;
    cancel.disabled = true;
    activeRequest?.abort();
});

// ══════════════════════════════════════════════════════════════════════════════
// Form submission handler
// ══════════════════════════════════════════════════════════════════════════════
form.addEventListener("submit", async event => {
    event.preventDefault();
    if (busy || !form.reportValidity()) return;
    const mode = form.elements.mode.value;
    const serverMode = mode === "folder" ? "file" : mode;
    const expire = form.elements.expire.value;
    const storageProvider = form.elements.storageProvider.value;
    const text = textInput.value;
    const password = passwordInput.value;
    const customKey = customKeyInput.value.trim();

    if (mode === "text" && (!text.trim() || Array.from(text).length > maxTextLength)) {
        status.textContent = `Enter non-blank text of at most ${maxTextLength.toLocaleString()} characters.`;
        textInput.focus();
        return;
    }
    if (customKey && !/^[A-Za-z0-9]{3,20}$/.test(customKey)) {
        status.textContent = "Custom code must be 3-20 letters or numbers.";
        customKeyInput.focus();
        return;
    }
    if (password && !hasCrypto) {
        status.textContent = "Password encryption requires a secure context (HTTPS). Your browser does not support it here.";
        return;
    }

    const queue = (mode === "file" || mode === "folder") ? Array.from(fileInput.files) : [null];
    busy = true;
    cancelled = false;
    controls.disabled = true;
    cancel.disabled = false;
    cancel.hidden = false;
    cancelNotice.hidden = false;
    progress.hidden = false;
    result.hidden = false;
    const batch = document.createElement("section");
    const summary = document.createElement("h3");
    summary.textContent = "Uploading...";
    batch.append(summary);
    result.append(batch);
    let completed = 0;
    let failures = 0;
    const allKeys = [];
    const addError = message => {
        const item = document.createElement("p");
        item.className = "upload-item error-item";
        item.textContent = message;
        batch.append(item);
        failures++;
    };
    try {
        if (mode === "folder" && queue.length > 0) {
            const data = new FormData();
            data.append("expire", expire);
            if (customKey) data.append("customKey", customKey);
            for (const file of queue) data.append("file", file, file.name);
            progress.value = 0;
            status.textContent = `Uploading ${queue.length} files as folder...`;
            let xhr;
            for (let attempt = 0; attempt < 3; attempt++) {
                xhr = await uploadRequest(data, "folder upload", "/upload-folder");
                if (xhr.status !== 429) break;
                const retryAfter = parseInt(xhr.getResponseHeader("Retry-After") || "30", 10);
                status.textContent = `Folder upload rate limited. Retrying in ${retryAfter}s...`;
                await new Promise(r => setTimeout(r, retryAfter * 1000));
            }
            let response;
            try {
                response = JSON.parse(xhr.responseText);
            } catch {
                throw new Error("Server returned an unreadable response.");
            }
            if (!response || typeof response !== "object") throw new Error("Invalid server response.");
            const uploads = Array.isArray(response.uploads) ? response.uploads : [];
            const errors = Array.isArray(response.errors) ? response.errors.filter(e => typeof e === "string") : [];
            if (typeof response.error === "string" && response.error) errors.push(response.error);
            for (const upload of uploads) {
                if (upload) {
                    renderUpload(upload, batch);
                    allKeys.push(upload.key);
                    completed++;
                    saveHistory({ key: upload.key, name: upload.name || "Folder", expires: upload.expires, timestamp: Date.now() });
                }
            }
            for (const error of errors) addError(error);
            if ((xhr.status < 200 || xhr.status >= 300) && !errors.length) addError("Folder upload failed.");
        } else {
        for (const [index, file] of queue.entries()) {
            const name = file ? file.name : "Shared Text";
            if (cancelled) {
                addError(`${name}: Not started because the queue was cancelled.`);
                continue;
            }
            const validationError = file && fileError(file, storageProvider);
            if (validationError) {
                addError(`${name}: ${validationError}`);
                continue;
            }
            const label = `${index + 1}/${queue.length} - ${name}`;
            progress.value = 0;
            status.textContent = `${label}: 0% uploaded.`;
            try {
                if (mode === "text" || storageProvider === "vercel") {
                    const data = new FormData();
                    data.append("mode", serverMode);
                    data.append("expire", expire);
                    if (mode === "file" || mode === "folder") data.append("storageProvider", storageProvider);
                    if (customKey) data.append("customKey", customKey);

                    if (mode === "text") {
                        if (password && hasCrypto) {
                            const enc = await encryptContent(password, text);
                            data.append("text", enc.data);
                            data.append("salt", enc.salt);
                            data.append("iv", enc.iv);
                            data.append("isEncrypted", "1");
                        } else {
                            data.append("text", text);
                        }
                    } else {
                        if (password && hasCrypto) {
                            const { encryptedBlob, salt, iv } = await encryptFileContent(password, file);
                            data.append("file", encryptedBlob, file.name);
                            data.append("salt", salt);
                            data.append("iv", iv);
                            data.append("isEncrypted", "1");
                        } else {
                            data.append("file", file);
                        }
                    }

                    let xhr;
                    for (let attempt = 0; attempt < 3; attempt++) {
                        xhr = await uploadRequest(data, label);
                        if (xhr.status !== 429) break;
                        const retryAfter = parseInt(xhr.getResponseHeader("Retry-After") || "30", 10);
                        status.textContent = `${label}: rate limited. Retrying in ${retryAfter}s...`;
                        await new Promise(r => setTimeout(r, retryAfter * 1000));
                    }
                    const httpError = xhr.status === 413
                        ? "Upload too large for this deployment or host (413). Try a smaller file; hosting may cap uploads below the displayed limit."
                        : xhr.status === 429
                            ? "Too many requests (429). Wait before trying again."
                            : `Upload failed (HTTP ${xhr.status}). The server or host could not complete the request.`;
                    let response;
                    try {
                        response = JSON.parse(xhr.responseText);
                    } catch {
                        throw new Error(xhr.status >= 200 && xhr.status < 300
                            ? "The server returned an unreadable response. This item may have been stored; verify before retrying."
                            : httpError);
                    }
                    if (!response || typeof response !== "object") throw new Error("Invalid server response. Verify before retrying.");
                    const uploads = Array.isArray(response.uploads) ? response.uploads : [];
                    const errors = Array.isArray(response.errors) ? response.errors.filter(error => typeof error === "string") : [];
                    if (typeof response.error === "string" && response.error) errors.push(`${name}: ${response.error}`);
                    for (const upload of uploads) {
                        try {
                            renderUpload(upload, batch);
                            allKeys.push(upload.key);
                            completed++;
                            saveHistory({ key: upload.key, name: upload.name || "Shared Text", expires: upload.expires, timestamp: Date.now() });
                        } catch {
                            addError(`${name}: Invalid share details returned. The item may have been stored; verify before retrying.`);
                        }
                    }
                    for (const error of errors) addError(error);
                    if ((xhr.status < 200 || xhr.status >= 300) && !errors.length) addError(`${name}: ${httpError}`);
                    else if (!uploads.length && !errors.length) addError(`${name}: No completed upload was returned.`);
                    else if (response.success !== true && !errors.length) addError(`${name}: The server reported a failure; any completed uploads are shown above.`);
                } else {
                    let fileToUpload = file;
                    let litterboxSalt = "";
                    let litterboxIv = "";
                    let litterboxEncrypted = false;
                    if (password && hasCrypto) {
                        const { encryptedBlob, salt, iv } = await encryptFileContent(password, file);
                        fileToUpload = new File([encryptedBlob], file.name, { type: "application/octet-stream" });
                        litterboxSalt = salt;
                        litterboxIv = iv;
                        litterboxEncrypted = true;
                    }
                    const paData = new FormData();
                    paData.append("time", expire);
                    paData.append("fileToUpload", fileToUpload);
                    status.textContent = `${label}: uploading directly to storage...`;
                    const paXhr = await uploadRequest(paData, label, LITTERBOX_PROXY_URL + "/upload");
                    let paResponse;
                    try {
                        paResponse = JSON.parse(paXhr.responseText);
                    } catch {
                        throw new Error("Storage proxy returned an unreadable response. Verify before retrying.");
                    }
                    if (!paResponse || paResponse.error) {
                        throw new Error(paResponse?.error || "Storage proxy rejected the upload.");
                    }
                    const litterboxUrl = paResponse.url;
                    if (!litterboxUrl || !litterboxUrl.startsWith("https://litter.catbox.moe/")) {
                        throw new Error("Storage proxy returned an invalid URL.");
                    }
                    status.textContent = `${label}: file uploaded to storage. Saving share record...`;
                    const savePayload = { url: litterboxUrl, name: file.name, size: file.size, expire, ...(customKey ? { customKey } : {}) };
                    if (litterboxEncrypted) {
                        savePayload.salt = litterboxSalt;
                        savePayload.iv = litterboxIv;
                        savePayload.isEncrypted = true;
                    }
                    const saveData = JSON.stringify(savePayload);
                    const saveXhr = await uploadRequest(saveData, label, "/upload-litterbox", {"Content-Type": "application/json"});
                    let saveResponse;
                    try {
                        saveResponse = JSON.parse(saveXhr.responseText);
                    } catch {
                        throw new Error("Server returned an unreadable response after storage upload. Verify before retrying.");
                    }
                    if (!saveResponse || typeof saveResponse !== "object") throw new Error("Invalid server response. Verify before retrying.");
                    const uploads = Array.isArray(saveResponse.uploads) ? saveResponse.uploads : [];
                    const errors = Array.isArray(saveResponse.errors) ? saveResponse.errors.filter(e => typeof e === "string") : [];
                    if (typeof saveResponse.error === "string" && saveResponse.error) errors.push(`${name}: ${saveResponse.error}`);
                    for (const upload of uploads) {
                        try {
                            renderUpload(upload, batch);
                            allKeys.push(upload.key);
                            completed++;
                            saveHistory({ key: upload.key, name: upload.name || "Shared Text", expires: upload.expires, timestamp: Date.now() });
                        } catch {
                            addError(`${name}: Invalid share details returned. The item may have been stored; verify before retrying.`);
                        }
                    }
                    for (const error of errors) addError(error);
                    if ((saveXhr.status < 200 || saveXhr.status >= 300) && !errors.length) addError(`${name}: Save failed (HTTP ${saveXhr.status}). The file was uploaded to storage but the share record may not have been saved.`);
                    else if (!uploads.length && !errors.length) addError(`${name}: No completed upload was returned.`);
                    else if (saveResponse.success !== true && !errors.length) addError(`${name}: The server reported a failure; any completed uploads are shown above.`);
                }
            } catch (error) {
                addError(`${name}: ${error.message}`);
            } finally {
                activeRequest = null;
            }
        }
        }
    } finally {
        summary.textContent = `${completed} uploaded; ${failures} error(s).${cancelled ? " Queue cancelled. The server might already finish the active item." : ""}`;
        batch.className = completed ? (failures ? "warning" : "success") : "error";
        status.textContent = summary.textContent;
        busy = false;
        controls.disabled = false;
        switchMode();
        progress.hidden = true;
        cancel.hidden = true;
        cancelNotice.hidden = !cancelled;
        if (cancelled) form.querySelector('button[type="submit"]').focus();
        renderHistory();
        showBulkDownloadButton(allKeys);
    }
});

// ══════════════════════════════════════════════════════════════════════════════
// Init
// ══════════════════════════════════════════════════════════════════════════════
switchMode();
updateFiles();
renderHistory();
controls.disabled = false;
