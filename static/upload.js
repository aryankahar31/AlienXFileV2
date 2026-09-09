"use strict";

const form = document.getElementById("uploadForm");
const controls = document.getElementById("uploadControls");
const fileInput = document.getElementById("fileInput");
const textInput = document.getElementById("textInput");
const fileLabel = document.getElementById("fileInputLabel");
const status = document.getElementById("uploadStatus");
const progress = document.getElementById("uploadProgress");
const cancel = document.getElementById("cancelUpload");
const result = document.getElementById("result");
const bannedExts = JSON.parse(document.getElementById("bannedExtensions").textContent);
const maxBytes = Number(form.dataset.maxBytes);
const maxTextLength = Number(form.dataset.maxTextLength);
let busy = false;
let cancelled = false;
let activeRequest = null;

function switchMode() {
    const isFile = form.elements.mode.value === "file";
    document.getElementById("fileInputContainer").hidden = !isFile;
    document.getElementById("textInputContainer").hidden = isFile;
    fileInput.disabled = !isFile;
    fileInput.required = isFile;
    textInput.disabled = isFile;
    textInput.required = !isFile;
}

function fileError(file) {
    if (file.size > maxBytes) return `Exceeds the ${form.dataset.limitLabel} per-file limit.`;
    if (bannedExts.some(ext => file.name.toLowerCase().endsWith(ext))) return "This file extension is blocked.";
    return "";
}

function updateFiles() {
    const list = document.getElementById("selectedFiles");
    list.replaceChildren();
    for (const file of fileInput.files) {
        const item = document.createElement("li");
        const error = fileError(file);
        item.textContent = `${file.name} (${file.size.toLocaleString()} bytes)${error ? ` - ${error}` : ""}`;
        list.append(item);
    }
    document.getElementById("fileInputText").textContent = fileInput.files.length
        ? `${fileInput.files.length} file(s) selected. Choose again to replace.`
        : "Choose files or drag here";
}

form.querySelectorAll('input[name="mode"]').forEach(radio => radio.addEventListener("change", switchMode));
fileInput.addEventListener("change", updateFiles);
fileLabel.addEventListener("dragover", event => {
    event.preventDefault();
    if (!busy) fileLabel.classList.add("dragover");
});
fileLabel.addEventListener("dragleave", () => fileLabel.classList.remove("dragover"));
fileLabel.addEventListener("drop", event => {
    event.preventDefault();
    fileLabel.classList.remove("dragover");
    if (busy || fileInput.disabled) return;
    fileInput.files = event.dataTransfer.files;
    updateFiles();
});

function renderUpload(upload, batch) {
    // Never turn an API-supplied URL into an executable link.
    const pageURL = new URL(upload.page_url);
    const directURL = new URL(upload.link);
    const expires = new Date(upload.expires);
    if (![pageURL, directURL].every(url => ["https:", "http:"].includes(url.protocol)) ||
        !/^\d{5}$/.test(upload.key) || !Number.isFinite(expires.getTime())) {
        throw new Error("The server returned invalid share details.");
    }
    const item = document.createElement("article");
    item.className = "upload-item";
    const name = document.createElement("b");
    name.textContent = upload.name || "Shared Text";
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
    const qrLink = document.createElement("a");
    qrLink.textContent = "QR Code";
    qrLink.href = `/qr/${upload.key}`;
    qrLink.target = "_blank";
    qrLink.rel = "noopener noreferrer";
    links.append(qrLink);
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

function uploadRequest(data, label) {
    return new Promise((resolve, reject) => {
        const xhr = new XMLHttpRequest();
        activeRequest = xhr;
        xhr.open("POST", form.action);
        xhr.timeout = 30 * 60 * 1000;
        xhr.upload.onprogress = event => {
            if (!event.lengthComputable) {
                progress.removeAttribute("value");
                status.textContent = `${label}: uploading browser to app; percentage unavailable.`;
                return;
            }
            const percent = Math.floor(event.loaded / event.total * 100);
            progress.value = percent;
            status.textContent = percent === 100
                ? `${label}: 100% browser to app. Waiting for storage provider / server confirmation.`
                : `${label}: ${percent}% browser to app only.`;
        };
        xhr.upload.onload = () => {
            progress.value = 100;
            status.textContent = `${label}: 100% browser to app. Waiting for storage provider / server confirmation.`;
        };
        xhr.onload = () => resolve(xhr);
        xhr.onerror = () => reject(new Error("Network error. Check your connection. The server may already have stored this item; verify before retrying."));
        xhr.ontimeout = () => reject(new Error("Upload timed out. The server may still finish; verify before retrying."));
        xhr.onabort = () => reject(new Error("Cancelled. The server might already finish storing this item; cancellation does not delete it."));
        xhr.send(data);
    });
}

cancel.addEventListener("click", () => {
    cancelled = true;
    cancel.disabled = true;
    activeRequest?.abort();
});

form.addEventListener("submit", async event => {
    event.preventDefault();
    if (busy || !form.reportValidity()) return;
    const mode = form.elements.mode.value;
    const expire = form.elements.expire.value;
    const text = textInput.value;
    if (mode === "text" && (!text.trim() || Array.from(text).length > maxTextLength)) {
        status.textContent = `Enter non-blank text of at most ${maxTextLength.toLocaleString()} characters.`;
        textInput.focus();
        return;
    }
    const queue = mode === "file" ? Array.from(fileInput.files) : [null];
    busy = true;
    cancelled = false;
    controls.disabled = true;
    cancel.disabled = false;
    cancel.hidden = false;
    document.getElementById("cancelNotice").hidden = false;
    progress.hidden = false;
    result.hidden = false;
    const batch = document.createElement("section");
    const summary = document.createElement("h3");
    summary.textContent = "Uploading...";
    batch.append(summary);
    result.append(batch);
    let completed = 0;
    let failures = 0;
    const addError = message => {
        const item = document.createElement("p");
        item.className = "upload-item error-item";
        item.textContent = message;
        batch.append(item);
        failures++;
    };
    try {
        for (const [index, file] of queue.entries()) {
            const name = file ? file.name : "Shared Text";
            if (cancelled) {
                addError(`${name}: Not started because the queue was cancelled.`);
                continue;
            }
            const validationError = file && fileError(file);
            if (validationError) {
                addError(`${name}: ${validationError}`);
                continue;
            }
            const label = `${index + 1}/${queue.length} - ${name}`;
            const data = new FormData();
            data.append("mode", mode);
            data.append("expire", expire);
            data.append(mode === "file" ? "file" : "text", file || text);
            progress.value = 0;
            status.textContent = `${label}: 0% browser to app only.`;
            try {
                // One file per request keeps the batch total out of the request-size limit.
                const xhr = await uploadRequest(data, label);
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
                        completed++;
                    } catch {
                        addError(`${name}: Invalid share details returned. The item may have been stored; verify before retrying.`);
                    }
                }
                for (const error of errors) addError(error);
                if ((xhr.status < 200 || xhr.status >= 300) && !errors.length) addError(`${name}: ${httpError}`);
                else if (!uploads.length && !errors.length) addError(`${name}: No completed upload was returned.`);
                else if (response.success !== true && !errors.length) addError(`${name}: The server reported a failure; any completed uploads are shown above.`);
            } catch (error) {
                addError(`${name}: ${error.message}`);
            } finally {
                activeRequest = null;
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
        document.getElementById("cancelNotice").hidden = !cancelled;
        if (cancelled) form.querySelector('button[type="submit"]').focus();
    }
});

switchMode();
controls.disabled = false;
