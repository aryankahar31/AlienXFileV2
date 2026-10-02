# AlienXFile V2 — Agent Progress Log

## Project Overview
Temporary file and text sharing platform with dual storage (Vercel Blob default + Litterbox for large files) on Render Free, with a Fly.io proxy to bypass Litterbox's IP-based blocking from Render.

## Infrastructure
- **Hosting**: Render Free (service `srv-d42hq3er433s73dm11d0`, workspace `tea-d3g06mjipnbc73bj61gg`, GitHub repo `aryankahar31/AlienXFileV2`)
- **Database**: Neon Free PostgreSQL (pooled URL in `DATABASE_URL`), SQLite for local dev
- **Storage**: Private Vercel Blob store `store_z4apuzG0d2WLuLHX` (Hobby/free, Singapore); Litterbox for large files
- **Litterbox API**: `POST https://litterbox.catbox.moe/resources/internals/api.php` (`reqtype=fileupload`, `time=1h|12h|24h|72h`)
- **Render → Litterbox 412 fix**: Set `User-Agent: curl/8.5.0` (BunkerWeb blocks python-requests UA)
- **Fly.io proxy**: `https://alienxfile-proxy.fly.dev` — app `alienxfile-proxy`, region `sjc`, 1GB RAM shared VM, 1 gunicorn worker, 600s timeout, `max-requests 50`, `MAX_CONTENT_LENGTH=1GB`
- **Proxy secret**: `gYDer61eCkvjXS153-ZHgj0m77ykWDmcmAIYoiz2oKo`
- **CSP**: `connect-src 'self' https://alienxfile-proxy.fly.dev`; `style-src` includes `https://fonts.googleapis.com`; `font-src https://fonts.gstatic.com`; `media-src 'self'`; `object-src 'self'`
- **Upload limits**: Default 1GB (`MAX_FILE_BYTES = 1_000_000_000`); Litterbox ~1GB; `MAX_ZIP_TOTAL_BYTES = 500_000_000`
- **Architecture**: Browser → Fly.io `/upload` → Litterbox → URL → Render `/upload-litterbox` → DB save → 5-digit code

## DB Schema
- `shares` table: `key, type, name, content, url, size, expires, provider, salt, iv, is_encrypted`
- `rate_limits` table: per-IP rate limiting
- Rate limits: `UPLOAD_RATE_LIMIT=30`, `LOOKUP_RATE_LIMIT=30` per 600s window

## Key Files
| File | Purpose |
|------|---------|
| `flask_app.py` | Backend — all endpoints, SSRF fix, rate limiting, ZIP size limits, preview proxy |
| `static/upload.js` | Frontend JS — upload logic, drag/drop, dark mode, paste, custom codes |
| `static/style.css` | CSS — neo-brutalist design, dark mode, graph-paper grid |
| `templates/index.html` | Upload page — file/folder/text modes, advanced options |
| `templates/download.html` | Download page — preview system, lightbox, countdown, decryption |
| `test_download.py` | 40 tests, all passing |
| `render.yaml` | Render Blueprint config |
| `pa_proxy/app.py` | Fly.io proxy app |
| `pa_proxy/fly.toml` | Fly.io config |
| `README.md` | Documentation |

## Features Implemented (39 → 40 tests)

### Core Features
1. Paste text/files
2. Upload history
3. Drag & drop
4. Dark mode toggle
5. Expiry countdown timer
6. Password encryption (browser-side AES-GCM)
7. Bulk download (ZIP)
8. URL paste with metadata preview
9. Expiry presets (1h, 12h, 1d, 3d)
10. Upload ETA display
11. Markdown preview (toggle raw/rendered)
12. File type icons
13. Custom codes (3-20 alphanumeric: "aryan", "hello89", "abc123")

### Storage & Upload
14. Auto-storage detection (file size → Vercel or Litterbox)
15. Vercel→Litterbox auto-fallback (transparent, server-side)
16. Folder upload (single code for entire folder)
17. Clipboard image paste (Ctrl+V)
18. Rate limiting with auto-retry on 429

### Security
19. SSRF protection (`_is_private_host()` on `/api/url-meta`)
20. Rate limiting on all upload/download endpoints
21. ZIP OOM protection (`MAX_ZIP_TOTAL_BYTES = 500_000_000`)
22. Banned file extensions (.bat, .cmd, .exe, etc.)

### Preview System (NEW)
23. **Image preview** — inline `<img>` on download page
24. **Image lightbox** — click to open fullscreen with zoom:
    - Scroll wheel zoom (toward cursor)
    - +/- toolbar buttons
    - Double-click toggle (1x ↔ 2.5x)
    - Click & drag to pan
    - Pinch-to-zoom on mobile
    - Keyboard: +/- zoom, 0 reset, ESC close
    - Zoom level display
25. **Video preview** — inline `<video>` player with controls
26. **Audio preview** — styled card with `<audio>` player + music icon
27. **PDF preview** — embedded `<embed>` viewer
28. **Code/text preview** — fetched via `/api/preview/<key>`, dark syntax theme:
    - Font size controls (A-/A+, 8px–32px)
    - Copy button
    - Truncation notice for files >100KB
29. **Preview endpoint** (`/api/preview/<key>`) — proxies file content with correct MIME type
30. **Preview link** in upload results ("Preview" / "Details Page" / "Direct Link")

### UI/Design
31. Neo-brutalist design: graph-paper grid, yellow/cyan/pink, Space Grotesk + Caveat fonts
32. QR code inline toggle (server-generated SVG via `qrcode` lib)
33. Desktop layout widened to 780px
34. Download CTA improved, mobile responsive
35. Advanced options collapsed by default
36. Full dark mode on download page (inputs, buttons, nav, preview containers)

## All Validation Patterns
- **Custom codes**: `[A-Za-z0-9]{3,20}` (backend + frontend + download page input)
- **Auto-generated keys**: `f'{secrets.randbelow(100_000):05d}'` (5-digit numeric)
- **Download key input**: `pattern="[A-Za-z0-9]{3,20}" maxlength="20" inputmode="text"`
- **File size limit**: 1GB default (`1_000_000_000` bytes)
- **Preview extensions**: image, video, audio, pdf, code categories

## Bugs Fixed (Audit)
1. Three routes (`/bulk-download`, `/download-folder/`, `/download-folder-zip/`) used old `[0-9]{5}` validation — fixed to `[A-Za-z0-9]{3,20}`
2. Feature card "Five-Digit Codes" → "Short Codes"
3. Decrypted text "Copy All Text" button had no click handler — fixed with proper event listener + HTML escaping
4. Download page dark mode broken (inline styles hardcoded light mode) — added full dark mode overrides
5. Dead `#storageWarning` CSS selector → `#storageNote`
6. Dead `removeAttribute("directory")` no-op removed
7. Redundant URL regex check removed from `fetchUrlMeta`
8. Paste hint visible in folder mode where pasting is blocked — now hidden
9. All "five-digit" text references updated across templates and README
10. `renderUpload()` key validation: `^\d{5}$` → `^[A-Za-z0-9]{3,20}$`

## Testing
- 40 tests passing (`python3 test_download.py`)
- Tests cover: upload, download, text, file, folder, encryption, rate limiting, CSP headers, QR codes, preview endpoint, custom codes, dark mode, template escaping

## Git History (Recent)
- `ae7b340` — Add zoom lightbox for image previews + font-size controls for code previews
- `bf71b4d` — Add file preview system: image, video, audio, PDF, and code previews
- `83fe74b` — Fix audit: alphanumeric key validation, download dark mode, copy button, paste hint
- `2a8e8e5` — Fix alphanumeric custom codes: update key validation, input fields, error messages
- `e1fae92` — Allow alphanumeric custom codes (3-20 chars) and auto-fallback Vercel→Litterbox
- `edce65b` — Hardcoded "1 GB" text across templates
- `80a17a1` — Security audit fixes + 1GB limit

## Render Dashboard
- `ALIENX_UPLOAD_MAX_BYTES=95000000` still set — must be removed or changed to `1000000000` for 1GB to take effect in production

## Hosting Constraint
- Free hosting only (user requirement)
