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
| `mcp.py` | MCP blueprint — stateless JSON-RPC 2.0 at `POST /mcp` (5 tools, Phase 1 auth, daily byte budgets) |
| `test_mcp.py` | 53 MCP tests, all passing |
| `test_pages.py` | 7 tests for /privacy /terms /support + challenge route, all passing |
| `render.yaml` | Render Blueprint config |
| `pa_proxy/app.py` | Fly.io proxy app |
| `pa_proxy/fly.toml` | Fly.io config |
| `README.md` | Documentation |

## Features Implemented (39 → 112 tests)

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

### MCP Integration (NEW)
37. **`POST /mcp`** — stateless JSON-RPC 2.0 MCP server (blueprint `mcp.py`, registered last in `flask_app.py` to resolve the circular import); 404 unless `ALIENX_MCP_ENABLED=1`
38. **5 tools**: `upload_file`, `share_text`, `get_shared_content`, `get_shared_file`, `check_share` — writes reuse the existing `/upload` view via a nested `request_context` (no `before_request` hooks → no double rate limiting); reads use `share_details()`/`get_db()`/`preview_file()`
39. **Phase 1 auth**: optional `MCP_API_KEY` bearer via `check_mcp_auth()` + `hmac.compare_digest` (OAuth 2.1 = Phase 2, same function); `securitySchemes` flips bearerAuth/noauth in `tools/list`
40. **Rate buckets**: `mcp` (default 60) vs `mcp_lookup` (default 20) per `MCP_RATE_WINDOW` (600s), separate from website buckets; per-action window pruning; 429 → JSON-RPC `-32005` + `Retry-After`
41. **Protocol errors**: `-32700` 400 parse, `-32600` 400/413/415/403/405, `-32601` 200 unknown method, `-32602` 200 invalid params, `-32001` 401 auth, `-32005` 429; tool failures are `isError: true` results
42. **Expiry validation**: `1h|12h|24h|72h|168h` + aliases (`1 hour`, `1d`, `1 day`, `tomorrow`, `3d`, `3 days`, `7d`, `1 week`), default 24h, unknown values rejected with help text
43. **Privacy**: encrypted shares return metadata + `is_encrypted` + website instructions only (never ciphertext/salt/IV, no password params); uniform `Share not found or expired.` for missing vs expired; no delete/list/enumerate tools; storage URLs and DB details never returned (`ALIENX_PUBLIC_BASE_URL` builds `/share/` + `/download/` links)
44. **Upload limits**: base64-only, `MCP_MAX_UPLOAD_BYTES` (5 MiB default) decoded cap with website fallback message; request body capped (413); banned extensions and `..` traversal rejected; directory components stripped

### Directory Prep (NEW)
45. **Daily byte budgets**: MCP writes consume `rate_limits` rows with action `mcp_bytes` (per-IP row + global row ip `'*'`, bytes in `hits`); `_ensure_daily_capacity()` fails fast before ChatGPT file downloads, `_reserve_daily_bytes()` rolls back over-cap adds (share_text UTF-8 + base64 decoded), `_charge_daily_bytes()` commits downloaded bytes then reports over-cap; reads are never metered; global rate-limit prune skips `mcp_bytes` (`action <> 'mcp_bytes'`); exact error `MCP daily capacity reached; please use the website …`
46. **Trust pages**: `/privacy`, `/terms`, `/support` (new templates, `.card` style, dark-mode script, indexable + canonical, sitemap untouched) — fact-checked content only; support contact shown only when `ALIENX_SUPPORT_EMAIL` is set and valid
47. **Challenge route**: `GET /.well-known/openai-apps-challenge` returns `OPENAI_APPS_CHALLENGE_TOKEN` as exact `text/plain`, 404 with empty body while unset; stays noindex
48. **`client_address()`** extracted from `limit_requests` so MCP byte accounting reuses the exact trusted-proxy IP logic

### Preview Security — `fix/preview-security` (F0)
49. **Encrypted preview gate**: `/api/preview/<key>` returns 400 `Encrypted shares preview after unlocking.` for `is_encrypted` rows before any storage fetch, so ciphertext is never proxied
50. **Decrypt path is DOM-only**: password unlock builds headings, decrypted text and the download link with `createElement` + `textContent`/`.download` (no `innerHTML`), so a filename or decrypted payload is never parsed as HTML
51. **Markdown link allowlist**: `renderMarkdown()` anchors only `http`, `https`, `mailto` and scheme-less links — the scheme is read from a whitespace-stripped copy so `java\tscript:` cannot slip through; any other scheme stays plain text; links keep `target="_blank"` and now carry `rel="noopener noreferrer"`
52. **One preview source of truth**: `_preview_category()` is exposed to templates as `preview_category` through `template_settings()`; the page no longer keeps its own extension list, and dotfiles (`.env`, `.gitignore`, `.dockerfile`, `.makefile`) plus bare `dockerfile`/`makefile` (`PREVIEW_FILENAMES`) match for both the page and the API
53. **Litterbox preview fetch**: `/api/preview` GETs Litterbox with `LITTERBOX_REQUEST_UA = 'curl/8.5.0'` (BunkerWeb rejects the default python-requests agent)

## All Validation Patterns
- **Custom codes**: `[A-Za-z0-9]{3,20}` (backend + frontend + download page input)
- **Auto-generated keys**: `f'{secrets.randbelow(100_000):05d}'` (5-digit numeric)
- **Download key input**: `pattern="[A-Za-z0-9]{3,20}" maxlength="20" inputmode="text"`
- **File size limit**: 1GB default (`1_000_000_000` bytes)
- **Preview categories**: single source `_preview_category()` (`PREVIEW_EXTENSIONS` suffixes + `PREVIEW_FILENAMES`), passed to templates as `preview_category`

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
- 112 tests passing (105 run + 7 skipped): `python3 -m unittest discover -v` → `test_download.py` (45) + `test_mcp.py` (53) + `test_pages.py` (7) + `test_postgres.py` (7, skips without `ALIENX_TEST_DATABASE_URL`)
- Website tests cover: upload, download, text, file, folder, encryption, rate limiting, CSP headers, QR codes, preview endpoint, custom codes, dark mode, template escaping, encrypted-preview 400, Litterbox preview User-Agent, preview-category page parity, decrypt DOM contract, markdown link allowlist (executes `renderMarkdown` in `node`)
- MCP tests cover: handshake, tools/list schema, all 5 tools, expiry aliases, auth (missing/wrong/right key), disabled 404, rate buckets, daily byte budgets (per-IP + global, fail-closed DB path, window reset), JSON-RPC error matrix, 413/415/403/405, DB-failure JSON shape, encrypted-share no-ciphertext, no-secrets sweep
- Pages tests cover: DB-free rendering, indexable headers/canonicals, fact-checked privacy/terms content, support email gating, challenge token exact-by-body/plain-text behavior, discovery untouched

## MCP Environment Variables (Step 7 — deploy when enabling)
- `ALIENX_MCP_ENABLED` (default `"0"` — off; set `1` in Render dashboard to enable)
- `MCP_API_KEY` (sync: false — set a long random value; empty = anonymous dev mode)
- `ALIENX_PUBLIC_BASE_URL` (default `https://alienxfilev2.onrender.com`)
- `MCP_MAX_UPLOAD_BYTES` (5242880 = 5 MiB), `MCP_RATE_LIMIT` (60), `MCP_LOOKUP_RATE_LIMIT` (20), `MCP_RATE_WINDOW` (600), `MCP_ALLOWED_ORIGINS` (chatgpt.com + chat.openai.com)
- `MCP_DAILY_BYTES_PER_IP` (52428800 = 50 MiB), `MCP_GLOBAL_DAILY_BYTES` (314572800 = 300 MiB), `MCP_DAILY_BYTES_WINDOW` (86400, min 60) — daily byte budgets in `rate_limits` action `mcp_bytes`
- `ALIENX_SUPPORT_EMAIL` (empty = hide contact on /support; invalid values rejected at startup-ish via warning), `OPENAI_APPS_CHALLENGE_TOKEN` (empty = challenge route 404)
- `render.yaml` already lists `ALIENX_MCP_ENABLED=0`, `MCP_API_KEY` (sync: false), `ALIENX_PUBLIC_BASE_URL`

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
