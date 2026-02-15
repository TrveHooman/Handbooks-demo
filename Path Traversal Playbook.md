#path-traversal #methodology #playbook 
#  Path Traversal Bug Bounty Playbook

Follow the **General Methodology**: Thoroughly browse/audit everything (automated + manual). Make a categorized list of parameters/endpoints (e.g., file refs), grade by interest (high if error leaks paths). Note why interesting (e.g., leads to cred exfil), what it could link to (e.g., chain to RCE via config read). Prioritize high-grade. Use checklists/payloads. Don't get stuck—note, break, return. Update this playbook after findings; link overlapping methodologies (e.g., Path Traversal + XSS for file injection, + Access Control for user-boundary bypass).

---
## **1. 🔍 Recon**

Thoroughly browse and audit **everything**: Every endpoint, parameter, variable (automated + manual while automated runs). Make a list (spreadsheet/Obsidian), categorize (e.g., file params, error responses), grade interest (high: file/image params; medium: downloads; low: static assets). Note why interesting (e.g., "Reveals FS structure"), what it could lead/link to (e.g., "Chain to cred exfil via /etc/passwd").

### **1.1. Inventory File-Referencing Vectors**
- [ ] Parameters: file, path, image, name, download, url, src.
- [ ] Forms/Endpoints: Uploads, downloads, includes (e.g., ?include=file.php).
- [ ] Headers/Cookies: Potentially file-related (e.g., custom paths).
- [ ] API Calls: File ops, storage refs (e.g., S3 keys).

### **1.2. Understand Application Behavior**
- [ ] Allowed Extensions: Check restrictions (e.g., .jpg only).
- [ ] Directory Prefixes: Note base paths (e.g., /var/www/images/).
- [ ] Error Messages: Probe for leaks (e.g., full paths in failures).
- [ ] Frameworks: Note path handling (e.g., weak normalization in PHP).
- [ ] Logs/Responses: Watch for reflected traversal strings.

> [!TIP] **Pro Tip: Error Hunting**  
> Force errors (e.g., invalid file) to reveal FS structure; use two tabs to compare valid/invalid responses.

Update list: Grade high if params reflect paths or errors leak structure.

---

## **2. ⚔️ Testing**

Prioritize **high-grade items** (e.g., file params first). Test reads/writes via GET/POST. Use context-specific payload sets with bypasses (encoding, double-encoding, recursive, null bytes, absolute paths, PIP). Tools: Burp Repeater/Intruder for fuzzing.

Don't get stuck: Note filters (e.g., ../ stripped), take break, return. Update playbook after findings (e.g., add new encoding bypass).

### **A. Basic Traversal** 🚀
Test simple directory climbing.

- **Detect**: Submit traversal sequences; check for unexpected file access.
- **Analyze**: Watch responses for file contents or errors.
- **Test**: Via GET/POST; target known files (e.g., /etc/passwd).
- **Payloads**: `../../../../etc/passwd`, `..\..\..\..\windows\win.ini`.

**Chain**: With Access Control (e.g., traverse beyond user dirs).

### **B. Bypass Techniques if Blocked** 🛡️
Handle filtering/normalization.

- **Detect**: Basic fails but variants work.
- **Analyze**: Test recursively; note stripped sequences.
- **Test**: Escalate from simple to advanced.
- **Bypasses**:
  - **Absolute Path**: `/etc/passwd`. Lab: Bypasses relative blocks.
  - **PIP (Payload in Payload)**: `....//....//etc/passwd`. Lab: Non-recursive strip.
  - **Encoding**: `..%2f..%2fetc/passwd`, `%2e%2e%2f`, `%2e%2e/`, UTF-8 overlong. Lab: Double/triple (%252f).
  - **Start-of-Path Validation**: `/var/www/images/../../../../etc/passwd`. Lab: Prefix check bypass.
  - **Null Byte (Extension Validation)**: `../../../../etc/passwd%00.jpg`. Lab: Truncates extension.
- **Conditions**: Test methods, encodings, browsers.

Update: After finding, note bypass; add to payload sets.

### **C. Post-Exploitation Targets** 💾
Once traversal confirmed, exfil/exploit.

- **Detect**: Access succeeds; enumerate files.
- **Analyze**: Prioritize sensitive paths.
- **Test**: Pull files; watch for listings.
- **Targets**:
  - System: /etc/passwd, /proc/self/environ.
  - App: Configs (app.conf, web.xml), logs (access.log).
  - Code: Source (index.php), .env, .git (for repo dump).
  - Creds: Credentials, private keys, Docker env.

**Chain**: With XSS (e.g., read/inject JS files).

### **D. Analysis & Verification** 📊
- **Inspect**: File contents in response? Error diffs?
- **Sanitization**: ../ stripped? Encoding decoded?
- **Behavior**: GET vs. POST; caching affects?

> [!WARNING] **Key Reminder**  
> Normalization varies by OS/language; test exhaustively.
