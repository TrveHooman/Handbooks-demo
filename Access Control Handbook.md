#access-control #methodology #handbook
## 1. 🔍 Recon

Start simple: Use 2 accounts (e.g., your own and a throwaway) to map the app like a user. Focus on finding "objects" like user profiles or files that might be accessible by changing IDs— that's where IDOR (Insecure Direct Object Reference) hides.

#### High-level:
- **Manual Browsing First:** Click everything—log in/out, view profiles, edit stuff. Note URLs with numbers/IDs (e.g., /user/123).
- **Automated Help:** Use Burp/ZAP to crawl while you browse; spot endpoints with IDs/params.
- **List & Grade Easy Stuff:** High: Pages with IDs (profiles, invoices); Medium: Files/downloads; Low: Static pages.
- **Categorize Simply:** User vs. Admin areas; Objects like IDs/UUIDs.
- **JS/HTML Scan:** Open DevTools (F12), search for "admin" or IDs in JS files. Tools: LinkFinder for quick endpoint grabs.
- **Pipeline for Subs:** `subfinder -d target.com | httpx`—check subs like admin.target.com.
- **Frameworks Check:** Look for JWT in cookies (decode with jwt.io)—easy role hints.

### Low-Level (Step-by-Step for IDOR Setup):
- Find **IDs Everywhere:** URLs (/profile?id=123), JSON bodies ({"user_id":123}), headers/cookies.
- Leak Sources: Blogs/posts leak user IDs; JS vars hold GUIDs; redirects show paths.
- Role Mapping: Compare UIs with 2 accounts—what's hidden for normal users?
- Multi-Step Flows: Note resets/profiles—easy to break by swapping IDs.
- Errors/Redirects: Trigger errors to leak paths/IDs.
- Grade: "High if sequential IDs—easy swap for IDOR."
- Beginner Tip: Always assume IDs are guessable until proven otherwise. Collect 5-10 from your account.

---
## 2. ⚔️ Testing (Start with IDOR Swaps)

Prioritize IDOR—it's the easiest first vuln. Test with low-priv account. Use Burp Repeater: Copy request, change one thing, send. If it works, boom—vuln.

### High-level:
- Test High-Grade First: IDs in profiles/apis.
- Simple Flow: View your data → swap ID → see if you get others'.
- Covers: Reads (view) first, then writes (edit/delete).
- Blind? Check response diffs (length/status).
- Tools: Burp Intruder for fuzzing IDs (e.g., 100-200).
- Indicators: Sequential IDs work; direct URLs load hidden stuff.
- Chain Easy: IDOR leak email → try password reset.
- Fuzz for valid headers

### Low-level (Hands-On Steps):
#### 1. Horizontal IDOR (Beginner Gold: Cross-User Access):
- **Ops:** Start with views (/profile) -> then edits (POST /update?id=other) -> then API endpoints
- **Blind IDOR:** No data shown? Diff status (200 vs 404) or length.

##### Finding/Bypassing:
- **JSON/PUT/POST** -> try injecting a new param name `{"example":"example","id":"1"} //id is injected`
- **UUID**:
	- Try integers
	- Try email/username
	- Look for leaks:
		- Dork
		- Application recon (in sign-up/reset-password/unsubscribe email etc. endpoints that translate properties into UUIDs)
	- Random value? -> generate more to find out pattern
- Fuzz :
	- **Parameters**: 
		- `GET /api/v1/user_info -> GET /api/v1/user_info?FUZZ=FUZZ1`
	- **Endpoints**: 
		- `GET /api/user/me -> GET /api/FUZZ/FUZZ1` (non-exclusive ID)
		- `GET /api/v1/get_data/12 -> GET /api/v1/get_data/12?FUZZ=FUZZ1` (exclusive ID)
	- **API Versions**:
		- `POST /api/v1/get_data | id=123-> POST /api/FUZZ/get_data | id=123`
	- **API Paths**:
		- `POST /api/v1/get_data | id=123-> POST /api/v1-FUZZ/get_data | id=123`
- HTTP Verb Tampering (on non state-changing endpoint)
- Leverage Mass Assignment to discover IDOR in state-changing functionalities
- Try parameter pollution on 403
- Try adding extensions on 403
- Manipulate JSON packets (\*)
	- `POST /api/v1/get_data | {"id":111} -> POST /api/v1/get_data | {"id":[111]}`
	- `POST /api/v1/get_data | {"id":111} -> POST /api/v1/get_data | {"id":{"id":111}}`
- Path traversal bypass:
	- `GET /api/v1/get_data/10 -> GET /api/v1/get_data/10/../11`
	- `GET /api/v1/get_data/10 -> GET /api/v1/get_data/10%2f%2e%2e%2f11`

#### 2. Vertical Escalation (After IDOR Basics):
- **Detect:** Hidden /admin in JS/robots.txt; role in cookie (admin=false).
- **HTTP 403 Bypass:**
- HTTP Verb Tampering
- Path (smart) fuzzing
- Manual path fuzzing:
```
https://example.com/test.doc
https://example.com/test%2edoc

https://example.com/admin
https://example.com/./admin
https://example.com/%2e/admin
https://example.com/%252e/admin

https://example.com/%61dmin
https://example.com/%2561dmin

https://example.com/admin.json
```
- User-Agent fuzzing(rare)
- Auth cookies
- Header fuzzing:
```
X-Original-URL: /forbidden/path
X-Redirect-URL: /forbidden/path
X-Rewrite-URL: /forbidden/path

//headers
Forwarded
X-Forward-For
X-Forwarded-For
X-Forwarded-Host
X-Forwarded-Proto
X-Forwarded-Server
X-Real-IP
X-Client-IP
X-Trusted-IP
X-Originating-IP
X-Remote-IP
X-Remote-Addr
X-Requested-By
X-Requested-For


// values:
127.0.0.1 (or anything in the `127.0.0.0/8` or `::1/128` address spaces)
localhost
10.0.0.0/8
172.16.0.0/1
192.168.0.0/16
169.254.0.0/16
```
- **Chain:** Escalate to admin → find Stored XSS for cookie theft.
- Try to traverse the website and check if some of pages that may miss the authorization check. For example:
```
/../.././userInfo.html
```

#### 3. Multi-Step Breaks (Build on IDOR):
- **Detect:** Flows like /reset?uid=123.
- **Test:** Swap uid mid-flow; skip steps (direct to /reset/step2).
- **Bypasses:** No check on step? Swap IDs.
- **Chain:** IDOR leaks uid → break reset.

#### 4. File Access
- **Test:** /file?id=123 → swap to 124.
- **Bypasses:** ../other/file; %2e%2e%2f.
- **Chain:** Traverse to inject XSS payload.

| Context | Beginner Example | Easy Tests | Quick Chain |
|---------|------------------|------------|-------------|
| **Query Params** | /user?id=123 | Swap to 122; fuzz ±5. | Leak email → reset. |
| **JSON Bodies** | {"id":123} | Change id; add "role=admin". | Mass-assign role. |
| **Cookies** | user_id=123 | Swap to other. | + Edit role=true. |
| **Direct URL** | /admin | Load from normal account. | + Header bypass. |
| **Redirects** | Location: /user/123 | Grab leaked ID. | Use in IDOR. |
| **Files** | /file/123.jpg | Swap 123; ../456.jpg. | Traverse configs. |
| **Multi-Step** | /reset?uid=123 | Swap uid. | Skip auth step. |

## 3. 🛠️ Tools & Beginner Tips
- **Essentials:** Burp Community (free)—Proxy to intercept, Repeater to test, Intruder to fuzz IDs.
- **Setup:** 2 browsers: One normal, one low-priv. Firefox Containers for easy role swap.
- **First Vuln Path:** Focus IDOR on profiles/apis—90% of beginner finds.
- **Verify:** Got data? Screenshot PoC; check if sensitive (PII = high impact).
- **Update Playbook:** After IDOR find, note "Sequential IDs leaked in blog—easy swap."
- **Resources:** PortSwigger Labs (start with IDOR); OWASP WSTG-ATHZ (simple read).