<img src="assets/images/recursive-ir-banner-light.png" alt="Recursive-IR" width="400">

Recursive-IR is a single-binary orchestration layer that transforms an OpenSearch stack into a fully capable and customisable DFIR log analytics platform.

![diagram](assets/images/recursive-ir-diagram.png)


Recursive-IR enables case-centric investigations with persistent enrichments such as tags, comments, and analyst context, while fully leveraging the strengths of OpenSearch and native OpenSearch Dashboards — scalable observability, visualisation, and Security Analytics for alerting and correlation across ingested forensic artefacts.

![diagram](assets/images/recursive-ir-screenshot.png)


---

## Features 

1. Case-centric investigation - allows grouping of artefacts into individual cases.
2. Dynamically generate filebeat input config files, logstash pipelines, and OpenSearch index templates to facilitate forensics artefacts ingestion.
3. Orchestrate arbitrary parsers (e.g., hayabusa, dissect, plaso, evtx_dump,  etc.) to convert forensics artefacts into OpenSearch-ingestable jsonl format. 
4. Add persistent enrichments to events in OpenSearch such as tags and comments and automatically project them into OpenSearch Dashboards.
5. Group a specific set of events into "collections" and an easy toggle to add hand-picked events to the final investigation timeline.
6. Intuitive user interface for event enrichments, marking indicators of compromise, and pivoting during artefacts analysis (e.g., all searches are saved in a "pivot tree". 
7. Command-line interface, also exposed via web API endpoints.
8. Config-driven normalisation, e.g., copy, rename, stringify, blobify, derive, or drop fields.
9. Easily reload/re-ingest forensics artefacts along with any previously added enrichments.
10. Run ingested artefacts through OpenSearch Security Analytics plugin supporting native Sigma rules, for alerting and correlation during investigations.
11. Enrich events with geolocation data using custom built mmdb database.

... more to come.



---

# 🚀 Quickstart

This guide walks through a **fresh single-node installation** of Recursive-IR on Ubuntu.

The installer script installs and configures:

- OpenSearch
- OpenSearch Dashboards
- Logstash
- Filebeat
- Recursive-IR 

The Web API and UI containers and OpenSearch Dashboards are all accessible through nginx (also a container)

---

## 1️⃣ Clone Recursive-IRR

```bash
git clone https://github.com/improvisec/recursive-ir.git
cd recursive-ir
```

---

## 2️⃣ Install OpenSearch Stack

```bash
sudo OPENSEARCH_INITIAL_ADDMIN_PASSWORD='StrongPasswordHere' \
  ./scripts/install_opensearch_stack.sh
```

This installs and configures:

- OpenSearch (single-node, bound to `127.0.0.1`)
- OpenSearch Dashboards (loopback only)
- Logstash (APT)
- Filebeat (APT)
- Recursive-IR Web UI and IP and nginx

---

### 📁 Stack Directory Layout

After installation, the core components live in the following locations:

#### 🔎 OpenSearch

| Path | Purpose |
|------|---------|
| `/var/lib/opensearch/` | OpenSearch data directory |
| `/var/log/opensearch/` | OpenSearch logs |
| `/etc/opensearch/` | OpenSearch configuration |
| `/etc/recursive-ir/certs/opensearch/` | TLS certificates (CA, node, admin) |

OpenSearch listens on:

```
https://127.0.0.1:9200
```

---

#### 📊 OpenSearch Dashboards

| Path | Purpose |
|------|---------|
| `/etc/opensearch-dashboards/` | Dashboards configuration |
| `/var/log/opensearch-dashboards/` | Dashboards logs |

Dashboards listens on:

```
http://127.0.0.1:5601
```

External access is handled by nginx (accessible via OSD_HOST_LAN).

---

#### 🔁 Logstash (Recursive-IR Managed)

| Path | Purpose |
|------|---------|
| `/usr/share/logstash/` | Logstash binaries (APT installed) |
| `/etc/recursive-ir/logstash/` | Recursive-IR Logstash pipelines + config |
| `/var/lib/recursive-ir/logstash/` | Logstash data + dead letter queue |
| `/var/log/recursive-ir/logstash/` | Logstash logs |

---

#### 📦 Filebeat (Recursive-IR Managed)

| Path | Purpose |
|------|---------|
| `/usr/share/filebeat/` | Filebeat binaries (APT installed) |
| `/etc/recursive-ir/filebeat/` | Recursive-IR Filebeat input files + config|
| `/var/lib/recursive-ir/filebeat/` | Filebeat registry/state |
| `/var/log/recursive-ir/filebeat/` | Filebeat logs |

---

#### 🗂 Recursive-IR Core

| Path | Purpose |
|------|---------|
| `/etc/recursive-ir/` | Main configuration directory |
| `/etc/recursive-ir/conf/recursive.env` | Runtime environment configuration |
| `/var/log/recursive-ir/cases/` | Case storage root |
| `/var/lib/recursive-ir/` | LMDB databases + worker state |

---

#### 🔐 TLS Certificates

All OpenSearch TLS materials are stored under:

```
/etc/recursive-ir/certs/opensearch/
```

This includes:

- `root-ca.pem`
- `node.pem`
- `admin.pem`
- Corresponding private keys

---

## 3️⃣ Bootstrap Recursive-IR

```bash
sudo ./bin/dfir init --bootstrap-env --enable --create-recursive-user
```

This initializes Recursive-IR services, databases, and default configuration files in:

```
/etc/recursive-ir/conf/
```

The following services will also be installed:

1. dfir-watcher - Watches folders for any artefacts droped into:

```
 /var/log/recursive-ir/cases/<case_id>/hosts/<host_ip>/inbox
```
and routes them into 

```
 /var/log/recursive-ir/cases/<case_id>/hosts/<host_ip>/raw_artefacts/<source_type>
```

2. dfir-parser - Watches files from the raw_artefacts/<source_type> folder above and runs corresponding parser that will write the jsonl into:

```
 /var/log/recursive-ir/cases/<case_id>/hosts/<host_ip>/jsonified_artefacts/<source_type>
```

3. dfir-enricher - Runs every 30 seconds to see if there are any enrichments in the lmdb database that need to be projected into OpenSearch and automatically projects them.

```
/var/log/recursive-ir/cases/<case_id>/enrichments/data.mdb
```

4. dfir-worker - Constaintly monitors the sqlite database for new jobs submitted via the web API.

```
/var/lib/recursive-ir/web/jobs.db
```

---

## 4️⃣ Configure Environment

Edit:

```bash
sudo nano /etc/recursive-ir/conf/recursive.env
```

Update:

```bash
OS_USER="admin"
OS_PASS="CHANGE_THIS"

# LAN host/IP used for UI + OSD deep links
OSD_HOST_LAN="http://<your-server-ip>"
```

⚠ Replace `<your-server-ip>` with the actual IP or hostname of your server.

| Variable | Description |
|----------|------------|
| `OS_HOST` | Internal OpenSearch endpoint (loopback) |
| `OSD_HOST` | Internal OpenSearch-Dashboards (loopback) |
| `OSD_HOST_LAN` | Public host/IP users will access via nginx |

---

## 5️⃣ Start Logstash and Filebeat

```bash
sudo systemctl restart logstash filebeat
```

---

# 🌐 Deploy Web API + UI + OSD Gateway

Recursive-IR web components run in Docker.

---

## 6️⃣ Install Docker

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg |   sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg
echo   "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/ubuntu \
$(. /etc/os-release && echo "$VERSION_CODENAME") stable" |   sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install -y   docker-ce   docker-ce-cli   containerd.io   docker-buildx-plugin   docker-compose-plugin

cd web/docker
docker compose --env-file /etc/recursive-ir/conf/recursive.env \
  -f /home/matato/recursive-ir/web/docker-compose.yml pull

docker compose --env-file /etc/recursive-ir/conf/recursive.env \
  -f /home/matato/recursive-ir/web/docker-compose.yml up -d
```
This starts:

- FastAPI backend
- React UI
- nginx gateway
- Reverse proxy to OpenSearch Dashboards

---

## 8️⃣ Access the Platform

From another machine on the network, type this on your browser:

```
http://<your-server-ip>/
```

The nginx gateway proxies connections to the following:

- OpenSearch Dashboards → `/`
- Recursive-IR UI → `/recursive-ir/`
- Recursive-IR API → `/recursive-ir/api/v1`


![diagram](assets/images/login.png)

---

# 🔎 Verify Full Stack

Check system services:

```bash
systemctl status opensearch opensearch-dashboards logstash filebeat dfir-watcher dfir-parser.timer dfir-enricher.timer dfir-worker
```

Check Docker containers:

```bash
docker ps
```

Check OpenSearch:

```bash
curl --cacert /etc/recursive-ir/certs/opensearch/root-ca.pem \
  -u admin:StrongPasswordHere \
  https://127.0.0.1:9200/_cluster/health?pretty
```

---

# ✅ Installation Complete

Your Recursive-IR deployment now includes:

- Secure OpenSearch (loopback only)
- Log ingestion via Logstash + Filebeat
- Recursive-IR worker + enrichment engine
- FastAPI backend
- React Pivot + Enrichment UI
- nginx LAN gateway for controlled access

---

# 📘 User Guide

Recursive-IR is currently actively being developed. As such, all CLI commands listed below will have a corresponding API endpoint accessible via the web UI. 

---

## ➕ Add a New Parser (CLI)

The first step in using the platform is adding new parser definitions. By default, Recursive-IR ships with a number of sample parsers, that can be enabled by modifying the enabled setting in:

```
/etc/recursive-ir/conf/parsers.yml
```

An example parser command that adds a parser definition to convert EVTX logs into jsonl format is shown below:

```bash
dfir parser new -t evtx --patterns "*.evtx" --bin evtx_dump --args '-o,jsonl,--no-confirm-overwrite,-f,{out},{in}' -f
```
The command above means that any file in *.evtx format shall be handled by the program evtx_dump (parsers can be found or put into bin/ folder of the recursive-ir repository). The command above will create the following entry in parsers.yml (if it doesn't exist yet).

```
  evtx:
    enabled: true
    patterns: ["*.evtx"]
    bin: evtx_dump
    args: ["-o", "jsonl", "--no-confirm-overwrite", "-f", "{out}", "{in}"]
    route_mode: walk
    inherit_type: false
    expand_archives: top
    id: 100
```

Parser concepts:

- `enabled` - Whether the dfir-parser will activate the parser to perform jsonl conversion
- `patterns` - For individual files, globbing patterns are allowed. For artefacts inside folders, exact folder name must be specified
- `bin` - the name of the program to run to perform the parsing or jsonl conversion.
- `args` - a comma-separated list of arguments that the dfir-parser service will pass into the parser program when spawning it.
- `route_mode: [walk|bundle] - whether the individual files will be recursively processed and fed into the parser program or the whole folder will be handed over.
- `inherit_type` - If a folder contains different types of artefacts, and you want to process them under a specific parsers.yml entry, set this to true. Otherwise, all parsers.yml entry that matches the patterns of each file will activate. For example, dropping an *.evtx will trigger both evtx_dump and hayabusa parsers.
- `expand_archives` - Automatically expand supported archives (tar/gz/zip).
- `id` - an auto-generated parsers entry id.


After a parser entry is created, several things happen behind the scene. Configuration files such as filebeat inputs, logstash pipelines, opensearch index templates, etc. are created. This allows recursive-ir to ingest practically any type of forensics artefacts as long as they are in jsonl format, without shipping any vendor-specific normalization pipelines. The following files/folders are modified:

```
/etc/recursive-ir/conf/parsers.yml
```
```
/etc/recursive-ir/confi/field-mappings.yml
```
```
/etc/recursive-ir/filebeat/inputs.d/<source_type>.yml
```
```
/etc/recursive-ir/logstash/pipelines.yml
/etc/recursive-ir/logstash/pipelines/nnn-<source_type>.conf
```


---

## 📂 Create a New Case

```bash
dfir case new <case_id>
```

Example:

```bash
dfir case new dfir-0001
```

This will:

- Create case folder structure
- Initialize case metadata
- Prepare OpenSearch case indexes

📸 _Screenshot placeholder: Case folder structure_

---

## 🖥 Add a Host into a Case

```bash
dfir host add --case dfir-0001 --host 127.0.0.1
```

This will:

- Create host directory
- Prepare inbox
- Register host metadata

---

## 📥 Drop Artefacts into Host Inbox

Copy artefacts into:

```
/var/log/recursive-ir/cases/<case_id>/hosts/<host>/inbox/
```

Watcher service automatically:

- Detects artefact  
- Routes to parser  
- Normalizes to JSONL  
- Sends to OpenSearch  

📸 _Screenshot placeholder: Artefact ingestion flow_

---

## 👤 Create a New User

```bash
dfir user allow user@example.com --os-create
```

This will:

- Create OpenSearch internal user
- Seed private tenant data views
- Apply default OSD settings

---

# 🔎 Enriching Events

Recursive-IR enrichment UI is opened from OpenSearch Discover via:

```
Add_Enrichment
```

---

## 🏷 Adding Tags

Single event:

```bash
dfir tag add --case dfir-0001 --index evtxjson-* --id <doc_id> --tag suspicious
```

Bulk (via UI or CLI):

```bash
dfir tag bulk ...
```

Notes:

- Stored in LMDB (source of truth)
- Projected to OpenSearch
- Fully reversible

---

## 💬 Adding Comments

```bash
dfir comment add ...
```

Features:

- Case-scoped
- Event-scoped
- Versioned in LMDB

---

## 🕒 Adding into Timeline

```bash
dfir timeline add ...
```

Features:

- Stored in timeline DBI
- Linked to event
- Supports custom timestamps
- Appears in Pivot UI timeline panel

---

## 📦 Adding into a Collection

Collections allow grouping of events across:

- Different indexes
- Different hosts
- Different artefact types

Example:

```bash
dfir collection add ...
```

Use cases:

- Suspicious login grouping
- Data exfiltration investigation set
- Incident phase grouping

---

## 🔍 Searching for Strings

From Pivot UI:

- Basic search
- Wildcard search (`.wc` fields)
- Smart pivot queries
- OpenSearch Discover deep-link

Design principle:

- LMDB = source of truth (enrichment)
- OpenSearch = projection + search engine

📸 _Screenshot placeholder: Pivot UI search panel_

---

# 📁 Directory Layout

---

## Configuration Files

```
/etc/recursive-ir/
├── parsers.yml
├── templates/
├── columns.yml
└── opensearch-dashboards/
```

---

## Case Artefacts

```
/var/log/recursive-ir/cases/
└── dfir-0001/
    ├── hosts/
    │   └── <host>/
    │       ├── inbox/
    │       ├── raw_artefacts/
    │       └── metadata.json
    └── case_metadata.json
```

---

## Installation Directories

```
/usr/local/bin/dfir
/opt/recursive-ir/
```

---

## Database Folders

### LMDB Databases

```
/var/lib/recursive-ir/
├── enrichment/
├── projmeta/
├── queue/
├── artefacts/
├── timeline/
├── collections/
└── collections_by_event/
```

| DBI | Purpose |
|-----|---------|
| enrichment | Tags, comments, IOCs |
| projmeta | Projection tracking |
| queue | Worker job queue |
| artefacts | Artefact metadata |
| timeline | Timeline entries |
| collections | Collection definitions |
| collections_by_event | Event → collection mapping |

---

# 🛠 Troubleshooting

---

## ⚠ Resolving Type Conflicts

Check index:

```
ingestion-error-*
```

Steps:

1. Identify conflicting field  
2. Inspect original JSON  
3. Fix parser mapping  
4. Re-ingest artefact  

---

## 🐛 Run in Verbose / Debug Mode

```bash
VERBOSE=1 DFIR_HTTP_DEBUG=3 dfir <command>
```

Useful for:

- OSD sync issues
- Security API calls
- Template seeding
- Data view conflicts

---

## 📜 Viewing systemd Logs

```bash
journalctl -u dfir-watcher -f
journalctl -u dfir-parser -f
journalctl -u dfir-enricher -f
journalctl -u dfir-worker -f
```

Service roles:

- **dfir-watcher** → monitors inbox  
- **dfir-parser** → executes parsers  
- **dfir-enricher** → handles enrichment jobs  
- **dfir-worker** → processes queue + projection  

---

## 🗃 Viewing Database Contents

Example:

```bash
mdb_dump /var/lib/recursive-ir/enrichment/
```

Or:

```bash
dfir db inspect enrichment
```

Important:

- LMDB is authoritative
- Projection mismatches can be re-synced
- OpenSearch can be rebuilt from LMDB

---

# 🏗 Architecture Overview

```
Artefact
   ↓
Watcher
   ↓
Parser
   ↓
OpenSearch  (search + projection layer)
   ↑
LMDB        (source of truth)
   ↑
Worker / Queue
```

📸 _Architecture diagram placeholder_

---

# 📌 Notes

- OpenSearch is NOT the source of truth.
- LMDB stores authoritative enrichment.
- OpenSearch is a projection/search layer.
- Reset operations do not destroy enrichment unless explicitly forced.
- Designed for deterministic DFIR workflows.

---

# 📄 License

```
TODO: Add license information (e.g., Apache-2.0)
```

---

# 🤝 Contributing

```
TODO: Add contribution guidelines
```

---

# 🔐 Security

```
TODO: Add responsible disclosure policy
```
