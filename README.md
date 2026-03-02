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

## Quickstart

Initialise the environment:

```bash
sudo ./bin/dfir init
