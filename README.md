# Recursive-IR

Recursive-IR is a single-binary orchestration that turns an OpenSearch stack into a fully capable and customisable DFIR log analytics platform.

It supports case-centric investigations and persistent enrichments (tags, comments, and analyst context), while fully harnessing the strengths of OpenSearch and native OpenSearch Dashboards—scalable observability, visualisation, and Security Analytics for alerting and correlation across ingested forensic artefacts.

Recursive-IR can drive arbitrary parsers and facilitate log ingestion through dynamically generated parsing pipelines and mapping templates, allowing heterogeneous forensic data to be ingested safely and consistently.

Field normalisation such as copying and renaming are defined declaratively, enabling schemas to be adapted and evolved without hard-coding logic into ingestion pipelines.

Data-type conflicts and other ingestion issues are isolated into a dedicated index, with built-in facilities to correct mapping conflicts and seamlessly reload previously ingested data, ensuring investigations remain accurate, reproducible, and deterministic.

Recursive-IR is not a forensic artefact collection or live response tool. It focuses on the orchestration, ingestion, normalisation, enrichment, and analysis of forensic data after collection, and is designed to integrate cleanly with existing acquisition workflows and tooling.

Instead of enforcing a fixed investigation model or interface, Recursive-IR provides a flexible analytics foundation that adapts to different DFIR workflows, enabling teams to shape investigations around their needs rather than conforming to a predefined tool workflow.



## Quickstart

Run:

    sudo ./bin/dfir init

See docs/ for details.
