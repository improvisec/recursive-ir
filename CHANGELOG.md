# Changelog

## 2026-07-09

### v0.10.3

- Added System Health panel in the homepage to monitor ram and disk utilization.

### v0.10.2

- Added source type-scoped case artefacts reload for faster re-ingestion.

## 2026-07-08

### v0.10.1

- Improved quick steps status cards in the homepage by adding ready/not ready state.
- Added Ingestion Health panel in the homepage to indicate ingestion issues and interface to resolve them.
- Added ingestion services status and start/stop controls within the Ingestion Heatlh panel.
- Configured default 4gb heap to OpenSearch jvm.options to resolve crashes.
- Fixed authentication failing issues when OSD randomly returns 401.

## 2026-07-02

### v0.9.47

- Improved ingestion error pipeline's error field extraction logic.
- Updated ingestion-error index template.

### v0.9.46

- Added default jvm.options file with 4gb default heap size for logstash 

## 2026-07-02

### v0.9.45

- Fixed index not found error when loading SettingsPage on fresh install.

## 2026-07-02

### v0.9.41 - v0.9.44

- Added `update.sh` for upgrading an existing Recursive-IR installation without performing a full reinstall.

### v0.9.40 

- Added version tracking. The web interface now displays the installed version next to Recursive-IR banner.

## 2026-07-01

### v0.9.39

- Fixed missing flags enrichment badges next to each item in the search result panel.
- Added lock/unlock button to pin pivot tree panel.

### v0.9.38

- Fixed bulk enrichment issue due to malformed json object.
- Improved search result panel by making columns resizable.

### v0.9.37

- Fixed pivot tree node creation bug when clicking prev/next buttons in the search panel.

## 2026-06-30

### v0.9.35, v0.9.36

- Fixed search result freezing when the clicking the first item. 

### v0.9.34

- Fixed collections panel auto-closing after clicking apply button.

## 2026-06-29

### v0.9.33

- Fixed layout of search panel and added drag handle to make statistics panel resizable.

### v0.9.32

- Fixed improper rootca certificate permission.



