# Post-Hoc Review: PR #5 (React Dashboard Frontend & API Connection)

**PR:** #5 (`feature/bhumit-dashboard` -> `main`)  
**Author:** Bhumit Sethi (`bhumitsethi11-eng`)  
**Reviewer:** Soham (Project Coordination & Integration)  
**Date:** 2026-10-13  
**Status:** Merged  

---

## 1. Scope & Deliverable Overview
PR #5 delivered the initial React 18 single-page application under `frontend/`:
- Components: `Header.jsx`, `ApiConfigBar.jsx`, `SingleQueryForm.jsx`, `BatchAnalysisForm.jsx`, `LiveStatsCards.jsx`, `LiveAlertsTable.jsx`, `TrafficTimelinePlaceholder.jsx`, `OfflineModelPerformance.jsx`, `OfflineFeatureImportance.jsx`
- Client networking: `frontend/src/api/client.js`
- Design styling: Custom CSS design tokens, responsive cards, dark theme in `frontend/src/index.css`.

## 2. Technical Strengths
- **Clean Aesthetic & Modular Design:** Well-structured component architecture, accessible form controls, clear separation of single query vs batch forms.
- **Honest Placeholders:** Rather than mocking fake streaming numbers, empty state components (`LiveStatsCards`, `LiveAlertsTable`, `TrafficTimelinePlaceholder`) clearly declared that live packet sniffing / streaming data was pending.
- **Vite Proxy Setup:** Included reverse proxy configuration in `vite.config.js` to route `/predict`, `/analyze`, and `/health` to backend `127.0.0.1:8000`.

## 3. Concrete Issues & Code References
1. **Unwired Static Data:**
   - `LiveStatsCards.jsx` displayed static placeholder strings (`--`) even after queries were successfully submitted through the interactive forms.
   - `LiveAlertsTable.jsx` was completely disconnected from the detection stream. When a user submitted an attack query in `/predict` or `/analyze`, the table remained statically empty with "No alerts yet".
   - `OfflineModelPerformance.jsx` loaded metrics from a hardcoded JavaScript file (`frontend/src/data/offlineEvaluationData.js`) instead of fetching from the backend API.
2. **Missing CSV Upload Flow:**
   - `BatchAnalysisForm.jsx` supported only manual JSON text pasting; no file picker or multipart CSV upload mechanism existed.
3. **Missing Test Script in `package.json`:**
   - In PR #5, `package.json` had scripts for `dev`, `build`, and `preview`, but was **missing a `test` script**, causing `npm test` to fail immediately.

## 4. Downstream Integration Impact & Resolution
- In `integration/soham-e2e`, I wire up `LiveAlertsTable` and `LiveStatsCards` to real backend endpoints (`GET /alerts`, `GET /statistics`), replace static offline data with `GET /model-performance`, add CSV drag-and-drop / file upload to `BatchAnalysisForm.jsx`, and provide comprehensive test coverage in `frontend/src/api/client.test.js`.
