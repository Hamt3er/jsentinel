# JSentinel Report

## Overview

- Target: ./test.js
- Mode: file
- Scanned At: 2026-04-09T15:22:01Z
- JS Files Analyzed: 1

## Summary

- Endpoints: 0
- Domains: 0
- API Paths: 1
- Suspected Secrets: 4
- Dangerous Sinks: 2
- Source Maps: 0
- Storage Keys: 0

## JavaScript Files

- ./test.js

## API Paths

- `/api/user/profile` — source: `./test.js`

## Interesting Lines

- `const api_key = "AIzaSyEXAMPLEEXAMPLEEXAMPLE12345";` — source: `./test.js`
- `const token = "ghp_exampletoken12345678901234567890";` — source: `./test.js`
- `localStorage.setItem("authToken", "123");` — source: `./test.js`

## Suspected Secrets

- kind: `Google API Key-like`, confidence: `high`, preview: `AIzaSyEX...E12345`, source: `./test.js`
- kind: `GitHub Token-like`, confidence: `high`, preview: `ghp_exam...567890`, source: `./test.js`
- kind: `Generic secret key/value: api_key`, confidence: `low`, preview: `AIzaSyEX...E12345`, source: `./test.js`
- kind: `Generic secret key/value: token`, confidence: `low`, preview: `ghp_exam...567890`, source: `./test.js`

## Dangerous Sinks

- sink: `fetch(`, source: `./test.js`
  - snippet: `345"; const token = "ghp_exampletoken12345678901234567890"; fetch("/api/user/profile"); localStorage.setItem("authToken", "123"); eval("console.log('test')");`
- sink: `eval(`, source: `./test.js`
  - snippet: `i/user/profile"); localStorage.setItem("authToken", "123"); eval("console.log('test')");`

