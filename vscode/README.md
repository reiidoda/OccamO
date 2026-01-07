# OccamO VS Code Extension (Beta)

This extension reads an OccamO JSON report and surfaces findings as
VS Code diagnostics.

## Quick start

1. Build the extension:

```bash
cd vscode
npm install
npm run compile
```

2. Launch the Extension Development Host (F5 in VS Code) or package it.
3. Set `occamo.reportPath` to your report path (default: `out/occamo.json`).
4. Run "OccamO: Load Report" from the command palette.

## Settings

- `occamo.reportPath`: JSON report path (relative to workspace).
- `occamo.autoLoad`: Automatically load diagnostics on startup.

## Notes

- This is a local-only extension; no data leaves your machine.
- Diagnostics are regenerated each time you load a report.
