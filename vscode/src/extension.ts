import * as fs from "fs";
import * as path from "path";
import * as vscode from "vscode";

type OccamOFinding = {
  file?: string;
  lineno?: number;
  end_lineno?: number;
  severity?: string;
  risk_score?: number;
  complexity_hint?: string;
  explanation?: string;
};

type OccamORegression = {
  file?: string;
  lineno?: number;
  regression_severity?: string;
  risk_delta?: number;
  base_hint?: string;
  head_hint?: string;
  explanation?: string;
};

type OccamOReport = {
  findings?: OccamOFinding[];
  regressions?: OccamORegression[];
};

function toLine(value: unknown): number {
  const num = Number(value);
  if (!Number.isFinite(num) || num <= 0) {
    return 1;
  }
  return Math.floor(num);
}

function toRisk(value: unknown): string {
  const num = Number(value);
  if (!Number.isFinite(num)) {
    return "n/a";
  }
  return num.toFixed(3);
}

function toDelta(value: unknown): string {
  const num = Number(value);
  if (!Number.isFinite(num)) {
    return "n/a";
  }
  return num.toFixed(3);
}

function toSeverity(value: unknown): vscode.DiagnosticSeverity {
  const level = String(value || "").toLowerCase();
  if (level === "critical" || level === "high") {
    return vscode.DiagnosticSeverity.Error;
  }
  if (level === "medium") {
    return vscode.DiagnosticSeverity.Warning;
  }
  return vscode.DiagnosticSeverity.Information;
}

function resolveReportPath(): string | undefined {
  const config = vscode.workspace.getConfiguration("occamo");
  const reportPath = config.get<string>("reportPath", "out/occamo.json");
  if (!reportPath) {
    return undefined;
  }
  if (path.isAbsolute(reportPath)) {
    return reportPath;
  }
  const folders = vscode.workspace.workspaceFolders || [];
  for (const folder of folders) {
    const candidate = path.join(folder.uri.fsPath, reportPath);
    if (fs.existsSync(candidate)) {
      return candidate;
    }
  }
  if (folders.length > 0) {
    return path.join(folders[0].uri.fsPath, reportPath);
  }
  return undefined;
}

function resolveSourcePath(filePath: string, folders: readonly vscode.WorkspaceFolder[]): string | undefined {
  if (!filePath) {
    return undefined;
  }
  if (path.isAbsolute(filePath)) {
    return filePath;
  }
  for (const folder of folders) {
    const candidate = path.join(folder.uri.fsPath, filePath);
    if (fs.existsSync(candidate)) {
      return candidate;
    }
  }
  if (folders.length > 0) {
    return path.join(folders[0].uri.fsPath, filePath);
  }
  return undefined;
}

function parseReport(raw: string): OccamOReport {
  try {
    return JSON.parse(raw) as OccamOReport;
  } catch (err) {
    throw new Error("Invalid OccamO JSON report.");
  }
}

function buildDiagnostics(report: OccamOReport): Map<string, vscode.Diagnostic[]> {
  const diagnosticsByFile = new Map<string, vscode.Diagnostic[]>();
  const folders = vscode.workspace.workspaceFolders || [];

  const add = (filePath: string | undefined, diagnostic: vscode.Diagnostic) => {
    if (!filePath) {
      return;
    }
    const list = diagnosticsByFile.get(filePath) || [];
    list.push(diagnostic);
    diagnosticsByFile.set(filePath, list);
  };

  for (const finding of report.findings || []) {
    const filePath = resolveSourcePath(String(finding.file || ""), folders);
    const line = toLine(finding.lineno);
    const endLine = toLine(finding.end_lineno ?? finding.lineno);
    const range = new vscode.Range(line - 1, 0, Math.max(line, endLine) - 1, 0);
    const hint = finding.complexity_hint || "Complexity hotspot";
    const risk = toRisk(finding.risk_score);
    let message = `OccamO hotspot: ${hint} (risk ${risk})`;
    if (finding.explanation) {
      message += `: ${finding.explanation}`;
    }
    const diagnostic = new vscode.Diagnostic(range, message, toSeverity(finding.severity));
    diagnostic.source = "occamo";
    add(filePath, diagnostic);
  }

  for (const regression of report.regressions || []) {
    const filePath = resolveSourcePath(String(regression.file || ""), folders);
    const line = toLine(regression.lineno);
    const range = new vscode.Range(line - 1, 0, line - 1, 0);
    const baseHint = regression.base_hint || "n/a";
    const headHint = regression.head_hint || "n/a";
    const delta = toDelta(regression.risk_delta);
    let message = `OccamO regression: ${baseHint} -> ${headHint} (risk +${delta})`;
    if (regression.explanation) {
      message += `: ${regression.explanation}`;
    }
    const diagnostic = new vscode.Diagnostic(
      range,
      message,
      toSeverity(regression.regression_severity),
    );
    diagnostic.source = "occamo";
    add(filePath, diagnostic);
  }

  return diagnosticsByFile;
}

async function loadReport(collection: vscode.DiagnosticCollection): Promise<void> {
  const reportPath = resolveReportPath();
  if (!reportPath) {
    vscode.window.showErrorMessage("OccamO: no workspace folder or report path configured.");
    return;
  }
  if (!fs.existsSync(reportPath)) {
    const pick = await vscode.window.showOpenDialog({
      title: "Select OccamO JSON report",
      canSelectMany: false,
      filters: { "OccamO report": ["json"] },
    });
    if (!pick || pick.length === 0) {
      return;
    }
    const report = parseReport(fs.readFileSync(pick[0].fsPath, "utf-8"));
    collection.clear();
    for (const [filePath, diagnostics] of buildDiagnostics(report)) {
      collection.set(vscode.Uri.file(filePath), diagnostics);
    }
    return;
  }

  const report = parseReport(fs.readFileSync(reportPath, "utf-8"));
  collection.clear();
  for (const [filePath, diagnostics] of buildDiagnostics(report)) {
    collection.set(vscode.Uri.file(filePath), diagnostics);
  }
}

export function activate(context: vscode.ExtensionContext): void {
  const collection = vscode.languages.createDiagnosticCollection("occamo");
  context.subscriptions.push(collection);

  context.subscriptions.push(
    vscode.commands.registerCommand("occamo.loadReport", async () => {
      await loadReport(collection);
    }),
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("occamo.clearDiagnostics", () => {
      collection.clear();
    }),
  );

  context.subscriptions.push(
    vscode.workspace.onDidChangeConfiguration(event => {
      if (event.affectsConfiguration("occamo")) {
        const config = vscode.workspace.getConfiguration("occamo");
        if (config.get<boolean>("autoLoad", true)) {
          void loadReport(collection);
        }
      }
    }),
  );

  const config = vscode.workspace.getConfiguration("occamo");
  if (config.get<boolean>("autoLoad", true)) {
    void loadReport(collection);
  }
}

export function deactivate(): void {
  // VS Code disposes subscriptions automatically on deactivate.
}
