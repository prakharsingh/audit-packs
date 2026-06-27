import * as vscode from 'vscode';
import * as cp from 'child_process';
import * as path from 'path';
import * as fs from 'fs';

let diagnosticCollection: vscode.DiagnosticCollection;

export function activate(context: vscode.ExtensionContext) {
    diagnosticCollection = vscode.languages.createDiagnosticCollection('audit-packs');
    context.subscriptions.push(diagnosticCollection);

    // Register run scan command
    let runScanCmd = vscode.commands.registerCommand('auditPacks.runScan', () => {
        runAuditScan();
    });
    context.subscriptions.push(runScanCmd);

    // Register init configuration command
    let initCmd = vscode.commands.registerCommand('auditPacks.init', () => {
        runAuditInit();
    });
    context.subscriptions.push(initCmd);

    // Run on save
    if (vscode.workspace.getConfiguration('auditPacks').get('scanOnSave', true)) {
        vscode.workspace.onDidSaveTextDocument((document) => {
            if (document.uri.scheme === 'file') {
                runAuditScan(document);
            }
        });
    }

    vscode.window.showInformationMessage('Audit Packs compliance extension is active!');
}

function runAuditInit() {
    const workspaceFolders = vscode.workspace.workspaceFolders;
    if (!workspaceFolders) {
        vscode.window.showErrorMessage('Please open a workspace folder to initialize Audit Packs.');
        return;
    }
    const workspaceRoot = workspaceFolders[0].uri.fsPath;

    // Run 'audit-packs --init' through integrated terminal
    const terminal = vscode.window.createTerminal('Audit Packs Init');
    terminal.show();
    terminal.sendText('audit-packs --init');
}

function runAuditScan(targetDocument?: vscode.TextDocument) {
    const workspaceFolders = vscode.workspace.workspaceFolders;
    if (!workspaceFolders) {
        return;
    }
    const workspaceRoot = workspaceFolders[0].uri.fsPath;

    const config = vscode.workspace.getConfiguration('auditPacks');
    const frameworks = config.get<string>('frameworks', 'nist-800-53,soc2');
    const failOn = config.get<string>('failOn', 'high');
    const adjudicationMode = config.get<string>('adjudicationMode', 'off');

    // Run audit-packs full scan and generate aggregate SARIF file
    const command = `audit-packs --frameworks ${frameworks} --fail-on ${failOn} --adjudication-mode ${adjudicationMode} --workspace "${workspaceRoot}" --scan-mode full`;

    vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: "Running compliance audit scan...",
        cancellable: false
    }, () => {
        return new Promise<void>((resolve) => {
            cp.exec(command, { cwd: workspaceRoot }, (error, stdout, stderr) => {
                const sarifPath = path.join(workspaceRoot, 'audit-packs.sarif');
                if (fs.existsSync(sarifPath)) {
                    parseSarifAndDiagnostics(sarifPath);
                }
                resolve();
            });
        });
    });
}

function parseSarifAndDiagnostics(sarifPath: string) {
    try {
        diagnosticCollection.clear();
        const content = fs.readFileSync(sarifPath, 'utf8');
        const sarif = JSON.parse(content);
        const runs = sarif.runs || [];
        const diagnosticsMap = new Map<string, vscode.Diagnostic[]>();

        for (const run of runs) {
            const results = run.results || [];
            for (const result of results) {
                const ruleId = result.ruleId;
                const message = result.message?.text || 'Compliance violation';
                const level = result.level || 'warning';

                let severity = vscode.DiagnosticSeverity.Warning;
                if (level === 'error') {
                    severity = vscode.DiagnosticSeverity.Error;
                } else if (level === 'note') {
                    severity = vscode.DiagnosticSeverity.Information;
                }

                const locations = result.locations || [];
                for (const loc of locations) {
                    const physLoc = loc.physicalLocation;
                    const uri = physLoc?.artifactLocation?.uri;
                    const startLine = physLoc?.region?.startLine || 1;

                    if (uri) {
                        const fileUri = vscode.Uri.file(path.resolve(path.dirname(sarifPath), uri));
                        const range = new vscode.Range(startLine - 1, 0, startLine - 1, 100);
                        const diagnostic = new vscode.Diagnostic(range, `[${ruleId}] ${message}`, severity);
                        diagnostic.source = 'Audit Packs';

                        const list = diagnosticsMap.get(fileUri.toString()) || [];
                        list.push(diagnostic);
                        diagnosticsMap.set(fileUri.toString(), list);
                    }
                }
            }
        }

        // Apply diagnostics to VS Code
        for (const [uriStr, diagnostics] of diagnosticsMap.entries()) {
            diagnosticCollection.set(vscode.Uri.parse(uriStr), diagnostics);
        }
    } catch (e) {
        console.error('Failed to parse SARIF for VS Code diagnostics', e);
    }
}

export function deactivate() {}
