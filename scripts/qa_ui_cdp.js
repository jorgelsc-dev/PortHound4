#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const http = require('http');
const { spawnSync } = require('child_process');
const WebSocket = require('ws');

const QA_BASE_URL = process.env.QA_BASE_URL || 'http://127.0.0.1:45678';
const QA_DIR = path.resolve(process.cwd(), 'QA');
const SCREENSHOT_DIR = QA_DIR;
const VIEWPORT = { width: 1365, height: 768, deviceScaleFactor: 1, mobile: false };
const QA_SEED = String(process.env.QA_SEED || '1') !== '0';
const QA_DB_PATH = process.env.QA_DB_PATH || process.env.PORTHOUND_DB_PATH || 'Database.db';
const QA_VIDEO = String(process.env.QA_VIDEO || '1') !== '0';
const QA_VIDEO_FPS = Number(process.env.QA_VIDEO_FPS || '8');
const QA_VIDEO_DIR = path.resolve(QA_DIR, 'video');
const QA_VIDEO_FRAMES_DIR = path.join(QA_VIDEO_DIR, 'frames');
const QA_VIDEO_PATH = path.join(QA_VIDEO_DIR, 'qa-run.mp4');

function ensureDir(dirPath) {
  fs.mkdirSync(dirPath, { recursive: true });
}

function resolvePython() {
  const candidates = [process.env.PYTHON, 'python3', 'python'].filter(Boolean);
  for (const candidate of candidates) {
    const res = spawnSync(candidate, ['-V'], { stdio: 'ignore' });
    if (res.status === 0) return candidate;
  }
  return null;
}

function runSeedScript(action) {
  const scriptPath = path.join(process.cwd(), 'scripts', 'qa_seed_data.py');
  if (!fs.existsSync(scriptPath)) {
    return { ok: false, reason: 'missing-script', scriptPath };
  }
  const python = resolvePython();
  if (!python) {
    return { ok: false, reason: 'python-not-found', scriptPath };
  }
  const res = spawnSync(
    python,
    [scriptPath, action, '--db-path', QA_DB_PATH],
    {
      env: { ...process.env, QA_DB_PATH },
      encoding: 'utf-8',
    }
  );
  return {
    ok: res.status === 0,
    status: res.status,
    stdout: res.stdout || '',
    stderr: res.stderr || '',
    scriptPath,
  };
}

function commandExists(command, args = ['-version']) {
  const res = spawnSync(command, args, { stdio: 'ignore' });
  return res.status === 0;
}

function fetchWsUrl() {
  return new Promise((resolve, reject) => {
    http
      .get('http://127.0.0.1:9222/json/version', (res) => {
        let data = '';
        res.on('data', (c) => (data += c));
        res.on('end', () => {
          try {
            const parsed = JSON.parse(data);
            resolve(parsed.webSocketDebuggerUrl);
          } catch (err) {
            reject(err);
          }
        });
      })
      .on('error', reject);
  });
}

class CDPClient {
  constructor(url) {
    this.url = url;
    this.ws = null;
    this.nextId = 1;
    this.pending = new Map();
    this.listeners = new Map();
  }

  connect() {
    return new Promise((resolve, reject) => {
      this.ws = new WebSocket(this.url);
      this.ws.on('open', resolve);
      this.ws.on('error', reject);
      this.ws.on('message', (data) => this._onMessage(data));
      this.ws.on('close', () => {
        for (const { reject } of this.pending.values()) {
          reject(new Error('WebSocket closed'));
        }
        this.pending.clear();
      });
    });
  }

  _onMessage(data) {
    let msg;
    try {
      msg = JSON.parse(data.toString());
    } catch {
      return;
    }
    if (msg.id) {
      const pending = this.pending.get(msg.id);
      if (!pending) return;
      this.pending.delete(msg.id);
      if (msg.error) {
        pending.reject(new Error(msg.error.message || 'CDP error'));
      } else {
        pending.resolve(msg.result);
      }
      return;
    }
    if (msg.method) {
      const handlers = this.listeners.get(msg.method);
      if (handlers) {
        for (const handler of handlers) {
          try {
            handler(msg.params || {}, msg.sessionId);
          } catch {
            // ignore
          }
        }
      }
    }
  }

  send(method, params = {}, sessionId) {
    const id = this.nextId++;
    const payload = { id, method, params };
    if (sessionId) payload.sessionId = sessionId;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.ws.send(JSON.stringify(payload), (err) => {
        if (err) {
          this.pending.delete(id);
          reject(err);
        }
      });
    });
  }

  on(method, handler) {
    if (!this.listeners.has(method)) {
      this.listeners.set(method, []);
    }
    this.listeners.get(method).push(handler);
  }

  close() {
    if (this.ws) this.ws.close();
  }
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function nowIso() {
  return new Date().toISOString();
}

function sanitizeFilename(name) {
  return name.replace(/[^a-zA-Z0-9_-]+/g, '_');
}

async function main() {
  ensureDir(QA_DIR);
  ensureDir(SCREENSHOT_DIR);

  const wsUrl = process.env.CHROME_WS || (await fetchWsUrl());
  const client = new CDPClient(wsUrl);

  const logs = {
    consoleErrors: [],
    consoleWarnings: [],
    logErrors: [],
    networkErrors: [],
    networkFailures: [],
    runtimeExceptions: [],
    securityStates: [],
    performanceMetrics: [],
  };

  const steps = [];

  const snapshotCounts = () => ({
    consoleErrors: logs.consoleErrors.length,
    consoleWarnings: logs.consoleWarnings.length,
    logErrors: logs.logErrors.length,
    networkErrors: logs.networkErrors.length,
    networkFailures: logs.networkFailures.length,
    runtimeExceptions: logs.runtimeExceptions.length,
    securityStates: logs.securityStates.length,
    performanceMetrics: logs.performanceMetrics.length,
  });

  const sliceLogs = (before) => ({
    consoleErrors: logs.consoleErrors.slice(before.consoleErrors),
    consoleWarnings: logs.consoleWarnings.slice(before.consoleWarnings),
    logErrors: logs.logErrors.slice(before.logErrors),
    networkErrors: logs.networkErrors.slice(before.networkErrors),
    networkFailures: logs.networkFailures.slice(before.networkFailures),
    runtimeExceptions: logs.runtimeExceptions.slice(before.runtimeExceptions),
    securityStates: logs.securityStates.slice(before.securityStates),
    performanceMetrics: logs.performanceMetrics.slice(before.performanceMetrics),
  });

  let recordStep;

  let targetId;
  let sessionId;

  try {
    await client.connect();

    const target = await client.send('Target.createTarget', { url: 'about:blank' });
    targetId = target.targetId;
    const attach = await client.send('Target.attachToTarget', { targetId, flatten: true });
    sessionId = attach.sessionId;

    client.on('Runtime.consoleAPICalled', (params, sid) => {
      if (sid !== sessionId) return;
      const type = String(params.type || '').toLowerCase();
      const text = (params.args || [])
        .map((arg) => arg.value ?? arg.description ?? '')
        .join(' ')
        .trim();
      if (type === 'error') logs.consoleErrors.push(text);
      if (type === 'warning') logs.consoleWarnings.push(text);
    });

    client.on('Log.entryAdded', (params, sid) => {
      if (sid !== sessionId) return;
      const entry = params.entry || {};
      const level = String(entry.level || '').toLowerCase();
      if (level === 'error') {
        logs.logErrors.push(entry.text || entry.url || '');
      }
    });

    client.on('Network.loadingFailed', (params, sid) => {
      if (sid !== sessionId) return;
      logs.networkFailures.push({
        requestId: params.requestId,
        errorText: params.errorText || '',
      });
    });

    client.on('Network.responseReceived', (params, sid) => {
      if (sid !== sessionId) return;
      const resp = params.response || {};
      const status = resp.status || 0;
      if (status >= 400) {
        logs.networkErrors.push({ url: resp.url || '', status });
      }
    });

    client.on('Runtime.exceptionThrown', (params, sid) => {
      if (sid !== sessionId) return;
      const details = params.exceptionDetails || {};
      logs.runtimeExceptions.push({
        text: details.text || 'Runtime exception',
        url: details.url || '',
        line: details.lineNumber || 0,
        column: details.columnNumber || 0,
      });
    });

    client.on('Security.securityStateChanged', (params, sid) => {
      if (sid !== sessionId) return;
      logs.securityStates.push({
        securityState: params.securityState || '',
        schemeIsCryptographic: Boolean(params.schemeIsCryptographic),
      });
    });

    client.on('Page.javascriptDialogOpening', async (params, sid) => {
      if (sid !== sessionId) return;
      try {
        await client.send(
          'Page.handleJavaScriptDialog',
          { accept: true, promptText: '' },
          sessionId
        );
      } catch {
        // ignore
      }
    });

    await client.send('Page.enable', {}, sessionId);
    await client.send('Runtime.enable', {}, sessionId);
    await client.send('Log.enable', {}, sessionId);
    await client.send('Network.enable', {}, sessionId);
    await client.send('Security.enable', {}, sessionId);
    await client.send('Performance.enable', {}, sessionId);
    await client.send('Emulation.setDeviceMetricsOverride', VIEWPORT, sessionId);

    const evalExpr = (expression) =>
      client.send('Runtime.evaluate', { expression, returnByValue: true }, sessionId);

    const waitFor = async (expression, timeoutMs = 10000, stepMs = 250) => {
      const start = Date.now();
      while (Date.now() - start < timeoutMs) {
        const res = await evalExpr(`(() => Boolean(${expression}))()`);
        if (res?.result?.value) return true;
        await delay(stepMs);
      }
      throw new Error(`Timeout waiting for: ${expression}`);
    };

    const waitForPath = (path, timeoutMs = 10000) =>
      waitFor(`window.location.pathname === ${JSON.stringify(path)}`, timeoutMs);

    const clickNav = async (label) => {
      const res = await evalExpr(`(() => {
        const text = ${JSON.stringify(label)};
        const candidates = Array.from(document.querySelectorAll('a, button, [role="tab"]'))
          .filter(el => el.textContent.trim() === text);
        if (!candidates.length) return false;
        candidates[0].click();
        return true;
      })()`);
      if (!res?.result?.value) throw new Error(`Nav item not found: ${label}`);
    };

    const setInputValue = async (selector, value) => {
      const res = await evalExpr(`(() => {
        const input = document.querySelector(${JSON.stringify(selector)});
        if (!input) return false;
        input.focus();
        input.value = ${JSON.stringify(value)};
        input.dispatchEvent(new Event('input', { bubbles: true }));
        input.dispatchEvent(new Event('change', { bubbles: true }));
        return true;
      })()`);
      if (!res?.result?.value) throw new Error(`Input not found: ${selector}`);
    };

    const clickButton = async (label) => {
      const res = await evalExpr(`(() => {
        const text = ${JSON.stringify(label)};
        const btn = Array.from(document.querySelectorAll('button'))
          .find(b => b.textContent.trim() === text);
        if (!btn) return false;
        btn.click();
        return true;
      })()`);
      if (!res?.result?.value) throw new Error(`Button not found: ${label}`);
    };

    const clickRowAction = async (rowText, actionLabel) => {
      const res = await evalExpr(`(() => {
        const rows = Array.from(document.querySelectorAll('tr'));
        const row = rows.find(r => r.innerText.includes(${JSON.stringify(rowText)}));
        if (!row) return { ok: false, reason: 'row_not_found' };
        const btn = Array.from(row.querySelectorAll('button'))
          .find(b => b.textContent.trim() === ${JSON.stringify(actionLabel)});
        if (!btn) return { ok: false, reason: 'button_not_found' };
        btn.click();
        return { ok: true };
      })()`);
      const value = res?.result?.value || {};
      if (!value.ok) {
        throw new Error(`Row action failed: ${actionLabel} (${value.reason || 'unknown'})`);
      }
    };

    const confirmDialog = async () => {
      await evalExpr(`(() => {
        const btn = Array.from(document.querySelectorAll('.v-dialog button, [role="dialog"] button'))
          .find(b => ['Delete','Confirm','Yes'].includes(b.textContent.trim()));
        if (btn) { btn.click(); return true; }
        return false;
      })()`);
    };

    const captureScreenshot = async (name) => {
      const baseName = sanitizeFilename(name);
      const filename = `${baseName}.png`;
      const filePath = path.join(SCREENSHOT_DIR, filename);
      const res = await client.send('Page.captureScreenshot', { format: 'png' }, sessionId);
      fs.writeFileSync(filePath, Buffer.from(res.data, 'base64'));
      return filename;
    };

    recordStep = async (name, fn, screenshotName) => {
      console.log(`[QA] ${name}`);
      const before = snapshotCounts();
      let status = 'pass';
      let error = '';
      let screenshot = '';
      try {
        await fn();
        try {
          const perf = await client.send('Performance.getMetrics', {}, sessionId);
          if (perf && Array.isArray(perf.metrics)) {
            logs.performanceMetrics.push({
              step: name,
              metrics: perf.metrics,
            });
          }
        } catch {
          // ignore perf errors
        }
      } catch (err) {
        status = 'fail';
        error = err.message || String(err);
      }
      if (screenshotName) {
        try {
          screenshot = await captureScreenshot(screenshotName);
        } catch (err) {
          status = status === 'fail' ? 'fail' : 'warn';
          error = error || `Screenshot failed: ${err.message || err}`;
        }
      }
      steps.push({
        name,
        status,
        error,
        screenshot,
        logs: sliceLogs(before),
      });
    };

    const basePath = new URL(QA_BASE_URL).pathname === '/' ? '' : new URL(QA_BASE_URL).pathname;

    await recordStep('Open dashboard', async () => {
      const load = client.send('Page.navigate', { url: QA_BASE_URL }, sessionId);
      await load;
      await waitFor('document.querySelector("#app")');
      await delay(1000);
    }, '01-dashboard');

    await recordStep('Navigate to Targets', async () => {
      await clickNav('Targets');
      await waitForPath(`${basePath}/targets`);
      await delay(1000);
    }, '02-targets');

    const testNetwork = `127.0.0.1/32`;

    await recordStep('Create Target', async () => {
      await setInputValue('input[placeholder="10.0.0.0/24"]', testNetwork);
      await clickButton('Add');
      await waitFor(`document.body.innerText.includes(${JSON.stringify(testNetwork)})`, 10000);
      await delay(1000);
    }, '03-target-added');

    await recordStep('Start Target', async () => {
      await clickRowAction(testNetwork, 'Start');
      await delay(1000);
    }, '04-target-started');

    await recordStep('Stop Target', async () => {
      await clickRowAction(testNetwork, 'Stop');
      await delay(1000);
    }, '05-target-stopped');

    await recordStep('Delete Target', async () => {
      await clickRowAction(testNetwork, 'Delete');
      await delay(1000);
      await confirmDialog();
      await delay(1000);
      await waitFor(`!document.body.innerText.includes(${JSON.stringify(testNetwork)})`, 10000);
    }, '06-target-deleted');

    const navItems = [
      { label: 'Ports', path: '/ports', shot: '07-ports' },
      { label: 'Banners', path: '/banners', shot: '08-banners' },
      { label: 'Tags', path: '/tags', shot: '09-tags' },
      { label: 'Catalog', path: '/catalog', shot: '10-catalog' },
      { label: 'API', path: '/api', shot: '11-api' },
      { label: 'Charts', path: '/charts', shot: '12-charts' },
      { label: 'Map', path: '/map', shot: '13-map' },
      { label: 'Explorer', path: '/explorer', shot: '14-explorer' },
      { label: 'Agents', path: '/agents', shot: '15-agents' },
    ];

    for (const item of navItems) {
      await recordStep(`Navigate to ${item.label}`, async () => {
        await clickNav(item.label);
        await waitForPath(`${basePath}${item.path}`);
        await delay(1000);
      }, item.shot);
    }

    await recordStep('Return to Dashboard', async () => {
      await clickNav('Dashboard');
      await waitForPath(`${basePath}/`);
      await delay(1000);
    }, '16-dashboard-return');

    // Build report
    const reportLines = [];
    reportLines.push('# QA Report');
    reportLines.push('');
    reportLines.push(`Date: ${nowIso()}`);
    reportLines.push(`Base URL: ${QA_BASE_URL}`);
    reportLines.push(`CDP: ${wsUrl}`);
    reportLines.push(`Viewport: ${VIEWPORT.width}x${VIEWPORT.height}`);
    reportLines.push('');

    const failed = steps.filter((s) => s.status === 'fail');
    const warned = steps.filter((s) => s.status === 'warn');

    reportLines.push('## Summary');
    reportLines.push(`Steps: ${steps.length}`);
    reportLines.push(`Failed: ${failed.length}`);
    reportLines.push(`Warnings: ${warned.length}`);
    reportLines.push('');

    reportLines.push('## Steps');
    for (const step of steps) {
      reportLines.push(`- ${step.status.toUpperCase()} - ${step.name}`);
      if (step.error) reportLines.push(`  Error: ${step.error}`);
      if (step.screenshot) reportLines.push(`  Screenshot: ${step.screenshot}`);
      const issues = [];
      if (step.logs.consoleErrors.length) issues.push(`console errors: ${step.logs.consoleErrors.length}`);
      if (step.logs.consoleWarnings.length) issues.push(`console warnings: ${step.logs.consoleWarnings.length}`);
      if (step.logs.logErrors.length) issues.push(`log errors: ${step.logs.logErrors.length}`);
      if (step.logs.networkErrors.length) issues.push(`network errors: ${step.logs.networkErrors.length}`);
      if (step.logs.networkFailures.length) issues.push(`network failures: ${step.logs.networkFailures.length}`);
      if (step.logs.runtimeExceptions.length) issues.push(`runtime exceptions: ${step.logs.runtimeExceptions.length}`);
      if (step.logs.securityStates.length) issues.push(`security state changes: ${step.logs.securityStates.length}`);
      if (step.logs.performanceMetrics.length) issues.push(`performance samples: ${step.logs.performanceMetrics.length}`);
      if (issues.length) reportLines.push(`  Observed: ${issues.join(', ')}`);
    }
    reportLines.push('');

    reportLines.push('## DevTools Signals');
    reportLines.push(`Console errors: ${logs.consoleErrors.length}`);
    reportLines.push(`Console warnings: ${logs.consoleWarnings.length}`);
    reportLines.push(`Log errors: ${logs.logErrors.length}`);
    reportLines.push(`Network errors (>=400): ${logs.networkErrors.length}`);
    reportLines.push(`Network failures: ${logs.networkFailures.length}`);
    reportLines.push(`Runtime exceptions: ${logs.runtimeExceptions.length}`);
    reportLines.push(`Security state changes: ${logs.securityStates.length}`);
    reportLines.push(`Performance samples: ${logs.performanceMetrics.length}`);
    reportLines.push('');

    if (logs.consoleErrors.length) {
      reportLines.push('### Console Errors');
      logs.consoleErrors.forEach((e) => reportLines.push(`- ${e || '(empty)'}`));
      reportLines.push('');
    }

    if (logs.consoleWarnings.length) {
      reportLines.push('### Console Warnings');
      logs.consoleWarnings.forEach((e) => reportLines.push(`- ${e || '(empty)'}`));
      reportLines.push('');
    }

    if (logs.logErrors.length) {
      reportLines.push('### Log Errors');
      logs.logErrors.forEach((e) => reportLines.push(`- ${e || '(empty)'}`));
      reportLines.push('');
    }

    if (logs.networkErrors.length) {
      reportLines.push('### Network Errors');
      logs.networkErrors.forEach((e) => reportLines.push(`- ${e.status} ${e.url}`));
      reportLines.push('');
    }

    if (logs.networkFailures.length) {
      reportLines.push('### Network Failures');
      logs.networkFailures.forEach((e) => reportLines.push(`- ${e.errorText} (${e.requestId})`));
      reportLines.push('');
    }

    if (logs.runtimeExceptions.length) {
      reportLines.push('### Runtime Exceptions');
      logs.runtimeExceptions.forEach((e) =>
        reportLines.push(`- ${e.text} ${e.url ? `(${e.url}:${e.line}:${e.column})` : ''}`)
      );
      reportLines.push('');
    }

    if (logs.securityStates.length) {
      reportLines.push('### Security State Changes');
      logs.securityStates.forEach((e) =>
        reportLines.push(`- state=${e.securityState} cryptographic=${e.schemeIsCryptographic}`)
      );
      reportLines.push('');
    }

    if (logs.performanceMetrics.length) {
      const lastPerf = logs.performanceMetrics[logs.performanceMetrics.length - 1];
      if (lastPerf && Array.isArray(lastPerf.metrics)) {
        reportLines.push('### Performance (Last Sample)');
        lastPerf.metrics
          .filter((m) => ['JSHeapUsedSize', 'JSHeapTotalSize', 'Documents', 'Frames', 'Nodes'].includes(m.name))
          .forEach((m) => reportLines.push(`- ${m.name}: ${m.value}`));
        reportLines.push('');
      }
    }

    const reportPath = path.join(QA_DIR, 'report.md');
    fs.writeFileSync(reportPath, reportLines.join('\n'));

    if (failed.length) {
      process.exitCode = 1;
    }
  } finally {
    try {
      if (targetId) await client.send('Target.closeTarget', { targetId });
    } catch {
      // ignore
    }
    client.close();
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
