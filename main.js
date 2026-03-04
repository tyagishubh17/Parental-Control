// main.js — Electron Main Process for Parental Control Dashboard
const { app, BrowserWindow, Tray, Menu, dialog, nativeImage } = require('electron');
const { spawn, execSync } = require('child_process');
const path = require('path');
const fs = require('fs');
const http = require('http');

// ─── Paths ───
const isDev = !app.isPackaged;
const resourcesPath = isDev ? __dirname : process.resourcesPath;
const pythonDir = path.join(resourcesPath, 'python');
const backendDir = isDev ? __dirname : path.join(resourcesPath, 'backend');
const serverScript = path.join(backendDir, 'server.py');

const pythonExe = (() => {
    const logFile = path.join(backendDir, 'electron_debug.txt');
    const log = (msg) => fs.appendFileSync(logFile, msg + '\n');
    log(`--- Selection Start: ${new Date().toISOString()} ---`);
    log(`backendDir: ${backendDir}`);

    const checkPython = (cmd) => {
        try {
            execSync(`${cmd} -c "import flask, flask_cors, cryptography, pynput, pyautogui, pyscreeze, PIL"`, { stdio: 'ignore' });
            return true;
        } catch (e) {
            log(`checkPython(${cmd}) failed`);
            return false;
        }
    };

    let selected = null;
    // 1. Try local virtual environment (.venv)
    const venvPython = process.platform === 'win32'
        ? path.join(backendDir, '.venv', 'Scripts', 'python.exe')
        : path.join(backendDir, '.venv', 'bin', 'python');

    if (fs.existsSync(venvPython)) {
        log(`Found .venv: ${venvPython}`);
        selected = venvPython;
    } else if (checkPython('python3')) { // 2. Try system Python3
        log(`Using system python3`);
        selected = 'python3';
    } else if (checkPython('python')) { // 3. Try system Python
        log(`Using system python`);
        selected = 'python';
    } else { // 4. Fallback to bundled Python
        if (process.platform === 'win32') {
            const bundled = path.join(pythonDir, 'python.exe');
            if (fs.existsSync(bundled)) {
                log(`Fallback to bundled: ${bundled}`);
                selected = bundled;
            }
        }
    }
    log(`Selected: ${selected}`);
    return selected;
})();

const PORT = 5000;
const BACKEND_URL = `http://127.0.0.1:${PORT}`;

let mainWindow = null;
let tray = null;
let serverProcess = null;
let isQuitting = false;

// ─── Server Management ───

function isServerRunning() {
    return new Promise((resolve) => {
        const req = http.get(`${BACKEND_URL}/api/auth/check`, (res) => {
            resolve(res.statusCode === 200);
        });
        req.on('error', () => resolve(false));
        req.setTimeout(2000, () => { req.destroy(); resolve(false); });
    });
}

function waitForServer(maxAttempts = 30) {
    return new Promise((resolve, reject) => {
        let attempts = 0;
        const check = () => {
            attempts++;
            isServerRunning().then((running) => {
                if (running) {
                    resolve();
                } else if (attempts >= maxAttempts) {
                    reject(new Error('Server failed to start'));
                } else {
                    setTimeout(check, 1000);
                }
            });
        };
        check();
    });
}

function startServer() {
    return new Promise(async (resolve, reject) => {
        // Check if server is already running
        const alreadyRunning = await isServerRunning();
        if (alreadyRunning) {
            console.log('[Electron] Server already running');
            return resolve();
        }

        if (!pythonExe) {
            return reject(new Error('Python not found. Install Python 3.x or bundle it.'));
        }

        console.log(`[Electron] Starting server: ${pythonExe} ${serverScript}`);

        const env = {
            ...process.env,
            PYTHONUTF8: '1'
        };
        // On Windows, set creation flags to hide console window
        const options = {
            cwd: backendDir,
            env,
            stdio: ['ignore', 'pipe', 'pipe'],
        };

        if (process.platform === 'win32') {
            options.windowsHide = true;
        }

        serverProcess = spawn(pythonExe, [serverScript, '--headless', '--port', String(PORT)], options);

        serverProcess.stdout.on('data', (data) => {
            console.log(`[Server] ${data.toString().trim()}`);
        });

        serverProcess.stderr.on('data', (data) => {
            console.error(`[Server] ${data.toString().trim()}`);
        });

        serverProcess.on('error', (err) => {
            console.error('[Electron] Failed to start server:', err);
            reject(err);
        });

        serverProcess.on('exit', (code) => {
            console.log(`[Electron] Server exited with code ${code}`);
            serverProcess = null;
        });

        // Wait for it to be ready
        try {
            await waitForServer(60);
            console.log('[Electron] Server is ready');
            resolve();
        } catch (e) {
            reject(e);
        }
    });
}

function stopServer() {
    if (serverProcess) {
        console.log('[Electron] Stopping server...');
        if (process.platform === 'win32') {
            spawn('taskkill', ['/pid', String(serverProcess.pid), '/f', '/t']);
        } else {
            serverProcess.kill('SIGTERM');
        }
        serverProcess = null;
    }

    // Also clean PID file
    const pidFile = path.join(backendDir, 'server.pid');
    try { fs.unlinkSync(pidFile); } catch (e) { }
}

// ─── Window Management ───

function createWindow() {
    mainWindow = new BrowserWindow({
        width: 1280,
        height: 850,
        minWidth: 900,
        minHeight: 600,
        title: 'Parental Control Dashboard',
        icon: path.join(resourcesPath, 'assets', 'icon.png'),
        webPreferences: {
            preload: path.join(__dirname, 'preload.js'),
            contextIsolation: true,
            nodeIntegration: false,
        },
        show: false,
        backgroundColor: '#020617',
    });

    mainWindow.loadURL(BACKEND_URL);

    mainWindow.once('ready-to-show', () => {
        mainWindow.show();
    });

    // Minimize to tray on close (don't quit)
    mainWindow.on('close', (event) => {
        if (!isQuitting) {
            event.preventDefault();
            mainWindow.hide();
        }
    });

    mainWindow.on('closed', () => {
        mainWindow = null;
    });
}

// ─── System Tray ───

function createTray() {
    const iconPath = path.join(resourcesPath, 'assets', 'tray-icon.png');
    let trayIcon;

    if (fs.existsSync(iconPath)) {
        trayIcon = nativeImage.createFromPath(iconPath);
    } else {
        // Fallback: create a minimal 16x16 icon
        trayIcon = nativeImage.createEmpty();
    }

    tray = new Tray(trayIcon);
    tray.setToolTip('Parental Control Dashboard');

    const contextMenu = Menu.buildFromTemplate([
        {
            label: 'Open Dashboard',
            click: () => {
                if (mainWindow) {
                    mainWindow.show();
                    mainWindow.focus();
                } else {
                    createWindow();
                }
            },
        },
        { type: 'separator' },
        {
            label: 'Quit',
            click: () => {
                isQuitting = true;
                stopServer();
                app.quit();
            },
        },
    ]);

    tray.setContextMenu(contextMenu);

    tray.on('double-click', () => {
        if (mainWindow) {
            mainWindow.show();
            mainWindow.focus();
        } else {
            createWindow();
        }
    });
}

// ─── App Lifecycle ───

// Single instance lock — prevent multiple windows
const gotLock = app.requestSingleInstanceLock();
if (!gotLock) {
    app.quit();
} else {
    app.on('second-instance', () => {
        if (mainWindow) {
            if (mainWindow.isMinimized()) mainWindow.restore();
            mainWindow.show();
            mainWindow.focus();
        }
    });
}

app.on('ready', async () => {
    try {
        await startServer();
    } catch (err) {
        dialog.showErrorBox(
            'Server Error',
            `Could not start the backend server.\n\n${err.message}\n\nMake sure Python 3 is installed.`
        );
        app.quit();
        return;
    }

    createTray();
    createWindow();
});

app.on('window-all-closed', () => {
    // Don't quit — keep tray alive
});

app.on('before-quit', () => {
    isQuitting = true;
    stopServer();
});

app.on('activate', () => {
    if (mainWindow === null) {
        createWindow();
    }
});
