/**
 * bundle-python.js — Bundles a portable Python environment for Electron packaging.
 * 
 * Platform support:
 *   - Windows: Downloads Python embeddable package, enables pip, installs deps
 *   - Linux:   Creates a venv from system Python, installs deps into it
 * 
 * Usage: node scripts/bundle-python.js
 */

const { execSync } = require('child_process');
const https = require('https');
const fs = require('fs');
const path = require('path');

const PYTHON_VERSION = '3.12.2';
const PYTHON_WIN_URL = `https://www.python.org/ftp/python/${PYTHON_VERSION}/python-${PYTHON_VERSION}-embed-amd64.zip`;
const GET_PIP_URL = 'https://bootstrap.pypa.io/get-pip.py';

const PROJECT_ROOT = path.resolve(__dirname, '..');
const PYTHON_DIR = path.join(PROJECT_ROOT, 'python');

const REQUIRED_PACKAGES = [
    'flask',
    'flask-cors',
    'cryptography',
];

const isWindows = process.platform === 'win32';

function download(url, dest) {
    return new Promise((resolve, reject) => {
        const file = fs.createWriteStream(dest);
        https.get(url, (response) => {
            if (response.statusCode >= 300 && response.statusCode < 400 && response.headers.location) {
                file.close();
                fs.unlinkSync(dest);
                download(response.headers.location, dest).then(resolve).catch(reject);
                return;
            }
            response.pipe(file);
            file.on('finish', () => { file.close(resolve); });
        }).on('error', (err) => {
            fs.unlinkSync(dest);
            reject(err);
        });
    });
}

// ─── Windows: Python Embeddable ───
async function bundleWindows() {
    const pythonZip = path.join(PROJECT_ROOT, 'python-embed.zip');

    if (!fs.existsSync(PYTHON_DIR)) {
        console.log(`Downloading Python ${PYTHON_VERSION} embeddable (Windows amd64)...`);
        await download(PYTHON_WIN_URL, pythonZip);
        console.log('Extracting...');
        execSync('Import-Module Microsoft.PowerShell.Archive -Force');
        execSync(`Expand-Archive -Force '${pythonZip}' '${PYTHON_DIR}'"`, { stdio: 'inherit' });
        fs.unlinkSync(pythonZip);
        console.log('  ✓ Python extracted\n');
    } else {
        console.log('  ✓ Python directory already exists\n');
    }

    // Enable pip: uncomment 'import site' in ._pth
    const pthFile = fs.readdirSync(PYTHON_DIR).find(f => f.endsWith('._pth'));
    if (pthFile) {
        const pthPath = path.join(PYTHON_DIR, pthFile);
        let content = fs.readFileSync(pthPath, 'utf-8');
        if (content.includes('#import site')) {
            content = content.replace('#import site', 'import site');
            fs.writeFileSync(pthPath, content);
            console.log('  ✓ Enabled site-packages\n');
        }
    }

    const pythonExe = path.join(PYTHON_DIR, 'python.exe');
    const pipExe = path.join(PYTHON_DIR, 'Scripts', 'pip.exe');
    const getPipPath = path.join(PYTHON_DIR, 'get-pip.py');

    if (!fs.existsSync(pipExe)) {
        console.log('Installing pip...');
        await download(GET_PIP_URL, getPipPath);
        execSync(`"${pythonExe}" "${getPipPath}" --no-warn-script-location`, { stdio: 'inherit', cwd: PYTHON_DIR });
        try { fs.unlinkSync(getPipPath); } catch (e) { }
        console.log('  ✓ pip installed\n');
    }

    console.log('Installing dependencies...');
    execSync(`"${pipExe}" install ${REQUIRED_PACKAGES.join(' ')} --no-warn-script-location`, {
        stdio: 'inherit', cwd: PYTHON_DIR,
    });
    console.log('  ✓ Dependencies installed\n');
}

// ─── Linux: Python venv ───
async function bundleLinux() {
    // Find system Python
    let pythonBin;
    for (const name of ['python3', 'python']) {
        try {
            execSync(`${name} --version`, { stdio: 'pipe' });
            pythonBin = name;
            break;
        } catch (e) { }
    }
    if (!pythonBin) {
        throw new Error('Python 3 not found. Install python3 and python3-venv.');
    }

    const version = execSync(`${pythonBin} --version`).toString().trim();
    console.log(`Using system ${version}\n`);

    if (!fs.existsSync(PYTHON_DIR)) {
        console.log('Creating portable venv...');
        execSync(`${pythonBin} -m venv "${PYTHON_DIR}"`, { stdio: 'inherit' });
        console.log('  ✓ venv created\n');
    } else {
        console.log('  ✓ Python venv already exists\n');
    }

    const pipExe = path.join(PYTHON_DIR, 'bin', 'pip');

    console.log('Installing dependencies...');
    execSync(`"${pipExe}" install ${REQUIRED_PACKAGES.join(' ')}`, {
        stdio: 'inherit', cwd: PROJECT_ROOT,
    });
    console.log('  ✓ Dependencies installed\n');
}

// ─── Main ───
async function main() {
    console.log('=== Python Bundler for Electron ===');
    console.log(`Platform: ${process.platform}\n`);

    if (isWindows) {
        await bundleWindows();
    } else {
        await bundleLinux();
    }

    console.log('=== Bundle complete! Ready for electron-builder ===');
}

main().catch((err) => {
    console.error('Bundle failed:', err.message);
    process.exit(1);
});
