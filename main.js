import init, { Emulator, set_log_level, parse_elf_structure, parse_pe_structure } from './pkg/binb_web.js';
import { t, setLang, applyTranslations, getLang } from './i18n.js';

// ── State ───────────────────────────────────────────────────────────────────

let emulator = null;
let elfBytes = null;
/** ELF file name for argv[0] when passing arguments. */
let elfFileName = 'program';
/** Decompressed sysroot files from ZIP: { paths: string[], data: Uint8Array[], fileName: string }. */
let pendingSysrootFiles = null;
/** Set of VFS paths that came from the sysroot ZIP (no leading slash, for display tag). */
let sysrootPathSet = null;

/**
 * Normalize a sysroot file path for Windows PE VFS so the loader finds DLLs at /Windows/System32/*.dll.
 * Returns a path with lowercase filename so VFS lookup matches the PE loader (which looks up
 * /Windows/System32/msvcrt.dll etc.).
 * - "Windows/System32/ntdll.dll" or "Windows/System32/MSVCRT.DLL" → "Windows/System32/ntdll.dll", "Windows/System32/msvcrt.dll"
 * - "System32/ntdll.dll" → "Windows/System32/ntdll.dll"
 * - "ntdll.dll" → "Windows/System32/ntdll.dll"
 */
function pathForPeVfs(path) {
    const p = path.replace(/\\/g, '/').trim();
    let out;
    if (/^windows\/system32\//i.test(p)) {
        out = p;
    } else if (/^system32\//i.test(p)) {
        out = 'Windows/System32/' + p.slice(9);
    } else if (/\.dll$/i.test(p) && p.indexOf('/') === -1) {
        out = 'Windows/System32/' + p;
    } else {
        return p;
    }
    // Use lowercase filename so VFS key matches PE loader lookup (/Windows/System32/msvcrt.dll)
    const lastSlash = out.lastIndexOf('/');
    if (lastSlash !== -1) {
        out = out.slice(0, lastSlash + 1) + out.slice(lastSlash + 1).toLowerCase();
    }
    return out;
}
/** Currently selected VFS file path for viewer/editor. */
let selectedVfsPath = null;
let previousRegs = {};
let animFrame = null;
let isRunning = false;
/** True when we last stopped due to a breakpoint; next Run will call continue_execution() once to step past it. */
let lastStoppedAtBreakpoint = false;
const DISASM_LINES = 30;
const MEM_BYTES_PER_LINE = 32;
const MEM_LINES = 36;

// Trace / timeless debugger state
let traceMode = false;       // true when browsing recorded trace (not live)
let traceCursor = 0;          // local index into trace buffer
let focusedGprIndex = null;  // for register seek shortcut (Ctrl+[ / Ctrl+])
let traceMemAccesses = null;  // cached mem accesses at current trace position

// Data address tracking (QIRA-style daddr)
let daddr = null;            // { addr: number, size: number } or null
let watchList = [];          // [{addr, size, label}]
let elfFunctions = [];       // [{name, addr, size, bind, source}] from ELF symbols
let fnAddrMap = new Map();   // addr → name, rebuilt when elfFunctions changes

// Last step accesses (for non-trace mode highlighting)
let lastMemAccesses = [];

// Memory search: query string, matches in current view [{start,end}], current match index
let memSearchQuery = '';
let memSearchMatches = [];
let memSearchCurrentIndex = -1;

// Disassembly search: query, match line indices, current index
let disasmSearchQuery = '';
let disasmSearchMatches = [];
let disasmSearchCurrentIndex = -1;

// Strace/syscall search: query, match line indices, current index
let straceSearchQuery = '';
let straceSearchMatches = [];
let straceSearchCurrentIndex = -1;

// Tenet-style timeline zoom state
let tlZoomStart = 0;         // local index of left edge of zoomed view
let tlZoomEnd = 0;           // local index of right edge (exclusive)
let tlIaddrBreakpoint = null; // RIP address for execution breakpoint markers (number or null)
let tlDragging = false;      // true during drag-to-zoom selection
let tlDragStartX = 0;        // px coordinate where drag started
let tlDragEndX = 0;          // px coordinate where drag currently is

// ── Entropy utilities ────────────────────────────────────────────────────────

/**
 * Compute Shannon entropy (0–8 bits) of a byte array.
 * Returns 0 for empty/uniform data, up to 8.0 for perfectly random data.
 */
function computeEntropy(bytes, offset, length) {
    const off = offset || 0;
    const len = length || bytes.length - off;
    if (len <= 0) return 0;
    const freq = new Uint32Array(256);
    for (let i = 0; i < len; i++) freq[bytes[off + i]]++;
    let h = 0;
    for (let i = 0; i < 256; i++) {
        if (freq[i] === 0) continue;
        const p = freq[i] / len;
        h -= p * Math.log2(p);
    }
    return h;
}

/**
 * Map entropy value (0–8) to an RGB color string.
 * Blue (low/uniform) → Cyan → Green → Yellow → Orange → Red → Magenta (high/random).
 */
function entropyToColor(e) {
    // Clamp and normalize to 0–1
    const t = Math.min(Math.max(e / 8, 0), 1);
    // Multi-stop gradient: 0=dark blue, 0.15=blue, 0.3=cyan, 0.45=green, 0.6=yellow, 0.75=orange, 0.9=red, 1.0=magenta
    const stops = [
        [0.00, 10, 10, 40],
        [0.10, 20, 40, 120],
        [0.25, 30, 140, 200],
        [0.40, 40, 200, 100],
        [0.55, 200, 220, 40],
        [0.70, 240, 160, 20],
        [0.85, 230, 50, 30],
        [1.00, 200, 40, 180],
    ];
    let lo = stops[0], hi = stops[stops.length - 1];
    for (let i = 0; i < stops.length - 1; i++) {
        if (t >= stops[i][0] && t <= stops[i + 1][0]) { lo = stops[i]; hi = stops[i + 1]; break; }
    }
    const f = lo[0] === hi[0] ? 0 : (t - lo[0]) / (hi[0] - lo[0]);
    const r = Math.round(lo[1] + f * (hi[1] - lo[1]));
    const g = Math.round(lo[2] + f * (hi[2] - lo[2]));
    const b = Math.round(lo[3] + f * (hi[3] - lo[3]));
    return `rgb(${r},${g},${b})`;
}

// ── DOM refs ────────────────────────────────────────────────────────────────

const btnUpload    = document.getElementById('btn-upload');
const elfUpload    = document.getElementById('elf-upload');
const fileName     = document.getElementById('file-name');
const fileInfoBadge = document.getElementById('file-info-badge');
const sysrootZipUpload = document.getElementById('sysroot-zip-upload');
const btnDemo          = document.getElementById('btn-demo');
const btnSysrootZip    = document.getElementById('btn-sysroot-zip');
const sysrootName     = document.getElementById('sysroot-name');
const sysrootFileLabel = document.getElementById('sysroot-file-label');
const btnSysrootClear  = document.getElementById('btn-sysroot-clear');
const quickSysrootSelect = document.getElementById('quick-sysroot');
const programArgs     = document.getElementById('program-args');
const btnContinue  = document.getElementById('btn-continue');
const btnRun       = document.getElementById('btn-run');
const btnStep      = document.getElementById('btn-step');
const btnStepOver  = document.getElementById('btn-step-over');
const btnStep100   = document.getElementById('btn-step-100');
const stepNSelect  = document.getElementById('step-n-select');
const btnStop      = document.getElementById('btn-stop');
const btnReset     = document.getElementById('btn-reset');
const terminal     = document.getElementById('terminal-output');
const stdinPrompt  = document.getElementById('stdin-prompt');
const stdinPromptCount = document.getElementById('stdin-prompt-count');
const stdinInput   = document.getElementById('stdin-input');
const btnStdinSend = document.getElementById('btn-stdin-send');
const statusBadge  = document.getElementById('status-badge');
const modeBadge    = document.getElementById('mode-badge');
const registerDisp = document.getElementById('register-display');
const callstackList = document.getElementById('callstack-list');
const disasmList   = document.getElementById('disasm-listing');
const infoRip      = document.getElementById('info-rip');
const infoDisasm   = document.getElementById('info-disasm');
const infoCount    = document.getElementById('info-count');
const infoFlags    = document.getElementById('info-flags');
const infoDaddr    = document.getElementById('info-daddr');
const logLevel     = document.getElementById('log-level');
const straceToggle = document.getElementById('strace-toggle');
const straceOutput = document.getElementById('strace-output');
const bpAddrInput  = document.getElementById('bp-addr');
const btnBpAdd     = document.getElementById('btn-bp-add');
const bpSyscallInput = document.getElementById('bp-syscall');
const btnBpSyscallAdd = document.getElementById('btn-bp-syscall-add');
const bpAnySyscall   = document.getElementById('bp-any-syscall');
const bpList       = document.getElementById('bp-list');
const memAddr      = document.getElementById('mem-addr');
const btnMemGo     = document.getElementById('btn-mem-go');
const btnMemStack  = document.getElementById('btn-mem-stack');
const btnMemRip    = document.getElementById('btn-mem-rip');
const btnMemPgUp   = document.getElementById('btn-mem-pgup');
const btnMemPgDn   = document.getElementById('btn-mem-pgdn');
const btnMemWatch  = document.getElementById('btn-mem-watch');
const memAutoRefresh = document.getElementById('mem-auto-refresh');
const memoryDump   = document.getElementById('memory-dump');
const memInfo      = document.getElementById('mem-info');
const memSearchInput = document.getElementById('mem-search');
const memSearchMode = document.getElementById('mem-search-mode');
const btnMemSearchAll = document.getElementById('btn-mem-search-all');
const btnMemSearchPrev = document.getElementById('btn-mem-search-prev');
const btnMemSearchNext = document.getElementById('btn-mem-search-next');
const memSearchSpinner = document.getElementById('mem-search-spinner');
const memSearchStatus = document.getElementById('mem-search-status');
const disasmSearchInput = document.getElementById('disasm-search');
const disasmSearchMode = document.getElementById('disasm-search-mode');
const btnDisasmSearchPrev = document.getElementById('btn-disasm-search-prev');
const btnDisasmSearchNext = document.getElementById('btn-disasm-search-next');
const disasmSearchStatus = document.getElementById('disasm-search-status');
const straceSearchInput = document.getElementById('strace-search');
const straceSearchMode = document.getElementById('strace-search-mode');
const btnStraceSearchPrev = document.getElementById('btn-strace-search-prev');
const btnStraceSearchNext = document.getElementById('btn-strace-search-next');
const straceSearchStatus = document.getElementById('strace-search-status');
const memmapList   = document.getElementById('memmap-list');
const traceToggle  = document.getElementById('trace-toggle');
const timelineBar  = document.getElementById('timeline-bar');
const timelineCanvas = document.getElementById('timeline-canvas');
const timelineWrap = document.getElementById('timeline-canvas-wrap');
const timelineSelection = document.getElementById('timeline-selection');
const timelineCursor = document.getElementById('timeline-cursor');
const timelineSlider = document.getElementById('timeline-slider');
const tracePosition = document.getElementById('trace-position');
const btnTraceStart = document.getElementById('btn-trace-start');
const btnTraceBack  = document.getElementById('btn-trace-back');
const btnTraceBack10 = document.getElementById('btn-trace-back10');
const btnTraceFwd   = document.getElementById('btn-trace-fwd');
const btnTraceFwd10 = document.getElementById('btn-trace-fwd10');
const btnTraceEnd   = document.getElementById('btn-trace-end');
const btnTraceLive  = document.getElementById('btn-trace-live');
const btnZoomReset  = document.getElementById('btn-zoom-reset');
const zoomInfo      = document.getElementById('zoom-info');
const accessesList  = document.getElementById('accesses-list');
const accessesInfo  = document.getElementById('accesses-info');
const accessesMemDump = document.getElementById('accesses-mem-dump');
const accessesMemAddr = document.getElementById('accesses-mem-addr');
const watchAddrInput = document.getElementById('watch-addr');
const watchSizeInput = document.getElementById('watch-size');
const btnWatchAdd   = document.getElementById('btn-watch-add');
const watchListEl   = document.getElementById('watch-list');
const regionHistoryPlaceholder = document.getElementById('region-history-placeholder');
const regionHistoryTable = document.getElementById('region-history-table');
const regionHistoryTbody = document.getElementById('region-history-tbody');
const btnHistoryCopyCsv = document.getElementById('btn-history-copy-csv');
const vfsPathInput = document.getElementById('vfs-path-input');
const vfsDropZone = document.getElementById('vfs-drop-zone');
const vfsFileInput = document.getElementById('vfs-file-input');
const vfsList = document.getElementById('vfs-list');
const vfsListPlaceholder = document.getElementById('vfs-list-placeholder');
const vfsFilterSelect = document.getElementById('vfs-filter');
const vfsDetail = document.getElementById('vfs-detail');
const vfsDetailPath = document.getElementById('vfs-detail-path');
const vfsDetailText = document.getElementById('vfs-detail-text');
const vfsDetailBinary = document.getElementById('vfs-detail-binary');
const vfsDetailSize = document.getElementById('vfs-detail-size');
const vfsDetailSave = document.getElementById('vfs-detail-save');
const shellcodePanel = document.getElementById('shellcode-panel');
const shellcodePaste = document.getElementById('shellcode-paste');
const shellcodeArch = document.getElementById('shellcode-arch');
const shellcodeDemo = document.getElementById('shellcode-demo');
const btnLoadPaste = document.getElementById('btn-load-paste');
const shellcodeFilePrompt = document.getElementById('shellcode-file-prompt');
const shellcodeFileArch = document.getElementById('shellcode-file-arch');
const btnLoadFileShellcode = document.getElementById('btn-load-file-shellcode');
const btnDismissShellcodePrompt = document.getElementById('btn-dismiss-shellcode-prompt');
const btnShellcodeToggle = document.getElementById('btn-shellcode-toggle');
const btnSaveSnapshot = document.getElementById('btn-save-snapshot');
const btnLoadSnapshot = document.getElementById('btn-load-snapshot');
const snapshotUpload  = document.getElementById('snapshot-upload');

/** Pending raw bytes when user uploaded a non-ELF file; we offer "Load as shellcode". */
let pendingShellcodeBytes = null;

// ── Initialisation ──────────────────────────────────────────────────────────

async function boot() {
    await init();
    console.log('[binb] WASM module loaded');
    enableDragDrop();
    setupLogControls();
    setupTabs();
    setupVfsPanel();
    setupShellcodePanel();
    setupKeyboard();
    setupHelpModal();
    setupSummaryModal();
    setupI18n();
    // Build entropy legend gradient in memory controls
    const eLegend = document.getElementById('mem-entropy-legend-bar');
    if (eLegend) {
        let spans = '';
        for (let i = 0; i <= 16; i++) {
            spans += `<span style="flex:1;min-width:1px;background:${entropyToColor(i / 16 * 8)}"></span>`;
        }
        eLegend.innerHTML = spans;
    }
}

boot();

// ── Help Modal ───────────────────────────────────────────────────────────────

function setupHelpModal() {
    const modal = document.getElementById('help-modal');
    const btnOpen = document.getElementById('btn-help');
    const btnClose = document.getElementById('btn-help-close');
    if (!modal || !btnOpen) return;

    btnOpen.addEventListener('click', () => { modal.style.display = 'flex'; });
    btnClose.addEventListener('click', () => { modal.style.display = 'none'; });
    modal.addEventListener('click', (e) => {
        if (e.target === modal) modal.style.display = 'none';
    });
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && modal.style.display === 'flex') {
            modal.style.display = 'none';
            e.stopPropagation();
        }
    });
}

function setupSummaryModal() {
    const modal = document.getElementById('summary-modal');
    const btnOpen = document.getElementById('btn-summary');
    const btnClose = document.getElementById('btn-summary-close');
    if (!modal || !btnOpen) return;

    btnOpen.addEventListener('click', () => { modal.style.display = 'flex'; });
    btnClose.addEventListener('click', () => { modal.style.display = 'none'; });
    modal.addEventListener('click', (e) => {
        if (e.target === modal) modal.style.display = 'none';
    });
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && modal.style.display === 'flex') {
            modal.style.display = 'none';
            e.stopPropagation();
        }
    });
}

function applyTheme(theme, options) {
    const opts = options || {};
    const v = ['dark', 'light', 'unicorn', 'rainbow', 'nyan'].includes(theme) ? theme : 'dark';
    document.documentElement.setAttribute('data-theme', v);
    try { localStorage.setItem('binb-theme', v); } catch (_) {}
    const themeSelect = document.getElementById('theme-select');
    if (themeSelect) themeSelect.value = v;

    if (v === 'nyan' && opts.playNyan !== false) {
        playNyanCatRun();
    }
}

function playNyanCatRun() {
    const container = document.getElementById('nyan-cat-container');
    if (!container) return;
    const run = container.querySelector('.nyan-cat-run');
    if (!run) return;
    run.style.animation = 'none';
    run.offsetHeight;
    container.classList.add('nyan-cat-visible');
    run.style.animation = '';
    setTimeout(() => {
        container.classList.remove('nyan-cat-visible');
    }, 4800);
}

function setupI18n() {
    applyTranslations();
    setStatus('statusIdle');
    const themeSelect = document.getElementById('theme-select');
    if (themeSelect) {
        try {
            const saved = localStorage.getItem('binb-theme');
            if (['dark', 'light', 'unicorn', 'rainbow', 'nyan'].includes(saved)) {
                applyTheme(saved, { playNyan: false });
            } else {
                themeSelect.value = 'dark';
            }
        } catch (_) {
            themeSelect.value = 'dark';
        }
        themeSelect.addEventListener('change', () => {
            applyTheme(themeSelect.value);
        });
    }
    const langSelect = document.getElementById('lang-select');
    if (langSelect) {
        langSelect.value = getLang();
        langSelect.addEventListener('change', () => setLang(langSelect.value));
    }
    window.addEventListener('langchange', () => {
        if (fileName && !elfBytes && !pendingShellcodeBytes) fileName.textContent = t('fileNoFile');
        if (statusBadge) setStatus(_statusKey, _statusCls, _statusParam);
        if (daddr) updateDaddrDisplay();
    });
}
let _statusKey = 'statusIdle';
let _statusCls = '';
let _statusParam = undefined;

// ── Helpers ─────────────────────────────────────────────────────────────────

function isElf(bytes) {
    return bytes.length >= 4 && bytes[0] === 0x7f && bytes[1] === 0x45 && bytes[2] === 0x4c && bytes[3] === 0x46;
}

/** Detect Windows PE (EXE/DLL): MZ at 0, "PE\0\0" at e_lfanew. */
function isPe(bytes) {
    if (bytes.length < 64) return false;
    if (bytes[0] !== 0x4d || bytes[1] !== 0x5a) return false; // MZ
    const e_lfanew = bytes[0x3c] | (bytes[0x3d] << 8) | (bytes[0x3e] << 16) | (bytes[0x3f] << 24);
    if (e_lfanew + 4 > bytes.length) return false;
    return bytes[e_lfanew] === 0x50 && bytes[e_lfanew + 1] === 0x45 && bytes[e_lfanew + 2] === 0 && bytes[e_lfanew + 3] === 0;
}

// ── File loading ────────────────────────────────────────────────────────────

btnUpload.addEventListener('click', () => elfUpload.click());

if (btnDemo) {
    btnDemo.addEventListener('click', async () => {
        const demoUrl = 'examples/c/hello-x64';
        setStatus('statusLoading');
        try {
            const resp = await fetch(demoUrl);
            if (!resp.ok) {
                terminal.innerHTML = `<span class="error">Demo failed: ${resp.status} ${resp.statusText}. Ensure the app is served with \`${demoUrl}\` available (e.g. from repo root).</span>\n`;
                setStatus('statusReady');
                return;
            }
            const bytes = new Uint8Array(await resp.arrayBuffer());
            elfBytes = bytes;
            elfFileName = 'hello-x64';
            fileName.textContent = 'hello-x64';
            await updateFileInfoBadge('hello-x64', bytes);
            if (isElf(bytes)) {
                pendingShellcodeBytes = null;
                hideShellcodeFilePrompt();
                await fetchDemoSysrootIfNeeded(bytes, false);
                createEmulator(bytes);
            } else if (isPe(bytes)) {
                pendingShellcodeBytes = null;
                hideShellcodeFilePrompt();
                await fetchDemoSysrootIfNeeded(bytes, true);
                createEmulator(bytes, { asPe: true });
            } else {
                pendingShellcodeBytes = bytes;
                showShellcodeFilePrompt();
            }
        } catch (e) {
            terminal.innerHTML = `<span class="error">Demo failed: ${escapeHtml(String(e.message || e))}. Ensure the app is served with \`${demoUrl}\` available.</span>\n`;
            setStatus('statusReady');
        }
    });
}

function showSysrootStatus(msg, isError = false) {
    if (terminal) {
        const span = document.createElement('span');
        span.className = isError ? 'error' : 'info';
        span.textContent = msg;
        terminal.appendChild(span);
        terminal.appendChild(document.createTextNode('\n'));
        terminal.scrollTop = terminal.scrollHeight;
    }
    console.log('[binb] sysroot:', msg);
}

/**
 * Load sysroot from a ZIP blob (File or Blob from fetch). Sets pendingSysrootFiles,
 * updates UI, and reloads emulator if a binary is already loaded.
 * @param {Blob} blob - ZIP file as Blob
 * @param {string} fileName - Display name (e.g. file.name or URL basename)
 */
async function loadSysrootFromZipBlob(blob, fileName) {
    if (typeof JSZip === 'undefined') {
        showSysrootStatus('Error: JSZip library not loaded. Add the script tag or check network.', true);
        return;
    }
    if (sysrootFileLabel) sysrootFileLabel.textContent = t('loading');
    if (sysrootName) sysrootName.style.display = '';
    try {
        const zip = await JSZip.loadAsync(blob);
        const paths = [];
        const data = [];
        const entries = Object.entries(zip.files);
        for (const [name, entry] of entries) {
            if (entry.dir || name.endsWith('/')) continue;
            let path = name.replace(/^\.\//, '').replace(/^\/+/, '').replace(/\\/g, '/');
            if (!path) continue;
            const firstSlash = path.indexOf('/');
            if (firstSlash !== -1) {
                const first = path.slice(0, firstSlash);
                if (first.toLowerCase().includes('sysroot')) path = path.slice(firstSlash + 1);
            }
            if (!path) continue;
            const bytes = await entry.async('uint8array');
            paths.push(path);
            data.push(bytes);
        }
        pendingSysrootFiles = { paths, data, fileName };
        sysrootPathSet = new Set(paths);
        if (sysrootFileLabel) sysrootFileLabel.textContent = `${fileName} (${paths.length} files)`;
        showSysrootStatus('Sysroot loaded: ' + paths.length + ' files from ' + fileName + '. Load or reload an ELF to use it.');
        renderVfsList();
        if (elfBytes && elfBytes.length > 0 && (isElf(elfBytes) || isPe(elfBytes))) {
            showSysrootStatus('Reloading binary with sysroot…');
            createEmulator(elfBytes, isPe(elfBytes) ? { asPe: true } : {});
            showSysrootStatus('Binary reloaded with ' + paths.length + ' VFS files.');
            if (vfsFilterSelect) vfsFilterSelect.value = 'all';
            renderVfsList();
        }
    } catch (err) {
        const msg = 'Failed to decompress sysroot ZIP: ' + (err.message || err);
        showSysrootStatus(msg, true);
        console.error('[binb] sysroot ZIP error:', err);
        pendingSysrootFiles = null;
        sysrootPathSet = null;
        if (sysrootName) sysrootName.style.display = 'none';
        if (sysrootFileLabel) sysrootFileLabel.textContent = '';
    }
}

if (btnSysrootZip) {
    btnSysrootZip.addEventListener('click', () => {
        if (!sysrootZipUpload) {
            showSysrootStatus('Sysroot (ZIP): file input not found.', true);
            return;
        }
        sysrootZipUpload.click();
    });
} else {
    showSysrootStatus('Sysroot (ZIP) button not found.', true);
}
if (sysrootZipUpload) {
    sysrootZipUpload.addEventListener('change', async (e) => {
        const file = e.target.files[0];
        showSysrootStatus('Sysroot ZIP: file selected, processing…');
        if (!file) {
            showSysrootStatus('Sysroot ZIP: no file selected.', true);
            e.target.value = '';
            return;
        }
        showSysrootStatus('Sysroot ZIP: ' + file.name + ' (' + file.size + ' bytes)');
        await loadSysrootFromZipBlob(file, file.name);
        e.target.value = '';
    });
} else {
    showSysrootStatus('Sysroot (ZIP) file input not found.', true);
}
if (btnSysrootClear) {
    btnSysrootClear.addEventListener('click', () => {
        pendingSysrootFiles = null;
        sysrootPathSet = null;
        if (sysrootName) sysrootName.style.display = 'none';
        if (sysrootFileLabel) sysrootFileLabel.textContent = '';
        if (emulator) renderVfsList();
    });
}

if (quickSysrootSelect) {
    quickSysrootSelect.addEventListener('change', async () => {
        const url = quickSysrootSelect.value;
        if (!url) return;
        const fileName = url.split('/').pop() || url;
        showSysrootStatus('Quick sysroot: loading ' + fileName + '…');
        try {
            const resp = await fetch(url);
            if (!resp.ok) {
                showSysrootStatus('Quick sysroot failed: ' + resp.status + ' ' + resp.statusText + '.', true);
                quickSysrootSelect.value = '';
                return;
            }
            const blob = await resp.blob();
            await loadSysrootFromZipBlob(blob, fileName);
        } catch (e) {
            showSysrootStatus('Quick sysroot failed: ' + (e.message || e) + '.', true);
        }
        quickSysrootSelect.value = '';
    });
}

elfUpload.addEventListener('change', async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    await loadFile(file);
});

function parseProgramArgs(str) {
    if (!str || typeof str !== 'string') return [];
    return str.trim().split(/\s+/).filter(Boolean);
}

async function loadFile(file) {
    const bytes = new Uint8Array(await file.arrayBuffer());
    elfBytes = bytes;
    elfFileName = file.name || 'program';
    fileName.textContent = file.name;
    updateFileInfoBadge(file.name, bytes);
    if (isElf(bytes)) {
        pendingShellcodeBytes = null;
        hideShellcodeFilePrompt();
        await fetchDemoSysrootIfNeeded(bytes, false);
        console.log('[binb] ELF loaded, sysroot set?', !!pendingSysrootFiles, pendingSysrootFiles ? pendingSysrootFiles.paths.length + ' files' : '');
        createEmulator(bytes);
    } else if (isPe(bytes)) {
        pendingShellcodeBytes = null;
        hideShellcodeFilePrompt();
        await fetchDemoSysrootIfNeeded(bytes, true);
        console.log('[binb] PE loaded, sysroot set?', !!pendingSysrootFiles, pendingSysrootFiles ? pendingSysrootFiles.paths.length + ' files' : '');
        createEmulator(bytes, { asPe: true });
    } else {
        pendingShellcodeBytes = bytes;
        showShellcodeFilePrompt();
    }
}

// ── File info badge & popup ─────────────────────────────────────────────────

/** Compute SHA-256 of a Uint8Array and return hex string. */
async function sha256hex(data) {
    const hashBuf = await crypto.subtle.digest('SHA-256', data);
    return Array.from(new Uint8Array(hashBuf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

/** Detect ELF arch/class from header bytes. */
function elfArchString(bytes) {
    if (bytes.length < 20) return 'unknown';
    const ei_class = bytes[4]; // 1=32-bit, 2=64-bit
    const e_machine_lo = bytes[18];
    const e_machine_hi = bytes[19];
    const e_machine = e_machine_lo | (e_machine_hi << 8);
    const bits = ei_class === 1 ? '32' : ei_class === 2 ? '64' : '?';
    const arch = { 3: 'x86', 62: 'x86_64', 183: 'ARM64', 40: 'ARM', 8: 'MIPS', 21: 'PPC64' }[e_machine] || `EM ${e_machine}`;
    return `${arch} (${bits}-bit)`;
}

/** Detect ELF type (ET_EXEC / ET_DYN / ET_REL). */
function elfTypeString(bytes) {
    if (bytes.length < 18) return 'unknown';
    const et = bytes[16] | (bytes[17] << 8);
    return { 1: 'ET_REL (relocatable)', 2: 'ET_EXEC (executable)', 3: 'ET_DYN (shared/PIE)', 4: 'ET_CORE' }[et] || `ET ${et}`;
}

/** Detect PE arch from COFF header (after e_lfanew). */
function peArchString(bytes) {
    if (!isPe(bytes)) return 'unknown';
    const e_lfanew = bytes[0x3c] | (bytes[0x3d] << 8) | (bytes[0x3e] << 16) | (bytes[0x3f] << 24);
    const machineOff = e_lfanew + 4; // COFF header starts at e_lfanew+4, machine is first field
    if (machineOff + 2 > bytes.length) return 'unknown';
    const machine = bytes[machineOff] | (bytes[machineOff + 1] << 8);
    return { 0x14c: 'x86 (32-bit)', 0x8664: 'x86-64 (64-bit)', 0xaa64: 'ARM64' }[machine] || `Machine 0x${machine.toString(16)}`;
}

/** Detect PE type: EXE or DLL (IMAGE_FILE_DLL = 0x2000 in characteristics). */
function peTypeString(bytes) {
    if (!isPe(bytes)) return 'unknown';
    const e_lfanew = bytes[0x3c] | (bytes[0x3d] << 8) | (bytes[0x3e] << 16) | (bytes[0x3f] << 24);
    const charsOff = e_lfanew + 22; // Characteristics at offset 22 in COFF header
    if (charsOff + 2 > bytes.length) return 'PE';
    const ch = bytes[charsOff] | (bytes[charsOff + 1] << 8);
    return (ch & 0x2000) ? 'DLL' : 'EXE';
}

/** Return 'static' or 'dynamic' for ELF (based on PT_INTERP); '' for non-ELF. */
function elfLinkType(bytes) {
    if (!isElf(bytes)) return '';
    return elfHasInterpreter(bytes) ? 'dynamic' : 'static';
}

/** True if ELF has PT_INTERP (dynamic linker), i.e. needs a sysroot to run. */
function elfHasInterpreter(bytes) {
    if (!isElf(bytes) || bytes.length < 58) return false;
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const is64 = bytes[4] === 2;
    let e_phoff, e_phnum, e_phentsize;
    if (is64) {
        e_phoff = Number(dv.getBigUint64(32, true));
        e_phentsize = dv.getUint16(54, true);
        e_phnum = dv.getUint16(56, true);
    } else {
        e_phoff = dv.getUint32(28, true);
        e_phentsize = dv.getUint16(42, true);
        e_phnum = dv.getUint16(44, true);
    }
    const PT_INTERP = 3;
    for (let i = 0; i < e_phnum; i++) {
        const off = e_phoff + i * e_phentsize;
        if (off + 4 > bytes.length) break;
        if (dv.getUint32(off, true) === PT_INTERP) return true;
    }
    return false;
}

/** Return demo sysroot ZIP URL for this binary (ELF or PE), or null if not applicable. */
function getDemoSysrootUrlForBinary(bytes, isPe) {
    if (isPe) return '/sysroot-windows.zip';
    if (!isElf(bytes) || bytes.length < 20) return null;
    const e_machine = bytes[18] | (bytes[19] << 8);
    // EM_386 = 3 → i386 Linux; EM_X86_64 = 62, EM_AARCH64 = 183 → x64 Linux
    if (e_machine === 3) return '/sysroot-i386-linux.zip';
    return '/sysroot-x64-linux.zip';
}

/**
 * If the binary is dynamic (ELF with PT_INTERP or PE) and no sysroot is set,
 * fetch the demo sysroot so the user can still view/run the binary.
 */
async function fetchDemoSysrootIfNeeded(bytes, isPe) {
    if (pendingSysrootFiles) return;
    const needsSysroot = isPe || elfHasInterpreter(bytes);
    if (!needsSysroot) return;
    const url = getDemoSysrootUrlForBinary(bytes, isPe);
    if (!url) return;
    const fileName = url.split('/').pop() || 'sysroot.zip';
    showSysrootStatus(t('sysrootAutoFetch') + ' ' + fileName + '…');
    try {
        const resp = await fetch(url);
        if (!resp.ok) {
            console.warn('[binb] Demo sysroot fetch failed:', resp.status, resp.statusText);
            return;
        }
        const blob = await resp.blob();
        await loadSysrootFromZipBlob(blob, fileName);
        showSysrootStatus(t('sysrootAutoFetched') + ' ' + fileName);
    } catch (e) {
        console.warn('[binb] Demo sysroot fetch failed:', e);
    }
}

function formatSize(n) {
    if (n < 1024) return `${n} B`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
    return `${(n / (1024 * 1024)).toFixed(2)} MB`;
}

let _fileInfo = null; // { name, size, arch, type, sha256 }
let _fileInfoPopup = null;
let _lastPeStructure = null; // Parsed PE for at-a-glance summary (set when loading PE)
let _lastElfStructure = null; // Parsed ELF for at-a-glance summary (set when loading ELF)

async function updateFileInfoBadge(name, bytes) {
    const elf = isElf(bytes);
    const pe = isPe(bytes);
    const arch = elf ? elfArchString(bytes) : pe ? peArchString(bytes) : 'shellcode';
    const type = elf ? elfTypeString(bytes) : pe ? peTypeString(bytes) : 'raw';
    const linkType = elfLinkType(bytes); // 'static' | 'dynamic' | ''
    const hash = await sha256hex(bytes);
    _fileInfo = { name, size: bytes.length, arch, type, sha256: hash };
    if (fileInfoBadge) {
        const linkPart = linkType ? ` · ${linkType}` : '';
        fileInfoBadge.textContent = `${arch} · ${formatSize(bytes.length)}${linkPart}`;
        fileInfoBadge.style.display = '';
    }
}

function buildPeSummaryHtml(data) {
    if (!data || !data.header) return '';
    const h = data.header;
    let html = '<div class="pe-summary-block"><span class="pe-summary-title">PE / DLL at a glance</span><div class="pe-summary-body">';
    html += '<div class="pe-summary-section"><strong>Header</strong><pre class="pe-summary-pre">';
    html += `Format:     ${escapeHtml(h.format)}\nMachine:   ${escapeHtml(h.machine)}\nImageBase: ${escapeHtml(h.image_base)}\nEntry RVA: ${escapeHtml(h.entry_rva)}\nSubsystem: ${escapeHtml(h.subsystem)}\nType:      ${h.is_dll ? 'DLL' : 'EXE'}`;
    html += '</pre></div>';
    if (data.rich_header && data.rich_header.present) {
        const rh = data.rich_header;
        html += '<div class="pe-summary-section"><strong>Rich header (compiler / linker)</strong><pre class="pe-summary-pre">';
        html += `Present: yes\nSize: ${rh.size} bytes\nChecksum: ${escapeHtml(rh.checksum)}`;
        if (rh.tools && rh.tools.length > 0) {
            html += '\n\nTools:';
            for (const t of rh.tools) html += `\n  ${escapeHtml(t.name)} — build ${t.build} (×${t.use_count})`;
        } else if (rh.tool_count) html += `\nTools: ${rh.tool_count}`;
        html += '</pre></div>';
    }
    if (data.sections && data.sections.length > 0) {
        let maxEntropy = 0;
        for (const s of data.sections) {
            if (s.entropy != null) {
                const e = parseFloat(s.entropy);
                if (!Number.isNaN(e)) maxEntropy = Math.max(maxEntropy, e);
            }
        }
        html += '<div class="pe-summary-section"><strong>Entropy</strong> Max section: <span class="mono">' + (maxEntropy > 0 ? maxEntropy.toFixed(2) + ' bits' : '—') + '</span></div>';
        html += '<div class="pe-summary-section"><strong>Sections</strong> (' + data.sections.length + ')<table class="pe-summary-table"><thead><tr><th>Name</th><th>VAddr</th><th>Size</th><th>Entropy</th><th>Chars</th></tr></thead><tbody>';
        const maxSections = 8;
        for (let i = 0; i < Math.min(data.sections.length, maxSections); i++) {
            const s = data.sections[i];
            html += `<tr><td>${escapeHtml(s.name)}</td><td class="mono">${escapeHtml(s.virtual_address)}</td><td class="mono">${escapeHtml(s.raw_size)}</td><td>${escapeHtml(s.entropy != null ? s.entropy : '—')}</td><td>${escapeHtml(s.characteristics)}</td></tr>`;
        }
        if (data.sections.length > maxSections) html += `<tr><td colspan="5" class="muted">… and ${data.sections.length - maxSections} more</td></tr>`;
        html += '</tbody></table></div>';
    }
    if (data.imports && data.imports.length > 0) {
        const byDll = {};
        for (const i of data.imports) {
            byDll[i.dll] = (byDll[i.dll] || 0) + 1;
        }
        const dlls = Object.entries(byDll).sort((a, b) => b[1] - a[1]);
        html += '<div class="pe-summary-section"><strong>Imports</strong> (' + data.imports.length + ' from ' + dlls.length + ' DLLs)<ul class="pe-summary-list">';
        for (let i = 0; i < Math.min(dlls.length, 6); i++) {
            html += `<li>${escapeHtml(dlls[i][0])} <span class="muted">(${dlls[i][1]})</span></li>`;
        }
        if (dlls.length > 6) html += `<li class="muted">… and ${dlls.length - 6} more DLLs</li>`;
        html += '</ul></div>';
    }
    if (data.exports && data.exports.length > 0) {
        html += '<div class="pe-summary-section"><strong>Exports</strong> (' + data.exports.length + ')<ul class="pe-summary-list">';
        for (let i = 0; i < Math.min(data.exports.length, 6); i++) {
            html += `<li>${escapeHtml(data.exports[i].name)} <span class="muted">${escapeHtml(data.exports[i].rva)}</span></li>`;
        }
        if (data.exports.length > 6) html += `<li class="muted">… and ${data.exports.length - 6} more</li>`;
        html += '</ul></div>';
    }
    html += '<div class="pe-summary-section"><strong>Version / resources</strong><span class="muted">—</span></div>';
    if (data.security) {
        const dep = data.security.dep_nx ? '<span class="pe-sig-present">Yes (DEP/NX)</span>' : '<span class="pe-sig-absent">No</span>';
        const aslr = data.security.aslr ? '<span class="pe-sig-present">Yes (ASLR)</span>' : '<span class="pe-sig-absent">No</span>';
        html += '<div class="pe-summary-section"><strong>Security &amp; hardening</strong><ul class="pe-summary-list">';
        html += '<li>DEP (NX): ' + dep + '</li><li>ASLR: ' + aslr + '</li></ul></div>';
    }
    const sigText = data.signature_present ? '<span class="pe-sig-present">Present</span>' : '<span class="pe-sig-absent">Absent</span>';
    html += '<div class="pe-summary-section"><strong>Code signing</strong>' + sigText + '</div>';
    if (data.risk) {
        const r = data.risk;
        const scoreClass = r.score >= 75 ? 'pe-risk-high' : r.score >= 50 ? 'pe-risk-medium' : r.score >= 25 ? 'pe-risk-low' : 'pe-risk-none';
        html += '<div class="pe-summary-section pe-risk-block"><strong>Risk</strong>';
        html += `<span class="pe-risk-score ${scoreClass}">${r.score}</span> / 100`;
        if (r.tags && r.tags.length > 0) {
            html += '<ul class="pe-summary-list pe-risk-tags">';
            for (const tag of r.tags) html += `<li class="${scoreClass}">${escapeHtml(tag)}</li>`;
            html += '</ul>';
        }
        html += '</div>';
    }
    html += '</div></div>';
    return html;
}

function buildElfSummaryHtml(data) {
    if (!data || !data.header) return '';
    const h = data.header;
    let html = '<div class="pe-summary-block"><span class="pe-summary-title">ELF at a glance</span><div class="pe-summary-body">';
    html += '<div class="pe-summary-section"><strong>Header</strong><pre class="pe-summary-pre">';
    html += `Class:   ${escapeHtml(h.class)}\nData:    ${escapeHtml(h.data)}\nType:    ${escapeHtml(h.e_type)}\nMachine: ${escapeHtml(h.e_machine)}\nEntry:   ${escapeHtml(h.entry)}`;
    html += '</pre></div>';
    if (data.compiler_info && data.compiler_info.length > 0) {
        html += '<div class="pe-summary-section"><strong>Compiler / build tools</strong><ul class="pe-summary-list">';
        for (const c of data.compiler_info) html += '<li>' + escapeHtml(c) + '</li>';
        html += '</ul></div>';
    }
    const sec = data.security;
    const pieFromType = (h.e_type || '').indexOf('ET_DYN') !== -1;
    const pieStr = sec ? (sec.pie ? '<span class="pe-sig-present">Yes</span>' : '<span class="pe-sig-absent">No</span>') : (pieFromType ? '<span class="pe-sig-present">Yes</span>' : '<span class="pe-sig-absent">No</span>');
    const nxStr = sec ? (sec.nx ? '<span class="pe-sig-present">Yes</span>' : '<span class="pe-sig-absent">No</span>') : '<span class="muted">—</span>';
    const relroStr = sec ? escapeHtml(sec.relro || 'No') : '<span class="muted">—</span>';
    const canaryStr = sec ? (sec.canary ? '<span class="pe-sig-present">Yes</span>' : '<span class="pe-sig-absent">No</span>') : '<span class="muted">—</span>';
    const fortifyStr = sec ? (sec.fortify ? '<span class="pe-sig-present">Yes</span>' : '<span class="pe-sig-absent">No</span>') : '<span class="muted">—</span>';
    html += '<div class="pe-summary-section"><strong>Security &amp; hardening</strong><ul class="pe-summary-list">';
    html += '<li>PIE: ' + pieStr + '</li><li>RELRO: ' + relroStr + '</li><li>NX: ' + nxStr + '</li>';
    html += '<li>Canary: ' + canaryStr + '</li><li>Fortify: ' + fortifyStr + '</li></ul></div>';
    if (data.needed_libs && data.needed_libs.length > 0) {
        html += '<div class="pe-summary-section"><strong>Imported symbols</strong> (' + data.needed_libs.length + ' NEEDED)<ul class="pe-summary-list">';
        for (let i = 0; i < Math.min(data.needed_libs.length, 8); i++) {
            html += '<li>' + escapeHtml(data.needed_libs[i]) + '</li>';
        }
        if (data.needed_libs.length > 8) html += '<li class="muted">… and ' + (data.needed_libs.length - 8) + ' more</li>';
        html += '</ul></div>';
    } else {
        html += '<div class="pe-summary-section"><strong>Imported symbols</strong><span class="muted">' + (data.needed_libs ? '0 NEEDED' : '—') + '</span></div>';
    }
    html += '<div class="pe-summary-section"><strong>Code signing</strong><span class="muted">N/A (ELF)</span></div>';
    if (data.section_headers && data.section_headers.length > 0) {
        let maxEntropy = 0;
        for (const sh of data.section_headers) {
            if (sh.entropy != null) {
                const e = parseFloat(sh.entropy);
                if (!Number.isNaN(e)) maxEntropy = Math.max(maxEntropy, e);
            }
        }
        html += '<div class="pe-summary-section"><strong>Entropy</strong> Max section: <span class="mono">' + (maxEntropy > 0 ? maxEntropy.toFixed(2) + ' bits' : '—') + '</span></div>';
    }
    html += '</div></div>';
    return html;
}

function showFileInfoPopup() {
    if (!_fileInfo) return;
    removeFileInfoPopup();
    const fi = _fileInfo;
    let peData = _lastPeStructure;
    let elfData = _lastElfStructure;
    if (elfBytes && isPe(elfBytes) && !peData) {
        try {
            const json = parse_pe_structure(elfBytes);
            peData = JSON.parse(json);
            _lastPeStructure = peData;
        } catch (_) {}
    }
    if (elfBytes && isElf(elfBytes) && !elfData) {
        try {
            const json = parse_elf_structure(elfBytes);
            elfData = JSON.parse(json);
            _lastElfStructure = elfData;
        } catch (_) {}
    }
    const div = document.createElement('div');
    div.className = 'file-info-popup';
    let inner = [
        row('Name', fi.name),
        row('Size', formatSize(fi.size) + ` (${fi.size.toLocaleString()} bytes)`),
        row('Arch', fi.arch),
        row('Type', fi.type),
        row('SHA-256', fi.sha256),
    ].join('');
    if (fi.sha256) {
        const vtUrl = 'https://www.virustotal.com/gui/search/' + encodeURIComponent(fi.sha256);
        inner += `<div class="fi-row"><span class="fi-label">VirusTotal</span><span class="fi-value"><a href="${vtUrl}" target="_blank" rel="noopener noreferrer">Search by SHA-256</a></span></div>`;
    }
    if (peData) inner += buildPeSummaryHtml(peData);
    if (elfData) inner += buildElfSummaryHtml(elfData);
    div.innerHTML = inner;
    const rect = fileName.getBoundingClientRect();
    div.style.top = (rect.bottom + 6) + 'px';
    div.style.left = Math.max(4, rect.left) + 'px';
    document.body.appendChild(div);
    _fileInfoPopup = div;
    setTimeout(() => document.addEventListener('click', _closeFileInfoPopup, { once: true }), 0);
}
function row(label, value) {
    return `<div class="fi-row"><span class="fi-label">${label}</span><span class="fi-value">${escapeHtml(value)}</span></div>`;
}
function removeFileInfoPopup() {
    if (_fileInfoPopup) { _fileInfoPopup.remove(); _fileInfoPopup = null; }
}
function _closeFileInfoPopup(e) {
    if (_fileInfoPopup && !_fileInfoPopup.contains(e.target)) removeFileInfoPopup();
    else if (_fileInfoPopup) setTimeout(() => document.addEventListener('click', _closeFileInfoPopup, { once: true }), 0);
}
fileName.addEventListener('click', (e) => {
    e.stopPropagation();
    if (_fileInfoPopup) removeFileInfoPopup();
    else showFileInfoPopup();
});

function showShellcodeFilePrompt() {
    if (shellcodeFilePrompt) shellcodeFilePrompt.style.display = 'flex';
}

function hideShellcodeFilePrompt() {
    if (shellcodeFilePrompt) shellcodeFilePrompt.style.display = 'none';
    pendingShellcodeBytes = null;
}

/**
 * Create emulator from ELF bytes or from shellcode.
 * @param {Uint8Array} bytes - Raw ELF bytes or shellcode (raw or hex string as UTF-8 bytes).
 * @param {{ asShellcode?: boolean, arch?: string }} [opts] - If asShellcode is true, arch must be 'x86_64' or 'arm64'.
 */
function createEmulator(bytes, opts = {}) {
    try {
        if (opts.asShellcode && opts.arch) {
            console.log(`[binb] creating emulator from shellcode (${bytes.length} bytes), arch=${opts.arch}`);
            emulator = Emulator.new_shellcode(bytes, opts.arch);
        } else if (opts.asPe) {
            const argv0 = elfFileName || 'program';
            const userArgs = parseProgramArgs(programArgs ? programArgs.value : '');
            const argsArr = [argv0, ...userArgs];
            if (pendingSysrootFiles && pendingSysrootFiles.paths.length > 0) {
                const paths = pendingSysrootFiles.paths;
                const data = pendingSysrootFiles.data;
                // Normalize paths for Windows PE so DLLs are found at Windows/System32/*.dll
                const pathToData = new Map();
                for (let i = 0; i < paths.length; i++) {
                    const vfsPath = pathForPeVfs(paths[i]);
                    pathToData.set(vfsPath, data[i]);
                }
                const pathsArr = Array.from(pathToData.keys());
                const dataArr = pathsArr.map(k => pathToData.get(k));
                emulator = Emulator.new_from_pe_with_libs_and_args(bytes, pathsArr, dataArr, argsArr);
            } else {
                emulator = Emulator.new_from_pe_with_args(bytes, argsArr);
            }
        } else {
            const argv0 = elfFileName || 'program';
            const userArgs = parseProgramArgs(programArgs ? programArgs.value : '');
            const argsArr = [argv0, ...userArgs];
            if (pendingSysrootFiles && pendingSysrootFiles.paths.length > 0) {
                const paths = pendingSysrootFiles.paths;
                const data = pendingSysrootFiles.data;
                const pathsArr = Array.from(paths);
                const dataArr = Array.from(data);
                if (pathsArr.length !== dataArr.length) throw new Error('VFS paths/data length mismatch');
                emulator = Emulator.new_with_libs_and_args(bytes, pathsArr, dataArr, argsArr);
            } else {
                emulator = Emulator.new_with_args(bytes, argsArr);
            }
        }
        previousRegs = {};
        isRunning = false;
        lastStoppedAtBreakpoint = false;
        lastMemAccesses = [];
        terminal.innerHTML = `<span class="info">Binary loaded: ${escapeHtml(elfFileName)}. Use Step (F11) or Continue (F5) to begin.</span>\n`;
        straceOutput.innerHTML = '<span class="muted">Syscall trace will appear here when strace is enabled.</span>';
        if (stdinPrompt) stdinPrompt.style.display = 'none';
        setStatus('statusReady');
        enableButtons(true);
        if (straceToggle.checked) {
            emulator.set_syscall_trace(true);
        }
        if (traceToggle.checked) {
            emulator.set_trace_recording(true);
            timelineBar.style.display = '';
        } else {
            timelineBar.style.display = 'none';
        }
        traceMode = false;
        traceCursor = 0;
        focusedGprIndex = null;
        traceMemAccesses = null;
        daddr = null;
        tlZoomStart = 0;
        tlZoomEnd = 0;
        tlIaddrBreakpoint = null;
        updateDaddrDisplay();

        // Reset watch list and all search state for the new binary
        watchList = [];
        memSearchQuery = '';
        memSearchMatches = [];
        memSearchCurrentIndex = -1;
        disasmSearchQuery = '';
        disasmSearchMatches = [];
        disasmSearchCurrentIndex = -1;
        straceSearchQuery = '';
        straceSearchMatches = [];
        straceSearchCurrentIndex = -1;
        if (memSearchInput) memSearchInput.value = '';
        if (memSearchStatus) memSearchStatus.textContent = '';
        if (disasmSearchInput) disasmSearchInput.value = '';
        if (disasmSearchStatus) disasmSearchStatus.textContent = '';
        if (straceSearchInput) straceSearchInput.value = '';
        if (straceSearchStatus) straceSearchStatus.textContent = '';
        renderWatchList();
        renderRegionHistory();
        if (vfsFilterSelect) vfsFilterSelect.value = 'all';
        renderVfsList();

        const elfStructureEl = document.getElementById('elf-structure');
        const elfTitleEl = document.querySelector('.elf-title');
        if (opts.asShellcode) {
            if (elfTitleEl) elfTitleEl.textContent = 'Binary';
            if (elfStructureEl) elfStructureEl.innerHTML = '<span class="muted">Shellcode (no binary structure).</span>';
            elfFunctions = [];
            renderFunctions();
        } else if (opts.asPe) {
            _lastElfStructure = null;
            if (elfTitleEl) elfTitleEl.textContent = 'PE structure';
            try {
                const json = parse_pe_structure(bytes);
                const data = JSON.parse(json);
                _lastPeStructure = data;
                renderPeStructure(data);
                elfFunctions = (data.functions || []).map(f => ({
                    name: f.name,
                    addr: f.addr,
                    size: f.size || 0,
                    bind: 'export',
                    source: 'export',
                    file: null,
                    line: null
                }));
                renderFunctions();
            } catch (e) {
                if (elfStructureEl) elfStructureEl.innerHTML = '<span class="muted">Could not parse PE structure.</span>';
                elfFunctions = [];
                renderFunctions();
            }
        } else {
            _lastPeStructure = null;
            if (elfTitleEl) elfTitleEl.textContent = 'ELF structure';
            try {
                const json = parse_elf_structure(bytes);
                const data = JSON.parse(json);
                _lastElfStructure = data;
                renderElfStructure(data);
                elfFunctions = data.functions || [];
                renderFunctions();
            } catch (e) {
                if (elfStructureEl) elfStructureEl.innerHTML = '<span class="muted">Could not parse ELF structure.</span>';
                elfFunctions = [];
                renderFunctions();
            }
        }
        updateFullUI();
        if (opts.asPe) {
            const peYaraOnLoad = document.getElementById('pe-yara-on-load');
            if (peYaraOnLoad && peYaraOnLoad.checked && typeof YARA_EXAMPLES !== 'undefined' && YARA_EXAMPLES.pe_indicators) {
                setTimeout(() => runYaraScanWithSource(YARA_EXAMPLES.pe_indicators), 0);
            }
        }
        console.log(`[binb] emulator ready, RIP=${emulator.get_rip()}`);
    } catch (err) {
        console.error('[binb] Load error:', err);
        console.error('[binb] Load error stack:', err.stack);
        terminal.innerHTML = `<span class="error">Error: ${escapeHtml(err.message || err)}</span>\n`;
        setStatus('statusError', 'error');
        enableButtons(false);
    }
}

// ── Shellcode panel ──────────────────────────────────────────────────────────

/** Preset shellcode demos for quick testing. hex is space-separated bytes. */
const SHELLCODE_DEMOS = {
    x64_exit: { hex: '48 31 c0 b0 3c 48 31 ff 0f 05', arch: 'x86_64' },   // xor rax,rax; mov al,60; xor rdi,rdi; syscall
    x64_nop:  { hex: '90 90 90 90 90 90 90 90', arch: 'x86_64' },        // NOP sled
    x64_int3: { hex: 'cc', arch: 'x86_64' },                              // int3 breakpoint
};

function setupShellcodePanel() {
    if (!btnShellcodeToggle || !shellcodePanel) return;

    btnShellcodeToggle.addEventListener('click', () => {
        const visible = shellcodePanel.style.display !== 'none';
        shellcodePanel.style.display = visible ? 'none' : 'block';
    });

    if (shellcodeDemo) {
        shellcodeDemo.addEventListener('change', () => {
            const id = shellcodeDemo.value;
            if (!id || !SHELLCODE_DEMOS[id]) return;
            const demo = SHELLCODE_DEMOS[id];
            const arr = parseHexQuery(demo.hex);
            if (!arr || arr.length === 0) return;
            const bytes = new Uint8Array(arr);
            hideShellcodeFilePrompt();
            createEmulator(bytes, { asShellcode: true, arch: demo.arch });
            if (shellcodePanel) shellcodePanel.style.display = 'none';
            if (fileName) fileName.textContent = t('shellcodePasted');
            updateFileInfoBadge('shellcode (demo)', bytes);
            shellcodeDemo.value = '';
        });
    }

    if (btnLoadPaste) {
        btnLoadPaste.addEventListener('click', () => {
            const text = shellcodePaste ? shellcodePaste.value.trim() : '';
            if (!text) {
                terminal.innerHTML = '<span class="error">Paste hex or C-style shellcode first.</span>\n';
                return;
            }
            const bytes = new TextEncoder().encode(text);
            const arch = shellcodeArch ? shellcodeArch.value : 'x86_64';
            hideShellcodeFilePrompt();
            createEmulator(bytes, { asShellcode: true, arch });
            if (shellcodePanel) shellcodePanel.style.display = 'none';
            if (fileName) fileName.textContent = t('shellcodePasted');
            updateFileInfoBadge('shellcode (pasted)', bytes);
        });
    }

    if (btnLoadFileShellcode) {
        btnLoadFileShellcode.addEventListener('click', () => {
            if (!pendingShellcodeBytes) return;
            const arch = shellcodeFileArch ? shellcodeFileArch.value : 'x86_64';
            createEmulator(pendingShellcodeBytes, { asShellcode: true, arch });
            hideShellcodeFilePrompt();
            if (fileName) fileName.textContent = fileName.textContent + ' ' + t('shellcodeSuffix');
            updateFileInfoBadge(elfFileName + ' (shellcode)', pendingShellcodeBytes);
        });
    }

    if (btnDismissShellcodePrompt) {
        btnDismissShellcodePrompt.addEventListener('click', hideShellcodeFilePrompt);
    }
}

// ── Drag and drop ───────────────────────────────────────────────────────────

function enableDragDrop() {
    let counter = 0;
    document.addEventListener('dragenter', (e) => {
        e.preventDefault();
        counter++;
        document.body.classList.add('dragover');
    });
    document.addEventListener('dragleave', (e) => {
        e.preventDefault();
        counter--;
        if (counter <= 0) { counter = 0; document.body.classList.remove('dragover'); }
    });
    document.addEventListener('dragover', (e) => e.preventDefault());
    document.addEventListener('drop', async (e) => {
        e.preventDefault();
        counter = 0;
        document.body.classList.remove('dragover');
        const file = e.dataTransfer.files[0];
        if (file) await loadFile(file);
    });
}

// ── Tabs ────────────────────────────────────────────────────────────────────

function setupTabs() {
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const parent = btn.parentElement;
            const panel = parent.closest('.panel') || parent.closest('.right-panel') || parent.parentElement.parentElement;
            parent.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            const targetId = btn.dataset.tab;
            panel.querySelectorAll('.tab-content').forEach(tc => {
                tc.classList.toggle('active', tc.id === targetId);
            });
            if (targetId === 'history-tab') renderRegionHistory();
            if (targetId === 'vfs-tab') renderVfsList();
        });
    });
}

// ── VFS panel ────────────────────────────────────────────────────────────────

function renderVfsList() {
    if (!vfsList || !vfsListPlaceholder) return;

    // No emulator: show pending sysroot files if any, otherwise prompt to load a binary
    if (!emulator) {
        if (pendingSysrootFiles && pendingSysrootFiles.paths && pendingSysrootFiles.paths.length > 0) {
            const paths = pendingSysrootFiles.paths;
            const data = pendingSysrootFiles.data || [];
            const files = paths.map((path, i) => ({
                path: path.startsWith('/') ? path : '/' + path,
                size: (data[i] && data[i].length) || 0,
                modified: false,
                fromPending: true
            })).sort((a, b) => a.path.localeCompare(b.path));
            vfsListPlaceholder.style.display = 'none';
            let html = '<div class="vfs-pending-hint muted" style="font-size:0.7rem;margin-bottom:0.35rem">Sysroot (ZIP) — load an ELF to use these files.</div>';
            for (const f of files) {
                const path = f.path || '';
                const size = f.size != null ? f.size : 0;
                const sizeStr = size >= 1024 ? (size / 1024).toFixed(1) + ' KB' : size + ' B';
                const pathAttr = (path || '').replace(/"/g, '&quot;');
                html += `<div class="vfs-entry" data-vfs-path="${pathAttr}" data-pending="1" title="Click to view"><span class="vfs-path mono">${escapeHtml(path)} <span class="vfs-tag vfs-tag-sysroot" title="From sysroot ZIP">sysroot</span></span><span class="vfs-size">${sizeStr}</span></div>`;
            }
            vfsList.innerHTML = html;
            vfsList.querySelectorAll('.vfs-entry').forEach(el => {
                el.addEventListener('click', () => {
                    const p = el.getAttribute('data-vfs-path');
                    if (p) showVfsFile(p);
                });
            });
        } else {
            vfsListPlaceholder.textContent = t('vfsLoadBinary');
            vfsListPlaceholder.classList.remove('vfs-pending-hint');
            vfsListPlaceholder.style.display = '';
            vfsList.innerHTML = '';
        }
        if (vfsDetail) vfsDetail.style.display = 'none';
        selectedVfsPath = null;
        if (vfsFilterSelect) vfsFilterSelect.style.display = (pendingSysrootFiles?.paths?.length) ? 'none' : '';
        return;
    }

    vfsListPlaceholder.classList.remove('vfs-pending-hint');
    if (vfsFilterSelect) vfsFilterSelect.style.display = '';
    try {
        const json = emulator.get_vfs_files();
        const files = JSON.parse(json);
        if (!files || files.length === 0) {
            vfsListPlaceholder.textContent = t('vfsNoFilesShort');
            vfsListPlaceholder.style.display = '';
            vfsList.innerHTML = '';
            if (vfsDetail) vfsDetail.style.display = 'none';
            selectedVfsPath = null;
            return;
        }
        const filter = (vfsFilterSelect && vfsFilterSelect.value) ? vfsFilterSelect.value : 'all';
        const filtered = filter === 'all' ? files : filter === 'modified' ? files.filter(f => f.modified) : files.filter(f => !f.modified);
        if (filtered.length === 0) {
            vfsListPlaceholder.textContent = filter === 'modified' ? t('vfsNoModified') : filter === 'original' ? t('vfsNoOriginal') : t('vfsNoFilesShort');
            vfsListPlaceholder.style.display = '';
            vfsList.innerHTML = '';
            if (vfsDetail) vfsDetail.style.display = 'none';
            return;
        }
        vfsListPlaceholder.style.display = 'none';
        let html = '';
        for (const f of filtered) {
            const path = f.path || '';
            const size = f.size != null ? f.size : 0;
            const sizeStr = size >= 1024 ? (size / 1024).toFixed(1) + ' KB' : size + ' B';
            const pathKey = path.startsWith('/') ? path.slice(1) : path;
            const fromSysroot = sysrootPathSet && sysrootPathSet.has(pathKey);
            let tag = fromSysroot ? ' <span class="vfs-tag vfs-tag-sysroot" title="From sysroot ZIP">sysroot</span>' : '';
            if (f.modified) tag += ' <span class="vfs-tag vfs-tag-modified" title="Modified during run (differs from original)">modified</span>';
            const pathAttr = (path || '').replace(/"/g, '&quot;');
            html += `<div class="vfs-entry" data-vfs-path="${pathAttr}" title="Click to view/edit"><span class="vfs-path mono">${escapeHtml(path)}${tag}</span><span class="vfs-size">${sizeStr}</span></div>`;
        }
        vfsList.innerHTML = html;
        vfsList.querySelectorAll('.vfs-entry').forEach(el => {
            el.addEventListener('click', () => {
                const p = el.getAttribute('data-vfs-path');
                if (p) showVfsFile(p);
            });
        });
    } catch (e) {
        vfsListPlaceholder.textContent = t('vfsFailedList');
        vfsListPlaceholder.style.display = '';
        vfsList.innerHTML = '';
    }
}

function showVfsFile(path) {
    if (!vfsDetail || !vfsDetailPath || !vfsDetailText || !vfsDetailBinary) return;
    selectedVfsPath = path;
    vfsDetailPath.textContent = path;
    let content = null;
    if (emulator) {
        content = emulator.get_vfs_file_content(path);
    } else if (pendingSysrootFiles && pendingSysrootFiles.paths && pendingSysrootFiles.data) {
        const pathKey = path.replace(/^\//, '');
        const idx = pendingSysrootFiles.paths.findIndex(p => p.replace(/^\//, '') === pathKey);
        if (idx >= 0 && pendingSysrootFiles.data[idx]) content = pendingSysrootFiles.data[idx];
    }
    if (content == null || content.length === 0) {
        vfsDetailText.style.display = 'none';
        vfsDetailBinary.style.display = 'block';
        if (vfsDetailSize) vfsDetailSize.textContent = '0';
        vfsDetailSave.style.display = 'none';
    } else {
        const bytes = content instanceof Uint8Array ? content : new Uint8Array(content);
        try {
            const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
            vfsDetailText.value = text;
            vfsDetailText.style.display = 'block';
            vfsDetailBinary.style.display = 'none';
            vfsDetailSave.style.display = emulator ? '' : 'none';
        } catch (_) {
            vfsDetailText.style.display = 'none';
            vfsDetailBinary.style.display = 'block';
            if (vfsDetailSize) vfsDetailSize.textContent = String(bytes.length);
            vfsDetailSave.style.display = 'none';
        }
    }
    vfsDetail.style.display = 'block';
}

function setupVfsPanel() {
    if (!vfsDropZone || !vfsFileInput || !vfsPathInput) return;

    function addFileToVfs(file, guestPath, isMultiple) {
        if (!emulator) return;
        const base = (guestPath && guestPath.trim()) || '';
        const path = base
            ? (base.endsWith('/') ? base + (file.name || 'file') : (isMultiple ? base + '/' + (file.name || 'file') : base))
            : '/' + (file.name || 'file');
        const norm = path.startsWith('/') ? path : '/' + path;
        file.arrayBuffer().then(buf => {
            emulator.add_vfs_file(norm, new Uint8Array(buf));
            renderVfsList();
            if (!isMultiple) vfsPathInput.value = '';
        });
    }

    vfsDropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        vfsDropZone.classList.add('vfs-drop-active');
    });
    vfsDropZone.addEventListener('dragleave', () => {
        vfsDropZone.classList.remove('vfs-drop-active');
    });
    vfsDropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        vfsDropZone.classList.remove('vfs-drop-active');
        const file = e.dataTransfer.files[0];
        if (file) addFileToVfs(file, vfsPathInput.value.trim(), false);
    });
    vfsDropZone.addEventListener('click', () => vfsFileInput.click());
    vfsFileInput.addEventListener('change', () => {
        const path = vfsPathInput.value.trim();
        const files = Array.from(vfsFileInput.files);
        files.forEach((file, i) => {
            addFileToVfs(file, path || undefined, files.length > 1);
        });
        vfsFileInput.value = '';
    });
    if (vfsFilterSelect) {
        vfsFilterSelect.addEventListener('change', () => renderVfsList());
    }
    if (vfsDetailSave) {
        vfsDetailSave.addEventListener('click', () => {
            if (!emulator || selectedVfsPath == null) return;
            const text = vfsDetailText ? vfsDetailText.value : '';
            const bytes = new TextEncoder().encode(text);
            emulator.add_vfs_file(selectedVfsPath, bytes);
            renderVfsList();
            showVfsFile(selectedVfsPath);
        });
    }
}

// ── Keyboard shortcuts ──────────────────────────────────────────────────────

function setupKeyboard() {
    document.addEventListener('keydown', (e) => {
        if (!emulator) return;
        // Don't capture keys when user is typing in an input (including memory byte editor)
        const active = document.activeElement;
        const isInput = active && (active.tagName === 'INPUT' || active.tagName === 'TEXTAREA');
        const isMemByteEdit = active && active.classList && active.classList.contains('mem-byte-edit');
        const isTraceNavKey = (e.key === 'j' || e.key === 'k' || e.key === 'J' || e.key === 'K') && traceMode;
        if (isInput && !isTraceNavKey) return;
        if (isMemByteEdit) return; // never steal keys from memory byte editor

        if (e.key === 'F5') {
            e.preventDefault();
            if (traceMode) { exitTraceMode(); }
            if (!emulator.is_exited()) doContinue();
        } else if (e.key === 'F10') {
            e.preventDefault();
            if (traceMode) { exitTraceMode(); }
            if (!emulator.is_exited()) doStepOver();
        } else if (e.key === 'F11') {
            e.preventDefault();
            if (traceMode) { exitTraceMode(); }
            if (!emulator.is_exited()) doStep();
        } else if (e.key === 'ArrowLeft' && traceMode) {
            e.preventDefault();
            seekTrace(traceCursor - (e.shiftKey ? 10 : 1));
        } else if (e.key === 'ArrowRight' && traceMode) {
            e.preventDefault();
            seekTrace(traceCursor + (e.shiftKey ? 10 : 1));
        } else if (e.key === 'Escape' && traceMode) {
            e.preventDefault();
            exitTraceMode();
        }
        // QIRA-style: j/k to navigate invocations of current instruction (iaddr)
        else if (e.key === 'j' && !e.shiftKey && traceMode) {
            e.preventDefault();
            navigateIaddr(1);
        } else if (e.key === 'k' && !e.shiftKey && traceMode) {
            e.preventDefault();
            navigateIaddr(-1);
        }
        // QIRA-style: J/K (shift) to navigate data address touches (daddr)
        else if (e.key === 'J' && traceMode) {
            e.preventDefault();
            navigateDaddr(1);
        } else if (e.key === 'K' && traceMode) {
            e.preventDefault();
            navigateDaddr(-1);
        }
        // Register seeking: Ctrl+[ prev write, Ctrl+] next write (focus a register first by clicking it)
        else if (e.key === '[' && e.ctrlKey && traceMode && focusedGprIndex !== null) {
            e.preventDefault();
            const idx = emulator.prev_trace_by_register(focusedGprIndex, traceCursor);
            if (idx >= 0) seekTrace(idx);
        } else if (e.key === ']' && e.ctrlKey && traceMode && focusedGprIndex !== null) {
            e.preventDefault();
            const idx = emulator.next_trace_by_register(focusedGprIndex, traceCursor);
            if (idx >= 0) seekTrace(idx);
        }
    });
}

// ── QIRA-style navigation ───────────────────────────────────────────────────

function navigateIaddr(direction) {
    if (!emulator || !traceMode) return;
    // Get current RIP at trace cursor
    const regsJson = emulator.get_trace_registers(traceCursor);
    if (regsJson === 'null') return;
    const regs = JSON.parse(regsJson);
    const currentRip = parseInt(regs.rip, 16);
    if (isNaN(currentRip)) return;

    let nextIdx;
    if (direction > 0) {
        nextIdx = emulator.next_trace_by_rip(currentRip, traceCursor + 1);
    } else {
        nextIdx = emulator.prev_trace_by_rip(currentRip, Math.max(0, traceCursor - 1));
    }
    const idx = nextIdx >= 0 ? Math.floor(nextIdx) : -1;
    if (idx >= 0 && idx !== traceCursor) {
        seekTrace(idx);
        updateFullUI();
        if (disasmList) disasmList.focus({ preventScroll: true });
    }
}

function navigateDaddr(direction) {
    if (!emulator || !traceMode || !daddr) return;
    let nextIdx;
    if (direction > 0) {
        nextIdx = emulator.next_trace_by_addr(daddr.addr, daddr.size, traceCursor + 1);
    } else {
        nextIdx = emulator.prev_trace_by_addr(daddr.addr, daddr.size, Math.max(0, traceCursor - 1));
    }
    const idx = nextIdx >= 0 ? Math.floor(nextIdx) : -1;
    if (idx >= 0 && idx !== traceCursor) {
        seekTrace(idx);
        updateFullUI();
        if (disasmList) disasmList.focus({ preventScroll: true });
    }
}

function setDaddr(addr, size) {
    daddr = { addr, size: size || 4 };
    updateDaddrDisplay();
    if (emulator && emulator.get_trace_length() > 0) {
        const idx = traceMode ? traceCursor : emulator.get_trace_length() - 1;
        renderTimeline(idx);
    }
    renderWatchList();
    renderRegionHistory();
}

// Memory breakpoint (Tenet-style): click a byte in Memory view to set daddr and seek to that access
window._setMemBreakpoint = (byteAddr) => {
    if (!emulator) return;
    setDaddr(byteAddr, 1);
    if (emulator.get_trace_length() > 0) {
        const start = traceMode ? traceCursor : emulator.get_trace_length() - 1;
        const idx = emulator.prev_trace_by_addr(byteAddr, 1, start);
        if (idx >= 0) seekTrace(idx);
    }
    memAddr.value = '0x' + byteAddr.toString(16);
    refreshMemory();
}

function clearDaddr() {
    daddr = null;
    updateDaddrDisplay();
    if (emulator && emulator.get_trace_length() > 0) {
        const idx = traceMode ? traceCursor : emulator.get_trace_length() - 1;
        renderTimeline(idx);
    }
    renderRegionHistory();
}

function updateDaddrDisplay() {
    if (daddr) {
        infoDaddr.textContent = `0x${daddr.addr.toString(16)} (${daddr.size}B)`;
        infoDaddr.classList.add('active');
        infoDaddr.title = t('daddrClearTitle');
    } else {
        infoDaddr.textContent = '--';
        infoDaddr.classList.remove('active');
        infoDaddr.title = '';
    }
}

infoDaddr.addEventListener('click', () => {
    if (daddr) { clearDaddr(); refreshMemory(); }
});

// ── Button handlers ─────────────────────────────────────────────────────────

btnContinue.addEventListener('click', () => {
    if (!emulator || emulator.is_exited()) return;
    doContinue();
});

btnStep.addEventListener('click', () => {
    if (!emulator || emulator.is_exited()) return;
    doStep();
});

btnStepOver.addEventListener('click', () => {
    if (!emulator || emulator.is_exited()) return;
    doStepOver();
});

btnStep100.addEventListener('click', () => {
    if (!emulator || emulator.is_exited()) return;
    const n = parseInt(stepNSelect.value, 10) || 100;
    doStepN(n);
});

stepNSelect.addEventListener('change', () => {
    const n = parseInt(stepNSelect.value, 10) || 100;
    const label = n >= 1000 ? `x${(n/1000)}K` : `x${n}`;
    btnStep100.textContent = label;
    btnStep100.title = `Step x${n}`;
});

btnRun.addEventListener('click', () => {
    if (!emulator || emulator.is_exited()) return;
    doRun();
});

btnStop.addEventListener('click', () => {
    isRunning = false;
    if (animFrame) { cancelAnimationFrame(animFrame); animFrame = null; }
    setStatus('statusPaused', 'paused');
    enableButtons(true);
    updateFullUI();
});

/** Reset all state and UI to start a fresh session (no binary loaded). */
function resetSession() {
    isRunning = false;
    if (animFrame) {
        cancelAnimationFrame(animFrame);
        animFrame = null;
    }

    // Clear emulator and file state
    emulator = null;
    elfBytes = null;
    elfFileName = 'program';
    pendingSysrootFiles = null;
    sysrootPathSet = null;
    selectedVfsPath = null;
    pendingShellcodeBytes = null;

    // Clear runtime state
    previousRegs = {};
    lastStoppedAtBreakpoint = false;
    traceMode = false;
    traceCursor = 0;
    focusedGprIndex = null;
    traceMemAccesses = null;
    daddr = null;
    watchList = [];
    elfFunctions = [];
    fnAddrMap.clear();
    lastMemAccesses = [];
    memSearchQuery = '';
    memSearchMatches = [];
    memSearchCurrentIndex = -1;
    disasmSearchQuery = '';
    disasmSearchMatches = [];
    disasmSearchCurrentIndex = -1;
    straceSearchQuery = '';
    straceSearchMatches = [];
    straceSearchCurrentIndex = -1;
    tlZoomStart = 0;
    tlZoomEnd = 0;
    tlIaddrBreakpoint = null;
    tlDragging = false;
    tlDragStartX = 0;
    tlDragEndX = 0;
    disasmOverrideAddr = null;
    lastStringsData = null;
    xrefToMap.clear();
    xrefFromMap.clear();
    xrefTotal = -1;
    _fileInfo = null;
    _lastPeStructure = null;
    _lastElfStructure = null;
    removeFileInfoPopup();
    _statusKey = 'statusIdle';
    _statusCls = '';
    _statusParam = undefined;
    if (typeof lastAssembledBytes !== 'undefined') lastAssembledBytes = null;

    // Timeline: hide and clear cursor
    if (timelineCursor) timelineCursor.style.display = 'none';
    if (timelineBar) timelineBar.style.display = 'none';
    if (tracePosition) tracePosition.textContent = '';
    if (timelineSlider) {
        timelineSlider.max = 0;
        timelineSlider.value = 0;
    }

    // Terminal
    if (terminal) {
        terminal.innerHTML = `<span class="muted" data-i18n="terminalPrompt">${t('terminalPrompt')}</span>\n`;
        terminal.scrollTop = 0;
    }

    // Strace
    if (straceOutput) straceOutput.innerHTML = `<span class="muted" data-i18n="straceEnablePrompt">${t('straceEnablePrompt')}</span>`;
    if (straceSearchInput) straceSearchInput.value = '';
    if (straceSearchStatus) straceSearchStatus.textContent = '';

    // Memory
    if (memAddr) memAddr.value = '0x400000';
    if (memoryDump) memoryDump.innerHTML = `<span class="muted" data-i18n="memEnterAddress">${t('memEnterAddress')}</span>`;
    if (memInfo) memInfo.textContent = '';
    if (memSearchInput) memSearchInput.value = '';
    if (memSearchStatus) memSearchStatus.textContent = '';

    // Disassembly
    if (disasmList) disasmList.innerHTML = '';
    if (disasmSearchInput) disasmSearchInput.value = '';
    if (disasmSearchStatus) disasmSearchStatus.textContent = '';
    const disasmFnLabel = document.getElementById('disasm-fn-label');
    if (disasmFnLabel) disasmFnLabel.textContent = '';

    // Registers & call stack
    if (registerDisp) registerDisp.innerHTML = `<div class="muted" data-i18n="memmapNoBinary">${t('memmapNoBinary')}</div>`;
    if (callstackList) callstackList.innerHTML = `<div class="muted" data-i18n="noCallStack">${t('noCallStack')}</div>`;
    if (modeBadge) modeBadge.textContent = '--';
    if (infoRip) infoRip.textContent = '--';
    if (infoDisasm) infoDisasm.textContent = '--';
    if (infoCount) infoCount.textContent = '0';
    if (infoFlags) infoFlags.textContent = '--';
    if (infoDaddr) infoDaddr.textContent = '--';

    // Breakpoints
    if (bpList) bpList.innerHTML = '';
    if (bpAddrInput) bpAddrInput.value = '';
    if (bpSyscallInput) bpSyscallInput.value = '';
    if (bpAnySyscall) bpAnySyscall.checked = false;

    // Memory map
    if (memmapList) memmapList.innerHTML = `<div class="muted" data-i18n="memmapNoBinary">${t('memmapNoBinary')}</div>`;

    // Watch list & region history
    if (watchAddrInput) watchAddrInput.value = '';
    if (watchSizeInput) watchSizeInput.value = '';
    renderWatchList();
    if (regionHistoryPlaceholder) {
        regionHistoryPlaceholder.style.display = '';
        regionHistoryPlaceholder.textContent = t('regionHistoryPlaceholder');
    }
    if (regionHistoryTable) regionHistoryTable.style.display = 'none';
    if (regionHistoryTbody) regionHistoryTbody.innerHTML = '';
    if (btnHistoryCopyCsv) btnHistoryCopyCsv.style.display = 'none';

    // Accesses
    if (accessesList) accessesList.innerHTML = `<div class="muted" data-i18n="accessesNoAccesses">${t('accessesNoAccesses')}</div>`;
    if (accessesInfo) accessesInfo.textContent = t('accessesStepPrompt');
    if (accessesMemDump) accessesMemDump.innerHTML = '<span class="muted">—</span>';
    if (accessesMemAddr) accessesMemAddr.textContent = '';

    // Binary / ELF structure
    const elfStructureEl = document.getElementById('elf-structure');
    const elfTitleEl = document.querySelector('.elf-title');
    if (elfTitleEl) elfTitleEl.textContent = 'ELF structure';
    if (elfStructureEl) elfStructureEl.innerHTML = `<span class="muted" data-i18n="binaryLoadPrompt">${t('binaryLoadPrompt')}</span>`;

    // Functions
    if (fnListEl) fnListEl.innerHTML = `<div class="muted" data-i18n="fnNoBinary">${t('fnNoBinary')}</div>`;
    const fnCount = document.getElementById('fn-count');
    if (fnCount) fnCount.textContent = '';

    // Strings
    const stringsStructure = document.getElementById('strings-structure');
    if (stringsStructure) stringsStructure.innerHTML = `<span class="muted">${t('stringsLoadPrompt')}</span>`;
    const stringsCount = document.getElementById('strings-count');
    if (stringsCount) stringsCount.textContent = '';

    // VFS
    if (vfsFilterSelect) vfsFilterSelect.value = 'all';
    if (vfsListPlaceholder) vfsListPlaceholder.style.display = '';
    if (vfsList) vfsList.innerHTML = '';
    if (vfsDetail) vfsDetail.style.display = 'none';
    if (vfsDetailPath) vfsDetailPath.textContent = '';
    if (vfsDetailText) vfsDetailText.textContent = '';

    // File name & badge
    if (fileName) fileName.textContent = t('fileNoFile');
    if (fileInfoBadge) {
        fileInfoBadge.textContent = '';
        fileInfoBadge.style.display = 'none';
    }

    // Stdin & program args
    if (stdinPrompt) stdinPrompt.style.display = 'none';
    if (stdinInput) stdinInput.value = '';
    if (programArgs) programArgs.value = '';

    // Shellcode panels
    if (shellcodePanel) shellcodePanel.style.display = 'none';
    if (shellcodeFilePrompt) shellcodeFilePrompt.style.display = 'none';
    if (shellcodePaste) shellcodePaste.value = '';

    // YARA tab
    if (yaraEditor) yaraEditor.value = '';
    if (yaraHighlightLayer) yaraHighlightLayer.innerHTML = '';
    if (yaraResults) yaraResults.innerHTML = `<span class="muted">Write YARA rules and click &quot;Run all rules&quot; to scan memory and see all results.</span>`;
    if (yaraStatus) yaraStatus.textContent = '';
    if (yaraMatchCount) yaraMatchCount.textContent = '';
    if (yaraSummary) yaraSummary.textContent = '';
    _lastSelectedRuleSource = '';
    _lastSelectedRuleName = '';

    // Assembly tab
    if (asmEditor) asmEditor.value = '';
    if (asmHighlightLayer) asmHighlightLayer.textContent = '';
    if (asmListing) asmListing.innerHTML = `<span class="muted">Assemble to see address, bytes, and source.</span>`;
    if (asmHexOutput) asmHexOutput.textContent = '—';
    if (asmStatus) asmStatus.textContent = '';

    // XREFs
    if (xrefsSummary) xrefsSummary.innerHTML = '';
    if (xrefsDetail) xrefsDetail.innerHTML = '';
    if (xrefsList) xrefsList.innerHTML = '';

    setStatus('statusIdle');
    enableButtons(false);
}

btnReset.addEventListener('click', () => {
    resetSession();
});

// ── Snapshot & Restore ──────────────────────────────────────────────────────

btnSaveSnapshot.addEventListener('click', () => {
    if (!emulator) return;
    try {
        const data = emulator.save_snapshot();
        const blob = new Blob([data], { type: 'application/octet-stream' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        const name = elfFileName ? elfFileName.replace(/\.[^.]+$/, '') : 'snapshot';
        a.download = `${name}.bsnp`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        appendTerminal(`\n[Snapshot saved: ${(data.byteLength / 1024).toFixed(1)} KB]`, 'info');
    } catch (err) {
        appendTerminal(`\nSnapshot save error: ${err.message || err}`, 'error');
    }
});

btnLoadSnapshot.addEventListener('click', () => snapshotUpload.click());
snapshotUpload.addEventListener('change', async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    snapshotUpload.value = '';
    try {
        const buf = await file.arrayBuffer();
        const data = new Uint8Array(buf);
        if (!emulator) {
            // Create a minimal emulator if none exists — we'll overwrite state via snapshot
            appendTerminal('\n[No emulator loaded — please load a binary first, then restore snapshot]', 'error');
            return;
        }
        emulator.load_snapshot(data);
        appendTerminal(`\n[Snapshot restored from ${file.name}: ${(data.byteLength / 1024).toFixed(1)} KB]`, 'info');
        setStatus('statusPaused', 'paused');
        enableButtons(true);
        updateFullUI();
        renderBreakpoints();
    } catch (err) {
        appendTerminal(`\nSnapshot load error: ${err.message || err}`, 'error');
    }
});

// ── Hex Editor (click byte to edit) ─────────────────────────────────────────

/** Open inline editor for a hex byte. Single click on a hex digit opens this. */
function openMemoryByteEditor(span) {
    if (!span || !emulator) return;
    const addr = parseInt(span.dataset.addr, 10);
    if (isNaN(addr)) return;
    const currentHex = span.textContent.trim();
    if (currentHex === '??') return;

    const input = document.createElement('input');
    input.type = 'text';
    input.className = 'mem-byte-edit';
    input.value = currentHex;
    input.maxLength = 2;
    span.textContent = '';
    span.classList.add('editing');
    span.appendChild(input);
    // Defer focus so the input is in the DOM and can receive key events (avoids global keydown stealing focus)
    setTimeout(() => {
        input.focus();
        input.select();
    }, 0);

    let committed = false;
    function commit() {
        if (committed) return;
        committed = true;
        input.removeEventListener('blur', onBlur);
        input.removeEventListener('keydown', onKeydown);
        input.removeEventListener('input', onInput);
        const raw = input.value.trim().toLowerCase();
        if (input.parentNode) input.remove();
        span.classList.remove('editing');
        if (!/^[0-9a-f]{1,2}$/.test(raw)) {
            span.textContent = currentHex;
            return;
        }
        const val = parseInt(raw, 16);
        try {
            emulator.write_memory_byte(addr, val);
            span.textContent = val.toString(16).padStart(2, '0');
            refreshMemory();
        } catch (err) {
            console.warn('write_memory_byte failed:', err);
            span.textContent = currentHex;
        }
    }

    function onBlur() { commit(); }
    function onKeydown(ev) {
        if (ev.key === 'Enter') { ev.preventDefault(); commit(); }
        if (ev.key === 'Escape') {
            ev.preventDefault();
            committed = true;
            input.removeEventListener('blur', onBlur);
            input.removeEventListener('keydown', onKeydown);
            input.removeEventListener('input', onInput);
            if (input.parentNode) input.remove();
            span.classList.remove('editing');
            span.textContent = currentHex;
        }
        if (input.value.length >= 2 && /^[0-9a-fA-F]{2}$/.test(input.value) && ev.key.length === 1) {
            ev.preventDefault();
            commit();
        }
    }
    function onInput() {
        if (input.value.length >= 2 && /^[0-9a-fA-F]{2}$/.test(input.value)) commit();
    }

    input.addEventListener('blur', onBlur);
    input.addEventListener('keydown', onKeydown);
    input.addEventListener('input', onInput);
}

// Single click on hex byte = edit; single click on ASCII byte = track address. Right-click = track address.
memoryDump.addEventListener('click', (e) => {
    const span = e.target.closest('.mem-byte[data-addr]');
    if (!span) return;
    e.preventDefault();
    e.stopPropagation();
    const addr = parseInt(span.dataset.addr, 10);
    if (isNaN(addr)) return;
    if (span.classList.contains('mem-byte-hex')) {
        openMemoryByteEditor(span);
    } else {
        window._setMemBreakpoint(addr);
    }
});

memoryDump.addEventListener('contextmenu', (e) => {
    const span = e.target.closest('.mem-byte[data-addr]');
    if (!span) return;
    e.preventDefault();
    const addr = parseInt(span.dataset.addr, 10);
    if (!isNaN(addr)) window._setMemBreakpoint(addr);
});

// Stdin prompt: when program does read(0) and no data, we show this; user types and Send continues.
function submitStdin() {
    if (!emulator || !stdinInput) return;
    const text = stdinInput.value;
    const bytes = new TextEncoder().encode(text + '\n');
    emulator.set_stdin(bytes);
    if (stdinPrompt) stdinPrompt.style.display = 'none';
    stdinInput.value = '';
    doRun();
}
if (btnStdinSend) btnStdinSend.addEventListener('click', submitStdin);
if (stdinInput) stdinInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') { e.preventDefault(); submitStdin(); }
});

// Breakpoint controls
btnBpAdd.addEventListener('click', addBreakpointFromInput);
bpAddrInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') addBreakpointFromInput();
});
if (btnBpSyscallAdd) btnBpSyscallAdd.addEventListener('click', addSyscallBreakpointFromInput);
if (bpSyscallInput) bpSyscallInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') addSyscallBreakpointFromInput();
});
if (bpAnySyscall) bpAnySyscall.addEventListener('change', () => {
    if (emulator) {
        emulator.set_break_on_any_syscall(bpAnySyscall.checked);
        renderBreakpoints();
    }
});

// ── Resizable layout (drag dividers between Disassembly / Center / Right) ──
(function setupLayoutResize() {
    const LAYOUT_KEY = 'binb_layout_sizes';
    const layout = document.getElementById('debugger-layout');
    const resizerDisasm = document.getElementById('resizer-disasm');
    const resizerRight = document.getElementById('resizer-right');
    if (!layout || !resizerDisasm || !resizerRight) return;

    function px(name) {
        const v = getComputedStyle(layout).getPropertyValue(name).trim();
        const n = parseInt(v, 10);
        return isNaN(n) ? (name === '--col-disasm' ? 320 : 300) : n;
    }
    function setPx(name, value) {
        layout.style.setProperty(name, `${Math.round(value)}px`);
    }
    function save() {
        try {
            localStorage.setItem(LAYOUT_KEY, JSON.stringify({
                disasm: px('--col-disasm') || 320,
                right: px('--col-right') || 300
            }));
        } catch (_) {}
    }
    function load() {
        try {
            const raw = localStorage.getItem(LAYOUT_KEY);
            if (!raw) return;
            const o = JSON.parse(raw);
            if (typeof o.disasm === 'number' && o.disasm >= 200 && o.disasm <= 1200) setPx('--col-disasm', o.disasm);
            if (typeof o.right === 'number' && o.right >= 180 && o.right <= 800) setPx('--col-right', o.right);
        } catch (_) {}
    }
    load();

    function startResize(resizer, varName, minPx, maxPx) {
        const startX = event.clientX;
        const startW = px(varName) || (varName === '--col-disasm' ? 320 : 300);
        resizer.classList.add('resizing');
        document.body.style.cursor = 'col-resize';
        document.body.style.userSelect = 'none';

        function move(e) {
            const dx = e.clientX - startX;
            const newW = (varName === '--col-disasm' ? startW + dx : startW - dx);
            const clamped = Math.min(maxPx, Math.max(minPx, newW));
            setPx(varName, clamped);
        }
        function stop() {
            resizer.classList.remove('resizing');
            document.body.style.cursor = '';
            document.body.style.userSelect = '';
            document.removeEventListener('mousemove', move);
            document.removeEventListener('mouseup', stop);
            save();
        }
        document.addEventListener('mousemove', move);
        document.addEventListener('mouseup', stop);
    }

    resizerDisasm.addEventListener('mousedown', (e) => {
        e.preventDefault();
        startResize(resizerDisasm, '--col-disasm', 200, 900);
    });
    resizerRight.addEventListener('mousedown', (e) => {
        e.preventDefault();
        startResize(resizerRight, '--col-right', 180, 700);
    });
})();

// Memory viewer
btnMemGo.addEventListener('click', refreshMemory);
memAddr.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') refreshMemory();
});

memSearchInput.addEventListener('input', () => {
    memSearchQuery = memSearchInput.value;
    memSearchMatches = [];
    memSearchCurrentIndex = -1;
    refreshMemory();
    updateMemSearchStatus();
});
function runMemSearchAll() {
    memSearchQuery = memSearchInput.value;
    if (!memSearchQuery.trim()) { refreshMemory(); updateMemSearchStatus(); return; }
    if (memSearchSpinner) memSearchSpinner.classList.add('searching');
    memSearchStatus.textContent = '';
    searchAllMemoryAsync(memSearchQuery, memSearchMode.value, (matches) => {
        memSearchMatches = matches;
        memSearchCurrentIndex = matches.length > 0 ? 0 : -1;
        if (memSearchSpinner) memSearchSpinner.classList.remove('searching');
        updateMemSearchStatus();
        if (matches.length > 0) {
            memAddr.value = '0x' + matches[0].addr.toString(16);
        }
        refreshMemory();
    });
}
memSearchInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') runMemSearchAll();
});
if (btnMemSearchAll) btnMemSearchAll.addEventListener('click', runMemSearchAll);
function goToMemSearchMatch(direction) {
    memSearchQuery = memSearchInput.value;
    if (!memSearchQuery.trim()) return;
    if (memSearchMatches.length === 0) {
        memSearchMatches = searchAllMemory(memSearchQuery, memSearchMode.value);
        memSearchCurrentIndex = memSearchMatches.length > 0 ? 0 : -1;
        updateMemSearchStatus();
    }
    if (memSearchMatches.length === 0) return;
    memSearchCurrentIndex = direction === 'next'
        ? (memSearchCurrentIndex + 1) % memSearchMatches.length
        : (memSearchCurrentIndex - 1 + memSearchMatches.length) % memSearchMatches.length;
    const m = memSearchMatches[memSearchCurrentIndex];
    const matchAddr = m.addr;
    memAddr.value = '0x' + (matchAddr - (matchAddr % MEM_BYTES_PER_LINE)).toString(16);
    refreshMemory();
    updateMemSearchStatus();
}

btnMemSearchPrev.addEventListener('click', () => goToMemSearchMatch('prev'));
btnMemSearchNext.addEventListener('click', () => goToMemSearchMatch('next'));

// Disassembly search
if (disasmSearchInput) disasmSearchInput.addEventListener('input', () => {
    disasmSearchQuery = disasmSearchInput.value;
    disasmSearchCurrentIndex = -1;
    if (traceMode) renderTraceDisasm(traceCursor);
    else renderDisasm();
});
if (disasmSearchInput) disasmSearchInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
        if (traceMode) renderTraceDisasm(traceCursor);
        else renderDisasm();
        if (disasmSearchMatches.length > 0) disasmSearchCurrentIndex = 0;
        updateDisasmSearchStatus();
    }
});
function goToDisasmSearchMatch(direction) {
    disasmSearchQuery = disasmSearchInput.value;
    if (!disasmSearchQuery.trim()) return;
    if (traceMode) renderTraceDisasm(traceCursor);
    else renderDisasm();
    if (disasmSearchMatches.length === 0) return;
    disasmSearchCurrentIndex = direction === 'next'
        ? (disasmSearchCurrentIndex + 1) % disasmSearchMatches.length
        : (disasmSearchCurrentIndex - 1 + disasmSearchMatches.length) % disasmSearchMatches.length;
    if (traceMode) renderTraceDisasm(traceCursor);
    else renderDisasm();
    const lineIdx = disasmSearchMatches[disasmSearchCurrentIndex];
    const el = disasmList.querySelector(`.disasm-line[data-line-index="${lineIdx}"]`);
    if (el) el.scrollIntoView({ block: 'center', behavior: 'instant' });
    updateDisasmSearchStatus();
}
if (btnDisasmSearchPrev) btnDisasmSearchPrev.addEventListener('click', () => goToDisasmSearchMatch('prev'));
if (btnDisasmSearchNext) btnDisasmSearchNext.addEventListener('click', () => goToDisasmSearchMatch('next'));

// Strace/syscall search
if (straceSearchInput) straceSearchInput.addEventListener('input', () => {
    straceSearchQuery = straceSearchInput.value;
    straceSearchCurrentIndex = -1;
    renderStraceOutput();
});
if (straceSearchInput) straceSearchInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
        renderStraceOutput();
        if (straceSearchMatches.length > 0) straceSearchCurrentIndex = 0;
        updateStraceSearchStatus();
    }
});
function goToStraceSearchMatch(direction) {
    straceSearchQuery = straceSearchInput.value;
    if (!straceSearchQuery.trim()) return;
    renderStraceOutput();
    if (straceSearchMatches.length === 0) return;
    straceSearchCurrentIndex = direction === 'next'
        ? (straceSearchCurrentIndex + 1) % straceSearchMatches.length
        : (straceSearchCurrentIndex - 1 + straceSearchMatches.length) % straceSearchMatches.length;
    renderStraceOutput();
    const lineIdx = straceSearchMatches[straceSearchCurrentIndex];
    const el = straceOutput && straceOutput.querySelector(`.strace-row[data-line-index="${lineIdx}"]`);
    if (el) el.scrollIntoView({ block: 'center', behavior: 'instant' });
    updateStraceSearchStatus();
}
if (btnStraceSearchPrev) btnStraceSearchPrev.addEventListener('click', () => goToStraceSearchMatch('prev'));
if (btnStraceSearchNext) btnStraceSearchNext.addEventListener('click', () => goToStraceSearchMatch('next'));

btnMemStack.addEventListener('click', () => {
    if (!emulator) return;
    const regs = JSON.parse(emulator.get_registers());
    const esp = regs.gpr.find(r => r.name === 'RSP' || r.name === 'ESP');
    if (esp) { memAddr.value = esp.value; refreshMemory(); }
});
btnMemRip.addEventListener('click', () => {
    if (!emulator) return;
    memAddr.value = emulator.get_rip();
    refreshMemory();
});
btnMemPgUp.addEventListener('click', () => {
    const addr = parseAddr(memAddr.value);
    if (!isNaN(addr)) {
        memAddr.value = '0x' + Math.max(0, addr - MEM_BYTES_PER_LINE * MEM_LINES).toString(16);
        refreshMemory();
    }
});
btnMemPgDn.addEventListener('click', () => {
    const addr = parseAddr(memAddr.value);
    if (!isNaN(addr)) {
        memAddr.value = '0x' + (addr + MEM_BYTES_PER_LINE * MEM_LINES).toString(16);
        refreshMemory();
    }
});
btnMemWatch.addEventListener('click', () => {
    const addr = parseAddr(memAddr.value);
    if (!isNaN(addr)) {
        setDaddr(addr, 4);
    }
});

// Watch list
btnWatchAdd.addEventListener('click', addWatchFromInput);
watchAddrInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') addWatchFromInput();
});

// Timeline / trace navigation
btnTraceStart.addEventListener('click', () => seekTrace(0));
btnTraceBack.addEventListener('click', () => seekTrace(traceCursor - 1));
btnTraceBack10.addEventListener('click', () => seekTrace(traceCursor - 10));
btnTraceFwd.addEventListener('click', () => seekTrace(traceCursor + 1));
btnTraceFwd10.addEventListener('click', () => seekTrace(traceCursor + 10));
btnTraceEnd.addEventListener('click', () => {
    if (!emulator) return;
    seekTrace(emulator.get_trace_length() - 1);
});
btnTraceLive.addEventListener('click', exitTraceMode);
btnZoomReset.addEventListener('click', () => {
    if (!emulator) return;
    tlZoomStart = 0;
    tlZoomEnd = emulator.get_trace_length();
    updateZoomInfo();
    renderTimeline(traceCursor);
});
timelineSlider.addEventListener('input', () => {
    seekTrace(parseInt(timelineSlider.value));
});

// --- Tenet-style timeline interactions: click, drag-to-zoom, scroll-to-zoom ---

timelineWrap.addEventListener('mousedown', (e) => {
    if (!emulator || e.button !== 0) return;
    tlDragging = true;
    tlDragStartX = e.clientX - timelineWrap.getBoundingClientRect().left;
    tlDragEndX = tlDragStartX;
    timelineSelection.style.display = 'block';
    timelineSelection.style.left = tlDragStartX + 'px';
    timelineSelection.style.width = '0px';
});

document.addEventListener('mousemove', (e) => {
    if (!tlDragging) return;
    const rect = timelineWrap.getBoundingClientRect();
    tlDragEndX = Math.max(0, Math.min(e.clientX - rect.left, rect.width));
    const left = Math.min(tlDragStartX, tlDragEndX);
    const width = Math.abs(tlDragEndX - tlDragStartX);
    timelineSelection.style.left = left + 'px';
    timelineSelection.style.width = width + 'px';
});

document.addEventListener('mouseup', (e) => {
    if (!tlDragging) return;
    tlDragging = false;
    timelineSelection.style.display = 'none';
    if (!emulator) return;

    const rect = timelineWrap.getBoundingClientRect();
    const wrapWidth = rect.width;
    const dragDist = Math.abs(tlDragEndX - tlDragStartX);

    // If drag was very small (< 4px), treat as click -> seek
    if (dragDist < 4) {
        const fraction = tlDragStartX / wrapWidth;
        const zSpan = getZoomEnd() - getZoomStart();
        const targetIdx = Math.floor(getZoomStart() + fraction * zSpan);
        seekTrace(targetIdx);
        return;
    }

    // Drag-to-zoom: map pixel range to trace index range
    const left = Math.min(tlDragStartX, tlDragEndX);
    const right = Math.max(tlDragStartX, tlDragEndX);
    const zSpan = getZoomEnd() - getZoomStart();
    const newStart = Math.floor(getZoomStart() + (left / wrapWidth) * zSpan);
    const newEnd = Math.ceil(getZoomStart() + (right / wrapWidth) * zSpan);
    if (newEnd - newStart > 1) {
        tlZoomStart = Math.max(0, newStart);
        tlZoomEnd = Math.min(emulator.get_trace_length(), newEnd);
        updateZoomInfo();
        renderTimeline(traceCursor);
    }
});

// Scroll to zoom in/out centered on cursor position
timelineWrap.addEventListener('wheel', (e) => {
    if (!emulator) return;
    e.preventDefault();
    const len = emulator.get_trace_length();
    if (len === 0) return;

    const rect = timelineWrap.getBoundingClientRect();
    const fraction = (e.clientX - rect.left) / rect.width;
    const zStart = getZoomStart();
    const zEnd = getZoomEnd();
    const zSpan = zEnd - zStart;

    // Zoom factor: scroll down = zoom out, scroll up = zoom in
    const factor = e.deltaY > 0 ? 1.3 : 1 / 1.3;
    const newSpan = Math.max(10, Math.min(len, Math.round(zSpan * factor)));

    // Keep the point under the mouse at the same fraction
    const center = zStart + fraction * zSpan;
    let newStart = Math.round(center - fraction * newSpan);
    let newEnd = newStart + newSpan;

    // Clamp to bounds
    if (newStart < 0) { newEnd -= newStart; newStart = 0; }
    if (newEnd > len) { newStart -= (newEnd - len); newEnd = len; }
    newStart = Math.max(0, newStart);

    tlZoomStart = newStart;
    tlZoomEnd = newEnd;
    updateZoomInfo();
    renderTimeline(traceCursor);
}, { passive: false });

// Double-click to reset zoom
timelineWrap.addEventListener('dblclick', (e) => {
    if (!emulator) return;
    e.preventDefault();
    tlZoomStart = 0;
    tlZoomEnd = emulator.get_trace_length();
    updateZoomInfo();
    renderTimeline(traceCursor);
});

function getZoomStart() {
    if (!emulator) return 0;
    const len = emulator.get_trace_length();
    return (tlZoomEnd > tlZoomStart && tlZoomEnd <= len) ? tlZoomStart : 0;
}
function getZoomEnd() {
    if (!emulator) return 0;
    const len = emulator.get_trace_length();
    return (tlZoomEnd > tlZoomStart && tlZoomEnd <= len) ? tlZoomEnd : len;
}
function updateZoomInfo() {
    if (!emulator) { zoomInfo.textContent = ''; return; }
    const len = emulator.get_trace_length();
    const zStart = getZoomStart();
    const zEnd = getZoomEnd();
    if (zStart === 0 && zEnd >= len) {
        zoomInfo.textContent = '';
    } else {
        const pct = ((zEnd - zStart) / len * 100).toFixed(1);
        zoomInfo.textContent = `[${zStart}..${zEnd}] ${pct}%`;
    }
}

function enableButtons(on) {
    btnContinue.disabled = !on;
    btnRun.disabled = !on;
    btnStep.disabled = !on;
    btnStepOver.disabled = !on;
    btnStep100.disabled = !on;
    stepNSelect.disabled = !on;
    // Stop is enabled when the VM is loaded and not exited (user can always click Stop to halt)
    btnStop.disabled = !(on && emulator && !emulator.is_exited());
    btnReset.disabled = !on;
    btnSaveSnapshot.disabled = !on || !emulator;
}

function setRunningButtons() {
    btnContinue.disabled = true;
    btnRun.disabled = true;
    btnStep.disabled = true;
    btnStepOver.disabled = true;
    btnStep100.disabled = true;
    stepNSelect.disabled = true;
    btnStop.disabled = false;
    btnReset.disabled = false;
    btnSaveSnapshot.disabled = true;
}

function setupLogControls() {
    logLevel.addEventListener('change', () => {
        set_log_level(logLevel.value);
    });
    straceToggle.addEventListener('change', () => {
        if (emulator) {
            emulator.set_syscall_trace(straceToggle.checked);
        }
    });
    traceToggle.addEventListener('change', () => {
        if (emulator) {
            emulator.set_trace_recording(traceToggle.checked);
            timelineBar.style.display = traceToggle.checked ? '' : 'none';
            if (!traceToggle.checked) {
                exitTraceMode();
            }
        }
    });
}

// ── Emulation actions ───────────────────────────────────────────────────────

function doStep() {
    if (traceMode) exitTraceMode();
    try {
        const json = emulator.step();
        const info = JSON.parse(json);
        // After stepping, we're no longer at a breakpoint (we moved past it)
        if (info.status !== 'breakpoint') lastStoppedAtBreakpoint = false;
        handleStepInfo(info);
        // If the VM is still alive after a step, show "paused" (clears stale "breakpoint" badge)
        if (info.status === 'running') setStatus('statusPaused', 'paused');
        captureLastAccesses();
        updateFullUI();
    } catch (err) {
        appendTerminal(`\nError: ${err.message || err}`, 'error');
        setStatus('statusError', 'error');
    }
}

function doStepOver() {
    if (traceMode) exitTraceMode();
    try {
        // step_over executes one instruction without checking syscall breakpoints, so when
        // stopped at a syscall breakpoint it runs the syscall and stops at the next instruction.
        const json = emulator.step_over();
        const info = JSON.parse(json);
        if (info.status !== 'breakpoint') lastStoppedAtBreakpoint = false;
        handleStepInfo(info);
        if (info.status === 'running') setStatus('statusPaused', 'paused');
        captureLastAccesses();
        updateFullUI();
    } catch (err) {
        appendTerminal(`\nError: ${err.message || err}`, 'error');
        setStatus('statusError', 'error');
    }
}

function doStepN(n) {
    if (traceMode) exitTraceMode();
    // For small step counts, run synchronously for snappy response
    const CHUNK = 2000;
    if (n <= CHUNK) {
        try {
            const json = emulator.run_n(n);
            const info = JSON.parse(json);
            if (info.status !== 'breakpoint') lastStoppedAtBreakpoint = false;
            handleStepInfo(info);
            if (info.status === 'running') setStatus('statusPaused', 'paused');
            captureLastAccesses();
            updateFullUI();
        } catch (err) {
            appendTerminal(`\nError: ${err.message || err}`, 'error');
            setStatus('statusError', 'error');
        }
        return;
    }
    // For large step counts, use chunked rAF so Stop button stays responsive
    isRunning = true;
    setRunningButtons();
    setStatus('statusRunning', 'running');
    let remaining = n;

    function runChunk() {
        if (!emulator || emulator.is_exited() || !isRunning || remaining <= 0) {
            isRunning = false;
            if (!emulator?.is_exited()) setStatus('statusPaused', 'paused');
            enableButtons(true);
            captureLastAccesses();
            updateFullUI();
            return;
        }
        try {
            const batch = Math.min(remaining, CHUNK);
            const json = emulator.run_n(batch);
            const info = JSON.parse(json);
            remaining -= batch;
            if (info.status === 'breakpoint') {
                lastStoppedAtBreakpoint = true;
                isRunning = false;
                handleStepInfo(info);
                enableButtons(true);
                captureLastAccesses();
                updateFullUI();
            } else if (info.status === 'running' && remaining > 0) {
                animFrame = requestAnimationFrame(runChunk);
            } else {
                // Finished all steps or terminal state (exited, halted, etc.)
                if (info.status !== 'breakpoint') lastStoppedAtBreakpoint = false;
                isRunning = false;
                handleStepInfo(info);
                if (info.status === 'running') setStatus('statusPaused', 'paused');
                enableButtons(true);
                captureLastAccesses();
                updateFullUI();
            }
        } catch (err) {
            isRunning = false;
            appendTerminal(`\nError: ${err.message || err}`, 'error');
            setStatus('statusError', 'error');
            enableButtons(true);
        }
    }

    if (animFrame) cancelAnimationFrame(animFrame);
    runChunk();
}

function doContinue() {
    if (traceMode) exitTraceMode();
    isRunning = true;
    setRunningButtons();
    setStatus('statusRunning', 'running');
    lastStoppedAtBreakpoint = false;

    function runChunk() {
        if (!emulator || emulator.is_exited() || !isRunning) {
            isRunning = false;
            if (!emulator?.is_exited()) {
                setStatus('statusPaused', 'paused');
                enableButtons(true);
            }
            updateFullUI();
            return;
        }
        try {
            // run_n handles breakpoint resume internally and checks breakpoints.
            // Small chunks keep the UI responsive so Stop works.
            const json = emulator.run_n(2000);
            const info = JSON.parse(json);
            handleStepInfo(info);
            if (info.status === 'breakpoint') {
                lastStoppedAtBreakpoint = true;
                isRunning = false;
                setStatus('statusBreakpoint', 'breakpoint');
                enableButtons(true);
                captureLastAccesses();
                updateFullUI();
            } else if (info.status === 'running') {
                animFrame = requestAnimationFrame(runChunk);
            } else {
                isRunning = false;
                updateFullUI();
            }
        } catch (err) {
            isRunning = false;
            appendTerminal(`\nError: ${err.message || err}`, 'error');
            setStatus('statusError', 'error');
            enableButtons(true);
            updateFullUI();
        }
    }

    if (animFrame) cancelAnimationFrame(animFrame);
    runChunk();
}

function doRun() {
    if (traceMode) exitTraceMode();
    isRunning = true;
    setRunningButtons();
    setStatus('statusRunning', 'running');
    const startTime = performance.now();
    lastStoppedAtBreakpoint = false;

    function runChunk() {
        if (!emulator || emulator.is_exited() || !isRunning) {
            isRunning = false;
            if (!emulator?.is_exited()) setStatus('statusPaused', 'paused');
            enableButtons(true);
            updateFullUI();
            return;
        }
        try {
            // run_n checks breakpoints and handles resuming from breakpoint internally.
            // Small chunks (2000 instructions) yield to the browser so Stop clicks are responsive.
            const json = emulator.run_n(2000);
            const info = JSON.parse(json);
            handleStepInfo(info);
            if (info.status === 'running') {
                animFrame = requestAnimationFrame(runChunk);
            } else {
                if (info.status === 'breakpoint') lastStoppedAtBreakpoint = true;
                isRunning = false;
                const elapsed = (performance.now() - startTime).toFixed(1);
                console.log(`[binb] run: ${elapsed}ms, ${info.instruction_count} insns`);
                enableButtons(true);
                updateFullUI();
            }
        } catch (err) {
            isRunning = false;
            appendTerminal(`\nError: ${err.message || err}`, 'error');
            setStatus('statusError', 'error');
            enableButtons(true);
        }
    }

    if (animFrame) cancelAnimationFrame(animFrame);
    runChunk();
}

function captureLastAccesses() {
    if (!emulator || !traceToggle.checked) {
        lastMemAccesses = [];
        return;
    }
    const len = emulator.get_trace_length();
    if (len > 0) {
        try {
            lastMemAccesses = JSON.parse(emulator.get_trace_mem_accesses(len - 1));
        } catch (e) {
            lastMemAccesses = [];
        }
    }
}

function renderStraceOutput() {
    const straceWrap = document.getElementById('strace-output-wrap');
    if (!straceOutput) return;
    if (!straceToggle.checked || !emulator) {
        straceOutput.innerHTML = '<span class="muted">Enable strace to see syscall trace output.</span>';
        return;
    }
    const trace = emulator.get_syscall_trace();
    if (!trace || !trace.trim()) {
        straceOutput.innerHTML = '<span class="muted">No syscalls yet. Step or run to see trace.</span>';
        return;
    }
    const lines = trace.split('\n').filter(l => l.length > 0);
    if (straceSearchQuery.trim()) {
        straceSearchMatches = runStraceSearch(lines, straceSearchQuery, straceSearchMode.value);
        if (straceSearchMatches.length > 0 && (straceSearchCurrentIndex < 0 || straceSearchCurrentIndex >= straceSearchMatches.length)) {
            straceSearchCurrentIndex = 0;
        } else if (straceSearchMatches.length === 0) {
            straceSearchCurrentIndex = -1;
        }
        updateStraceSearchStatus();
    } else {
        straceSearchMatches = [];
        straceSearchCurrentIndex = -1;
        if (straceSearchStatus) straceSearchStatus.textContent = '';
    }
    const matchSet = new Set(straceSearchMatches);
    const currentMatchLine = straceSearchMatches.length > 0 && straceSearchCurrentIndex >= 0 ? straceSearchMatches[straceSearchCurrentIndex] : -1;
    const html = lines.map((line, i) => {
        const searchCls = matchSet.has(i) ? (i === currentMatchLine ? ' strace-search-current' : ' strace-search-hit') : '';
        const mResult = line.match(/^(\w+)\((.*)\)\s*=\s*(.+)$/);
        const mNoResult = line.match(/^(\w+)\((.*)\)\s*$/);
        const num = `<span class="strace-num">${String(i + 1).padStart(lines.length.toString().length)}</span>`;
        if (mResult) {
            const [, name, args, result] = mResult;
            return `<div class="strace-row${searchCls}" data-line-index="${i}">${num}<span class="strace-name">${escapeHtml(name)}</span><span class="strace-args">${escapeHtml(args)}</span><span class="strace-result">= ${escapeHtml(result)}</span></div>`;
        }
        if (mNoResult) {
            const [, name, args] = mNoResult;
            return `<div class="strace-row${searchCls}" data-line-index="${i}">${num}<span class="strace-name">${escapeHtml(name)}</span><span class="strace-args">${escapeHtml(args)}</span></div>`;
        }
        return `<div class="strace-row${searchCls}" data-line-index="${i}">${num}<span class="strace-plain">${escapeHtml(line)}</span></div>`;
    }).join('');
    straceOutput.innerHTML = html;
    if (!straceSearchQuery.trim() && straceWrap) straceWrap.scrollTop = straceWrap.scrollHeight;
}

function handleStepInfo(info) {
    if (info.stdout) {
        terminal.textContent = info.stdout;
    }
    if (info.stderr) {
        appendTerminal(info.stderr, 'error');
    }

    // Update strace tab
    renderStraceOutput();

    if (info.status === 'exited') {
        const code = info.exit_code ?? 0;
        appendTerminal(`\n[Process exited with code ${code}]`, code === 0 ? 'info' : 'error');
        setStatus('statusExited', 'exited', code);
        enableButtons(false);
        btnReset.disabled = false;
    } else if (info.status === 'halted') {
        appendTerminal('\n[Process halted]', 'info');
        setStatus('statusHalted', 'exited');
    } else if (info.status === 'max_instructions') {
        appendTerminal('\n[Instruction limit reached]', 'error');
        setStatus('statusLimit', 'error');
    } else if (info.status === 'breakpoint') {
        setStatus('statusBreakpoint', 'breakpoint');
    } else if (info.status === 'needs_stdin') {
        const n = info.needs_stdin_count ?? 0;
        if (stdinPromptCount) stdinPromptCount.textContent = n;
        if (stdinPrompt) {
            stdinPrompt.style.display = '';
            if (stdinInput) {
                stdinInput.value = '';
                stdinInput.focus();
            }
        }
        setStatus('statusWaitingInput', 'paused');
    } else if (info.status.startsWith?.('error')) {
        appendTerminal(`\n[${info.status}]`, 'error');
        setStatus('statusError', 'error');
        enableButtons(false);
        btnReset.disabled = false;
    }
}

// ── Breakpoint management ───────────────────────────────────────────────────

function addBreakpointFromInput() {
    if (!emulator) return;
    const text = bpAddrInput.value.trim();
    if (!text) return;
    const addr = parseAddr(text);
    if (isNaN(addr)) return;

    emulator.add_breakpoint(addr);
    bpAddrInput.value = '';
    renderBreakpoints();
    renderDisasm();
}

function removeBreakpoint(addr) {
    if (!emulator) return;
    emulator.remove_breakpoint(addr);
    renderBreakpoints();
    renderDisasm();
}

function toggleBreakpointAtAddr(addr) {
    if (!emulator) return;
    if (emulator.has_breakpoint(addr)) {
        emulator.remove_breakpoint(addr);
    } else {
        emulator.add_breakpoint(addr);
    }
    renderBreakpoints();
    renderDisasm();
}

// x86-64 syscall number -> name (matches core syscall_name_64)
const SYSCALL_NAMES = {
    0: 'read', 1: 'write', 2: 'open', 3: 'close', 4: 'stat', 5: 'fstat', 6: 'lstat', 7: 'poll',
    8: 'lseek', 9: 'mmap', 10: 'mprotect', 11: 'munmap', 12: 'brk', 13: 'rt_sigaction', 14: 'rt_sigprocmask',
    15: 'rt_sigreturn', 16: 'ioctl', 17: 'pread64', 18: 'pwrite64', 19: 'readv', 20: 'writev', 21: 'access',
    22: 'pipe', 24: 'sched_yield', 25: 'mremap', 28: 'madvise', 32: 'dup', 33: 'dup2', 35: 'nanosleep',
    37: 'alarm', 38: 'setitimer', 39: 'getpid', 41: 'socket', 42: 'connect', 43: 'accept',
    44: 'sendto', 45: 'recvfrom', 46: 'sendmsg', 47: 'recvmsg', 48: 'shutdown', 49: 'bind',
    50: 'listen', 51: 'getsockname', 52: 'getpeername', 53: 'socketpair', 54: 'setsockopt', 55: 'getsockopt',
    56: 'clone', 57: 'fork', 58: 'vfork', 59: 'execve', 60: 'exit', 61: 'wait4', 62: 'kill', 63: 'uname',
    72: 'fcntl', 73: 'flock', 74: 'fsync', 75: 'fdatasync', 76: 'truncate', 77: 'ftruncate', 78: 'getdents',
    79: 'getcwd', 80: 'chdir', 81: 'fchdir', 82: 'rename', 83: 'mkdir', 84: 'rmdir', 85: 'creat', 86: 'link',
    87: 'unlink', 88: 'symlink', 89: 'readlink', 90: 'chmod', 91: 'fchmod', 92: 'chown', 93: 'fchown',
    94: 'lchown', 95: 'umask', 96: 'gettimeofday', 97: 'getrlimit', 98: 'getrusage', 99: 'sysinfo',
    100: 'times', 101: 'ptrace', 102: 'getuid', 103: 'syslog', 104: 'getgid', 105: 'setuid',
    106: 'setgid', 107: 'geteuid', 108: 'getegid', 109: 'setpgid', 110: 'getppid', 111: 'getpgrp',
    112: 'setsid', 113: 'setreuid', 114: 'setregid', 115: 'getgroups', 116: 'setgroups', 117: 'getresuid',
    118: 'setresuid', 119: 'getresgid', 120: 'setresgid', 121: 'getpgid', 122: 'setfsuid', 123: 'setfsgid',
    124: 'getsid', 125: 'capget', 126: 'capset', 131: 'sigaltstack', 135: 'personality',
    137: 'statfs', 138: 'fstatfs', 155: 'pivot_root', 157: 'prctl', 158: 'arch_prctl', 160: 'setrlimit',
    161: 'chroot', 162: 'sync', 186: 'gettid', 200: 'tkill', 201: 'time', 202: 'futex',
    203: 'sched_setaffinity', 204: 'sched_getaffinity', 213: 'epoll_create', 217: 'getdents64',
    218: 'set_tid_address', 228: 'clock_gettime', 229: 'clock_getres', 230: 'clock_nanosleep', 231: 'exit_group',
    232: 'epoll_wait', 233: 'epoll_ctl', 234: 'tgkill', 257: 'openat', 258: 'mkdirat', 260: 'fchownat',
    261: 'futimesat', 262: 'newfstatat', 263: 'unlinkat', 264: 'renameat', 265: 'linkat', 266: 'symlinkat',
    267: 'readlinkat', 268: 'fchmodat', 269: 'faccessat', 270: 'pselect6', 271: 'ppoll', 272: 'unshare',
    273: 'set_robust_list', 274: 'get_robust_list', 275: 'splice', 276: 'tee', 278: 'vmsplice',
    281: 'epoll_pwait', 284: 'eventfd', 288: 'accept4', 289: 'signalfd4', 290: 'eventfd2', 291: 'epoll_create1',
    292: 'dup3', 293: 'pipe2', 296: 'timerfd_settime', 302: 'prlimit64', 318: 'getrandom', 319: 'memfd_create',
    322: 'execveat', 332: 'statx', 334: 'rseq', 435: 'clone3', 439: 'faccessat2',
};

// name -> [x64_nr, i386_nr] or [nr] for 64-bit-only; both ABIs hit when both numbers present
const SYSCALL_NAME_TO_NUMBERS = {
    read: [0, 3], write: [1, 4], open: [2, 5], close: [3, 6], stat: [4, 195], fstat: [5, 197], lstat: [6, 196],
    lseek: [8, 19], ioctl: [16, 54], pread64: [17], pwrite64: [18], readv: [19, 145], writev: [20, 146],
    access: [21, 33], pipe: [22, 42], dup: [32, 41], dup2: [33, 63], fcntl: [72, 55], getdents: [217, 220], getdents64: [217, 220],
    getcwd: [79, 183], chdir: [80, 12], creat: [85], readlink: [89, 85], umask: [95, 60], openat: [257, 295],
    newfstatat: [262, 300], readlinkat: [267, 305], faccessat: [269, 307], dup3: [292], pipe2: [293, 331],
    statx: [332, 383], faccessat2: [439], mmap: [9, 192], mprotect: [10, 125], munmap: [11, 91], brk: [12, 45],
    mremap: [25], madvise: [28], getpid: [39, 20], exit: [60, 1], wait4: [61, 114], kill: [62, 37], uname: [63, 122],
    getrlimit: [97, 191], getrusage: [98], sysinfo: [99, 116], getuid: [102, 199], getgid: [104, 200],
    geteuid: [107, 201], getegid: [108, 202], getppid: [110, 64], getresuid: [117, 209], getresgid: [119, 211],
    getpgid: [121], prctl: [157], arch_prctl: [158], gettid: [186, 224], tkill: [200], time: [201, 13],
    futex: [202, 240],
    sched_getaffinity: [204, 242], exit_group: [231, 252], prlimit64: [302, 340], set_thread_area: [243],
    gettimeofday: [96, 78], clock_gettime: [228, 265], clock_getres: [229, 266], clock_nanosleep: [230],
    rt_sigaction: [13, 174], rt_sigprocmask: [14, 175], sigaltstack: [131], statfs: [137, 268], fstatfs: [138],
    set_tid_address: [218, 258], set_robust_list: [273, 311], eventfd: [284, 328], eventfd2: [290, 328],
    getrandom: [318, 355], memfd_create: [319],
};

// Build reverse map: nr -> [nr64, nr32] (or [nr]) so adding by number also adds other ABI
const SYSCALL_NR_TO_NUMBERS = (() => {
    const map = {};
    for (const nrs of Object.values(SYSCALL_NAME_TO_NUMBERS)) {
        for (const nr of nrs) {
            if (!(nr in map)) map[nr] = [...nrs];
        }
    }
    return map;
})();

function parseSyscallInput(text) {
    const t = text.trim();
    const num = parseInt(t, 10);
    if (!isNaN(num) && num >= 0) return num;
    const m = t.match(/\((\d+)\)/);
    if (m) return parseInt(m[1], 10);
    const byName = Object.entries(SYSCALL_NAMES).find(([, name]) =>
        name.toLowerCase() === t.toLowerCase());
    if (byName) return parseInt(byName[0], 10);
    return NaN;
}

/** Returns [nr] or [nr, ...partners] for a number (so both x64 and i386 hit), or [nr64, nr32] for a name. */
function getSyscallNumbers(text) {
    const t = text.trim();
    const num = parseInt(t, 10);
    if (!isNaN(num) && num >= 0 && num === Math.floor(num)) {
        const paired = SYSCALL_NR_TO_NUMBERS[num];
        return paired ? paired.slice() : [num];
    }
    const m = t.match(/\((\d+)\)/);
    if (m) {
        const n = parseInt(m[1], 10);
        const paired = SYSCALL_NR_TO_NUMBERS[n];
        return paired ? paired.slice() : [n];
    }
    const name = t.toLowerCase();
    const nrs = SYSCALL_NAME_TO_NUMBERS[name];
    return nrs ? nrs.slice() : [];
}

function addSyscallBreakpointFromInput() {
    if (!emulator) return;
    const text = bpSyscallInput.value.trim();
    if (!text) return;
    const nrs = getSyscallNumbers(text);
    if (nrs.length === 0) return;
    for (const nr of nrs) {
        emulator.add_syscall_breakpoint(Math.round(Number(nr)));
    }
    bpSyscallInput.value = '';
    renderBreakpoints();
}

function removeSyscallBreakpoint(nr) {
    if (!emulator) return;
    emulator.remove_syscall_breakpoint(Math.round(Number(nr)));
    renderBreakpoints();
}

/** Remove a logical syscall breakpoint (all numbers in the group, e.g. 20 and 146 for writev). */
function removeSyscallBreakpointGroup(nrs) {
    if (!emulator) return;
    for (const nr of nrs) {
        emulator.remove_syscall_breakpoint(Math.round(Number(nr)));
    }
    renderBreakpoints();
}

/** Group syscall breakpoint numbers into logical breakpoints (same syscall, both ABIs). Returns array of sorted number arrays. */
function groupSyscallBreakpoints(syscallBps) {
    const bpsSet = new Set(syscallBps);
    const keyToGroup = {};
    for (const nr of syscallBps) {
        // A number (e.g. 202) can belong to multiple syscalls (getegid [108,202], futex [202,240]).
        // Use the group that is fully contained in current breakpoints and prefer the largest match.
        let canonical = null;
        for (const nrs of Object.values(SYSCALL_NAME_TO_NUMBERS)) {
            const sorted = nrs.slice().sort((a, b) => a - b);
            if (nrs.includes(nr) && sorted.every(n => bpsSet.has(n))) {
                if (!canonical || sorted.length > canonical.length) canonical = sorted;
            }
        }
        if (!canonical) canonical = [nr];
        const key = canonical.join(',');
        if (!keyToGroup[key]) keyToGroup[key] = canonical;
    }
    return Object.values(keyToGroup);
}

/** Find a name for a group of syscall numbers (e.g. [20, 146] -> "writev"). */
function nameForSyscallGroup(nrs) {
    const sorted = nrs.slice().sort((a, b) => a - b);
    for (const [name, arr] of Object.entries(SYSCALL_NAME_TO_NUMBERS)) {
        const a = arr.slice().sort((a, b) => a - b);
        if (a.length === sorted.length && a.every((v, i) => v === sorted[i])) return name;
    }
    return null;
}

function renderBreakpoints() {
    if (!emulator) return;
    try {
        if (bpAnySyscall) bpAnySyscall.checked = emulator.get_break_on_any_syscall();
        const addrBps = JSON.parse(emulator.get_breakpoints());
        const syscallBps = JSON.parse(emulator.get_syscall_breakpoints());
        const anySyscall = emulator.get_break_on_any_syscall();
        if (addrBps.length === 0 && syscallBps.length === 0 && !anySyscall) {
            bpList.innerHTML = '<div class="muted">No breakpoints set. Add an address or syscall number, or enable "Break on any syscall".</div>';
            return;
        }
        let html = '';
        if (anySyscall) {
            html += `<div class="bp-entry bp-any-syscall-entry">
                <span class="bp-icon">&#x1F535;</span>
                <span class="bp-type">syscall</span>
                <span class="bp-addr mono">any syscall</span>
                <span class="muted">(toggle above to remove)</span>
            </div>`;
        }
        for (const addr of addrBps) {
            const numAddr = parseInt(addr, 16);
            html += `<div class="bp-entry">
                <span class="bp-icon">&#x1F534;</span>
                <span class="bp-type">addr</span>
                <span class="bp-addr mono">${addr}</span>
                <button class="btn btn-xs btn-danger" onclick="window._removeBp(${numAddr})">x</button>
            </div>`;
        }
        const groups = groupSyscallBreakpoints(syscallBps);
        for (const nrs of groups) {
            const name = nameForSyscallGroup(nrs);
            const label = name ? name : nrs.join(', ');
            const dataNrs = nrs.map(n => n.toString()).join(',');
            html += `<div class="bp-entry">
                <span class="bp-icon">&#x1F535;</span>
                <span class="bp-type">syscall</span>
                <span class="bp-addr mono">${escapeHtml(label)}</span>
                <button class="btn btn-xs btn-danger" data-syscall-nrs="${escapeHtml(dataNrs)}" onclick="window._removeSyscallBpGroupFromBtn(this)">x</button>
            </div>`;
        }
        bpList.innerHTML = html;
    } catch (e) {
        // ignore
    }
}
window._removeBp = (addr) => removeBreakpoint(addr);
window._removeSyscallBp = (nr) => removeSyscallBreakpoint(nr);
window._removeSyscallBpGroupFromBtn = (btn) => {
    const dataNrs = btn.getAttribute('data-syscall-nrs');
    if (dataNrs) removeSyscallBreakpointGroup(dataNrs.split(',').map(s => parseInt(s, 10)));
};

// ── Functions tab ────────────────────────────────────────────────────────────

const fnSearchInput = document.getElementById('fn-search');
const fnListEl = document.getElementById('fn-list');
const fnCountEl = document.getElementById('fn-count');
let lastStringsData = null;
const stringsSearchInput = document.getElementById('strings-search');
const stringsCountEl = document.getElementById('strings-count');

function renderFunctions(filter) {
    if (!fnListEl) return;
    // Rebuild global address map for disasm labels
    fnAddrMap = new Map();
    if (elfFunctions && elfFunctions.length > 0) {
        for (const fn of elfFunctions) fnAddrMap.set(fn.addr, fn.name);
    }

    if (!elfFunctions || elfFunctions.length === 0) {
        fnListEl.innerHTML = '<div class="muted">No functions found (binary may be stripped).</div>';
        if (fnCountEl) fnCountEl.textContent = '';
        return;
    }

    const query = (filter || '').toLowerCase().trim();
    const filtered = query
        ? elfFunctions.filter(f =>
            f.name.toLowerCase().includes(query) ||
            f.addr.toString(16).includes(query) ||
            (f.file && f.file.toLowerCase().includes(query)))
        : elfFunctions;

    if (fnCountEl) {
        const dwarfCount = elfFunctions.filter(f => f.file).length;
        const dwarfBadge = dwarfCount > 0 ? ` (DWARF: ${dwarfCount})` : '';
        fnCountEl.textContent = query
            ? `${filtered.length} / ${elfFunctions.length}${dwarfBadge}`
            : `${elfFunctions.length} functions${dwarfBadge}`;
    }

    if (filtered.length === 0) {
        fnListEl.innerHTML = '<div class="muted">No matches.</div>';
        return;
    }

    // Limit display to avoid lag with thousands of symbols
    const MAX_DISPLAY = 500;
    const showing = filtered.slice(0, MAX_DISPLAY);
    const hasBp = (addr) => {
        try { return emulator && emulator.has_breakpoint(addr); } catch { return false; }
    };

    const hasDwarf = showing.some(f => f.file);
    let html = '<table class="fn-table"><thead><tr><th class="fn-bp-col"></th><th>Name</th><th>Address</th><th>Size</th>';
    if (hasDwarf) html += '<th>Source</th>';
    html += '<th>Bind</th></tr></thead><tbody>';
    for (const f of showing) {
        const bp = hasBp(f.addr);
        const addrHex = '0x' + f.addr.toString(16);
        const fileLine = f.file ? `${escapeHtml(f.file)}${f.line ? ':' + f.line : ''}` : '';
        html += `<tr class="fn-row${bp ? ' fn-bp-active' : ''}" data-addr="${f.addr}">
            <td class="fn-bp-col"><span class="fn-bp-dot${bp ? ' active' : ''}" title="${bp ? 'Remove breakpoint' : 'Add breakpoint'}" data-fn-addr="${f.addr}">&#9679;</span></td>
            <td class="fn-name" title="${escapeHtml(f.name)}">${escapeHtml(f.name)}</td>
            <td class="fn-addr mono" title="Click to navigate disassembly">${addrHex}</td>
            <td class="fn-size mono">${f.size > 0 ? f.size : ''}</td>`;
        if (hasDwarf) html += `<td class="fn-file" title="${fileLine}">${fileLine}</td>`;
        html += `<td class="fn-bind">${f.bind}</td>
        </tr>`;
    }
    html += '</tbody></table>';
    if (filtered.length > MAX_DISPLAY) {
        html += `<div class="muted fn-truncated">${filtered.length - MAX_DISPLAY} more functions not shown. Refine your search.</div>`;
    }
    fnListEl.innerHTML = html;

    // Click on address or name → navigate disassembly to that function
    fnListEl.querySelectorAll('.fn-addr, .fn-name').forEach(td => {
        td.addEventListener('click', () => {
            const row = td.closest('.fn-row');
            if (!row) return;
            const addr = parseInt(row.dataset.addr, 10);
            if (isNaN(addr) || !emulator) return;
            navigateDisasmTo(addr);
        });
    });

    // Click on breakpoint dot → toggle breakpoint
    fnListEl.querySelectorAll('.fn-bp-dot').forEach(dot => {
        dot.addEventListener('click', (e) => {
            e.stopPropagation();
            const addr = parseInt(dot.dataset.fnAddr, 10);
            if (isNaN(addr) || !emulator) return;
            try {
                if (emulator.has_breakpoint(addr)) {
                    emulator.remove_breakpoint(addr);
                } else {
                    emulator.add_breakpoint(addr);
                }
            } catch (err) {
                console.warn('breakpoint toggle failed:', err);
            }
            renderFunctions(fnSearchInput ? fnSearchInput.value : '');
            renderBreakpoints();
        });
    });
}

if (fnSearchInput) {
    fnSearchInput.addEventListener('input', () => {
        renderFunctions(fnSearchInput.value);
    });
}

// ── ELF structure tab ───────────────────────────────────────────────────────

function renderElfStructure(data) {
    const el = document.getElementById('elf-structure');
    if (!el) return;
    if (!data || (!data.header && !data.program_headers && !data.section_headers)) {
        el.innerHTML = '<span class="muted">No ELF structure data.</span>';
        renderStrings(data);
        return;
    }
    let html = '';
    html += '<div class="pe-at-a-glance">' + buildElfSummaryHtml(data) + '</div>';
    if (data.header) {
        html += '<div class="elf-section"><span class="elf-section-title">ELF Header</span><pre class="elf-header-pre">';
        const h = data.header;
        html += `Class:      ${escapeHtml(h.class)}
Data:       ${escapeHtml(h.data)}
Version:    ${h.version}
OS/ABI:     ${escapeHtml(h.os_abi)}
Type:       ${escapeHtml(h.e_type)}
Machine:    ${escapeHtml(h.e_machine)}
Entry:      ${escapeHtml(h.entry)}
e_phoff:    ${h.e_phoff}
e_shoff:    ${h.e_shoff}
e_phnum:    ${h.e_phnum}
e_shnum:    ${h.e_shnum}
e_shstrndx: ${h.e_shstrndx}
`;
        html += '</pre></div>';
    }
    if (data.compiler_info && data.compiler_info.length > 0) {
        html += '<div class="elf-section"><span class="elf-section-title">Compiler / build tools</span><ul class="elf-compiler-list">';
        for (const c of data.compiler_info) html += '<li>' + escapeHtml(c) + '</li>';
        html += '</ul></div>';
    }
    if (data.program_headers && data.program_headers.length > 0) {
        html += '<div class="elf-section"><span class="elf-section-title">Program Headers</span>';
        html += '<table class="elf-table"><thead><tr><th>Type</th><th>Flags</th><th>Offset</th><th>VirtAddr</th><th>FileSiz</th><th>MemSiz</th><th>Align</th></tr></thead><tbody>';
        for (const ph of data.program_headers) {
            html += `<tr><td>${escapeHtml(ph.type_)}</td><td>${escapeHtml(ph.flags)}</td><td class="mono">${escapeHtml(ph.offset)}</td><td class="mono">${escapeHtml(ph.vaddr)}</td><td class="mono">${escapeHtml(ph.filesz)}</td><td class="mono">${escapeHtml(ph.memsz)}</td><td class="mono">${escapeHtml(ph.align)}</td></tr>`;
        }
        html += '</tbody></table></div>';
    }
    if (data.section_headers && data.section_headers.length > 0) {
        html += '<div class="elf-section"><span class="elf-section-title">Section Headers</span>';
        html += '<table class="elf-table"><thead><tr><th>Name</th><th>Type</th><th>Flags</th><th>Addr</th><th>Offset</th><th>Size</th><th>Entropy</th><th>Align</th></tr></thead><tbody>';
        for (const sh of data.section_headers) {
            html += `<tr><td>${escapeHtml(sh.name)}</td><td>${escapeHtml(sh.type_)}</td><td>${escapeHtml(sh.flags)}</td><td class="mono">${escapeHtml(sh.addr)}</td><td class="mono">${escapeHtml(sh.offset)}</td><td class="mono">${escapeHtml(sh.size)}</td><td>${escapeHtml(sh.entropy != null ? sh.entropy : '')}</td><td>${sh.align}</td></tr>`;
        }
        html += '</tbody></table></div>';
    }
    // DWARF debug info section
    if (data.dwarf && data.dwarf.has_debug_info) {
        html += '<div class="elf-section"><span class="elf-section-title">DWARF Debug Info</span>';
        html += `<p class="elf-dwarf-summary">${data.dwarf.compilation_units.length} compilation units</p>`;
        html += '<table class="elf-table"><thead><tr><th>Source File</th><th>Comp Dir</th><th>Language</th><th>Low PC</th><th>High PC</th></tr></thead><tbody>';
        for (const cu of data.dwarf.compilation_units) {
            html += `<tr>`;
            html += `<td>${cu.name ? escapeHtml(cu.name) : '<span class="muted">-</span>'}</td>`;
            html += `<td class="fn-file" title="${cu.comp_dir ? escapeHtml(cu.comp_dir) : ''}">${cu.comp_dir ? escapeHtml(cu.comp_dir) : '<span class="muted">-</span>'}</td>`;
            html += `<td>${cu.language ? escapeHtml(cu.language) : '<span class="muted">-</span>'}</td>`;
            html += `<td class="mono">${cu.low_pc != null ? '0x' + cu.low_pc.toString(16) : ''}</td>`;
            html += `<td class="mono">${cu.high_pc != null ? '0x' + cu.high_pc.toString(16) : ''}</td>`;
            html += `</tr>`;
        }
        html += '</tbody></table></div>';
    }
    el.innerHTML = html;
    el.querySelectorAll('.xref-addr').forEach(node => {
        node.addEventListener('click', () => {
            const addr = parseInt(node.getAttribute('data-addr'), 10);
            if (!isNaN(addr) && emulator) navigateDisasmTo(addr);
        });
    });
    renderStrings(data);
}

function renderStrings(data) {
    const el = document.getElementById('strings-structure');
    if (!el) return;
    if (data != null) lastStringsData = data;
    if (!lastStringsData || !lastStringsData.strings || lastStringsData.strings.length === 0) {
        el.innerHTML = '<span class="muted">' + escapeHtml(t('stringsLoadPrompt')) + '</span>';
        if (stringsCountEl) stringsCountEl.textContent = '';
        return;
    }
    const query = (stringsSearchInput ? stringsSearchInput.value : '').toLowerCase().trim();
    const all = lastStringsData.strings;
    const filtered = query
        ? all.filter(s => {
            const preview = (s.preview || '').toLowerCase();
            const offsetHex = '0x' + Number(s.offset).toString(16);
            return preview.includes(query) || offsetHex.toLowerCase().includes(query);
        })
        : all;
    if (stringsCountEl) {
        stringsCountEl.textContent = filtered.length === all.length
            ? String(all.length)
            : filtered.length + ' / ' + all.length;
    }
    let html = '<table class="elf-table"><thead><tr><th>Offset</th><th>Length</th><th>Preview</th></tr></thead><tbody>';
    for (const str of filtered) {
        const va = str.va != null && str.va !== 0 ? str.va : null;
        const addrCell = va != null
            ? `<td class="mono xref-addr" data-addr="${va}" title="Go to disassembly">${escapeHtml('0x' + Number(str.offset).toString(16))}</td>`
            : `<td class="mono">${escapeHtml('0x' + Number(str.offset).toString(16))}</td>`;
        html += `<tr>${addrCell}<td>${str.length}</td><td class="string-preview">${escapeHtml(str.preview || '')}</td></tr>`;
    }
    html += '</tbody></table>';
    el.innerHTML = html;
    el.querySelectorAll('.xref-addr').forEach(node => {
        node.addEventListener('click', () => {
            const addr = parseInt(node.getAttribute('data-addr'), 10);
            if (!isNaN(addr) && emulator) navigateDisasmTo(addr);
        });
    });
}

if (stringsSearchInput) {
    stringsSearchInput.addEventListener('input', () => {
        if (lastStringsData) renderStrings(lastStringsData);
    });
}

function renderPeStructure(data) {
    const el = document.getElementById('elf-structure');
    if (!el) return;
    if (!data || !data.header) {
        el.innerHTML = '<span class="muted">No PE structure data.</span>';
        renderStrings(null);
        return;
    }
    let html = '';
    // At-a-glance PE/DLL summary at top
    html += '<div class="pe-at-a-glance">' + buildPeSummaryHtml(data) + '</div>';
    const h = data.header;
    html += '<div class="elf-section"><span class="elf-section-title">PE Header</span><pre class="elf-header-pre">';
    html += `Format:     ${escapeHtml(h.format)}
Machine:   ${escapeHtml(h.machine)}
ImageBase: ${escapeHtml(h.image_base)}
Entry RVA: ${escapeHtml(h.entry_rva)}
Subsystem: ${escapeHtml(h.subsystem)}
Sections:  ${h.num_sections}
Type:      ${h.is_dll ? 'DLL' : 'EXE'}
`;
    html += '</pre></div>';
    if (data.sections && data.sections.length > 0) {
        html += '<div class="elf-section"><span class="elf-section-title">Sections</span>';
        html += '<table class="elf-table"><thead><tr><th>Name</th><th>Virtual Address</th><th>Virtual Size</th><th>Raw Size</th><th>Entropy</th><th>Characteristics</th></tr></thead><tbody>';
        for (const s of data.sections) {
            html += `<tr><td>${escapeHtml(s.name)}</td><td class="mono">${escapeHtml(s.virtual_address)}</td><td class="mono">${escapeHtml(s.virtual_size)}</td><td class="mono">${escapeHtml(s.raw_size)}</td><td>${escapeHtml(s.entropy != null ? s.entropy : '')}</td><td>${escapeHtml(s.characteristics)}</td></tr>`;
        }
        html += '</tbody></table></div>';
    }
    // Always show Rich Header section for PE (present or not)
    {
        const rh = data.rich_header;
        html += '<div class="elf-section"><span class="elf-section-title">Rich Header (compiler / linker)</span><pre class="elf-header-pre">';
        if (rh && rh.present) {
            html += 'Present: yes\nSize: ' + rh.size + ' bytes\nChecksum: ' + escapeHtml(rh.checksum);
            if (rh.tools && rh.tools.length > 0) {
                html += '\n\nTools:';
                for (const t of rh.tools) html += '\n  ' + escapeHtml(t.name) + ' — build ' + t.build + ' (×' + t.use_count + ')';
            } else if (rh.tool_count) html += '\nTools: ' + rh.tool_count;
        } else {
            html += 'Present: no';
        }
        html += '</pre></div>';
    }
    if (data.overlay) {
        const ov = data.overlay;
        html += '<div class="elf-section"><span class="elf-section-title">Overlay</span>';
        html += '<pre class="elf-header-pre">Offset: 0x' + ov.offset.toString(16) + '\nSize: ' + ov.size + ' bytes</pre></div>';
    }
    if (data.exports && data.exports.length > 0) {
        html += '<div class="elf-section"><span class="elf-section-title">Exports</span>';
        html += '<table class="elf-table"><thead><tr><th>Name</th><th>RVA</th><th>Ordinal</th></tr></thead><tbody>';
        for (const e of data.exports) {
            html += `<tr><td>${escapeHtml(e.name)}</td><td class="mono">${escapeHtml(e.rva)}</td><td>${e.ordinal}</td></tr>`;
        }
        html += '</tbody></table></div>';
    }
    if (data.imports && data.imports.length > 0) {
        const imageBase = typeof data.image_base === 'number' ? data.image_base : (parseInt(String(data.image_base).replace(/^0x/i, ''), 16) || 0);
        html += '<div class="elf-section"><span class="elf-section-title">Imports</span>';
        html += '<table class="elf-table"><thead><tr><th>DLL</th><th>Name</th><th>IAT Offset</th><th>Referenced at</th></tr></thead><tbody>';
        for (const i of data.imports) {
            let refsCell = '<span class="muted">—</span>';
            if (i.refs && i.refs.length > 0) {
                refsCell = i.refs.map(rva => {
                    const addr = imageBase + Number(rva);
                    return `<span class="mono xref-addr" data-addr="${addr}" title="Go to disassembly">0x${addr.toString(16)}</span>`;
                }).join(', ');
            }
            html += `<tr><td>${escapeHtml(i.dll)}</td><td>${escapeHtml(i.name)}</td><td class="mono">${escapeHtml(i.iat_offset)}</td><td class="import-refs">${refsCell}</td></tr>`;
        }
        html += '</tbody></table></div>';
    }
    el.innerHTML = html;
    // Click-to-navigate for xref addresses (Binary tab)
    el.querySelectorAll('.xref-addr').forEach(node => {
        node.addEventListener('click', () => {
            const addr = parseInt(node.getAttribute('data-addr'), 10);
            if (!isNaN(addr) && emulator) navigateDisasmTo(addr);
        });
    });
    renderStrings(data);
}

// ── Watch list management ───────────────────────────────────────────────────

function addWatchFromInput() {
    const text = watchAddrInput.value.trim();
    if (!text) return;
    const addr = parseAddr(text);
    if (isNaN(addr)) return;
    const size = parseInt(watchSizeInput.value) || 4;

    watchList.push({ addr, size, label: `0x${addr.toString(16)}` });
    watchAddrInput.value = '';
    setDaddr(addr, size);
    renderWatchList();
}

function renderWatchList() {
    if (watchList.length === 0) {
        watchListEl.innerHTML = '<div class="muted">Track data addresses to see all reads/writes across execution. Use <kbd>j</kbd>/<kbd>k</kbd> to navigate invocations, <kbd>J</kbd>/<kbd>K</kbd> for data accesses.</div>';
        return;
    }
    let html = '';
    for (let i = 0; i < watchList.length; i++) {
        const w = watchList[i];
        const isActive = daddr && daddr.addr === w.addr && daddr.size === w.size;
        const activeCls = isActive ? 'watch-active' : '';
        // Count hits if trace is available
        let hitInfo = '';
        if (emulator && traceToggle.checked && emulator.get_trace_length() > 0) {
            const hits = JSON.parse(emulator.search_trace_by_addr(w.addr, w.size, 10000));
            hitInfo = `<span class="watch-hits">${hits.length} hits</span>`;
        }
        html += `<div class="watch-entry ${activeCls}" data-idx="${i}">
            <span class="watch-color" style="background:${isActive ? 'var(--yellow)' : 'var(--border)'}"></span>
            <span class="watch-addr mono" onclick="window._setDaddr(${w.addr}, ${w.size})">0x${w.addr.toString(16)}</span>
            <span class="watch-size">${w.size}B</span>
            ${hitInfo}
            <button class="btn btn-xs btn-danger" onclick="window._removeWatch(${i})">x</button>
        </div>`;
    }
    watchListEl.innerHTML = html;
}
window._removeWatch = (idx) => {
    const removed = watchList.splice(idx, 1)[0];
    if (daddr && removed && daddr.addr === removed.addr) clearDaddr();
    renderWatchList();
};
window._setDaddr = (addr, size) => setDaddr(addr, size);

function syncHistoryToTrace() {
    if (!regionHistoryTbody || !regionHistoryTbody.rows.length) return;
    const idx = traceMode ? traceCursor : (emulator && emulator.get_trace_length() > 0 ? emulator.get_trace_length() - 1 : -1);
    if (idx < 0) return;
    let firstCurrent = null;
    for (const row of regionHistoryTbody.rows) {
        const seek = parseInt(row.dataset.seek, 10);
        if (seek === idx) {
            row.classList.add('history-row-current');
            if (firstCurrent === null) firstCurrent = row;
        } else {
            row.classList.remove('history-row-current');
        }
    }
    if (firstCurrent) firstCurrent.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
}

function renderRegionHistory() {
    if (!regionHistoryPlaceholder || !regionHistoryTable || !regionHistoryTbody) return;
    const showPlaceholder = () => {
        regionHistoryPlaceholder.style.display = '';
        regionHistoryTable.style.display = 'none';
    };
    if (!daddr || !emulator || emulator.get_trace_length() <= 0) {
        if (btnHistoryCopyCsv) btnHistoryCopyCsv.style.display = 'none';
        showPlaceholder();
        return;
    }
    try {
        const maxEntries = 2000;
        const json = emulator.get_trace_region_history(daddr.addr, daddr.size, maxEntries);
        const entries = JSON.parse(json);
        if (!entries || entries.length === 0) {
            if (btnHistoryCopyCsv) btnHistoryCopyCsv.style.display = 'none';
            regionHistoryPlaceholder.textContent = t('noAccessesToRegion');
            regionHistoryPlaceholder.style.display = '';
            regionHistoryTable.style.display = 'none';
            return;
        }
        regionHistoryPlaceholder.style.display = 'none';
        regionHistoryTable.style.display = 'table';
        if (btnHistoryCopyCsv) btnHistoryCopyCsv.style.display = '';
        let html = '';
        for (const e of entries) {
            const rw = e.is_write ? 'W' : 'R';
            const value = e.data != null ? e.data : '—';
            const seek = typeof e.local_index === 'number' ? e.local_index : parseInt(e.local_index, 10);
            html += `<tr class="history-row" data-seek="${seek}" title="Seek to instruction #${seek}">
                <td class="mono">${e.local_index}</td>
                <td class="mono">${e.rip}</td>
                <td>${rw}</td>
                <td class="mono">${e.addr}</td>
                <td>${e.size}</td>
                <td class="mono">${value}</td>
            </tr>`;
        }
        regionHistoryTbody.innerHTML = html;
        regionHistoryTbody.querySelectorAll('.history-row').forEach(row => {
            row.addEventListener('click', () => {
                const idx = parseInt(row.dataset.seek, 10);
                if (!isNaN(idx)) seekTrace(idx);
            });
        });
        syncHistoryToTrace();
    } catch (err) {
        if (btnHistoryCopyCsv) btnHistoryCopyCsv.style.display = 'none';
        regionHistoryPlaceholder.textContent = t('failedLoadRegionHistory') + ' ' + (err && err.message ? err.message : String(err));
        regionHistoryPlaceholder.style.display = '';
        regionHistoryTable.style.display = 'none';
    }
}

function copyRegionHistoryCsv() {
    if (!regionHistoryTbody || !regionHistoryTbody.rows.length) return;
    const rows = [];
    rows.push(['#', 'RIP', 'R/W', 'Addr', 'Size', 'Value']);
    for (const tr of regionHistoryTbody.rows) {
        const cells = Array.from(tr.cells).map(c => (c.textContent || '').trim());
        rows.push(cells);
    }
    const csv = rows.map(r => r.map(c => `"${String(c).replace(/"/g, '""')}"`).join(',')).join('\n');
    navigator.clipboard.writeText(csv).then(() => {
        if (btnHistoryCopyCsv) { btnHistoryCopyCsv.textContent = t('copied'); setTimeout(() => { btnHistoryCopyCsv.textContent = t('copyCsv'); }, 1500); }
    }).catch(() => {});
}
if (btnHistoryCopyCsv) btnHistoryCopyCsv.addEventListener('click', copyRegionHistoryCsv);

window._previewAccMem = (addr, size, isWrite) => {
    const accesses = traceMode ? (traceMemAccesses || []) : lastMemAccesses;
    previewAccessMemory(addr, size, isWrite, accesses);
};

// ── Memory search ───────────────────────────────────────────────────────────

/** Parse hex query to byte array. Supports "41 42", "0x41 0x42", "4142", "41 42 43". */
function parseHexQuery(str) {
    const s = str.trim();
    if (!s) return null;
    const tokens = s.split(/\s+/).filter(Boolean);
    const out = [];
    for (const t of tokens) {
        let hex = t;
        if (hex.toLowerCase().startsWith('0x')) hex = hex.slice(2);
        if (hex.length === 2) {
            const n = parseInt(hex, 16);
            if (isNaN(n)) return null;
            out.push(n & 0xff);
        } else if (hex.length > 2) {
            for (let i = 0; i < hex.length; i += 2) {
                const n = parseInt(hex.slice(i, i + 2), 16);
                if (isNaN(n)) return null;
                out.push(n & 0xff);
            }
        }
    }
    return out.length ? out : null;
}

/** Detect search mode from query when mode is 'auto'. */
function detectSearchMode(query) {
    const q = query.trim();
    if (/^\/.*\/[gimsuy]*$/.test(q)) return 'regex';
    if (/^([0-9a-fA-Fx\s]+)$/.test(q) && /[0-9a-fA-F]/.test(q)) return 'hex';
    return 'string';
}

/** Run search on byte array. Returns array of { start, end } (end exclusive). */
function runMemorySearch(bytes, query, mode) {
    const q = query.trim();
    if (!q) return [];
    const effectiveMode = mode === 'auto' ? detectSearchMode(q) : mode;
    const matches = [];

    if (effectiveMode === 'hex') {
        const needle = parseHexQuery(q);
        if (!needle || needle.length === 0) return [];
        const n = needle.length;
        for (let i = 0; i <= bytes.length - n; i++) {
            let found = true;
            for (let j = 0; j < n; j++) {
                if (bytes[i + j] !== needle[j]) { found = false; break; }
            }
            if (found) matches.push({ start: i, end: i + n });
        }
        return matches;
    }

    if (effectiveMode === 'string') {
        const needle = new TextEncoder().encode(q);
        const n = needle.length;
        for (let i = 0; i <= bytes.length - n; i++) {
            let found = true;
            for (let j = 0; j < n; j++) {
                if (bytes[i + j] !== needle[j]) { found = false; break; }
            }
            if (found) matches.push({ start: i, end: i + n });
        }
        return matches;
    }

    if (effectiveMode === 'regex') {
        let pattern = q;
        if (pattern.startsWith('/') && pattern.lastIndexOf('/') > 0) {
            const lastSlash = pattern.lastIndexOf('/');
            let flags = pattern.slice(lastSlash + 1);
            if (!flags.includes('g')) flags += 'g';
            pattern = pattern.slice(1, lastSlash);
            try {
                const re = new RegExp(pattern, flags);
                const asciiView = Array.from(bytes).map(b => (b >= 32 && b < 127) ? String.fromCharCode(b) : '.').join('');
                let m;
                re.lastIndex = 0;
                while ((m = re.exec(asciiView)) !== null) {
                    matches.push({ start: m.index, end: m.index + m[0].length });
                    if (m[0].length === 0) re.lastIndex++;
                }
            } catch (_) { return []; }
        }
        return matches;
    }

    return [];
}

/** Get visible memory as byte array (same region as dump). Unmapped bytes as 0. */
function getVisibleMemoryBytes(addr) {
    if (!emulator) return new Uint8Array(0);
    const total = MEM_LINES * MEM_BYTES_PER_LINE;
    if (typeof emulator.read_memory_bytes === 'function') {
        const raw = emulator.read_memory_bytes(addr, total);
        return raw.subarray(0, total); // first half = data bytes
    }
    // Fallback
    const hex = emulator.read_memory_hex(addr, total);
    const tokens = hex.split(/\s+/);
    const bytes = new Uint8Array(total);
    for (let i = 0; i < total && i < tokens.length; i++) {
        const t = tokens[i];
        bytes[i] = (t === '??' || isNaN(parseInt(t, 16))) ? 0 : (parseInt(t, 16) & 0xff);
    }
    return bytes;
}

const MEM_SEARCH_CHUNK = 4096;
const MEM_SEARCH_MAX_MATCHES = 2000;

/** Parse hex string from read_memory_hex into byte array. */
function parseHexChunkToBytes(hex, maxBytes) {
    const tokens = hex.split(/\s+/);
    const bytes = new Uint8Array(Math.min(tokens.length, maxBytes));
    for (let i = 0; i < bytes.length; i++) {
        const t = tokens[i];
        bytes[i] = (t === '??' || isNaN(parseInt(t, 16))) ? 0 : (parseInt(t, 16) & 0xff);
    }
    return bytes;
}

/**
 * Search all mapped memory using the fast native (Rust/WASM) implementation.
 * Returns array of { addr, length }. Capped at 2000 matches.
 */
function searchAllMemory(query, mode) {
    if (!emulator || !query.trim()) return [];
    const effectiveMode = mode === 'auto' ? detectSearchMode(query.trim()) : mode;
    try {
        const raw = emulator.search_memory(query.trim(), effectiveMode);
        const arr = JSON.parse(raw); // [[addr, length], ...]
        return arr.map(([a, l]) => ({ addr: a, length: l }));
    } catch (e) {
        console.warn('[binb] search_memory error:', e);
        return [];
    }
}

/**
 * Async wrapper — the native search is fast enough to be synchronous,
 * but we keep the async API for backward compat (shows spinner).
 */
function searchAllMemoryAsync(query, mode, done) {
    // Run synchronously since the Rust implementation is fast enough.
    // Use setTimeout(0) so the spinner can render before we block.
    setTimeout(() => {
        done(searchAllMemory(query, mode));
    }, 0);
}

function updateMemSearchStatus() {
    if (!memSearchQuery.trim()) {
        memSearchStatus.textContent = '';
        return;
    }
    if (memSearchMatches.length === 0) {
        memSearchStatus.textContent = t('noMatches');
        memSearchStatus.className = 'mem-search-status muted';
    } else {
        const cap = memSearchMatches.length >= MEM_SEARCH_MAX_MATCHES ? '+' : '';
        memSearchStatus.textContent = `${memSearchCurrentIndex + 1}/${memSearchMatches.length}${cap}`;
        memSearchStatus.className = 'mem-search-status';
    }
}

// ── Disassembly search ──────────────────────────────────────────────────────

/** Run search on disassembly lines. lines = array of { addr, text }. Returns line indices. */
function runDisasmSearch(lines, query, mode) {
    const q = query.trim();
    if (!q) return [];
    const effectiveMode = mode === 'auto' ? detectSearchMode(q) : mode;
    const matches = [];

    if (effectiveMode === 'hex') {
        const hexStr = q.replace(/^0x/i, '').replace(/\s/g, '');
        const hexNum = parseInt(hexStr, 16);
        if (isNaN(hexNum)) return [];
        const addrStr = hexNum.toString(16).toLowerCase();
        lines.forEach((line, i) => {
            const addrHex = (line.addr || '').replace(/^0x/i, '').toLowerCase();
            const full = (line.addr || '') + ' ' + (line.text || '');
            if (addrHex.includes(addrStr) || full.toLowerCase().includes(addrStr)) matches.push(i);
        });
        return matches;
    }

    if (effectiveMode === 'string') {
        const lower = q.toLowerCase();
        lines.forEach((line, i) => {
            const full = (line.addr || '') + ' ' + (line.text || '');
            if (full.toLowerCase().includes(lower)) matches.push(i);
        });
        return matches;
    }

    if (effectiveMode === 'regex') {
        let pattern = q;
        if (pattern.startsWith('/') && pattern.lastIndexOf('/') > 0) {
            const lastSlash = pattern.lastIndexOf('/');
            let flags = pattern.slice(lastSlash + 1);
            if (!flags.includes('g')) flags += 'g';
            pattern = pattern.slice(1, lastSlash);
            try {
                const re = new RegExp(pattern, flags.replace(/g/g, '') + 'i');
                lines.forEach((line, i) => {
                    const full = (line.addr || '') + ' ' + (line.text || '');
                    if (re.test(full)) matches.push(i);
                });
            } catch (_) { return []; }
        }
        return matches;
    }

    return [];
}

function updateDisasmSearchStatus() {
    if (!disasmSearchQuery.trim() || !disasmSearchStatus) {
        if (disasmSearchStatus) disasmSearchStatus.textContent = '';
        return;
    }
    if (disasmSearchMatches.length === 0) {
        disasmSearchStatus.textContent = t('noMatches');
        disasmSearchStatus.className = 'disasm-search-status muted';
    } else {
        disasmSearchStatus.textContent = `${disasmSearchCurrentIndex + 1}/${disasmSearchMatches.length}`;
        disasmSearchStatus.className = 'disasm-search-status';
    }
}

// ── Strace/syscall search ───────────────────────────────────────────────────

/** Run search on strace lines. Returns line indices. */
function runStraceSearch(lines, query, mode) {
    const q = query.trim();
    if (!q) return [];
    const effectiveMode = mode === 'auto' ? (q.startsWith('/') && q.lastIndexOf('/') > 0 ? 'regex' : 'string') : mode;
    const matches = [];

    if (effectiveMode === 'string') {
        const lower = q.toLowerCase();
        lines.forEach((line, i) => {
            if (line.toLowerCase().includes(lower)) matches.push(i);
        });
        return matches;
    }

    if (effectiveMode === 'regex') {
        if (q.startsWith('/') && q.lastIndexOf('/') > 0) {
            const lastSlash = q.lastIndexOf('/');
            let flags = q.slice(lastSlash + 1);
            if (!flags.includes('g')) flags += 'g';
            const pattern = q.slice(1, lastSlash);
            try {
                const re = new RegExp(pattern, flags.replace(/g/g, '') + 'i');
                lines.forEach((line, i) => {
                    if (re.test(line)) matches.push(i);
                });
            } catch (_) { return []; }
        }
        return matches;
    }

    return matches;
}

function updateStraceSearchStatus() {
    if (!straceSearchStatus) return;
    if (!straceSearchQuery.trim()) {
        straceSearchStatus.textContent = '';
        return;
    }
    if (straceSearchMatches.length === 0) {
        straceSearchStatus.textContent = t('noMatches');
        straceSearchStatus.className = 'strace-search-status muted';
    } else {
        straceSearchStatus.textContent = `${straceSearchCurrentIndex + 1}/${straceSearchMatches.length}`;
        straceSearchStatus.className = 'strace-search-status';
    }
}

// ── Memory viewer ───────────────────────────────────────────────────────────

/** Pre-built hex lookup table for byte→hex. */
const _HEX_TABLE = new Array(256);
for (let i = 0; i < 256; i++) _HEX_TABLE[i] = i.toString(16).padStart(2, '0');

function refreshMemory() {
    if (!emulator) return;
    const text = memAddr.value.trim();
    const addr = parseAddr(text);
    if (isNaN(addr)) { memoryDump.textContent = t('invalidAddress'); return; }

    // Use global memory search matches (from searchAllMemory) to highlight bytes in current view
    if (!memSearchQuery.trim()) {
        memSearchMatches = [];
        memSearchCurrentIndex = -1;
        memSearchStatus.textContent = '';
    }
    const curMatch = memSearchMatches.length > 0 && memSearchCurrentIndex >= 0 ? memSearchMatches[memSearchCurrentIndex] : null;
    const totalBytes = MEM_LINES * MEM_BYTES_PER_LINE;

    // Read all visible bytes in one bulk call (data + validity bitmask)
    let data, valid;
    if (typeof emulator.read_memory_bytes === 'function') {
        const raw = emulator.read_memory_bytes(addr, totalBytes);
        data = raw.subarray(0, totalBytes);
        valid = raw.subarray(totalBytes, totalBytes * 2);
    } else {
        // Fallback to hex string parsing if WASM hasn't been rebuilt
        data = new Uint8Array(totalBytes);
        valid = new Uint8Array(totalBytes);
        const hex = emulator.read_memory_hex(addr, totalBytes);
        const tokens = hex.split(' ');
        for (let i = 0; i < totalBytes && i < tokens.length; i++) {
            if (tokens[i] !== '??') {
                data[i] = parseInt(tokens[i], 16);
                valid[i] = 0xff;
            }
        }
    }

    // Build access map for highlighting
    const accesses = traceMode ? (traceMemAccesses || []) : lastMemAccesses;
    const accessMap = new Map(); // addr -> 'r'|'w'|'rw'
    for (const acc of accesses) {
        for (let b = 0; b < acc.size; b++) {
            const a = acc.addr + b;
            const prev = accessMap.get(a) || '';
            if (acc.is_write && !prev.includes('w')) accessMap.set(a, prev + 'w');
            else if (!acc.is_write && !prev.includes('r')) accessMap.set(a, prev + 'r');
        }
    }

    // Build a Set of byte addresses that are in any search match (for O(1) lookup)
    const searchHitSet = new Set();
    const searchCurSet = new Set();
    if (memSearchMatches.length > 0) {
        const viewEnd = addr + totalBytes;
        for (const m of memSearchMatches) {
            const mEnd = m.addr + m.length;
            if (mEnd <= addr || m.addr >= viewEnd) continue; // outside view
            const lo = Math.max(m.addr, addr);
            const hi = Math.min(mEnd, viewEnd);
            const isCurrent = (curMatch && m.addr === curMatch.addr && m.length === curMatch.length);
            for (let a = lo; a < hi; a++) {
                searchHitSet.add(a);
                if (isCurrent) searchCurSet.add(a);
            }
        }
    }

    const hasTrace = traceMode && emulator.get_trace_length() > 0;
    const byteTitle = 'Click to edit · Right-click to track address';
    const parts = [];
    for (let line = 0; line < MEM_LINES; line++) {
        const lineAddr = addr + line * MEM_BYTES_PER_LINE;
        const lineOff = line * MEM_BYTES_PER_LINE;
        const addrStr = lineAddr.toString(16).padStart(8, '0');

        let hexHtml = '';
        let asciiHtml = '';
        for (let bi = 0; bi < MEM_BYTES_PER_LINE; bi++) {
            const idx = lineOff + bi;
            const byteAddr = lineAddr + bi;
            const isValid = valid[idx] !== 0;
            const byteVal = data[idx];
            const hexStr = isValid ? _HEX_TABLE[byteVal] : '??';

            const accType = accessMap.get(byteAddr);
            const isDaddr = daddr && byteAddr >= daddr.addr && byteAddr < daddr.addr + daddr.size;
            const daddrCls = isDaddr ? ' mem-byte-daddr' : '';
            const searchCls = searchHitSet.has(byteAddr)
                ? (searchCurSet.has(byteAddr) ? ' mem-search-current' : ' mem-search-hit')
                : '';

            let cls = '';
            if (accType) {
                if (accType.includes('w') && accType.includes('r')) cls = 'mem-byte-rw';
                else if (accType.includes('w')) cls = 'mem-byte-write';
                else cls = 'mem-byte-read';
            }

            const clsStr = cls ? `mem-byte clickable ${cls}${daddrCls}${searchCls}` : `mem-byte clickable${daddrCls}${searchCls}`;
            hexHtml += `<span class="mem-byte-hex ${clsStr}" data-addr="${byteAddr}" title="${byteTitle}">${hexStr}</span> `;

            if (!isValid) {
                asciiHtml += '.';
            } else {
                const ch = (byteVal >= 32 && byteVal < 127) ? String.fromCharCode(byteVal) : '.';
                asciiHtml += `<span class="${clsStr}" data-addr="${byteAddr}" title="${byteTitle}">${ch === '<' ? '&lt;' : ch === '>' ? '&gt;' : ch === '&' ? '&amp;' : ch}</span>`;
            }
        }
        // Compute per-line entropy (only for valid bytes)
        let validCount = 0;
        for (let bi = 0; bi < MEM_BYTES_PER_LINE; bi++) {
            if (valid[lineOff + bi] !== 0) validCount++;
        }
        let entropyBar = '';
        if (validCount > 0) {
            const lineEntropy = computeEntropy(data, lineOff, MEM_BYTES_PER_LINE);
            const color = entropyToColor(lineEntropy);
            entropyBar = `<span class="mem-entropy-bar" style="background:${color}" title="entropy: ${lineEntropy.toFixed(2)} bits"></span>`;
        } else {
            entropyBar = `<span class="mem-entropy-bar mem-entropy-unmapped" title="unmapped"></span>`;
        }
        parts.push(`<span class="mem-addr-col" data-addr="${lineAddr}" onclick="window._memGo('0x${lineAddr.toString(16)}')">${addrStr}</span>  ${hexHtml} |${asciiHtml}| ${entropyBar}\n`);
    }
    memoryDump.innerHTML = parts.join('');
    memInfo.textContent = `${totalBytes} bytes from 0x${addr.toString(16)}`;
}

// ── Memory Accesses Panel ───────────────────────────────────────────────────

function renderAccesses(accesses) {
    if (!accesses || accesses.length === 0) {
        accessesList.innerHTML = '<div class="muted">No memory accesses for this instruction.</div>';
        accessesInfo.textContent = t('accessesCount');
        accessesMemDump.innerHTML = '<span class="muted">No accesses</span>';
        accessesMemAddr.textContent = '';
        return;
    }

    const reads = accesses.filter(a => !a.is_write);
    const writes = accesses.filter(a => a.is_write);
    accessesInfo.textContent = `${reads.length} ${t('readsWrites')} ${writes.length} ${t('writes')}`;

    let html = '';
    for (const acc of accesses) {
        const typeCls = acc.is_write ? 'acc-write' : 'acc-read';
        const typeLabel = acc.is_write ? 'W' : 'R';
        const addrHex = '0x' + acc.addr.toString(16);
        let valStr = '';
        if (acc.data !== undefined && acc.data !== null) {
            // Format based on size
            if (acc.size <= 1) valStr = '0x' + (acc.data & 0xFF).toString(16).padStart(2, '0');
            else if (acc.size <= 2) valStr = '0x' + (acc.data & 0xFFFF).toString(16).padStart(4, '0');
            else if (acc.size <= 4) valStr = '0x' + (acc.data >>> 0).toString(16).padStart(8, '0');
            else valStr = '0x' + acc.data.toString(16);
        }
        html += `<div class="acc-entry ${typeCls}" onclick="window._previewAccMem(${acc.addr}, ${acc.size}, ${acc.is_write})" style="cursor:pointer">
            <span class="acc-type">${typeLabel}</span>
            <span class="acc-addr mono" onclick="event.stopPropagation(); window._memGo('${addrHex}')" title="Open in Memory tab">${addrHex}</span>
            <span class="acc-size">${acc.size}B</span>
            ${valStr ? `<span class="acc-val mono">${valStr}</span>` : ''}
            <button class="btn btn-xs" onclick="event.stopPropagation(); window._setDaddr(${acc.addr}, ${acc.size})" title="Track this address">&#x1F50D;</button>
        </div>`;
    }
    accessesList.innerHTML = html;

    // Auto-show memory context for the first access
    if (accesses.length > 0) {
        previewAccessMemory(accesses[0].addr, accesses[0].size, accesses[0].is_write, accesses);
    }
}

/// Show a compact hex dump in the accesses panel, centered on the given address,
/// with highlighting for all current accesses.
function previewAccessMemory(centerAddr, size, isWrite, allAccesses) {
    if (!emulator) return;

    // Build access map for highlighting (uses all accesses from current instruction)
    const accesses = allAccesses || (traceMode ? (traceMemAccesses || []) : lastMemAccesses);
    const accessMap = new Map();
    for (const acc of accesses) {
        for (let b = 0; b < acc.size; b++) {
            const a = acc.addr + b;
            const prev = accessMap.get(a) || '';
            if (acc.is_write && !prev.includes('w')) accessMap.set(a, prev + 'w');
            else if (!acc.is_write && !prev.includes('r')) accessMap.set(a, prev + 'r');
        }
    }

    const previewLines = 8;
    const bytesPerLine = 16;
    // Align start to 16 bytes, centering the target
    const alignedCenter = centerAddr - (centerAddr % bytesPerLine);
    const startAddr = Math.max(0, alignedCenter - bytesPerLine * Math.floor(previewLines / 2));

    let output = '';
    for (let line = 0; line < previewLines; line++) {
        const lineAddr = startAddr + line * bytesPerLine;
        const hex = emulator.read_memory_hex(lineAddr, bytesPerLine);
        const addrStr = lineAddr.toString(16).padStart(8, '0');

        const bytes = hex.split(' ');
        let hexHtml = '';
        let asciiHtml = '';
        for (let bi = 0; bi < bytes.length; bi++) {
            const b = bytes[bi];
            const byteAddr = lineAddr + bi;
            const accType = accessMap.get(byteAddr);

            // Highlight the exact bytes of the selected access more strongly
            const isTarget = byteAddr >= centerAddr && byteAddr < centerAddr + size;
            let cls = '';
            if (accType) {
                if (accType.includes('w') && accType.includes('r')) cls = 'mem-byte-rw';
                else if (accType.includes('w')) cls = 'mem-byte-write';
                else cls = 'mem-byte-read';
            }
            if (isTarget && !cls) cls = isWrite ? 'mem-byte-write' : 'mem-byte-read';

            const byteTitle = 'Set memory breakpoint';
            if (cls) {
                hexHtml += `<span class="mem-byte clickable ${cls}" data-addr="${byteAddr}" onclick="window._setMemBreakpoint(${byteAddr})" title="${byteTitle}">${b}</span> `;
            } else {
                hexHtml += `<span class="mem-byte clickable" data-addr="${byteAddr}" onclick="window._setMemBreakpoint(${byteAddr})" title="${byteTitle}">${b}</span> `;
            }

            if (b === '??') {
                asciiHtml += '.';
            } else {
                const v = parseInt(b, 16);
                const ch = (v >= 32 && v < 127) ? String.fromCharCode(v) : '.';
                if (cls) {
                    asciiHtml += `<span class="mem-byte clickable ${cls}" data-addr="${byteAddr}" onclick="window._setMemBreakpoint(${byteAddr})" title="${byteTitle}">${escapeHtml(ch)}</span>`;
                } else {
                    asciiHtml += `<span class="mem-byte clickable" data-addr="${byteAddr}" onclick="window._setMemBreakpoint(${byteAddr})" title="${byteTitle}">${escapeHtml(ch)}</span>`;
                }
            }
        }
        output += `<span class="mem-addr-col">${addrStr}</span>  ${hexHtml} |${asciiHtml}|\n`;
    }

    accessesMemDump.innerHTML = output;
    accessesMemAddr.textContent = `@ 0x${centerAddr.toString(16)}`;
}

// ── Disassembly view ────────────────────────────────────────────────────────

// Navigate the disassembly panel to an arbitrary address.
// Navigate the disassembly panel to an arbitrary address.
// Reuses the normal renderDisasm logic but overrides the base address temporarily.
let disasmOverrideAddr = null;

function navigateDisasmTo(addr) {
    if (!emulator) return;
    if (!disasmList) return;
    disasmOverrideAddr = addr;
    renderDisasm();
    disasmOverrideAddr = null;
}

// Resolve an address to its containing function (binary search).
function resolveFunctionAtAddr(addr) {
    if (!elfFunctions || elfFunctions.length === 0) return null;
    // Find the last function whose addr <= the given addr
    let lo = 0, hi = elfFunctions.length - 1, best = null;
    while (lo <= hi) {
        const mid = (lo + hi) >>> 1;
        if (elfFunctions[mid].addr <= addr) {
            best = elfFunctions[mid];
            lo = mid + 1;
        } else {
            hi = mid - 1;
        }
    }
    if (!best) return null;
    // If function has known size, check we're within it
    if (best.size > 0 && addr >= best.addr + best.size) return null;
    return best;
}

function renderDisasm() {
    if (!emulator) return;

    const ripNum = disasmOverrideAddr !== null ? disasmOverrideAddr : emulator.get_rip_num();
    const json = emulator.disasm_range(ripNum, DISASM_LINES);
    const instrs = JSON.parse(json);

    const disasmLines = instrs.map(instr => ({ addr: instr.addr, text: instr.text }));
    if (disasmSearchQuery.trim()) {
        disasmSearchMatches = runDisasmSearch(disasmLines, disasmSearchQuery, disasmSearchMode.value);
        if (disasmSearchMatches.length > 0 && (disasmSearchCurrentIndex < 0 || disasmSearchCurrentIndex >= disasmSearchMatches.length)) {
            disasmSearchCurrentIndex = 0;
        } else if (disasmSearchMatches.length === 0) {
            disasmSearchCurrentIndex = -1;
        }
        updateDisasmSearchStatus();
    } else {
        disasmSearchMatches = [];
        disasmSearchCurrentIndex = -1;
        if (disasmSearchStatus) disasmSearchStatus.textContent = '';
    }
    const matchSet = new Set(disasmSearchMatches);
    const currentMatchLine = disasmSearchMatches.length > 0 && disasmSearchCurrentIndex >= 0 ? disasmSearchMatches[disasmSearchCurrentIndex] : -1;
    const visibleAddrs = new Set(instrs.map(instr => Number(instr.addr_num)));

    let html = '';
    let lastSrcLine = null; // track to show source annotation only on line change
    for (let i = 0; i < instrs.length; i++) {
        const instr = instrs[i];
        const addrNum = Number(instr.addr_num);

        // Insert function label at function entry points
        if (fnAddrMap.has(addrNum)) {
            html += `<div class="disasm-fn-header">${escapeHtml(fnAddrMap.get(addrNum))}:</div>`;
            lastSrcLine = null; // reset on function boundary
        }

        // Insert XREF annotations (show who references this address)
        if (xrefToMap.has(addrNum)) {
            const refs = xrefToMap.get(addrNum);
            const maxShow = 5;
            const refStrs = refs.slice(0, maxShow).map(x => {
                const fn = resolveFunctionAtAddr(x.from_num);
                return `<span class="xref-inline-ref" onclick="event.stopPropagation(); window._goDisasmAddr(${x.from_num})" title="${x.from}">${x.kind === 'call' ? '↳' : x.kind === 'data' ? '&' : '↗'}${fn || x.from}</span>`;
            });
            const more = refs.length > maxShow ? `<span class="xref-inline-more" onclick="event.stopPropagation(); window._showXrefsFor(${addrNum})">+${refs.length - maxShow} more</span>` : '';
            html += `<div class="disasm-xref-line" onclick="window._showXrefsFor(${addrNum})" title="Click for full XREF details"><span class="xref-inline-label">; XREF[${refs.length}]:</span> ${refStrs.join(', ')} ${more}</div>`;
        }

        // Insert source line annotation when the line changes
        const srcKey = instr.src_file ? `${instr.src_file}:${instr.src_line}` : null;
        if (srcKey && srcKey !== lastSrcLine) {
            html += `<div class="disasm-src-line" title="${escapeHtml(instr.src_file)}:${instr.src_line}">; ${escapeHtml(instr.src_file)}:${instr.src_line}</div>`;
            lastSrcLine = srcKey;
        }

        const currentCls = instr.is_current ? 'disasm-current' : '';
        const bpCls = instr.has_bp ? 'disasm-bp' : '';
        const searchCls = matchSet.has(i) ? (i === currentMatchLine ? ' disasm-search-current' : ' disasm-search-hit') : '';
        const bpMarker = instr.has_bp ? '<span class="bp-marker" title="Breakpoint (click to remove)">&#9679;</span>' : '<span class="bp-marker-empty" title="Click to add breakpoint">&#9675;</span>';
        const regionBadge = instr.region ? `<span class="disasm-region" title="Source: ${escapeHtml(instr.region)}">${escapeHtml(shortRegionLabel(instr.region))}</span>` : '';

        html += `<div class="disasm-line ${currentCls} ${bpCls}${searchCls}" data-addr="${instr.addr_num}" data-line-index="${i}">`;
        html += `<span class="disasm-bp-col">${bpMarker}</span>`;
        html += `<span class="disasm-addr">${instr.addr}</span>`;
        html += regionBadge;
        html += `<span class="disasm-instr">${syntaxHighlightDisasm(instr.text)}</span>`;
        if (instr.branch_target != null) {
            const targetNum = Number(instr.branch_target);
            const targetHex = '0x' + (targetNum >>> 0).toString(16);
            const inView = visibleAddrs.has(targetNum);
            html += `<span class="disasm-jump-arrow ${inView ? 'disasm-jump-inview' : ''}" data-target-addr="${targetNum}" title="Jump target ${targetHex}">→ ${targetHex}</span>`;
        }
        if (instr.is_current) {
            html += `<span class="disasm-arrow">&larr;</span>`;
        }
        html += `</div>`;
    }

    disasmList.innerHTML = html;

    disasmList.querySelectorAll('.disasm-line').forEach(el => {
        el.addEventListener('click', (e) => {
            if (e.target.closest('.disasm-jump-arrow.disasm-jump-inview')) {
                const targetAddr = Number(e.target.closest('.disasm-jump-arrow').dataset.targetAddr);
                const targetLine = disasmList.querySelector(`.disasm-line[data-addr="${targetAddr}"]`);
                if (targetLine) targetLine.scrollIntoView({ block: 'center', behavior: 'smooth' });
                return;
            }
            const addr = Number(el.dataset.addr);
            if (!isNaN(addr)) toggleBreakpointAtAddr(addr);
        });
    });

    const currentEl = disasmList.querySelector('.disasm-current');
    if (currentEl) {
        currentEl.scrollIntoView({ block: 'center', behavior: 'instant' });
    }

    // Show current function name in panel header
    const fnLabel = document.getElementById('disasm-fn-label');
    if (fnLabel) {
        const fn = resolveFunctionAtAddr(ripNum);
        fnLabel.textContent = fn ? fn.name : '';
        fnLabel.title = fn ? `${fn.name} @ 0x${fn.addr.toString(16)}` : '';
    }
}

// ── UI updates ──────────────────────────────────────────────────────────────

function updateFullUI() {
    if (!emulator) return;

    if (traceMode) {
        seekTrace(traceCursor);
        renderMemoryMap();
        renderBreakpoints();
        renderWatchList();
        return;
    }

    // Info bar
    infoRip.textContent = emulator.get_rip();
    infoDisasm.textContent = emulator.current_disasm();
    infoCount.textContent = emulator.get_instruction_count().toLocaleString();

    // Registers
    try {
        const regs = JSON.parse(emulator.get_registers());
        renderRegisters(regs);
        modeBadge.textContent = regs.mode;
        infoFlags.textContent = regs.flags.length > 0 ? regs.flags.join(' ') : '--';
    } catch (err) {
        // ignore
    }

    // Call stack
    renderCallStack();

    // Refresh XREF cache and summary (only when count changed)
    if (emulator.get_xref_count) {
        const count = emulator.get_xref_count();
        if (count !== xrefTotal) {
            refreshXrefCache();
            renderXrefSummary();
        }
    }

    // Disassembly (uses xref cache for inline annotations)
    renderDisasm();

    // Breakpoints
    renderBreakpoints();

    // Syscall trace (keep in sync when UI refreshes)
    renderStraceOutput();

    // Memory map
    renderMemoryMap();

    // Watch list
    renderWatchList();

    // Accesses panel (last step)
    renderAccesses(lastMemAccesses);

    // Auto-refresh memory viewer
    if (memAutoRefresh.checked) {
        refreshMemory();
    }

    // Timeline (update if recording; clear when no trace so Reset clears the canvas)
    if (traceToggle.checked) {
        const len = emulator.get_trace_length();
        timelineBar.style.display = '';
        if (len > 0) {
            timelineSlider.max = len - 1;
            timelineSlider.value = timelineSlider.max;
            tracePosition.textContent = `${len.toLocaleString()} ${t('recorded')}`;
            if (tlZoomEnd <= 0 || tlZoomEnd >= len - 1) {
                tlZoomEnd = len;
            }
        } else {
            timelineSlider.max = 0;
            timelineSlider.value = 0;
            tracePosition.textContent = '';
        }
        renderTimeline();
    }
}

// x86 sub-register name map: RAX→{e:'EAX',x:'AX',h:'AH',l:'AL'}, etc.
const x86SubRegMap = {
    RAX: {e:'EAX',x:'AX',h:'AH',l:'AL'}, RCX: {e:'ECX',x:'CX',h:'CH',l:'CL'},
    RDX: {e:'EDX',x:'DX',h:'DH',l:'DL'}, RBX: {e:'EBX',x:'BX',h:'BH',l:'BL'},
    RSP: {e:'ESP',x:'SP'},               RBP: {e:'EBP',x:'BP'},
    RSI: {e:'ESI',x:'SI',l:'SIL'},       RDI: {e:'EDI',x:'DI',l:'DIL'},
    R8:  {d:'R8D',w:'R8W',l:'R8B'},      R9:  {d:'R9D',w:'R9W',l:'R9B'},
    R10: {d:'R10D',w:'R10W',l:'R10B'},    R11: {d:'R11D',w:'R11W',l:'R11B'},
    R12: {d:'R12D',w:'R12W',l:'R12B'},    R13: {d:'R13D',w:'R13W',l:'R13B'},
    R14: {d:'R14D',w:'R14W',l:'R14B'},    R15: {d:'R15D',w:'R15W',l:'R15B'},
    // 32-bit mode
    EAX: {x:'AX',h:'AH',l:'AL'}, ECX: {x:'CX',h:'CH',l:'CL'},
    EDX: {x:'DX',h:'DH',l:'DL'}, EBX: {x:'BX',h:'BH',l:'BL'},
    ESP: {x:'SP'},                EBP: {x:'BP'},
    ESI: {x:'SI'},                EDI: {x:'DI'},
};

function buildSubRegs(name, hexValue, mode) {
    if (mode === 'arm64') {
        // ARM64: show W register (lower 32 bits) for X0–X30
        if (name.startsWith('X')) {
            const num = name.slice(1);
            const val = BigInt(hexValue);
            const w = val & 0xFFFFFFFFn;
            return `<span class="sub-reg"><span class="sub-name">W${num}</span><span class="sub-val">${'0x' + w.toString(16).padStart(8, '0')}</span></span>`;
        }
        return '';
    }

    const map = x86SubRegMap[name];
    if (!map) return '';
    const val = BigInt(hexValue);
    let parts = [];

    if (mode === 'x86_64') {
        // 64-bit: show EAX (32), AX (16), AH (8h), AL (8l)
        if (map.e) {
            const e = val & 0xFFFFFFFFn;
            parts.push(`<span class="sub-reg"><span class="sub-name">${map.e}</span><span class="sub-val">${'0x' + e.toString(16).padStart(8, '0')}</span></span>`);
        } else if (map.d) {
            const d = val & 0xFFFFFFFFn;
            parts.push(`<span class="sub-reg"><span class="sub-name">${map.d}</span><span class="sub-val">${'0x' + d.toString(16).padStart(8, '0')}</span></span>`);
        }
        if (map.x) {
            const x = val & 0xFFFFn;
            parts.push(`<span class="sub-reg"><span class="sub-name">${map.x}</span><span class="sub-val">${'0x' + x.toString(16).padStart(4, '0')}</span></span>`);
        } else if (map.w) {
            const w = val & 0xFFFFn;
            parts.push(`<span class="sub-reg"><span class="sub-name">${map.w}</span><span class="sub-val">${'0x' + w.toString(16).padStart(4, '0')}</span></span>`);
        }
        if (map.h) {
            const h = (val >> 8n) & 0xFFn;
            parts.push(`<span class="sub-reg"><span class="sub-name">${map.h}</span><span class="sub-val">${'0x' + h.toString(16).padStart(2, '0')}</span></span>`);
        }
        if (map.l) {
            const l = val & 0xFFn;
            parts.push(`<span class="sub-reg"><span class="sub-name">${map.l}</span><span class="sub-val">${'0x' + l.toString(16).padStart(2, '0')}</span></span>`);
        }
    } else {
        // 32-bit: show AX (16), AH (8h), AL (8l)
        if (map.x) {
            const x = val & 0xFFFFn;
            parts.push(`<span class="sub-reg"><span class="sub-name">${map.x}</span><span class="sub-val">${'0x' + x.toString(16).padStart(4, '0')}</span></span>`);
        }
        if (map.h) {
            const h = (val >> 8n) & 0xFFn;
            parts.push(`<span class="sub-reg"><span class="sub-name">${map.h}</span><span class="sub-val">${'0x' + h.toString(16).padStart(2, '0')}</span></span>`);
        }
        if (map.l) {
            const l = val & 0xFFn;
            parts.push(`<span class="sub-reg"><span class="sub-name">${map.l}</span><span class="sub-val">${'0x' + l.toString(16).padStart(2, '0')}</span></span>`);
        }
    }
    return parts.join('');
}

// ── Call Stack rendering ─────────────────────────────────────────────────────

function renderCallStack() {
    if (!emulator || !callstackList) return;
    let frames;
    try {
        frames = JSON.parse(emulator.get_call_stack());
    } catch {
        callstackList.innerHTML = '<div class="callstack-empty">Call stack unavailable.</div>';
        return;
    }
    if (!frames || frames.length === 0) {
        callstackList.innerHTML = '<div class="callstack-empty">Call stack is empty (at top-level).</div>';
        return;
    }

    let html = `<div class="callstack-count">${frames.length} frame${frames.length !== 1 ? 's' : ''}</div>`;

    // Show innermost frame last (bottom of list), so reverse for display (top = current)
    for (let i = frames.length - 1; i >= 0; i--) {
        const f = frames[i];
        const depth = frames.length - 1 - i;
        const isTop = (i === frames.length - 1);

        // Try to resolve function name from elfFunctions
        const fn_ = resolveFunctionAtAddr(f.target_num);
        const name = fn_ ? fn_.name : '';
        const nameHtml = name
            ? `<span class="callstack-name" title="${escapeHtml(name)}">${escapeHtml(name)}</span>`
            : '';

        html += `<div class="callstack-frame${isTop ? ' active' : ''}" data-target="${f.target_num}" data-callsite="${f.call_site}" title="Called from ${f.call_site} → ${f.target}  SP=${f.sp}">
            <span class="callstack-depth">#${depth}</span>
            ${nameHtml}
            <span class="callstack-addr">${f.target}</span>
            <span class="callstack-callsite">← ${f.call_site}</span>
        </div>`;
    }

    callstackList.innerHTML = html;

    // Click frame → navigate disassembly to that function
    callstackList.querySelectorAll('.callstack-frame').forEach(el => {
        el.addEventListener('click', () => {
            const addr = parseFloat(el.dataset.target);
            if (!isNaN(addr) && addr > 0) navigateDisasmTo(addr);
        });
    });
}

function renderRegisters(regs, opts) {
    opts = opts || {};
    const enableRegisterSeek = opts.traceSeek && traceMode && emulator && emulator.get_trace_length() > 0;
    let html = '';
    if (enableRegisterSeek) {
        html += '<div class="reg-seek-hint muted">↩ ↪ seek by register — click a register then <kbd>Ctrl+[</kbd> prev / <kbd>Ctrl+]</kbd> next</div>';
    }

    const isArm64 = regs.mode === 'arm64';
    const is64 = regs.mode === 'x86_64';
    const is32 = regs.mode === 'x86';

    // RIP — clickable to set execution breakpoint on timeline
    const ripLabel = isArm64 ? 'PC' : (is32 ? 'EIP' : 'RIP');
    const ripChanged = previousRegs['RIP'] && previousRegs['RIP'] !== regs.rip;
    const ripAddr = parseInt(regs.rip, 16);
    const ripActive = tlIaddrBreakpoint === ripAddr ? ' reg-bp-active' : '';
    html += `<div class="reg-row">
        <span class="reg-name">${ripLabel}</span>
        <span class="reg-value clickable${ripActive} ${ripChanged ? 'changed' : ''}"
              onclick="window._toggleExecBreakpoint(${ripAddr})"
              title="Click to highlight all executions of this address on the timeline">${regs.rip}</span>
    </div>`;
    previousRegs['RIP'] = regs.rip;

    // GPRs — in trace mode: click value = seek to instruction that set this register; arrow = seek to next write
    // Double-click value to edit (set register).
    for (let i = 0; i < regs.gpr.length; i++) {
        const r = regs.gpr[i];
        const prevVal = previousRegs[r.name];
        const changed = prevVal && prevVal !== r.value;

        // Build previous-value indicator
        let prevHtml = '';
        if (changed) {
            prevHtml = `<span class="reg-prev" title="Previous: ${escapeHtml(prevVal)}">${prevVal}</span>`;
        }

        // Build sub-register breakdown
        const subHtml = buildSubRegs(r.name, r.value, regs.mode);

        if (enableRegisterSeek) {
            const prevIdx = emulator.prev_trace_by_register(i, traceCursor);
            const nextIdx = emulator.next_trace_by_register(i, traceCursor);
            const hasPrev = prevIdx >= 0 && prevIdx !== traceCursor;
            const hasNext = nextIdx >= 0;
            const prevTitle = hasPrev ? 'Seek to instruction that set this register' : '';
            const nextTitle = hasNext ? 'Seek to next instruction that writes this register' : '';
            html += `<div class="reg-row reg-row-seek${subHtml ? ' has-subs' : ''}" data-gpr="${i}">
                <span class="reg-name">${r.name}</span>
                <span class="reg-value clickable reg-value-editable ${changed ? 'changed' : ''}" data-gpr-index="${i}" data-value="${escapeHtml(r.value)}"
                      onclick="window._focusGprAndSeekPrev(${i})" ondblclick="window._startEditRegister(${i}, event)"
                      title="${prevTitle} — double-click to edit">${r.value}</span>
                ${prevHtml}
                <span class="reg-seek-arrows">
                    <span class="reg-seek-prev ${hasPrev ? '' : 'disabled'}" onclick="window._focusGprAndSeekPrev(${i})" title="${prevTitle}">&#8619;</span>
                    <span class="reg-seek-next ${hasNext ? '' : 'disabled'}" onclick="window._focusGprAndSeekNext(${i})" title="${nextTitle}">&#8620;</span>
                </span>
                ${subHtml ? `<div class="reg-subs">${subHtml}</div>` : ''}
            </div>`;
        } else {
            html += `<div class="reg-row${subHtml ? ' has-subs' : ''}" data-gpr="${i}">
                <span class="reg-name">${r.name}</span>
                <span class="reg-value reg-value-editable ${changed ? 'changed' : ''}" data-gpr-index="${i}" data-value="${escapeHtml(r.value)}"
                      ondblclick="window._startEditRegister(${i}, event)" title="Double-click to edit">${r.value}</span>
                ${prevHtml}
                ${subHtml ? `<div class="reg-subs">${subHtml}</div>` : ''}
            </div>`;
        }
        previousRegs[r.name] = r.value;
    }

    // Flags — click to toggle (x86: CF,PF,AF,ZF,SF,DF,OF; ARM64: N,Z,C,V)
    const flagBits = regs.mode === 'arm64'
        ? { N: 31, Z: 30, C: 29, V: 28 }
        : { CF: 0, PF: 2, AF: 4, ZF: 6, SF: 7, DF: 10, OF: 11 };
    const allFlags = regs.mode === 'arm64' ? ['N', 'Z', 'C', 'V'] : ['CF', 'PF', 'AF', 'ZF', 'SF', 'DF', 'OF'];
    html += `<div class="flags-row" data-rflags="${escapeHtml(regs.rflags)}" title="Click a flag to toggle">`;
    for (const f of allFlags) {
        const isSet = regs.flags.includes(f);
        html += `<span class="flag-tag clickable ${isSet ? 'set' : 'clear'}" data-flag="${f}">${f}</span>`;
    }
    html += '</div>';

    registerDisp.innerHTML = html;

    // Flag click: toggle bit and set rflags
    registerDisp.querySelectorAll('.flag-tag').forEach(tag => {
        tag.addEventListener('click', (e) => {
            e.stopPropagation();
            if (!emulator) return;
            const row = tag.closest('.flags-row');
            const rflagsStr = row && row.dataset.rflags ? row.dataset.rflags.trim().replace(/^0x/i, '') : '0';
            let val = parseInt(rflagsStr, 16);
            if (isNaN(val)) val = 0;
            const bit = flagBits[tag.dataset.flag];
            if (bit === undefined) return;
            val ^= (1 << bit);
            try {
                emulator.set_rflags('0x' + (val >>> 0).toString(16));
            } catch (err) {
                console.warn('set_rflags failed:', err);
                return;
            }
            const regsJson = emulator.get_registers();
            renderRegisters(JSON.parse(regsJson), opts);
        });
    });
}

function startEditRegister(gprIndex, event) {
    event.preventDefault();
    event.stopPropagation();
    if (!emulator) return;
    const row = document.querySelector(`.reg-value-editable[data-gpr-index="${gprIndex}"]`);
    if (!row || row.querySelector('input')) return;
    const currentValue = row.dataset.value || row.textContent.trim();
    const input = document.createElement('input');
    input.type = 'text';
    input.className = 'reg-edit-input';
    input.value = currentValue;
    input.dataset.gprIndex = String(gprIndex);
    row.textContent = '';
    row.appendChild(input);
    input.focus();
    input.select();

    function commit() {
        const raw = input.value.trim();
        const valueHex = /^[0-9a-fA-F]+$/.test(raw) ? '0x' + raw : raw;
        input.remove();
        row.textContent = currentValue;
        row.dataset.value = currentValue;
        try {
            emulator.set_register(gprIndex, valueHex);
        } catch (err) {
            console.warn('set_register failed:', err);
            row.textContent = currentValue;
            return;
        }
        const regsJson = emulator.get_registers();
        const opts = traceMode && emulator.get_trace_length() > 0 ? { traceSeek: true } : {};
        renderRegisters(JSON.parse(regsJson), opts);
    }

    input.addEventListener('blur', commit);
    input.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') { e.preventDefault(); commit(); }
        if (e.key === 'Escape') {
            e.preventDefault();
            input.remove();
            row.textContent = currentValue;
            row.dataset.value = currentValue;
        }
    });
}
window._startEditRegister = startEditRegister;

function setStatus(key, cls, param) {
    _statusKey = key;
    _statusCls = cls || '';
    _statusParam = param;
    statusBadge.textContent = param !== undefined ? t(key) + ` (${param})` : t(key);
    statusBadge.className = 'badge ' + (_statusCls || '');
}

function appendTerminal(text, cls) {
    const span = document.createElement('span');
    if (cls) span.className = cls;
    span.textContent = text;
    terminal.appendChild(span);
    terminal.scrollTop = terminal.scrollHeight;
}

function escapeHtml(str) {
    if (str == null) return '';
    const s = typeof str === 'string' ? str : String(str);
    return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

// Syntax-highlight disassembly (mnemonic, registers, immediates, memory).
function syntaxHighlightDisasm(text) {
    if (!text) return '';
    const e = escapeHtml(text);
    let s = e;
    // Mnemonic (first word only)
    s = s.replace(/^(\w+)/, '<span class="disasm-mnemonic">$1</span>');
    // Intel-style hex with 'h' suffix (e.g. 1Ch, 000005h in "add esp,1Ch" or "call 000005h") — before decimal so 000005h is one token
    s = s.replace(/\b([0-9A-Fa-f]+h)\b/gi, '<span class="disasm-imm">$1</span>');
    // C-style hex immediates
    s = s.replace(/\b(0x[0-9A-Fa-f]+)\b/gi, '<span class="disasm-imm">$1</span>');
    // Decimal immediates (only when not part of 0x... or ...h)
    s = s.replace(/(?<!0x)(?<!x)(?<!h)\b(\d+)\b/g, '<span class="disasm-imm">$1</span>');
    // Registers (x86/x64 and ARM64 X0–X30, SP, W0–W30)
    const regs = 'rax|rcx|rdx|rbx|rsp|rbp|rsi|rdi|r8|r9|r10|r11|r12|r13|r14|r15|' +
        'eax|ecx|edx|ebx|esp|ebp|esi|edi|ax|cx|dx|bx|si|di|bp|sp|al|ah|bl|bh|cl|ch|dl|dh|' +
        'rip|r8d|r9d|r10d|r11d|r12d|r13d|r14d|r15d|' +
        'x0|x1|x2|x3|x4|x5|x6|x7|x8|x9|x10|x11|x12|x13|x14|x15|x16|x17|x18|x19|x20|x21|x22|x23|x24|x25|x26|x27|x28|x29|x30|sp|w0|w1|w2|w3|w4|w5|w6|w7|w8|w9|w10|w11|w12|w13|w14|w15|w16|w17|w18|w19|w20|w21|w22|w23|w24|w25|w26|w27|w28|w29|w30';
    s = s.replace(new RegExp('\\b(' + regs + ')\\b', 'gi'), '<span class="disasm-reg">$1</span>');
    // Memory operands [...]
    s = s.replace(/\[([^\]]+)\]/g, '<span class="disasm-mem">[$1]</span>');
    return s;
}

function parseAddr(text) {
    text = text.trim();
    if (text.startsWith('0x') || text.startsWith('0X')) return parseInt(text, 16);
    if (/^[0-9a-fA-F]+$/.test(text) && text.length > 4) return parseInt(text, 16);
    return parseInt(text, 10) || parseInt(text, 16);
}

// ── Trace / Timeless Debugging ──────────────────────────────────────────────

function seekTrace(idx) {
    if (!emulator) return;
    const len = emulator.get_trace_length();
    if (len === 0) return;

    idx = Math.max(0, Math.min(idx, len - 1));
    traceCursor = idx;

    // Restore VM state (CPU + memory) to this trace index so memory view shows correct values
    emulator.seek_trace_index(idx);

    if (!traceMode) {
        traceMode = true;
        setStatus('statusTrace', 'trace');
    }

    // Update slider
    timelineSlider.max = len - 1;
    timelineSlider.value = idx;

    // Update position display
    const base = emulator.get_trace_base_index();
    tracePosition.textContent = `#${Math.floor(base + idx)} / ${Math.floor(base + len - 1)}`;

    // Get register state at this point
    const regsJson = emulator.get_trace_registers(idx);
    if (regsJson !== 'null') {
        const regs = JSON.parse(regsJson);
        renderRegisters(regs, { traceSeek: true });
        modeBadge.textContent = regs.mode;
        infoFlags.textContent = regs.flags.length > 0 ? regs.flags.join(' ') : '--';
        infoRip.textContent = regs.rip;
    }

    // Get disassembly at this trace point
    const disasm = emulator.get_trace_disasm(idx);
    infoDisasm.textContent = disasm;
    infoCount.textContent = Math.floor(base + idx).toLocaleString();

    // Get memory accesses for highlighting
    traceMemAccesses = JSON.parse(emulator.get_trace_mem_accesses(idx));

    // Render accesses panel
    renderAccesses(traceMemAccesses);

    // Render disassembly centered on the trace RIP
    renderTraceDisasm(idx);

    // Render timeline
    renderTimeline(idx);

    // In trace mode always refresh memory so access highlighting stays in sync with current instruction
    if (traceMode) {
        refreshMemory();
    } else if (memAutoRefresh.checked) {
        refreshMemory();
    }

    // Sync History tab: highlight row for current instruction and scroll into view
    syncHistoryToTrace();
}

function exitTraceMode() {
    traceMode = false;
    traceCursor = 0;
    focusedGprIndex = null;
    traceMemAccesses = null;
    tlIaddrBreakpoint = null;
    timelineCursor.style.display = 'none';
    if (emulator && !emulator.is_exited()) {
        setStatus('statusReady');
    }
    updateFullUI();
}

function renderTraceDisasm(traceIdx) {
    if (!emulator) return;
    const regsJson = emulator.get_trace_registers(traceIdx);
    if (regsJson === 'null') return;
    const regs = JSON.parse(regsJson);
    const rip = parseInt(regs.rip, 16);
    if (isNaN(rip)) return;

    const json = emulator.disasm_range(rip, DISASM_LINES);
    const instrs = JSON.parse(json);

    const disasmLines = instrs.map(instr => ({ addr: instr.addr, text: instr.text }));
    if (disasmSearchQuery.trim()) {
        disasmSearchMatches = runDisasmSearch(disasmLines, disasmSearchQuery, disasmSearchMode.value);
        if (disasmSearchMatches.length > 0 && (disasmSearchCurrentIndex < 0 || disasmSearchCurrentIndex >= disasmSearchMatches.length)) {
            disasmSearchCurrentIndex = 0;
        } else if (disasmSearchMatches.length === 0) {
            disasmSearchCurrentIndex = -1;
        }
        updateDisasmSearchStatus();
    } else {
        disasmSearchMatches = [];
        disasmSearchCurrentIndex = -1;
        if (disasmSearchStatus) disasmSearchStatus.textContent = '';
    }
    const matchSet = new Set(disasmSearchMatches);
    const currentMatchLine = disasmSearchMatches.length > 0 && disasmSearchCurrentIndex >= 0 ? disasmSearchMatches[disasmSearchCurrentIndex] : -1;
    const visibleAddrs = new Set(instrs.map(instr => Number(instr.addr_num)));
    const isSyscallAtCursor = emulator.get_trace_entry_is_syscall(traceIdx);

    let html = '';
    let lastSrcLine = null;
    for (let i = 0; i < instrs.length; i++) {
        const instr = instrs[i];
        const addrNum = Number(instr.addr_num);
        if (fnAddrMap.has(addrNum)) {
            html += `<div class="disasm-fn-header">${escapeHtml(fnAddrMap.get(addrNum))}:</div>`;
            lastSrcLine = null;
        }
        // Source line annotation (DWARF)
        const srcKey = instr.src_file ? `${instr.src_file}:${instr.src_line}` : null;
        if (srcKey && srcKey !== lastSrcLine) {
            html += `<div class="disasm-src-line" title="${escapeHtml(instr.src_file)}:${instr.src_line}">; ${escapeHtml(instr.src_file)}:${instr.src_line}</div>`;
            lastSrcLine = srcKey;
        }
        const isCurrent = (parseInt(instr.addr, 16) === rip);
        const currentCls = isCurrent ? 'disasm-current' : '';
        const syscallCls = isCurrent && isSyscallAtCursor ? ' disasm-syscall' : '';
        const bpCls = instr.has_bp ? 'disasm-bp' : '';
        const searchCls = matchSet.has(i) ? (i === currentMatchLine ? ' disasm-search-current' : ' disasm-search-hit') : '';
        const bpMarker = instr.has_bp ? '<span class="bp-marker" title="Breakpoint (click to remove)">&#9679;</span>' : '<span class="bp-marker-empty" title="Click to add breakpoint">&#9675;</span>';
        const regionBadge = instr.region ? `<span class="disasm-region" title="Source: ${escapeHtml(instr.region)}">${escapeHtml(shortRegionLabel(instr.region))}</span>` : '';

        html += `<div class="disasm-line ${currentCls} ${bpCls}${syscallCls}${searchCls}" data-addr="${instr.addr_num}" data-line-index="${i}">`;
        html += `<span class="disasm-bp-col">${bpMarker}</span>`;
        html += `<span class="disasm-addr">${instr.addr}</span>`;
        html += regionBadge;
        html += `<span class="disasm-instr">${syntaxHighlightDisasm(instr.text)}</span>`;
        if (instr.branch_target != null) {
            const targetNum = Number(instr.branch_target);
            const targetHex = '0x' + (targetNum >>> 0).toString(16);
            const inView = visibleAddrs.has(targetNum);
            html += `<span class="disasm-jump-arrow ${inView ? 'disasm-jump-inview' : ''}" data-target-addr="${targetNum}" title="Jump target ${targetHex}">→ ${targetHex}</span>`;
        }
        if (isCurrent) {
            html += `<span class="disasm-arrow">&larr;</span>`;
        }
        html += `</div>`;
    }

    disasmList.innerHTML = html;

    disasmList.querySelectorAll('.disasm-line').forEach(el => {
        el.addEventListener('click', (e) => {
            if (e.target.closest('.disasm-jump-arrow.disasm-jump-inview')) {
                const targetAddr = Number(e.target.closest('.disasm-jump-arrow').dataset.targetAddr);
                const targetLine = disasmList.querySelector(`.disasm-line[data-addr="${targetAddr}"]`);
                if (targetLine) targetLine.scrollIntoView({ block: 'center', behavior: 'smooth' });
                return;
            }
            const addr = Number(el.dataset.addr);
            if (!isNaN(addr)) toggleBreakpointAtAddr(addr);
        });
    });

    const currentEl = disasmList.querySelector('.disasm-current');
    if (currentEl) {
        currentEl.scrollIntoView({ block: 'center', behavior: 'instant' });
    }

    // Show current function name in panel header (trace mode)
    const fnLabel = document.getElementById('disasm-fn-label');
    if (fnLabel) {
        const fn = resolveFunctionAtAddr(rip);
        fnLabel.textContent = fn ? fn.name : '';
        fnLabel.title = fn ? `${fn.name} @ 0x${fn.addr.toString(16)}` : '';
    }
}

/** Short label for disasm region (main, interpreter path basename, or "mapped"). */
function shortRegionLabel(region) {
    if (!region) return '';
    if (region === 'main') return 'main';
    if (region === 'mapped') return 'mapped';
    if (region === 'interpreter') return 'ld';
    const slash = region.lastIndexOf('/');
    return slash >= 0 ? region.slice(slash + 1) : region;
}

function renderTimeline(selectedIdx) {
    if (!emulator) return;
    const canvas = timelineCanvas;
    const wrap = timelineWrap;
    const width = wrap.clientWidth;
    const height = 120;

    canvas.width = width;
    canvas.height = height;
    const ctx = canvas.getContext('2d');

    const len = emulator.get_trace_length();
    if (len === 0) {
        ctx.fillStyle = '#171923';
        ctx.fillRect(0, 0, width, height);
        timelineCursor.style.display = 'none';
        return;
    }

    // Zoom range — ensure we always have a valid range when trace has entries so the RIP lane draws
    let zStart = getZoomStart();
    let zEnd = getZoomEnd();
    if (zEnd <= zStart && len > 0) {
        zStart = 0;
        zEnd = len;
    }
    const zSpan = zEnd - zStart;

    // Get sampled timeline data for visible range
    const samplesJson = emulator.get_trace_timeline_ranged(zStart, zEnd, width * 2);
    const samples = JSON.parse(samplesJson);
    if (samples.length === 0) return;

    // ── Background ──
    ctx.fillStyle = '#0f1117';
    ctx.fillRect(0, 0, width, height);

    // ── Lane layout ──
    //  Lane 0: RIP color map                  (top, 40px)
    //  Lane 1: MEM activity (all R/W per insn) (big, 40px) — always visible
    //  Lane 2: daddr access markers             (20px, if daddr set)
    //  Lane 3: EXEC breakpoint hits             (12px, if exec bp set)
    //  Lane 4: FLOW forward/backward trail      (8px)
    const laneRipH = 40;
    const laneMemY = laneRipH;
    const laneMemH = 40;
    const laneDaddrY = laneMemY + laneMemH;
    const laneDaddrH = daddr ? 18 : 0;
    const laneBpY = laneDaddrY + laneDaddrH;
    const laneBpH = tlIaddrBreakpoint ? 12 : 0;
    const laneFlowY = laneBpY + laneBpH;
    const laneFlowH = height - laneFlowY;

    const colWidth = Math.max(1, width / samples.length);

    // ── Lane 0: RIP color map (syscall instructions in distinct color) ──
    let minRip = Infinity, maxRip = 0;
    for (const s of samples) {
        const rip = s[1];
        if (rip < minRip) minRip = rip;
        if (rip > maxRip) maxRip = rip;
    }
    const ripRange = maxRip - minRip || 1;

    const syscallColor = '#06b6d4'; // cyan — syscall instructions in timeline
    for (let i = 0; i < samples.length; i++) {
        const s = samples[i];
        const localIdx = s[0];
        const rip = s[1];
        const isSyscall = s.length > 2 && s[2];
        if (isSyscall) {
            ctx.fillStyle = syscallColor;
        } else {
            const normalized = (rip - minRip) / ripRange;
            const hue = normalized * 280;
            ctx.fillStyle = `hsl(${hue}, 70%, 45%)`;
        }
        const x = ((localIdx - zStart) / zSpan) * width;
        ctx.fillRect(x, 0, colWidth + 1, laneRipH);
    }

    ctx.font = '9px monospace';
    ctx.fillStyle = 'rgba(255,255,255,0.3)';
    ctx.fillText('RIP', 3, 10);

    // ── Lane 1: MEM activity — all reads/writes for every instruction ──
    ctx.fillStyle = '#0d0e15';
    ctx.fillRect(0, laneMemY, width, laneMemH);
    ctx.strokeStyle = 'rgba(255,255,255,0.06)';
    ctx.beginPath(); ctx.moveTo(0, laneMemY); ctx.lineTo(width, laneMemY); ctx.stroke();

    try {
        const actJson = emulator.get_trace_mem_activity_ranged(zStart, zEnd, width * 2);
        const actSamples = JSON.parse(actJson);
        for (const [localIdx, activity] of actSamples) {
            if (activity === 0) continue;
            const x = ((localIdx - zStart) / zSpan) * width;
            if (activity === 3) {
                // Both read + write: bright yellow (write dominates, underlined by read)
                ctx.fillStyle = '#b7a42e';
                ctx.fillRect(x, laneMemY + 1, Math.max(1, colWidth), laneMemH - 2);
                ctx.fillStyle = '#fef08a';
                ctx.fillRect(x, laneMemY + 1, Math.max(1, colWidth), Math.floor((laneMemH - 2) / 2));
            } else if (activity === 2) {
                // Write only: bright yellow
                ctx.fillStyle = '#fef08a';
                ctx.fillRect(x, laneMemY + 1, Math.max(1, colWidth), laneMemH - 2);
            } else {
                // Read only: dark yellow
                ctx.fillStyle = '#b7a42e';
                ctx.fillRect(x, laneMemY + 1, Math.max(1, colWidth), laneMemH - 2);
            }
        }
    } catch (e) { /* ignore */ }

    ctx.fillStyle = 'rgba(255,255,255,0.3)';
    ctx.fillText('MEM', 3, laneMemY + 10);
    // Legend
    ctx.fillStyle = '#b7a42e';
    ctx.fillText('R', 32, laneMemY + 10);
    ctx.fillStyle = '#fef08a';
    ctx.fillText('W', 42, laneMemY + 10);

    // ── Lane 2: daddr-specific access markers ──
    if (daddr && laneDaddrH > 0) {
        ctx.fillStyle = '#0e1020';
        ctx.fillRect(0, laneDaddrY, width, laneDaddrH);
        ctx.strokeStyle = 'rgba(255,255,255,0.06)';
        ctx.beginPath(); ctx.moveTo(0, laneDaddrY); ctx.lineTo(width, laneDaddrY); ctx.stroke();

        try {
            const hitsJson = emulator.get_trace_daddr_timeline_ranged(
                daddr.addr, daddr.size, zStart, zEnd, width * 2
            );
            const hits = JSON.parse(hitsJson);
            for (const [hitIdx, isWrite] of hits) {
                const x = ((hitIdx - zStart) / zSpan) * width;
                ctx.fillStyle = isWrite > 0 ? '#fef08a' : '#b7a42e';
                ctx.fillRect(x, laneDaddrY + 1, Math.max(1, colWidth), laneDaddrH - 2);
            }
        } catch (e) { /* ignore */ }

        ctx.fillStyle = 'rgba(255,255,255,0.3)';
        ctx.fillText('DADDR 0x' + daddr.addr.toString(16), 3, laneDaddrY + 10);
    }

    // ── Lane 3: Execution breakpoint markers (iaddr) ──
    if (tlIaddrBreakpoint !== null && laneBpH > 0) {
        ctx.fillStyle = '#1a1a2e';
        ctx.fillRect(0, laneBpY, width, laneBpH);
        ctx.strokeStyle = 'rgba(255,255,255,0.08)';
        ctx.beginPath(); ctx.moveTo(0, laneBpY); ctx.lineTo(width, laneBpY); ctx.stroke();

        try {
            const hitsJson = emulator.get_trace_rip_hits(tlIaddrBreakpoint, zStart, zEnd, width * 2);
            const hits = JSON.parse(hitsJson);
            for (const hitIdx of hits) {
                const x = ((hitIdx - zStart) / zSpan) * width;
                ctx.fillStyle = '#fc8181';
                ctx.fillRect(x, laneBpY + 1, Math.max(1, colWidth), laneBpH - 2);
            }
        } catch (e) { /* ignore */ }

        ctx.fillStyle = 'rgba(255,255,255,0.25)';
        ctx.fillText('EXEC', 3, laneBpY + 9);
    }

    // ── Lane 4: Forward/backward flow ──
    if (laneFlowH > 2) {
        ctx.fillStyle = '#111320';
        ctx.fillRect(0, laneFlowY, width, laneFlowH);
        ctx.strokeStyle = 'rgba(255,255,255,0.06)';
        ctx.beginPath(); ctx.moveTo(0, laneFlowY); ctx.lineTo(width, laneFlowY); ctx.stroke();

        if (selectedIdx !== undefined && selectedIdx >= 0 && selectedIdx >= zStart && selectedIdx < zEnd) {
            const cursorFraction = (selectedIdx - zStart) / zSpan;
            const cursorPx = cursorFraction * width;

            const fwdGrad = ctx.createLinearGradient(cursorPx, 0, Math.min(cursorPx + width * 0.3, width), 0);
            fwdGrad.addColorStop(0, 'rgba(99, 179, 237, 0.7)');
            fwdGrad.addColorStop(1, 'rgba(99, 179, 237, 0)');
            ctx.fillStyle = fwdGrad;
            ctx.fillRect(cursorPx, laneFlowY + 1, width * 0.3, laneFlowH - 2);

            const bwdGrad = ctx.createLinearGradient(Math.max(cursorPx - width * 0.3, 0), 0, cursorPx, 0);
            bwdGrad.addColorStop(0, 'rgba(252, 129, 129, 0)');
            bwdGrad.addColorStop(1, 'rgba(252, 129, 129, 0.7)');
            ctx.fillStyle = bwdGrad;
            ctx.fillRect(Math.max(cursorPx - width * 0.3, 0), laneFlowY + 1, width * 0.3, laneFlowH - 2);
        }
    }

    // ── Breakpoint markers (red ticks at top of RIP lane) ──
    try {
        const bps = JSON.parse(emulator.get_breakpoints());
        for (const bpAddr of bps) {
            const addr = parseInt(bpAddr, 16);
            for (let i = 0; i < samples.length; i++) {
                if (Math.abs(samples[i][1] - addr) < 16) {
                    const x = ((samples[i][0] - zStart) / zSpan) * width;
                    ctx.fillStyle = '#fc8181';
                    ctx.fillRect(x, 0, 2, 5);
                }
            }
        }
    } catch (e) { /* ignore */ }

    // ── Zoomed-out minimap indicator ──
    if (zStart > 0 || zEnd < len) {
        const minimapH = 3;
        ctx.fillStyle = 'rgba(255,255,255,0.05)';
        ctx.fillRect(0, 0, width, minimapH);
        const mleft = (zStart / len) * width;
        const mwidth = ((zEnd - zStart) / len) * width;
        ctx.fillStyle = 'rgba(99, 179, 237, 0.5)';
        ctx.fillRect(mleft, 0, Math.max(2, mwidth), minimapH);
    }

    // ── Cursor position (CSS overlay) ──
    if (selectedIdx !== undefined && selectedIdx >= 0 && selectedIdx >= zStart && selectedIdx < zEnd) {
        const cursorX = ((selectedIdx - zStart) / zSpan) * width;
        timelineCursor.style.display = 'block';
        timelineCursor.style.left = cursorX + 'px';
    } else {
        timelineCursor.style.display = 'none';
    }
}

// ── Memory Map ──────────────────────────────────────────────────────────────

function renderMemoryMap() {
    if (!emulator) return;
    try {
        const regions = JSON.parse(emulator.get_memory_regions());
        if (regions.length === 0) {
            memmapList.innerHTML = '<div class="muted">No memory mapped</div>';
            return;
        }
        // Header
        let html = '<div class="memmap-header">';
        html += '<span class="memmap-col-addr">Address Range</span>';
        html += '<span class="memmap-col-size">Size</span>';
        html += '<span class="memmap-col-perms">Perms</span>';
        html += '<span class="memmap-col-entropy">Entropy</span>';
        html += '<span class="memmap-col-heatmap">Heatmap</span>';
        html += '</div>';

        // Entropy legend bar
        html += '<div class="memmap-legend">';
        html += '<span class="memmap-legend-label">0</span>';
        html += '<div class="memmap-legend-bar">';
        for (let i = 0; i <= 32; i++) {
            const e = (i / 32) * 8;
            html += `<span style="background:${entropyToColor(e)}"></span>`;
        }
        html += '</div>';
        html += '<span class="memmap-legend-label">8 bits</span>';
        html += '</div>';

        for (const r of regions) {
            const endAddr = r.start_num + r.size;
            const endHex = '0x' + endAddr.toString(16);
            const permsHtml = r.perms.split('').map(c => {
                if (c === 'r') return '<span class="memmap-perms-r">r</span>';
                if (c === 'w') return '<span class="memmap-perms-w">w</span>';
                if (c === 'x') return '<span class="memmap-perms-x">x</span>';
                return '<span class="memmap-perms-none">-</span>';
            }).join('');

            const sizeKB = r.size >= 1024 ? `${(r.size / 1024).toFixed(0)}K` : `${r.size}`;

            // Compute entropy: sample blocks spread across the region
            const BLOCK_SIZE = 256;
            const MAX_BLOCKS = 64; // max heatmap cells
            const regionSize = r.size;
            const blockCount = Math.min(MAX_BLOCKS, Math.max(1, Math.floor(regionSize / BLOCK_SIZE)));
            const stride = regionSize / blockCount;
            let totalEntropy = 0;
            let heatmapCells = '';
            const entropies = [];

            try {
                if (typeof emulator.read_memory_bytes === 'function') {
                    // For each block, read BLOCK_SIZE bytes at the sampled offset
                    for (let bi = 0; bi < blockCount; bi++) {
                        const blockAddr = r.start_num + Math.floor(bi * stride);
                        const blockLen = Math.min(BLOCK_SIZE, r.start_num + regionSize - blockAddr);
                        if (blockLen <= 0) break;
                        const raw = emulator.read_memory_bytes(blockAddr, blockLen);
                        const blockData = raw.subarray(0, blockLen);
                        entropies.push(computeEntropy(blockData, 0, blockLen));
                    }
                    // Overall entropy from first block sample (representative)
                    if (entropies.length > 0) {
                        totalEntropy = entropies.reduce((a, b) => a + b, 0) / entropies.length;
                    }
                }
            } catch (_) { /* region may be unreadable */ }

            if (entropies.length > 0) {
                for (const e of entropies) {
                    heatmapCells += `<span class="memmap-heat-cell" style="background:${entropyToColor(e)}" title="${e.toFixed(2)} bits"></span>`;
                }
            } else {
                heatmapCells = '<span class="muted" style="font-size:0.6rem">n/a</span>';
            }

            html += `<div class="memmap-entry" data-addr="${r.start}" onclick="window._memGo('${r.start}')">`;
            html += `<span class="memmap-col-addr memmap-addr">${r.start}&ndash;${endHex}</span>`;
            html += `<span class="memmap-col-size memmap-size">${sizeKB} (${r.size_hex})</span>`;
            html += `<span class="memmap-col-perms memmap-perms">${permsHtml}</span>`;
            html += `<span class="memmap-col-entropy memmap-entropy" style="color:${entropyToColor(totalEntropy)}">${totalEntropy.toFixed(1)}</span>`;
            html += `<span class="memmap-col-heatmap memmap-heatmap">${heatmapCells}</span>`;
            html += `</div>`;
        }
        memmapList.innerHTML = html;
    } catch (e) {
        memmapList.innerHTML = '<div class="muted">Error loading memory map</div>';
    }
}
window._memGo = (addr) => {
    memAddr.value = addr;
    refreshMemory();
    const memTabBtn = document.querySelector('[data-tab="memory-tab"]');
    if (memTabBtn) memTabBtn.click();
};

// Toggle execution breakpoint on timeline (Tenet-style: click RIP to show all executions)
window._toggleExecBreakpoint = (ripAddr) => {
    if (tlIaddrBreakpoint === ripAddr) {
        tlIaddrBreakpoint = null; // toggle off
    } else {
        tlIaddrBreakpoint = ripAddr;
    }
    renderTimeline(traceCursor);
    // Re-render registers to update active highlight
    if (emulator && traceMode) {
        const regsJson = emulator.get_trace_registers(traceCursor);
        if (regsJson !== 'null') renderRegisters(JSON.parse(regsJson), { traceSeek: true });
    }
};

// Register seeking (Tenet-style): seek trace to instruction that set this register
window._focusGprAndSeekPrev = (gprIndex) => {
    focusedGprIndex = gprIndex;
    if (!emulator || !traceMode) return;
    const idx = emulator.prev_trace_by_register(gprIndex, traceCursor);
    if (idx >= 0) seekTrace(idx);
};
window._focusGprAndSeekNext = (gprIndex) => {
    focusedGprIndex = gprIndex;
    if (!emulator || !traceMode) return;
    const idx = emulator.next_trace_by_register(gprIndex, traceCursor);
    if (idx >= 0) seekTrace(idx);
};
window._seekTraceToRegisterPrev = (gprIndex) => { window._focusGprAndSeekPrev(gprIndex); };
window._seekTraceToRegisterNext = (gprIndex) => { window._focusGprAndSeekNext(gprIndex); };

// ── Dynamic cross-references (XREFs) ────────────────────────────────────────

/** Cached xref maps built from WASM data. */
let xrefToMap = new Map();   // target addr → [{from, from_num, kind, count}]
let xrefFromMap = new Map(); // source addr → [{to, to_num, kind, count}]
let xrefTotal = -1; // -1 so first updateFullUI triggers a refresh

const xrefsSummary = document.getElementById('xrefs-summary');
const xrefsDetail = document.getElementById('xrefs-detail');
const xrefsList = document.getElementById('xrefs-list');
const btnXrefsRefresh = document.getElementById('btn-xrefs-refresh');

/** Rebuild the JS-side xref cache from WASM. */
function refreshXrefCache() {
    if (!emulator) return;
    xrefToMap.clear();
    xrefFromMap.clear();
    xrefTotal = -1;
    if (typeof emulator.get_all_xrefs !== 'function') return;
    try {
        const raw = emulator.get_all_xrefs();
        if (typeof raw !== 'string') return;
        const all = JSON.parse(raw);
        if (!Array.isArray(all)) return;
        xrefTotal = all.length;
        for (const x of all) {
            const toNum = Number(x.to_num);
            const fromNum = Number(x.from_num);
            if (!xrefToMap.has(toNum)) xrefToMap.set(toNum, []);
            xrefToMap.get(toNum).push(x);
            if (!xrefFromMap.has(fromNum)) xrefFromMap.set(fromNum, []);
            xrefFromMap.get(fromNum).push(x);
        }
    } catch (e) {
        console.error('[XREFs] refreshXrefCache failed:', e);
    }
}

/** Render the XREFs summary panel with top targets. */
function renderXrefSummary() {
    if (!xrefsSummary || !xrefsList) return;
    if (!emulator) {
        xrefsSummary.textContent = t('xrefsNoEmulator');
        xrefsList.innerHTML = '<div class="muted">Load a binary first.</div>';
        return;
    }
    if (typeof emulator.get_xref_summary !== 'function') {
        xrefsSummary.textContent = t('xrefsApiUnavailable');
        xrefsList.innerHTML = '<div class="muted">Rebuild the web package to enable cross-references.</div>';
        return;
    }
    try {
        const raw = emulator.get_xref_summary();
        if (typeof raw !== 'string') {
            xrefsSummary.textContent = t('xrefsInvalidResponse');
            return;
        }
        const summary = JSON.parse(raw);
        const total = summary.total != null ? summary.total : 0;
        const calls = summary.calls != null ? summary.calls : 0;
        const jumps = summary.jumps != null ? summary.jumps : 0;
        const dataRefs = summary.data_refs != null ? summary.data_refs : 0;

        xrefsSummary.innerHTML =
            `<span class="xref-stat">${total} xrefs</span>` +
            `<span class="xref-stat xref-call">${calls} calls</span>` +
            `<span class="xref-stat xref-jmp">${jumps} jumps</span>` +
            `<span class="xref-stat xref-data">${dataRefs} data</span>`;

        const topTargets = summary.top_targets || [];
        if (topTargets.length > 0) {
            let html = '<div class="xrefs-top-header">Most referenced addresses:</div>';
            for (const t of topTargets) {
                const addrNum = Number(t.addr_num);
                const addrStr = t.addr != null ? String(t.addr) : ('0x' + addrNum.toString(16));
                const refsCount = t.refs_count != null ? t.refs_count : 0;
                const kinds = Array.isArray(t.kinds) ? t.kinds : [];
                const fnName = resolveFunctionAtAddr(addrNum);
                const kindBadges = kinds.map(k =>
                    `<span class="xref-kind-badge xref-kind-${k}">${k}</span>`
                ).join('');
                html += `<div class="xref-top-entry" data-addr="${addrNum}" onclick="window._showXrefsFor(${addrNum})">`;
                html += `<span class="xref-top-addr mono">${escapeHtml(addrStr)}</span>`;
                if (fnName != null && fnName !== '') html += `<span class="xref-top-name">${escapeHtml(String(fnName))}</span>`;
                html += `<span class="xref-top-count">${refsCount} ref${refsCount !== 1 ? 's' : ''}</span>`;
                html += kindBadges;
                html += `</div>`;
            }
            xrefsList.innerHTML = html;
        } else {
            xrefsList.innerHTML = '<div class="muted">No xrefs collected yet. Run the program first.</div>';
        }
    } catch (e) {
        console.error('[XREFs] renderXrefSummary failed:', e);
        xrefsSummary.textContent = t('xrefsError') + ' ' + (e.message || String(e));
    }
}

/** Show detailed xrefs for a specific address in the detail panel. */
window._showXrefsFor = function(addr) {
    if (!emulator || !xrefsDetail) return;
    // Switch to XREFs tab
    const xrefTabBtn = document.querySelector('[data-tab="xrefs-tab"]');
    if (xrefTabBtn) xrefTabBtn.click();

    const refsTo = xrefToMap.get(addr) || [];
    const refsFrom = xrefFromMap.get(addr) || [];
    const fnName = resolveFunctionAtAddr(addr);
    const addrHex = '0x' + addr.toString(16);

    let html = `<div class="xref-detail-header">`;
    html += `<span class="mono xref-detail-addr">${addrHex}</span>`;
    if (fnName) html += `<span class="xref-detail-name">${escapeHtml(fnName)}</span>`;
    html += `</div>`;

    // Incoming references (who references this address)
    if (refsTo.length > 0) {
        html += `<div class="xref-section-title">Referenced by (${refsTo.length}):</div>`;
        // Sort: calls first, then jumps, then data
        const sorted = [...refsTo].sort((a, b) => {
            const order = { call: 0, jmp: 1, data: 2 };
            return (order[a.kind] || 3) - (order[b.kind] || 3);
        });
        for (const x of sorted) {
            const fromFn = resolveFunctionAtAddr(x.from_num);
            html += `<div class="xref-ref-entry" onclick="window._goDisasmAddr(${x.from_num})" title="Go to ${x.from}">`;
            html += `<span class="xref-kind-badge xref-kind-${x.kind}">${x.kind}</span>`;
            html += `<span class="xref-ref-addr mono">${x.from}</span>`;
            if (fromFn) html += `<span class="xref-ref-name">${escapeHtml(fromFn)}</span>`;
            if (x.count > 1) html += `<span class="xref-ref-count">×${x.count}</span>`;
            html += `</div>`;
        }
    } else {
        html += `<div class="muted">No incoming references.</div>`;
    }

    // Outgoing references (what does this address reference)
    if (refsFrom.length > 0) {
        html += `<div class="xref-section-title" style="margin-top:0.5rem">References from here (${refsFrom.length}):</div>`;
        for (const x of refsFrom) {
            const toFn = resolveFunctionAtAddr(x.to_num);
            html += `<div class="xref-ref-entry" onclick="window._goDisasmAddr(${x.to_num})" title="Go to ${x.to}">`;
            html += `<span class="xref-kind-badge xref-kind-${x.kind}">${x.kind}</span>`;
            html += `<span class="xref-ref-addr mono">${x.to}</span>`;
            if (toFn) html += `<span class="xref-ref-name">${escapeHtml(toFn)}</span>`;
            if (x.count > 1) html += `<span class="xref-ref-count">×${x.count}</span>`;
            html += `</div>`;
        }
    }

    xrefsDetail.innerHTML = html;
};

/** Navigate disassembly to a specific address. */
window._goDisasmAddr = function(addr) {
    if (!emulator) return;
    disasmOverrideAddr = addr;
    renderDisasm();
};

// Event: refresh xrefs button
if (btnXrefsRefresh) {
    btnXrefsRefresh.addEventListener('click', () => {
        refreshXrefCache();
        renderXrefSummary();
    });
}

// resolveFunctionAtAddr is defined earlier in the file (binary search over elfFunctions)

// ── YARA Tab ────────────────────────────────────────────────────────────────

const yaraEditor = document.getElementById('yara-editor');
const yaraHighlightLayer = document.getElementById('yara-highlight-layer');
const yaraResults = document.getElementById('yara-results');
const yaraStatus = document.getElementById('yara-status');
const yaraMatchCount = document.getElementById('yara-match-count');
const yaraSummary = document.getElementById('yara-summary');
const btnYaraScan = document.getElementById('btn-yara-scan');
const btnYaraRunAll = document.getElementById('btn-yara-run-all');
const btnYaraRunSelected = document.getElementById('btn-yara-run-selected');
const btnYaraClear = document.getElementById('btn-yara-clear');
const yaraFileInput = document.getElementById('yara-file-input');
const yaraExampleSelect = document.getElementById('yara-example-select');
const yaraRuleSearch = document.getElementById('yara-rule-search');
const btnYaraFetchForge = document.getElementById('btn-yara-fetch-forge');

const YARA_FORGE_ZIP_URL = '/yara-forge-rules-full.zip';

/** Parsed YARA-Forge rules after fetch; used when user picks from Example Rules. [{ name, source }] */
let _yaraForgeRules = [];

/** Last rule source/name selected from Example Rules dropdown; used by "Run selected rule". */
let _lastSelectedRuleSource = '';
let _lastSelectedRuleName = '';

/** Rebuild YARA-Forge optgroup from _yaraForgeRules, filtered by search query (case-insensitive match on rule name). */
function refreshYaraForgeOptgroup(searchQuery) {
    const optgroup = document.getElementById('yara-forge-optgroup');
    if (!optgroup) return;
    optgroup.innerHTML = '';
    const q = (searchQuery || '').trim().toLowerCase();
    _yaraForgeRules.forEach((r, i) => {
        if (q && !r.name.toLowerCase().includes(q)) return;
        const opt = document.createElement('option');
        opt.value = 'forge:' + i;
        opt.textContent = r.name;
        optgroup.appendChild(opt);
    });
}

/** Parses a blob of YARA source into individual rules (by rule name and matching braces). Returns [{ name, source }]. */
function parseYaraRulesFromSource(text) {
    const rules = [];
    const re = /\brule\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\{/g;
    let m;
    while ((m = re.exec(text)) !== null) {
        const name = m[1];
        let depth = 1;
        let i = m.index + m[0].length;
        let inString = false;
        let escape = false;
        while (i < text.length && depth > 0) {
            const c = text[i];
            if (escape) { escape = false; i++; continue; }
            if (c === '\\' && inString) { escape = true; i++; continue; }
            if (c === '"') { inString = !inString; i++; continue; }
            if (!inString) {
                if (c === '{') depth++;
                else if (c === '}') depth--;
            }
            i++;
        }
        rules.push({ name, source: text.slice(m.index, i).trim() });
    }
    return rules;
}

/** Escape for HTML text content */
function escapeHtmlYara(s) {
    return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

/** YARA syntax highlighter: returns HTML string with span classes */
function highlightYara(source) {
    if (!source) return '';
    const lines = source.split('\n');
    const out = [];
    let inBlockComment = false;
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        let html = '';
        let pos = 0;
        while (pos < line.length) {
            if (inBlockComment) {
                const end = line.indexOf('*/', pos);
                if (end === -1) {
                    html += '<span class="yara-comment">' + escapeHtmlYara(line.slice(pos)) + '</span>';
                    pos = line.length;
                } else {
                    html += '<span class="yara-comment">' + escapeHtmlYara(line.slice(pos, end + 2)) + '</span>';
                    pos = end + 2;
                    inBlockComment = false;
                }
                continue;
            }
            // Single-line comment
            if (line.slice(pos, pos + 2) === '//') {
                html += '<span class="yara-comment">' + escapeHtmlYara(line.slice(pos)) + '</span>';
                pos = line.length;
                break;
            }
            // Multi-line comment start
            if (line.slice(pos, pos + 2) === '/*') {
                const end = line.indexOf('*/', pos + 2);
                if (end === -1) {
                    html += '<span class="yara-comment">' + escapeHtmlYara(line.slice(pos)) + '</span>';
                    pos = line.length;
                    inBlockComment = true;
                } else {
                    html += '<span class="yara-comment">' + escapeHtmlYara(line.slice(pos, end + 2)) + '</span>';
                    pos = end + 2;
                }
                continue;
            }
            // Double-quoted string
            if (line[pos] === '"') {
                let end = pos + 1;
                while (end < line.length) {
                    if (line[end] === '\\') { end += 2; continue; }
                    if (line[end] === '"') { end += 1; break; }
                    end++;
                }
                html += '<span class="yara-str">' + escapeHtmlYara(line.slice(pos, end)) + '</span>';
                pos = end;
                continue;
            }
            // Hex block { ... }
            if (line[pos] === '{') {
                let end = line.indexOf('}', pos + 1);
                if (end === -1) end = line.length; else end += 1;
                html += '<span class="yara-hex">' + escapeHtmlYara(line.slice(pos, end)) + '</span>';
                pos = end;
                continue;
            }
            // Identifier $foo
            const idMatch = line.slice(pos).match(/^(\$[a-zA-Z_][a-zA-Z0-9_]*)/);
            if (idMatch) {
                html += '<span class="yara-id">' + escapeHtmlYara(idMatch[1]) + '</span>';
                pos += idMatch[1].length;
                continue;
            }
            // Keyword
            const kwMatch = line.slice(pos).match(/^\b(rule|meta|strings|condition|nocase|ascii|wide|fullword|and|or|any|all|of|them|true|false)\b/);
            if (kwMatch) {
                html += '<span class="yara-kw">' + escapeHtmlYara(kwMatch[1]) + '</span>';
                pos += kwMatch[1].length;
                continue;
            }
            html += escapeHtmlYara(line[pos]);
            pos += 1;
        }
        out.push(html || ' ');
    }
    return out.join('\n');
}

function refreshYaraHighlight() {
    if (!yaraHighlightLayer || !yaraEditor) return;
    yaraHighlightLayer.innerHTML = highlightYara(yaraEditor.value) || '\n';
    yaraHighlightLayer.scrollTop = yaraEditor.scrollTop;
    yaraHighlightLayer.scrollLeft = yaraEditor.scrollLeft;
}

const YARA_EXAMPLES = {
    hello_world: `rule hello_world {
    meta:
        description = "Detect hello/world strings in memory"
    strings:
        $hello = "Hello" nocase
        $world = "world" nocase
        $hi = "Hi"
    condition:
        any of them
}`,
    elf_header: `rule elf_header {
    meta:
        description = "Detect ELF magic header in memory"
    strings:
        $elf_magic = { 7F 45 4C 46 }
    condition:
        $elf_magic
}`,
    nop_sled: `rule nop_sled {
    meta:
        description = "Detect NOP sleds (10+ consecutive NOPs)"
    strings:
        $nops_x86 = { 90 90 90 90 90 90 90 90 90 90 }
    condition:
        $nops_x86
}`,
    stack_pivot: `rule stack_pivot_gadgets {
    meta:
        description = "Detect stack pivot gadgets (xchg rax,rsp; ret)"
    strings:
        $xchg_rax_rsp = { 48 94 C3 }
        $xchg_rsp_rax = { 48 94 C3 }
        $mov_rsp_rax = { 48 89 C4 C3 }
    condition:
        any of them
}`,
    syscall_int80: `rule linux_syscall_instructions {
    meta:
        description = "Detect Linux syscall instructions"
    strings:
        $syscall = { 0F 05 }
        $int80 = { CD 80 }
        $sysenter = { 0F 34 }
    condition:
        any of them
}`,
    pe_indicators: `rule pe_mz_header {
    meta: description = "PE MZ header"
    strings: $mz = { 4D 5A }
    condition: $mz
}
rule pe_signature {
    meta: description = "PE signature"
    strings: $pe = { 50 45 00 00 }
    condition: $pe
}
rule pe_suspicious_apis {
    meta: description = "Suspicious API names (injection/shellcode)"
    strings:
        $valloc = "VirtualAlloc" nocase
        $wpm = "WriteProcessMemory" nocase
        $crt = "CreateRemoteThread" nocase
        $gpa = "GetProcAddress" nocase
        $lla = "LoadLibrary" nocase
        $op = "OpenProcess" nocase
        $ntct = "NtCreateThreadEx" nocase
    condition: any of them
}
rule pe_packer_sections {
    meta: description = "Packer-like section names"
    strings:
        $upx = ".upx" ascii
        $pack = ".pack" ascii
        $aspack = ".aspack" ascii
        $themida = ".themida" ascii
        $enigma = ".enigma" ascii
    condition: any of them
}`
};

/** Run YARA scan with given rule source and render results. Runs each rule separately so parse errors in one rule don't block others. */
function runYaraScanWithSource(source) {
    if (!emulator) return;
    const rulesSource = (typeof source === 'string' ? source : '').trim();
    if (!rulesSource) return;

    yaraResults.innerHTML = '';
    if (yaraMatchCount) yaraMatchCount.textContent = '';
    if (yaraSummary) yaraSummary.textContent = '';

    const parsedRules = parseYaraRulesFromSource(rulesSource);
    const t0 = performance.now();

    if (parsedRules.length === 0) {
        // No rules could be parsed (e.g. single malformed rule or empty). Try running the whole source once.
        if (yaraStatus) yaraStatus.textContent = 'Scanning (single rule)...';
        try {
            const json = emulator.yara_scan(rulesSource);
            const matches = JSON.parse(json);
            const elapsed = ((performance.now() - t0) / 1000).toFixed(3);
            renderYaraResults(matches, elapsed, 0, []);
            return;
        } catch (e) {
            const errMsg = e.message || String(e);
            if (yaraStatus) yaraStatus.textContent = `Error: ${errMsg}`;
            if (yaraResults) yaraResults.innerHTML = `<span style="color:var(--red)">${escapeHtmlYara(errMsg)}</span>`;
            console.error('[YARA] Scan failed:', e);
            return;
        }
    }

    if (yaraStatus) yaraStatus.textContent = `Scanning ${parsedRules.length} rule(s)...`;
    const allMatches = [];
    const skipped = [];

    for (const r of parsedRules) {
        try {
            const json = emulator.yara_scan(r.source);
            const matches = JSON.parse(json);
            allMatches.push(...matches);
        } catch (e) {
            const errMsg = e.message || String(e);
            skipped.push({ name: r.name, error: errMsg });
            console.warn(`[YARA] Rule "${r.name}" skipped:`, errMsg);
        }
    }

    const elapsed = ((performance.now() - t0) / 1000).toFixed(3);
    renderYaraResults(allMatches, elapsed, parsedRules.length, skipped);
}

/** Render YARA match list and status; skippedList is [{ name, error }]. */
function renderYaraResults(matches, elapsed, rulesScanned, skippedList) {
    const rulesMatched = new Set(matches.map(m => m.rule));

    let statusText = `${matches.length} match(es) in ${elapsed}s (${rulesMatched.size} rule(s) matched)`;
    if (skippedList.length > 0) {
        statusText += ` · ${skippedList.length} rule(s) skipped (parse errors)`;
    }
    if (yaraStatus) yaraStatus.textContent = statusText;
    if (yaraMatchCount) yaraMatchCount.textContent = matches.length > 0 ? `(${matches.length} matches)` : '';
    if (yaraSummary && (matches.length > 0 || skippedList.length > 0)) {
        let s = `${rulesMatched.size} rule(s) matched`;
        if (skippedList.length > 0) s += `, ${skippedList.length} skipped`;
        yaraSummary.textContent = s;
    }

    console.log(`[YARA] Scanned ${rulesScanned} rule(s) in ${elapsed}s: ${matches.length} match(es), ${rulesMatched.size} rule(s) matched${skippedList.length > 0 ? `, ${skippedList.length} skipped` : ''}`);

    let html = '';
    if (skippedList.length > 0) {
        html += `<div class="yara-skipped-log">`;
        html += `<div class="yara-skipped-log-title">⚠ ${skippedList.length} rule(s) skipped (errors):</div>`;
        for (const s of skippedList) {
            html += `<div class="yara-skipped-log-line"><span class="yara-skipped-log-rule">${escapeHtmlYara(s.name)}</span><span class="yara-skipped-log-error">${escapeHtmlYara(s.error)}</span></div>`;
        }
        html += '</div>';
    }
    if (matches.length === 0) {
        html += '<span class="muted">No matches found. Run all rules to scan full memory.</span>';
        yaraResults.innerHTML = html;
        return;
    }
    for (const m of matches) {
        html += `<div class="yara-match-row" data-addr="${m.addr_num}" title="Click to view in memory">`;
        html += `<span class="yara-match-rule">${escapeHtmlYara(m.rule)}</span>`;
        html += `<span class="yara-match-pattern">${escapeHtmlYara(m.pattern)}</span>`;
        html += `<span class="yara-match-addr">${m.addr}</span>`;
        html += `<span class="yara-match-len">${m.len}B</span>`;
        html += `<span class="yara-match-preview">${escapeHtmlYara(m.preview)}</span>`;
        html += `</div>`;
    }
    yaraResults.innerHTML = html;

    yaraResults.querySelectorAll('.yara-match-row').forEach(row => {
        row.addEventListener('click', () => {
            const addr = parseFloat(row.dataset.addr);
            if (!isNaN(addr) && emulator) {
                const memAddr = document.getElementById('mem-addr');
                if (memAddr) {
                    memAddr.value = '0x' + Math.floor(addr).toString(16);
                    document.getElementById('btn-mem-go')?.click();
                }
                const memTab = document.querySelector('[data-tab="memory-tab"]');
                if (memTab) memTab.click();
            }
        });
    });
}

/** Returns combined source of all available rules: built-in examples + all YARA-Forge rules (if loaded). */
function getAllYaraRulesSource() {
    const builtInKeys = Object.keys(YARA_EXAMPLES).filter(k => k !== 'all_examples');
    const parts = builtInKeys.map(k => YARA_EXAMPLES[k]).filter(Boolean);
    if (_yaraForgeRules.length > 0) {
        parts.push(..._yaraForgeRules.map(r => r.source));
    }
    return parts.join('\n\n');
}

/** Run YARA scan using the editor content (used by Scan Memory). */
function runYaraScanAndShowResults() {
    if (!emulator) {
        if (yaraStatus) yaraStatus.textContent = 'No binary loaded';
        return;
    }
    const source = yaraEditor ? yaraEditor.value.trim() : '';
    if (!source) {
        if (yaraStatus) yaraStatus.textContent = 'Enter YARA rules first';
        return;
    }
    runYaraScanWithSource(source);
}

/** Run YARA scan with all available rules (built-in + YARA-Forge). */
function runAllYaraRules() {
    if (!emulator) {
        if (yaraStatus) yaraStatus.textContent = 'No binary loaded';
        return;
    }
    const source = getAllYaraRulesSource();
    if (!source.trim()) {
        if (yaraStatus) yaraStatus.textContent = 'No rules loaded. Load examples or fetch YARA-Forge rules.';
        return;
    }
    runYaraScanWithSource(source);
}

if (btnYaraRunAll) {
    btnYaraRunAll.addEventListener('click', () => {
        runAllYaraRules();
    });
}

if (btnYaraRunSelected) {
    btnYaraRunSelected.addEventListener('click', () => {
        if (!emulator) {
            if (yaraStatus) yaraStatus.textContent = 'No binary loaded';
            return;
        }
        if (!_lastSelectedRuleSource) {
            if (yaraStatus) yaraStatus.textContent = 'Select a rule from Example Rules first, then click Run selected rule.';
            return;
        }
        if (_lastSelectedRuleName) console.log(`[YARA] Running selected rule: ${_lastSelectedRuleName}`);
        runYaraScanWithSource(_lastSelectedRuleSource);
    });
}

if (btnYaraScan) {
    btnYaraScan.addEventListener('click', () => runYaraScanAndShowResults());
}

if (btnYaraClear) {
    btnYaraClear.addEventListener('click', () => {
        yaraEditor.value = '';
        refreshYaraHighlight();
        yaraResults.innerHTML = '<span class="muted">Write YARA rules and click &quot;Run all rules&quot; to scan memory and see all results.</span>';
        yaraStatus.textContent = '';
        if (yaraMatchCount) yaraMatchCount.textContent = '';
        if (yaraSummary) yaraSummary.textContent = '';
    });
}

const peYaraOnLoadCheckbox = document.getElementById('pe-yara-on-load');
if (peYaraOnLoadCheckbox) {
    try {
        peYaraOnLoadCheckbox.checked = localStorage.getItem('binb-pe-yara-on-load') === '1';
    } catch (_) {}
    peYaraOnLoadCheckbox.addEventListener('change', () => {
        try { localStorage.setItem('binb-pe-yara-on-load', peYaraOnLoadCheckbox.checked ? '1' : '0'); } catch (_) {}
    });
}

if (yaraFileInput) {
    yaraFileInput.addEventListener('change', (e) => {
        const file = e.target.files[0];
        if (!file) return;
        const reader = new FileReader();
        reader.onload = () => {
            yaraEditor.value = reader.result;
            refreshYaraHighlight();
            yaraStatus.textContent = `Loaded: ${file.name}. Click "Run all rules" to see results.`;
        };
        reader.readAsText(file);
        yaraFileInput.value = '';
    });
}

if (yaraExampleSelect) {
    yaraExampleSelect.addEventListener('change', () => {
        const key = yaraExampleSelect.value;
        if (!key) return;
        if (key === 'all_examples') {
            const all = Object.keys(YARA_EXAMPLES)
                .filter(k => k !== 'all_examples')
                .map(k => YARA_EXAMPLES[k])
                .join('\n\n');
            yaraEditor.value = all;
            _lastSelectedRuleSource = '';
            _lastSelectedRuleName = '';
            yaraStatus.textContent = 'Loaded all examples. Click "Run all rules" to see results.';
        } else if (key.startsWith('forge:')) {
            const i = parseInt(key.slice(6), 10);
            if (!isNaN(i) && _yaraForgeRules[i]) {
                const r = _yaraForgeRules[i];
                yaraEditor.value = r.source;
                _lastSelectedRuleSource = r.source;
                _lastSelectedRuleName = r.name;
                yaraStatus.textContent = `YARA-Forge: ${r.name}. Click "Run selected rule" to scan with this rule only.`;
            }
        } else if (YARA_EXAMPLES[key]) {
            yaraEditor.value = YARA_EXAMPLES[key];
            _lastSelectedRuleSource = YARA_EXAMPLES[key];
            _lastSelectedRuleName = key;
            yaraStatus.textContent = `Example: ${key}. Click "Run selected rule" to scan with this rule only.`;
        }
        refreshYaraHighlight();
        yaraExampleSelect.value = '';
    });
}

if (yaraRuleSearch) {
    yaraRuleSearch.addEventListener('input', () => {
        refreshYaraForgeOptgroup(yaraRuleSearch.value);
    });
    yaraRuleSearch.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            yaraRuleSearch.value = '';
            refreshYaraForgeOptgroup('');
            yaraRuleSearch.blur();
        }
    });
}

if (btnYaraFetchForge && typeof JSZip !== 'undefined') {
    btnYaraFetchForge.addEventListener('click', async () => {
        if (!yaraStatus) return;
        btnYaraFetchForge.disabled = true;
        yaraStatus.textContent = 'Fetching YARA-Forge rules...';
        try {
            const res = await fetch(YARA_FORGE_ZIP_URL);
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const buf = await res.arrayBuffer();
            const zip = await JSZip.loadAsync(buf);
            const entries = Object.entries(zip.files).filter(([, file]) => !file.dir);
            if (entries.length === 0) {
                yaraStatus.textContent = 'No files found in the archive.';
                return;
            }
            const contents = await Promise.all(entries.map(([, file]) => file.async('text')));
            const combined = contents.join('\n\n');
            const rules = parseYaraRulesFromSource(combined);
            if (rules.length === 0) {
                yaraStatus.textContent = 'No YARA rules found in the archive.';
                return;
            }
            _yaraForgeRules = rules;
            refreshYaraForgeOptgroup(yaraRuleSearch ? yaraRuleSearch.value.trim() : '');
            yaraStatus.textContent = `Loaded ${rules.length} rule(s) into Example Rules. Select a rule to load.`;
        } catch (e) {
            yaraStatus.textContent = `Failed to load YARA-Forge: ${e.message || String(e)}`;
        } finally {
            btnYaraFetchForge.disabled = false;
        }
    });
} else if (btnYaraFetchForge) {
    btnYaraFetchForge.title = 'Fetch YARA-Forge rules (requires JSZip)';
}

// YARA editor: Tab key and syntax highlight sync
if (yaraEditor) {
    yaraEditor.addEventListener('keydown', (e) => {
        if (e.key === 'Tab') {
            e.preventDefault();
            const start = yaraEditor.selectionStart;
            const end = yaraEditor.selectionEnd;
            yaraEditor.value = yaraEditor.value.substring(0, start) + '    ' + yaraEditor.value.substring(end);
            yaraEditor.selectionStart = yaraEditor.selectionEnd = start + 4;
        }
    });
    yaraEditor.addEventListener('input', () => refreshYaraHighlight());
    yaraEditor.addEventListener('scroll', () => {
        if (yaraHighlightLayer) {
            yaraHighlightLayer.scrollTop = yaraEditor.scrollTop;
            yaraHighlightLayer.scrollLeft = yaraEditor.scrollLeft;
        }
    });
}

// Refresh YARA highlight when YARA tab is shown
document.querySelectorAll('.tab-btn[data-tab="yara-tab"]').forEach(btn => {
    btn.addEventListener('click', () => {
        setTimeout(refreshYaraHighlight, 0);
    });
});

// ── Assembly tab (educational: write ASM, assemble, run as shellcode) ───────

const asmEditor = document.getElementById('asm-editor');
const asmHighlightLayer = document.getElementById('asm-highlight-layer');
const asmListing = document.getElementById('asm-listing');
const asmHexOutput = document.getElementById('asm-hex-output');
const asmStatus = document.getElementById('asm-status');
const btnAsmAssemble = document.getElementById('btn-asm-assemble');
const btnAsmRun = document.getElementById('btn-asm-run');
const btnAsmClear = document.getElementById('btn-asm-clear');
const asmExampleSelect = document.getElementById('asm-example-select');

/** x86-64 register index: rax=0, rcx=1, rdx=2, rbx=3, rsp=4, rbp=5, rsi=6, rdi=7, r8..r15=8..15 */
const ASM_REG64 = { rax: 0, rcx: 1, rdx: 2, rbx: 3, rsp: 4, rbp: 5, rsi: 6, rdi: 7, r8: 8, r9: 9, r10: 10, r11: 11, r12: 12, r13: 13, r14: 14, r15: 15 };
const ASM_REG32 = { eax: 0, ecx: 1, edx: 2, ebx: 3, esp: 4, ebp: 5, esi: 6, edi: 7, r8d: 8, r9d: 9, r10d: 10, r11d: 11, r12d: 12, r13d: 13, r14d: 14, r15d: 15 };

function writeU8(arr, offset, val) { arr[offset] = val & 0xff; }
function writeU32LE(arr, offset, val) {
    arr[offset] = val & 0xff;
    arr[offset + 1] = (val >> 8) & 0xff;
    arr[offset + 2] = (val >> 16) & 0xff;
    arr[offset + 3] = (val >> 24) & 0xff;
}
function writeU64LE(arr, offset, val) {
    writeU32LE(arr, offset, val >>> 0);
    writeU32LE(arr, offset + 4, Math.floor(val / 0x100000000));
}

/**
 * Minimal x86-64 assembler (Intel syntax, educational subset).
 * Returns { bytes: Uint8Array, listing: string[], error: string|null }.
 */
function assembleX64(source) {
    const lines = source.split(/\r?\n/);
    const bytes = [];
    const listing = [];
    let addr = 0;

    function emit(...b) {
        const start = addr;
        for (const x of b) bytes.push(x & 0xff);
        addr += b.length;
        return start;
    }

    function parseImm(s) {
        s = s.trim();
        if (/^0x[0-9a-fA-F]+$/.test(s)) return parseInt(s.slice(2), 16);
        if (/^[0-9]+$/.test(s)) return parseInt(s, 10);
        if (/^-?[0-9]+$/.test(s)) return parseInt(s, 10) >>> 0;
        return null;
    }

    for (let i = 0; i < lines.length; i++) {
        const raw = lines[i];
        const commentIdx = raw.indexOf(';');
        const line = (commentIdx >= 0 ? raw.slice(0, commentIdx) : raw).trim();
        if (!line) {
            listing.push({ addr: null, bytes: '', source: raw || ' ' });
            continue;
        }

        const parts = line.split(/\s+/).filter(Boolean);
        const mnem = (parts[0] || '').toLowerCase();
        const rest = parts.slice(1).join(' ');
        const startAddr = addr;

        try {
            if (mnem === 'nop') {
                emit(0x90);
                listing.push({ addr: startAddr, bytes: '90', source: raw });
                continue;
            }
            if (mnem === 'ret') {
                emit(0xc3);
                listing.push({ addr: startAddr, bytes: 'C3', source: raw });
                continue;
            }
            if (mnem === 'syscall') {
                emit(0x0f, 0x05);
                listing.push({ addr: startAddr, bytes: '0F 05', source: raw });
                continue;
            }

            if (mnem === 'int') {
                const imm = parseImm(rest);
                if (imm === null || imm < 0 || imm > 255) throw new Error('int requires 8-bit immediate');
                emit(0xcd, imm);
                listing.push({ addr: startAddr, bytes: `CD ${imm.toString(16).toUpperCase().padStart(2, '0')}`, source: raw });
                continue;
            }

            if (mnem === 'mov') {
                const comma = rest.indexOf(',');
                if (comma < 0) throw new Error('mov requires two operands');
                const dst = rest.slice(0, comma).trim().toLowerCase();
                const src = rest.slice(comma + 1).trim();
                const imm = parseImm(src);

                if (ASM_REG64[dst] !== undefined && imm !== null) {
                    const rd = ASM_REG64[dst];
                    if (rd < 8) {
                        emit(0x48, 0xb8 + rd);
                        const n = bytes.length;
                        bytes.length += 8;
                        writeU64LE(bytes, n, imm >= 0 ? imm : (imm >>> 0));
                        addr = bytes.length;
                        const hex = Array.from(bytes.slice(startAddr, addr)).map(b => b.toString(16).toUpperCase().padStart(2, '0')).join(' ');
                        listing.push({ addr: startAddr, bytes: hex, source: raw });
                    } else {
                        emit(0x49, 0xb8 + (rd - 8));
                        const n = bytes.length;
                        bytes.length += 8;
                        writeU64LE(bytes, n, imm >= 0 ? imm : (imm >>> 0));
                        addr = bytes.length;
                        const hex = Array.from(bytes.slice(startAddr, addr)).map(b => b.toString(16).toUpperCase().padStart(2, '0')).join(' ');
                        listing.push({ addr: startAddr, bytes: hex, source: raw });
                    }
                    continue;
                }
                if (ASM_REG32[dst] !== undefined && imm !== null) {
                    const rd = ASM_REG32[dst];
                    if (rd < 8) {
                        emit(0xb8 + rd);
                        const n = bytes.length;
                        bytes.length += 4;
                        writeU32LE(bytes, n, imm >>> 0);
                        addr = bytes.length;
                        const hex = Array.from(bytes.slice(startAddr, addr)).map(b => b.toString(16).toUpperCase().padStart(2, '0')).join(' ');
                        listing.push({ addr: startAddr, bytes: hex, source: raw });
                    } else {
                        emit(0x41, 0xb8 + (rd - 8));
                        const n = bytes.length;
                        bytes.length += 4;
                        writeU32LE(bytes, n, imm >>> 0);
                        addr = bytes.length;
                        const hex = Array.from(bytes.slice(startAddr, addr)).map(b => b.toString(16).toUpperCase().padStart(2, '0')).join(' ');
                        listing.push({ addr: startAddr, bytes: hex, source: raw });
                    }
                    continue;
                }
                throw new Error(`mov: unsupported operands "${dst}", "${src}"`);
            }

            if (mnem === 'xor') {
                const comma = rest.indexOf(',');
                if (comma < 0) throw new Error('xor requires two operands');
                const dst = rest.slice(0, comma).trim().toLowerCase();
                const src = rest.slice(comma + 1).trim().toLowerCase();
                if (ASM_REG32[dst] !== undefined && ASM_REG32[src] !== undefined && dst === src) {
                    const rd = ASM_REG32[dst];
                    if (rd < 8) {
                        emit(0x31, 0xc0 + rd * 9); // modrm: 11 dst src -> C0 + rd*9 for src=rd
                        listing.push({ addr: startAddr, bytes: (0x31).toString(16).toUpperCase() + ' ' + (0xc0 + rd * 9).toString(16).toUpperCase(), source: raw });
                    } else {
                        emit(0x41, 0x31, 0xc0 + (rd - 8) * 9);
                        listing.push({ addr: startAddr, bytes: '41 31 ' + (0xc0 + (rd - 8) * 9).toString(16).toUpperCase(), source: raw });
                    }
                    continue;
                }
                if (ASM_REG64[dst] !== undefined && ASM_REG64[src] !== undefined && dst === src) {
                    const rd = ASM_REG64[dst];
                    if (rd < 8) {
                        emit(0x48, 0x31, 0xc0 + rd * 9);
                        listing.push({ addr: startAddr, bytes: '48 31 ' + (0xc0 + rd * 9).toString(16).toUpperCase(), source: raw });
                    } else {
                        emit(0x49, 0x31, 0xc0 + (rd - 8) * 9);
                        listing.push({ addr: startAddr, bytes: '49 31 ' + (0xc0 + (rd - 8) * 9).toString(16).toUpperCase(), source: raw });
                    }
                    continue;
                }
                throw new Error(`xor: only same reg32/reg64 supported (e.g. xor eax, eax)`);
            }

            if (mnem === 'add') {
                const comma = rest.indexOf(',');
                if (comma < 0) throw new Error('add requires two operands');
                const dst = rest.slice(0, comma).trim().toLowerCase();
                const src = rest.slice(comma + 1).trim();
                const imm = parseImm(src);
                if (ASM_REG64[dst] !== undefined && imm !== null && imm >= 0 && imm <= 0xff) {
                    const rd = ASM_REG64[dst];
                    if (rd < 8) {
                        emit(0x48, 0x83, 0xc0 + rd, imm);
                        listing.push({ addr: startAddr, bytes: '48 83 ' + (0xc0 + rd).toString(16).toUpperCase() + ' ' + imm.toString(16).toUpperCase().padStart(2, '0'), source: raw });
                    } else {
                        emit(0x49, 0x83, 0xc0 + (rd - 8), imm);
                        listing.push({ addr: startAddr, bytes: '49 83 ' + (0xc0 + (rd - 8)).toString(16).toUpperCase() + ' ' + imm.toString(16).toUpperCase().padStart(2, '0'), source: raw });
                    }
                    continue;
                }
                throw new Error(`add: only add r64, imm8 supported`);
            }

            if (mnem === 'push') {
                const r = rest.trim().toLowerCase();
                if (ASM_REG64[r] !== undefined) {
                    const rd = ASM_REG64[r];
                    if (rd < 8) {
                        emit(0x50 + rd);
                        listing.push({ addr: startAddr, bytes: (0x50 + rd).toString(16).toUpperCase(), source: raw });
                    } else {
                        emit(0x41, 0x50 + (rd - 8));
                        listing.push({ addr: startAddr, bytes: '41 ' + (0x50 + (rd - 8)).toString(16).toUpperCase(), source: raw });
                    }
                    continue;
                }
                throw new Error(`push: unsupported operand`);
            }

            if (mnem === 'pop') {
                const r = rest.trim().toLowerCase();
                if (ASM_REG64[r] !== undefined) {
                    const rd = ASM_REG64[r];
                    if (rd < 8) {
                        emit(0x58 + rd);
                        listing.push({ addr: startAddr, bytes: (0x58 + rd).toString(16).toUpperCase(), source: raw });
                    } else {
                        emit(0x41, 0x58 + (rd - 8));
                        listing.push({ addr: startAddr, bytes: '41 ' + (0x58 + (rd - 8)).toString(16).toUpperCase(), source: raw });
                    }
                    continue;
                }
                throw new Error(`pop: unsupported operand`);
            }

            throw new Error(`Unknown instruction: ${mnem}`);
        } catch (err) {
            return { bytes: new Uint8Array(0), listing: [], error: `Line ${i + 1}: ${err.message}` };
        }
    }

    return { bytes: new Uint8Array(bytes), listing, error: null };
}

const ASM_EXAMPLES = {
    exit_linux: `; Linux exit(0) — syscall 60, arg1 = 0
mov rax, 60
xor edi, edi
syscall`,
    nop_sled: `; NOP sled then return (educational)
nop
nop
nop
ret`,
    add_numbers: `; Add 1 + 2, result in rax (then ret)
mov rax, 1
add rax, 2
ret`,
    hello_syscall: `; Linux exit(42) — syscall 60, arg1 = 42
mov rax, 60
mov edi, 42
syscall`
};

let lastAssembledBytes = null;

function runAsmAssemble() {
    if (!asmEditor) return;
    const source = asmEditor.value.trim();
    if (!source) {
        if (asmStatus) asmStatus.textContent = 'Enter assembly first';
        if (asmListing) asmListing.innerHTML = '<span class="muted">Enter x86-64 assembly (Intel syntax) and click Assemble.</span>';
        if (asmHexOutput) asmHexOutput.textContent = '—';
        lastAssembledBytes = null;
        return;
    }
    const result = assembleX64(source);
    lastAssembledBytes = result.bytes;

    if (result.error) {
        if (asmStatus) asmStatus.textContent = result.error;
        if (asmListing) asmListing.innerHTML = `<span class="asm-error">${escapeHtml(result.error)}</span>`;
        if (asmHexOutput) asmHexOutput.textContent = '—';
        return;
    }

    if (asmStatus) asmStatus.textContent = `${result.bytes.length} byte(s)`;
    let listHtml = '';
    for (const line of result.listing) {
        if (line.addr != null) {
            listHtml += `<span class="asm-addr">${line.addr.toString(16).toUpperCase().padStart(4, '0')}</span>  <span class="asm-bytes">${escapeHtml(line.bytes)}</span>  <span class="asm-source">${escapeHtml(line.source)}</span>\n`;
        } else {
            listHtml += '        ' + (line.bytes ? `<span class="asm-bytes">${escapeHtml(line.bytes)}</span>  ` : '') + `<span class="asm-source">${escapeHtml(line.source)}</span>\n`;
        }
    }
    if (asmListing) asmListing.innerHTML = listHtml || '<span class="muted">No instructions.</span>';
    if (asmHexOutput) {
        const hex = Array.from(result.bytes).map(b => b.toString(16).toUpperCase().padStart(2, '0')).join(' ');
        asmHexOutput.textContent = hex || '—';
    }
}

function runAsmAsShellcode() {
    if (!lastAssembledBytes || lastAssembledBytes.length === 0) {
        runAsmAssemble();
        if (!lastAssembledBytes || lastAssembledBytes.length === 0) {
            if (asmStatus) asmStatus.textContent = 'Assemble first (no bytes)';
            return;
        }
    }
    const bytes = new Uint8Array(lastAssembledBytes);
    createEmulator(bytes, { asShellcode: true, arch: 'x86_64' });
    if (asmStatus) asmStatus.textContent = 'Loaded as shellcode. Use Step or Run.';
}

if (btnAsmAssemble) btnAsmAssemble.addEventListener('click', runAsmAssemble);
if (btnAsmRun) btnAsmRun.addEventListener('click', runAsmAsShellcode);

if (btnAsmClear) {
    btnAsmClear.addEventListener('click', () => {
        if (asmEditor) asmEditor.value = '';
        if (asmHighlightLayer) asmHighlightLayer.textContent = '';
        if (asmListing) asmListing.innerHTML = '<span class="muted">Assemble to see address, bytes, and source.</span>';
        if (asmHexOutput) asmHexOutput.textContent = '—';
        if (asmStatus) asmStatus.textContent = '';
        lastAssembledBytes = null;
    });
}

if (asmExampleSelect) {
    asmExampleSelect.addEventListener('change', () => {
        const key = asmExampleSelect.value;
        if (key && ASM_EXAMPLES[key]) {
            asmEditor.value = ASM_EXAMPLES[key];
            refreshAsmHighlight();
            if (asmStatus) asmStatus.textContent = `Example: ${key}. Click Assemble then Run as shellcode.`;
        }
        asmExampleSelect.value = '';
    });
}

/** Simple ASM syntax highlight (comments + mnemonics) */
function highlightAsm(source) {
    if (!source) return '';
    const mnemonics = /\b(mov|xor|add|sub|push|pop|nop|ret|syscall|int)\b/gi;
    const lines = source.split('\n');
    const out = lines.map(line => {
        const i = line.indexOf(';');
        const code = i >= 0 ? line.slice(0, i) : line;
        const comment = i >= 0 ? line.slice(i) : '';
        let codeHtml = escapeHtml(code);
        codeHtml = codeHtml.replace(/\b(mov|xor|add|sub|push|pop|nop|ret|syscall|int)\b/gi, '<span class="asm-kw">$1</span>');
        codeHtml = codeHtml.replace(/\b(rax|rcx|rdx|rbx|rsp|rbp|rsi|rdi|r8|r9|r10|r11|r12|r13|r14|r15|eax|ecx|edx|ebx|esp|ebp|esi|edi|r8d|r9d|r10d|r11d|r12d|r13d|r14d|r15d)\b/gi, '<span class="asm-reg">$1</span>');
        const commentHtml = comment ? '<span class="asm-comment">' + escapeHtml(comment) + '</span>' : '';
        return codeHtml + commentHtml || ' ';
    });
    return out.join('\n');
}

function refreshAsmHighlight() {
    if (!asmHighlightLayer || !asmEditor) return;
    asmHighlightLayer.innerHTML = highlightAsm(asmEditor.value) || '\n';
    asmHighlightLayer.scrollTop = asmEditor.scrollTop;
    asmHighlightLayer.scrollLeft = asmEditor.scrollLeft;
}

if (asmEditor) {
    asmEditor.addEventListener('keydown', (e) => {
        if (e.key === 'Tab') {
            e.preventDefault();
            const start = asmEditor.selectionStart;
            const end = asmEditor.selectionEnd;
            asmEditor.value = asmEditor.value.substring(0, start) + '    ' + asmEditor.value.substring(end);
            asmEditor.selectionStart = asmEditor.selectionEnd = start + 4;
        }
    });
    asmEditor.addEventListener('input', () => refreshAsmHighlight());
    asmEditor.addEventListener('scroll', () => {
        if (asmHighlightLayer) {
            asmHighlightLayer.scrollTop = asmEditor.scrollTop;
            asmHighlightLayer.scrollLeft = asmEditor.scrollLeft;
        }
    });
}

document.querySelectorAll('.tab-btn[data-tab="asm-tab"]').forEach(btn => {
    btn.addEventListener('click', () => setTimeout(refreshAsmHighlight, 0));
});
