// ==================== 全局变量 ====================
let lweKeys = null;
let rsaKeyChart = null;
let lweGaussChart = null;

// ==================== 导航菜单 ====================
function toggleSidebar() {
    document.getElementById('sidebar').classList.toggle('active');
    document.getElementById('overlay').classList.toggle('active');
}

// ==================== RSA 功能 ====================
function rsaGenerateKeys() {
    const encryptor = new JSEncrypt({default_key_size: 2048});
    encryptor.generateKey();
    const publicKey = encryptor.getPublicKey();
    const privateKey = encryptor.getPrivateKey();
    localStorage.setItem('rsaPublicKey', publicKey);
    localStorage.setItem('rsaPrivateKey', privateKey);
    document.getElementById('rsaPublicKey').value = publicKey;
    document.getElementById('rsaPrivateKey').value = privateKey;
    updateRsaKeyChart();
    alert('✅ RSA 密钥对生成成功！');
}

function rsaEncrypt() {
    const input = document.getElementById('rsaEncryptInput').value;
    const publicKey = localStorage.getItem('rsaPublicKey');
    if (!publicKey) { alert('❌ 请先生成密钥对！'); return; }
    if (!input.trim()) { alert('❌ 请输入明文！'); return; }
    const encryptor = new JSEncrypt();
    encryptor.setPublicKey(publicKey);
    const encrypted = encryptor.encrypt(input);
    document.getElementById('rsaEncryptOutput').value = encrypted || '加密失败';
}

function rsaDecrypt() {
    const input = document.getElementById('rsaDecryptInput').value;
    const privateKey = localStorage.getItem('rsaPrivateKey');
    if (!privateKey) { alert('❌ 请先生成密钥对！'); return; }
    if (!input.trim()) { alert('❌ 请输入密文！'); return; }
    const encryptor = new JSEncrypt();
    encryptor.setPrivateKey(privateKey);
    const decrypted = encryptor.decrypt(input);
    document.getElementById('rsaDecryptOutput').value = decrypted || '❌ 解密失败';
}

function rsaExportKeys() {
    const publicKey = localStorage.getItem('rsaPublicKey');
    const privateKey = localStorage.getItem('rsaPrivateKey');
    if (!publicKey || !privateKey) { alert('❌ 没有可导出的密钥！'); return; }
    const keys = { type: 'RSA', publicKey, privateKey, date: new Date().toISOString() };
    downloadJSON(keys, 'rsa_keys.json');
}

function rsaImportKeys() {
    importKeysFromFile((keys) => {
        if (keys.type !== 'RSA') { alert('❌ 不是 RSA 密钥文件！'); return; }
        localStorage.setItem('rsaPublicKey', keys.publicKey);
        localStorage.setItem('rsaPrivateKey', keys.privateKey);
        document.getElementById('rsaPublicKey').value = keys.publicKey;
        document.getElementById('rsaPrivateKey').value = keys.privateKey;
        updateRsaKeyChart();
        alert('✅ RSA 密钥导入成功！');
    });
}

// RSA 过程记录
function saveRsaProcess() {
    const data = document.getElementById('rsaProcessRecord').value;
    localStorage.setItem('rsaProcessRecord', data);
    alert('✅ 已保存！');
}
function loadRsaProcess() {
    const data = localStorage.getItem('rsaProcessRecord') || '';
    document.getElementById('rsaProcessRecord').value = data;
    alert('📂 已加载！');
}
function clearRsaProcess() {
    document.getElementById('rsaProcessRecord').value = '';
    localStorage.removeItem('rsaProcessRecord');
    alert('🗑️ 已清空！');
}

// ==================== LWE 功能 ====================
function gaussianRandom(mean = 0, stdev = 1) {
    const u = 1 - Math.random();
    const v = Math.random();
    const z = Math.sqrt(-2.0 * Math.log(u)) * Math.cos(2.0 * Math.PI * v);
    return Math.round(z * stdev + mean);
}

function randomMatrix(n, q) {
    const matrix = [];
    for (let i = 0; i < n; i++) {
        const row = [];
        for (let j = 0; j < n; j++) { row.push(Math.floor(Math.random() * q)); }
        matrix.push(row);
    }
    return matrix;
}

function randomVector(n, q) {
    const vec = [];
    for (let i = 0; i < n; i++) { vec.push(Math.floor(Math.random() * q)); }
    return vec;
}

function lweGenerateKeys() {
    const n = parseInt(document.getElementById('lweN').value) || 8;
    const q = parseInt(document.getElementById('lweQ').value) || 97;
    const sigma = parseFloat(document.getElementById('lweSigma').value) || 2.0;
    const A = randomMatrix(n, q);
    const s = randomVector(n, q);
    const e = [];
    for (let i = 0; i < n; i++) { e.push(gaussianRandom(0, sigma)); }
    const b = [];
    for (let i = 0; i < n; i++) {
        let sum = 0;
        for (let j = 0; j < n; j++) { sum += A[i][j] * s[j]; }
        b.push(((sum + e[i]) % q + q) % q);
    }
    lweKeys = { n, q, sigma, A, s, b, e };
    document.getElementById('lwePublicKey').value = `A: ${JSON.stringify(A)}\n\nb: ${JSON.stringify(b)}`;
    document.getElementById('lwePrivateKey').value = `s: ${JSON.stringify(s)}`;
    updateLweGaussChart(sigma);
    generateNoiseVisual();
    alert('✅ LWE 密钥对生成成功！');
}

function lweEncrypt() {
    if (!lweKeys) { alert('❌ 请先生成密钥对！'); return; }
    const input = document.getElementById('lweEncryptInput').value.trim();
    if (input !== '0' && input !== '1') { alert('❌ 明文只能输入 0 或 1！'); return; }
    const m = parseInt(input) === 1 ? Math.floor(lweKeys.q / 2) : 0;
    const { n, q, A, b } = lweKeys;
    const r = [];
    for (let i = 0; i < n; i++) { r.push(Math.floor(Math.random() * 2)); }
    const u = [];
    for (let j = 0; j < n; j++) {
        let sum = 0;
        for (let i = 0; i < n; i++) { sum += A[i][j] * r[i]; }
        u.push(sum % q);
    }
    let v = 0;
    for (let i = 0; i < n; i++) { v += b[i] * r[i]; }
    v = ((v + m) % q + q) % q;
    document.getElementById('lweEncryptOutput').value = JSON.stringify({ u, v });
}

function lweDecrypt() {
    if (!lweKeys) { alert('❌ 请先生成密钥对！'); return; }
    const input = document.getElementById('lweDecryptInput').value.trim();
    if (!input) { alert('❌ 请输入密文！'); return; }
    try {
        const ciphertext = JSON.parse(input);
        const { u, v } = ciphertext;
        const { s, q } = lweKeys;
        let su = 0;
        for (let i = 0; i < s.length; i++) { su += s[i] * u[i]; }
        let m = ((v - su) % q + q) % q;
        const decrypted = m > q / 4 ? 1 : 0;
        document.getElementById('lweDecryptOutput').value = `解密结果：${decrypted}\n(计算值：${m})`;
    } catch (e) {
        alert('❌ 密文格式错误！');
    }
}

function lweExportKeys() {
    if (!lweKeys) { alert('❌ 没有可导出的密钥！'); return; }
    const keys = { type: 'LWE', ...lweKeys, date: new Date().toISOString() };
    downloadJSON(keys, 'lwe_keys.json');
}

function lweImportKeys() {
    importKeysFromFile((keys) => {
        if (keys.type !== 'LWE') { alert('❌ 不是 LWE 密钥文件！'); return; }
        lweKeys = keys;
        document.getElementById('lweN').value = keys.n;
        document.getElementById('lweQ').value = keys.q;
        document.getElementById('lweSigma').value = keys.sigma;
        document.getElementById('lwePublicKey').value = `A: ${JSON.stringify(keys.A)}\n\nb: ${JSON.stringify(keys.b)}`;
        document.getElementById('lwePrivateKey').value = `s: ${JSON.stringify(keys.s)}`;
        updateLweGaussChart(keys.sigma);
        generateNoiseVisual();
        alert('✅ LWE 密钥导入成功！');
    });
}

// LWE 过程记录
function saveLweProcess() {
    const data = document.getElementById('lweProcessRecord').value;
    localStorage.setItem('lweProcessRecord', data);
    alert('✅ 已保存！');
}
function loadLweProcess() {
    const data = localStorage.getItem('lweProcessRecord') || '';
    document.getElementById('lweProcessRecord').value = data;
    alert('📂 已加载！');
}
function clearLweProcess() {
    document.getElementById('lweProcessRecord').value = '';
    localStorage.removeItem('lweProcessRecord');
    alert('🗑️ 已清空！');
}

// ==================== 工具函数 ====================
function downloadJSON(data, filename) {
    const blob = new Blob([JSON.stringify(data, null, 2)], {type: 'application/json'});
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
}

function importKeysFromFile(callback) {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.json';
    input.onchange = e => {
        const file = e.target.files[0];
        if (!file) return;
        const reader = new FileReader();
        reader.onload = event => {
            try {
                const keys = JSON.parse(event.target.result);
                callback(keys);
            } catch (err) { alert('❌ 文件读取失败！'); }
        };
        reader.readAsText(file);
    };
    input.click();
}

// ==================== 可视化 ====================
function updateRsaKeyChart() {
    const ctx = document.getElementById('rsaKeyChart').getContext('2d');
    if (rsaKeyChart) rsaKeyChart.destroy();
    rsaKeyChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: ['1024 位', '2048 位', '3072 位', '4096 位'],
            datasets: [{
                label: '安全等级 (年)',
                data: [2028, 2030, 2040, 2050],
                backgroundColor: ['#f44336', '#ff9800', '#ffc107', '#00c853']
            }]
        },
        options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } } }
    });
}

function updateLweGaussChart(sigma) {
    const ctx = document.getElementById('lweGaussChart').getContext('2d');
    if (lweGaussChart) lweGaussChart.destroy();
    const data = [], labels = [];
    for (let x = -5; x <= 5; x += 0.5) {
        labels.push(x.toFixed(1));
        const y = (1 / Math.sqrt(2 * Math.PI * sigma * sigma)) * Math.exp(-0.5 * x * x / (sigma * sigma));
        data.push(y.toFixed(4));
    }
    lweGaussChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [{
                label: `高斯分布 (σ=${sigma})`,
                data: data,
                borderColor: '#ff6b6b',
                backgroundColor: 'rgba(255, 107, 107, 0.2)',
                fill: true,
                tension: 0.4
            }]
        },
        options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: true } } }
    });
}

function generateNoiseVisual() {
    const container = document.getElementById('noiseVisual');
    container.innerHTML = '';
    const sigma = parseFloat(document.getElementById('lweSigma').value) || 2.0;
    for (let i = 0; i < 50; i++) {
        const bar = document.createElement('div');
        bar.className = 'noise-bar';
        const height = Math.abs(gaussianRandom(0, sigma)) * 5 + 5;
        bar.style.height = `${Math.min(height, 45)}px`;
        container.appendChild(bar);
    }
}

// ==================== 初始化 ====================
window.onload = function() {
    const rsaPublicKey = localStorage.getItem('rsaPublicKey');
    const rsaPrivateKey = localStorage.getItem('rsaPrivateKey');
    if (rsaPublicKey) document.getElementById('rsaPublicKey').value = rsaPublicKey;
    if (rsaPrivateKey) document.getElementById('rsaPrivateKey').value = rsaPrivateKey;
    updateRsaKeyChart();
    updateLweGaussChart(2.0);
    generateNoiseVisual();
};
