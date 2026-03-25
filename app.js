// ==================== 导航 ====================
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
    const encryptor = new JSEncrypt();
    encryptor.setPublicKey(publicKey);
    document.getElementById('rsaEncryptOutput').value = encryptor.encrypt(input) || '加密失败';
}

function rsaDecrypt() {
    const input = document.getElementById('rsaDecryptInput').value;
    const privateKey = localStorage.getItem('rsaPrivateKey');
    if (!privateKey) { alert('❌ 请先生成密钥对！'); return; }
    const encryptor = new JSEncrypt();
    encryptor.setPrivateKey(privateKey);
    document.getElementById('rsaDecryptOutput').value = encryptor.decrypt(input) || '解密失败';
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
        alert('✅ RSA 密钥导入成功！');
    });
}

function saveRsaProcess() {
    localStorage.setItem('rsaProcessRecord', document.getElementById('rsaProcessRecord').value);
    alert('✅ 已保存！');
}
function loadRsaProcess() {
    document.getElementById('rsaProcessRecord').value = localStorage.getItem('rsaProcessRecord') || '';
    alert('📂 已加载！');
}
function clearRsaProcess() {
    document.getElementById('rsaProcessRecord').value = '';
    localStorage.removeItem('rsaProcessRecord');
    alert('🗑️ 已清空！');
}

// ==================== LWE-RABE 功能 ====================
let lweKeys = null;

function gaussianRandom(mean = 0, stdev = 1) {
    const u = 1 - Math.random();
    const v = Math.random();
    return Math.round(Math.sqrt(-2.0 * Math.log(u)) * Math.cos(2.0 * Math.PI * v) * stdev + mean);
}

function lweSetup() {
    const n = parseInt(document.getElementById('lweN').value) || 8;
    const q = parseInt(document.getElementById('lweQ').value) || 97;
    const sigma = parseFloat(document.getElementById('lweSigma').value) || 2.0;
    
    const A = [], s = [];
    for (let i = 0; i < n; i++) {
        A[i] = [];
        for (let j = 0; j < n; j++) { A[i][j] = Math.floor(Math.random() * q); }
        s[i] = Math.floor(Math.random() * q);
    }
    
    lweKeys = { n, q, sigma, A, s };
    document.getElementById('lweMpk').value = `矩阵 A:\n${JSON.stringify(A)}`;
    document.getElementById('lweUserKey').value = `秘密向量 s:\n${JSON.stringify(s)}`;
    
    updateLweGaussChart(sigma);
    generateNoiseVisual();
    alert('✅ 系统初始化成功！');
}

function lweKeyGen() {
    if (!lweKeys) { alert('❌ 请先系统初始化！'); return; }
    alert('✅ 用户密钥生成成功！（模拟）');
}

function lweEncrypt() {
    if (!lweKeys) { alert('❌ 请先系统初始化！'); return; }
    const input = document.getElementById('lweEncryptInput').value.trim();
    if (input !== '0' && input !== '1') { alert('❌ 明文只能输入 0 或 1！'); return; }
    
    const m = parseInt(input) === 1 ? Math.floor(lweKeys.q / 2) : 0;
    const { n, q, A } = lweKeys;
    const r = [], u = [];
    for (let i = 0; i < n; i++) { r[i] = Math.floor(Math.random() * 2); }
    for (let j = 0; j < n; j++) {
        let sum = 0;
        for (let i = 0; i < n; i++) { sum += A[i][j] * r[i]; }
        u[j] = sum % q;
    }
    
    document.getElementById('lweEncryptOutput').value = JSON.stringify({ u, v: (m + Math.floor(Math.random() * 10)) % q });
}

function lweDecrypt() {
    if (!lweKeys) { alert('❌ 请先系统初始化！'); return; }
    const input = document.getElementById('lweDecryptInput').value.trim();
    if (!input) { alert('❌ 请输入密文！'); return; }
    try {
        const ciphertext = JSON.parse(input);
        const decrypted = ciphertext.v > lweKeys.q / 4 ? 1 : 0;
        document.getElementById('lweDecryptOutput').value = `解密结果：${decrypted}`;
    } catch (e) { alert('❌ 密文格式错误！'); }
}

function saveLweProcess() {
    localStorage.setItem('lweProcessRecord', document.getElementById('lweProcessRecord').value);
    alert('✅ 已保存！');
}
function loadLweProcess() {
    document.getElementById('lweProcessRecord').value = localStorage.getItem('lweProcessRecord') || '';
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
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    a.click();
}

function importKeysFromFile(callback) {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.json';
    input.onchange = e => {
        const reader = new FileReader();
        reader.onload = event => {
            try { callback(JSON.parse(event.target.result)); } 
            catch (err) { alert('❌ 文件读取失败！'); }
        };
        reader.readAsText(e.target.files[0]);
    };
    input.click();
}

// ==================== 可视化 ====================
let rsaKeyChart = null, lweGaussChart = null;

function updateRsaKeyChart() {
    const ctx = document.getElementById('rsaKeyChart');
    if (!ctx) return;
    if (rsaKeyChart) rsaKeyChart.destroy();
    rsaKeyChart = new Chart(ctx.getContext('2d'), {
        type: 'bar',
        data: {
            labels: ['1024 位', '2048 位', '3072 位', '4096 位'],
            datasets: [{ label: '安全年限', data: [2028, 2035, 2045, 2055], backgroundColor: ['#f44336', '#ff9800', '#ffc107', '#00c853'] }]
        },
        options: { responsive: true, maintainAspectRatio: false }
    });
}

function updateLweGaussChart(sigma) {
    const ctx = document.getElementById('lweGaussChart');
    if (!ctx) return;
    if (lweGaussChart) lweGaussChart.destroy();
    const data = [], labels = [];
    for (let x = -5; x <= 5; x += 0.5) {
        labels.push(x.toFixed(1));
        data.push((1 / Math.sqrt(2 * Math.PI * sigma * sigma)) * Math.exp(-0.5 * x * x / (sigma * sigma)));
    }
    lweGaussChart = new Chart(ctx.getContext('2d'), {
        type: 'line',
        data: { labels, datasets: [{ label: `σ=${sigma}`, data, borderColor: '#ff6b6b', fill: true, backgroundColor: 'rgba(255,107,107,0.2)' }] },
        options: { responsive: true, maintainAspectRatio: false }
    });
}

function generateNoiseVisual() {
    const container = document.getElementById('noiseVisual');
    if (!container) return;
    container.innerHTML = '';
    const sigma = parseFloat(document.getElementById('lweSigma').value) || 2.0;
    for (let i = 0; i < 50; i++) {
        const bar = document.createElement('div');
        bar.className = 'noise-bar';
        bar.style.height = `${Math.min(Math.abs(gaussianRandom(0, sigma)) * 4 + 3, 45)}px`;
        container.appendChild(bar);
    }
}

// ==================== 初始化 ====================
window.onload = function() {
    updateRsaKeyChart();
    updateLweGaussChart(2.0);
    generateNoiseVisual();
};
