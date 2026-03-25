// ==================== 全局变量 ====================
let lweKeys = null;
let rsaKeyChart = null;
let lweGaussChart = null;

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
    alert('✅ RSA 密钥对生成成功！(2048 位)');
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
    document.getElementById('rsaDecryptOutput').value = decrypted || '❌ 解密失败 (密文错误或密钥不匹配)';
}

function rsaExportKeys() {
    const publicKey = localStorage.getItem('rsaPublicKey');
    const privateKey = localStorage.getItem('rsaPrivateKey');
    if (!publicKey || !privateKey) { alert('❌ 没有可导出的密钥！'); return; }
    const keys = { type: 'RSA', publicKey, privateKey, date: new Date().toISOString() };
    downloadJSON(keys, 'rsa_keys_' + new Date().toISOString().slice(0,10) + '.json');
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

function rsaClearKeys() {
    if (confirm('确定要清除 RSA 密钥吗？此操作不可恢复！')) {
        localStorage.removeItem('rsaPublicKey');
        localStorage.removeItem('rsaPrivateKey');
        document.getElementById('rsaPublicKey').value = '';
        document.getElementById('rsaPrivateKey').value = '';
        alert('🗑️ RSA 密钥已清除！');
    }
}

function saveRsaProcess() {
    const data = document.getElementById('rsaProcessRecord').value;
    localStorage.setItem('rsaProcessRecord', data);
    alert('✅ 实验记录已保存！');
}

function loadRsaProcess() {
    const data = localStorage.getItem('rsaProcessRecord') || '';
    document.getElementById('rsaProcessRecord').value = data;
    if (data) alert('📂 实验记录已加载！'); else alert('⚠️ 暂无保存的记录');
}

function clearRsaProcess() {
    if (confirm('确定要清空实验记录吗？')) {
        document.getElementById('rsaProcessRecord').value = '';
        localStorage.removeItem('rsaProcessRecord');
        alert('🗑️ 实验记录已清空！');
    }
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
    
    document.getElementById('lwePublicKey').value = `矩阵 A (${n}×${n}):\n${JSON.stringify(A)}\n\n向量 b:\n${JSON.stringify(b)}`;
    document.getElementById('lwePrivateKey').value = `秘密向量 s:\n${JSON.stringify(s)}`;
    
    document.getElementById('sigmaDisplay').textContent = sigma.toFixed(1);
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
    
    document.getElementById('lweEncryptOutput').value = JSON.stringify({ u, v }, null, 2);
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
        document.getElementById('lweDecryptOutput').value = `解密结果：${decrypted}\n\n计算过程:\nv - s^T·u = ${v} - ${su} = ${m} (mod ${q})\n阈值 q/4 = ${Math.floor(q/4)}\n${m > q/4 ? m + ' > ' + Math.floor(q/4) : m + ' ≤ ' + Math.floor(q/4)} → 输出 ${decrypted}`;
    } catch (e) {
        alert('❌ 密文格式错误！请使用 JSON 格式');
    }
}

function lweExportKeys() {
    if (!lweKeys) { alert('❌ 没有可导出的密钥！'); return; }
    const keys = { type: 'LWE', ...lweKeys, date: new Date().toISOString() };
    downloadJSON(keys, 'lwe_keys_' + new Date().toISOString().slice(0,10) + '.json');
}

function lweImportKeys() {
    importKeysFromFile((keys) => {
        if (keys.type !== 'LWE') { alert('❌ 不是 LWE 密钥文件！'); return; }
        lweKeys = keys;
        document.getElementById('lweN').value = keys.n;
        document.getElementById('lweQ').value = keys.q;
        document.getElementById('lweSigma').value = keys.sigma;
        document.getElementById('lwePublicKey').value = `矩阵 A:\n${JSON.stringify(keys.A)}\n\n向量 b:\n${JSON.stringify(keys.b)}`;
        document.getElementById('lwePrivateKey').value = `秘密向量 s:\n${JSON.stringify(keys.s)}`;
        document.getElementById('sigmaDisplay').textContent = keys.sigma.toFixed(1);
        updateLweGaussChart(keys.sigma);
        generateNoiseVisual();
        alert('✅ LWE 密钥导入成功！');
    });
}

function saveLweProcess() {
    const data = document.getElementById('lweProcessRecord').value;
    localStorage.setItem('lweProcessRecord', data);
    alert('✅ 实验记录已保存！');
}

function loadLweProcess() {
    const data = localStorage.getItem('lweProcessRecord') || '';
    document.getElementById('lweProcessRecord').value = data;
    if (data) alert('📂 实验记录已加载！'); else alert('⚠️ 暂无保存的记录');
}

function clearLweProcess() {
    if (confirm('确定要清空实验记录吗？')) {
        document.getElementById('lweProcessRecord').value = '';
        localStorage.removeItem('
