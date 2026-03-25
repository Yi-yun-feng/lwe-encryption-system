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
    
    const keys = { type: 'RSA', publicKey, privateKey };
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

// ==================== LWE 功能（模拟） ====================

let lweKeys = null;

// 高斯分布随机数
function gaussianRandom(mean = 0, stdev = 1) {
    const u = 1 - Math.random();
    const v = Math.random();
    const z = Math.sqrt(-2.0 * Math.log(u)) * Math.cos(2.0 * Math.PI * v);
    return Math.floor(z * stdev + mean);
}

// 生成随机矩阵
function randomMatrix(n, q) {
    const matrix = [];
    for (let i = 0; i < n; i++) {
        const row = [];
        for (let j = 0; j < n; j++) {
            row.push(Math.floor(Math.random() * q));
        }
        matrix.push(row);
    }
    return matrix;
}

// 生成随机向量
function randomVector(n, q) {
    const vec = [];
    for (let i = 0; i < n; i++) {
        vec.push(Math.floor(Math.random() * q));
    }
    return vec;
}

// 向量点积
function dotProduct(a, b, q) {
    let sum = 0;
    for (let i = 0; i < a.length; i++) {
        sum += a[i] * b[i];
    }
    return ((sum % q) + q) % q;
}

// 向量加法
function vectorAdd(a, b, q) {
    const result = [];
    for (let i = 0; i < a.length; i++) {
        result.push(((a[i] + b[i]) % q + q) % q);
    }
    return result;
}

function lweGenerateKeys() {
    const n = parseInt(document.getElementById('lweN').value) || 10;
    const q = parseInt(document.getElementById('lweQ').value) || 97;
    const sigma = parseFloat(document.getElementById('lweSigma').value) || 2.5;
    
    // 生成矩阵 A
    const A = randomMatrix(n, q);
    
    // 生成秘密向量 s
    const s = randomVector(n, q);
    
    // 生成噪声向量 e（高斯分布）
    const e = [];
    for (let i = 0; i < n; i++) {
        e.push(gaussianRandom(0, sigma));
    }
    
    // 计算 b = A·s + e
    const b = [];
    for (let i = 0; i < n; i++) {
        let sum = 0;
        for (let j = 0; j < n; j++) {
            sum += A[i][j] * s[j];
        }
        b.push(((sum + e[i]) % q + q) % q);
    }
    
    lweKeys = { n, q, sigma, A, s, b, e };
    
    document.getElementById('lwePublicKey').value = `A: ${JSON.stringify(A)}\nb: ${JSON.stringify(b)}`;
    document.getElementById('lwePrivateKey').value = `s: ${JSON.stringify(s)}`;
    
    alert('✅ LWE 密钥对生成成功！');
    generateNoiseVisual();
}

function lweEncrypt() {
    if (!lweKeys) { alert('❌ 请先生成密钥对！'); return; }
    
    const input = document.getElementById('lweEncryptInput').value.trim();
    if (!input) { alert('❌ 请输入明文 (0 或 1)！'); return; }
    
    const m = parseInt(input) === 1 ? Math.floor(lweKeys.q / 2) : 0;
    const { n, q, A, b } = lweKeys;
    
    // 生成随机向量 r
    const r = randomVector(n, 2);
    
    // u = A^T · r
    const u = [];
    for (let j = 0; j < n; j++) {
        let sum = 0;
        for (let i = 0; i < n; i++) {
            sum += A[i][j] * r[i];
        }
        u.push(sum % q);
    }
    
    // v = b^T · r + m
    let v = 0;
    for (let i = 0; i < n; i++) {
        v += b[i] * r[i];
    }
    v = ((v + m) % q + q) % q;
    
    const ciphertext = { u, v };
    document.getElementById('lweEncryptOutput').value = JSON.stringify(ciphertext);
}

function lweDecrypt() {
    if (!lweKeys) { alert('❌ 请先生成密钥对！'); return; }
    
    const input = document.getElementById('lweDecryptInput').value.trim();
    if (!input) { alert('❌ 请输入密文！'); return; }
    
    try {
        const ciphertext = JSON.parse(input);
        const { u, v } = ciphertext;
        const { s, q } = lweKeys;
        
        // m = v - s^T · u
        let su = 0;
        for (let i = 0; i < s.length; i++) {
            su += s[i] * u[i];
        }
        let m = ((v - su) % q + q) % q;
        
        // 判断是 0 还是 1
        const decrypted = m > q / 4 ? 1 : 0;
        document.getElementById('lweDecryptOutput').value = `解密结果: ${decrypted}\n(原始值: ${m})`;
    } catch (e) {
        alert('❌ 密文格式错误！');
    }
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
            } catch (err) {
                alert('❌ 文件读取失败！');
            }
        };
        reader.readAsText(file);
    };
    input.click();
}

function toggleSidebar() {
    document.getElementById('sidebar').classList.toggle('active');
}

// ==================== 可视化 ====================

let gaussChart = null;

function initGaussChart() {
    const ctx = document.getElementById('gaussChart').getContext('2d');
    
    // 生成高斯分布数据
    const data = [];
    const labels = [];
    for (let x = -5; x <= 5; x += 0.5) {
        labels.push(x.toFixed(1));
        const y = (1 / Math.sqrt(2 * Math.PI)) * Math.exp(-0.5 * x * x);
        data.push(y.toFixed(4));
    }
    
    gaussChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [{
                label: '标准高斯分布',
                data: data,
                borderColor: '#667eea',
                backgroundColor: 'rgba(102, 126, 234, 0.2)',
                fill: true,
                tension: 0.4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: true }
            },
            scales: {
                x: { title: { display: true, text: 'x' } },
                y: { title: { display: true, text: '概率密度' } }
            }
        }
    });
}

function generateNoiseVisual() {
    const container = document.getElementById('noiseVisual');
    container.innerHTML = '';
    
    const sigma = parseFloat(document.getElementById('lweSigma').value) || 2.5;
    
    for (let i = 0; i < 50; i++) {
        const bar = document.createElement('div');
        bar.className = 'noise-bar';
        const height = Math.abs(gaussianRandom(0, sigma)) * 5 + 5;
        bar.style.height = `${Math.min(height, 50)}px`;
        container.appendChild(bar);
    }
}

// ==================== 初始化 ====================

window.onload = function() {
    // 恢复 RSA 密钥
    const rsaPublicKey = localStorage.getItem('rsaPublicKey');
    const rsaPrivateKey = localStorage.getItem('rsaPrivateKey');
    if (rsaPublicKey) document.getElementById('rsaPublicKey').value = rsaPublicKey;
    if (rsaPrivateKey) document.getElementById('rsaPrivateKey').value = rsaPrivateKey;
    
    // 初始化图表
    initGaussChart();
    
    // 生成噪声可视化
    generateNoiseVisual();
};
