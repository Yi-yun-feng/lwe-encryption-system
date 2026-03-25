// ==================== 全局变量 ====================
let lweKeys = null;
let gaussChart = null;

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
    downloadJSON(keys, 'rsa_keys_' + new Date().toISOString().slice(0,10) + '.json');
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

function rsaClearKeys() {
    if (confirm('确定要清除 RSA 密钥吗？')) {
        localStorage.removeItem('rsaPublicKey');
        localStorage.removeItem('rsaPrivateKey');
        document.getElementById('rsaPublicKey').value = '';
        document.getElementById('rsaPrivateKey').value = '';
        alert('🗑️ RSA 密钥已清除！');
    }
}

// ==================== RSA 过程记录 ====================

function saveRsaProcess() {
    const data = {
        keyGen: document.getElementById('rsaProcessKeyGen').value,
        encrypt: document.getElementById('rsaProcessEncrypt').value,
        decrypt: document.getElementById('rsaProcessDecrypt').value
    };
    localStorage.setItem('rsaProcess', JSON.stringify(data));
    alert('✅ RSA 过程记录已保存！');
}

function loadRsaProcess() {
    const data = JSON.parse(localStorage.getItem('rsaProcess') || '{}');
    if (data.keyGen) document.getElementById('rsaProcessKeyGen').value = data.keyGen;
    if (data.encrypt) document.getElementById('rsaProcessEncrypt').value = data.encrypt;
    if (data.decrypt) document.getElementById('rsaProcessDecrypt').value = data.decrypt;
    alert('📂 RSA 过程记录已加载！');
}

function clearRsaProcess() {
    if (confirm('确定要清空 RSA 过程记录吗？')) {
        document.getElementById('rsaProcessKeyGen').value = '';
        document.getElementById('rsaProcessEncrypt').value = '';
        document.getElementById('rsaProcessDecrypt').value = '';
        localStorage.removeItem('rsaProcess');
        alert('🗑️ RSA 过程记录已清空！');
    }
}

// ==================== LWE 功能（模拟） ====================

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
        for (let j = 0; j < n; j++) {
            row.push(Math.floor(Math.random() * q));
        }
        matrix.push(row);
    }
    return matrix;
}

function randomVector(n, q) {
    const vec = [];
    for (let i = 0; i < n; i++) {
        vec.push(Math.floor(Math.random() * q));
    }
    return vec;
}

function lweGenerateKeys() {
    const n = parseInt(document.getElementById('lweN').value) || 8;
    const q = parseInt(document.getElementById('lweQ').value) || 97;
    const sigma = parseFloat(document.getElementById('lweSigma').value) || 2.0;
    
    const A = randomMatrix(n, q);
    const s = randomVector(n, q);
    
    const e = [];
    for (let i = 0; i < n; i++) {
        e.push(gaussianRandom(0, sigma));
    }
    
    const b = [];
    for (let i = 0; i < n; i++) {
        let sum = 0;
        for (let j = 0; j < n; j++) {
            sum += A[i][j] * s[j];
        }
        b.push(((sum + e[i]) % q + q) % q);
    }
    
    lweKeys = { n, q, sigma, A, s, b, e };
    
    document.getElementById('lwePublicKey').value = `A: ${JSON.stringify(A)}\n\nb: ${JSON.stringify(b)}`;
    document.getElementById('lwePrivateKey').value = `s: ${JSON.stringify(s)}`;
    
    alert('✅ LWE 密钥对生成成功！');
    generateNoiseVisual();
}

function lweEncrypt() {
    if (!lweKeys) { alert('❌ 请先生成密钥对！'); return; }
    
    const input = document.getElementById('lweEncryptInput').value.trim();
    if (input !== '0' && input !== '1') { alert('❌ 明文只能输入 0 或 1！'); return; }
    
    const m = parseInt(input) === 1 ? Math.floor(lweKeys.q / 2) : 0;
    const { n, q, A, b } = lweKeys;
    
    const r = [];
    for (let i = 0; i < n; i++) {
        r.push(Math.floor(Math.random() * 2));
    }
    
    const u = [];
    for (let j = 0; j < n; j++) {
        let sum = 0;
        for (let i = 0; i < n; i++) {
            sum += A[i][j] * r[i];
        }
        u.push(sum % q);
    }
    
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
        
        let su = 0;
        for (let i = 0; i < s.length; i++) {
            su += s[i] * u[i];
        }
        let m = ((v - su) % q + q) % q;
        
        const decrypted = m > q / 4 ? 1 : 0;
        document.getElementById('lweDecryptOutput').value = `解密结果: ${decrypted}\n(计算值: ${m}, 阈值: ${Math.floor(q/4)})`;
    } catch (e) {
        alert('❌ 密文格式错误！请使用 JSON 格式。');
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
        document.getElementById('lwePublicKey').value = `A: ${JSON.stringify(keys.A)}\n\nb: ${JSON.stringify(keys.b)}`;
        document.getElementById('lwePrivateKey').value = `s: ${JSON.stringify(keys.s)}`;
        alert('✅ LWE 密钥导入成功！');
    });
}

// ==================== LWE 过程记录 ====================

function saveLweProcess() {
    const data = {
        keyGen: document.getElementById('lweProcessKeyGen').value,
        encrypt: document.getElementById('lweProcessEncrypt').value,
        decrypt: document.getElementById('lweProcessDecrypt').value
    };
    localStorage.setItem('lweProcess', JSON.stringify(data));
    alert('✅ LWE 过程记录已保存！');
}

function loadLweProcess() {
    const data = JSON.parse(localStorage.getItem('lweProcess') || '{}');
    if (data.keyGen) document.getElementById('lweProcessKeyGen').value = data.keyGen;
    if (data.encrypt) document.getElementById('lweProcessEncrypt').value = data.encrypt;
    if (data.decrypt) document.getElementById('lweProcessDecrypt').value = data.decrypt;
    alert('📂 LWE 过程记录已加载！');
}

function clearLweProcess() {
    if (confirm('确定要清空 LWE 过程记录吗？')) {
        document.getElementById('lweProcessKeyGen').value = '';
        document.getElementById('lweProcessEncrypt').value = '';
        document.getElementById('lweProcessDecrypt').value = '';
        localStorage.removeItem('lweProcess');
        alert('🗑️ LWE 过程记录已清空！');
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

// ==================== 可视化 ====================

function initGaussChart() {
    const ctx = document.getElementById('gaussChart').getContext('2d');
    
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
                borderColor: '#00d9ff',
                backgroundColor: 'rgba(0, 217, 255, 0.2)',
                fill: true,
                tension: 0.4,
                pointRadius: 4,
                pointBackgroundColor: '#ff6b6b'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: true, position: 'top' }
            },
            scales: {
                x: { title: { display: true, text: 'x' }, grid: { color: '#eee' } },
                y: { title: { display: true, text: '概率密度' }, grid: { color: '#eee' } }
            }
        }
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
        bar.style.height = `${Math.min(height, 55)}px`;
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
