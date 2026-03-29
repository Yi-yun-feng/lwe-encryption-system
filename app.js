// 全局LWE-RABE实例
let lweRabeInstance = null;

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
function lweSetup() {
    try {
        const n = parseInt(document.getElementById('lweN').value) || 8;
        const q = BigInt(document.getElementById('lweQ').value) || 97n;
        const sigma = parseFloat(document.getElementById('lweSigma').value) || 2.0;
        // 初始化LWE-RABE实例
        lweRabeInstance = new LWE_RABE(n, q, ['A', 'B', 'C', 'D']);
        // 系统初始化
        const { pk, msk } = lweRabeInstance.setup();
        // 展示主公钥（简化展示）
        document.getElementById('lweMpk').value = `系统公钥：
维度n: ${pk.n}
模数q: ${pk.q}
属性空间: ${pk.attributeSpace.join(',')}
版本号: ${pk.version}`;
        document.getElementById('lweUserKey').value = '请点击「生成用户密钥」生成私钥';
        
        updateLweGaussChart(sigma);
        generateNoiseVisual();
        alert('✅ LWE-RABE系统初始化成功！');
    } catch (e) {
        alert(`❌ 初始化失败：${e.message}`);
    }
}

function lweKeyGen() {
    try {
        if (!lweRabeInstance) { alert('❌ 请先系统初始化！'); return; }
        const userAttrs = document.getElementById('lweAttrs').value.split(',').map(attr => attr.trim());
        const userId = `user_${Math.floor(Math.random() * 1000)}`;
        const { sk } = lweRabeInstance.keyGen(userId, userAttrs);
        // 展示用户私钥（简化展示）
        let skStr = `用户ID: ${userId}
属性列表: ${userAttrs.join(',')}
私钥（属性-私钥映射）:
`;
        sk.forEach((value, key) => {
            skStr += `${key}: [${value.slice(0, 5)}...]（前5位）\n`;
        });
        document.getElementById('lweUserKey').value = skStr;
        alert(`✅ 用户密钥生成成功！用户ID：${userId}`);
    } catch (e) {
        alert(`❌ 密钥生成失败：${e.message}`);
    }
}

function lweEncrypt() {
    try {
        if (!lweRabeInstance) { alert('❌ 请先系统初始化！'); return; }
        const plaintext = document.getElementById('lweEncryptInput').value.trim();
        if (!plaintext) { alert('❌ 请输入明文！'); return; }
        const policyAttrs = document.getElementById('lwePolicy').value.replace('AND(', '').replace(')', '').split(',').map(attr => attr.trim());
        // 加密
        const ciphertext = lweRabeInstance.encrypt(plaintext, policyAttrs);
        // 展示密文（简化展示）
        let ctStr = `访问策略: AND(${policyAttrs.join(',')})
版本号: ${ciphertext.version}
密文组件（属性-密文映射）:
`;
        ciphertext.cipherComponents.forEach((value, key) => {
            ctStr += `${key}: [${value.length}个比特密文]\n`;
        });
        document.getElementById('lweEncryptOutput').value = JSON.stringify(ciphertext, (k, v) => {
            if (v instanceof Map) return Object.fromEntries(v);
            return v;
        }, 2);
    } catch (e) {
        alert(`❌ 加密失败：${e.message}`);
    }
}

function lweDecrypt() {
    try {
        if (!lweRabeInstance) { alert('❌ 请先系统初始化！'); return; }
        const ctInput = document.getElementById('lweDecryptInput').value.trim();
        if (!ctInput) { alert('❌ 请输入密文！'); return; }
        // 解析密文
        const ciphertext = JSON.parse(ctInput, (k, v) => {
            if (typeof v === 'object' && v !== null && Object.keys(v).some(key => isNaN(Number(key)))) {
                return new Map(Object.entries(v));
            }
            return v;
        });
        const userAttrs = document.getElementById('lweAttrs').value.split(',').map(attr => attr.trim());
        const userId = `user_${Math.floor(Math.random() * 1000)}`;
        // 生成临时用户私钥（用于解密）
        const { sk } = lweRabeInstance.keyGen(userId, userAttrs);
        // 解密
        const plaintext = lweRabeInstance.decrypt(ciphertext, sk, userId);
        document.getElementById('lweDecryptOutput').value = `解密结果：${plaintext}`;
    } catch (e) {
        alert(`❌ 解密失败：${e.message}`);
    }
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

function gaussianRandom(mean = 0, stdev = 1) {
    const u = 1 - Math.random();
    const v = Math.random();
    return Math.round(Math.sqrt(-2.0 * Math.log(u)) * Math.cos(2.0 * Math.PI * v) * stdev + mean);
}

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
    // 加载lwe.js后初始化
    if (typeof LWE_RABE !== 'undefined') {
        updateRsaKeyChart();
        updateLweGaussChart(2.0);
        generateNoiseVisual();
    } else {
        alert('⚠️ LWE核心库未加载，请检查lwe.js是否引入！');
    }
};
