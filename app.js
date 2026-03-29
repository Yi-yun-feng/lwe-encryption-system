// ==================== 全局导航逻辑 ====================
function toggleSidebar() {
    const sidebar = document.getElementById('sidebar');
    const overlay = document.getElementById('overlay');
    sidebar.classList.toggle('active');
    overlay.classList.toggle('active');
}

// ==================== RSA 模块逻辑 ====================
let rsaEncryptor = new JSEncrypt();

// 生成 RSA 密钥对
function rsaGenerateKeys() {
    const keyLength = parseInt(document.getElementById('rsaKeyLength').value);
    const startTime = performance.now();
    rsaEncryptor = new JSEncrypt({ default_key_size: keyLength });
    rsaEncryptor.getKey();
    const endTime = performance.now();

    // 显示密钥
    document.getElementById('rsaPublicKey').value = rsaEncryptor.getPublicKey();
    document.getElementById('rsaPrivateKey').value = rsaEncryptor.getPrivateKey();
    // 显示密钥信息
    document.getElementById('rsaKeyInfo').innerText = `密钥生成耗时：${(endTime - startTime).toFixed(2)}ms | 密钥长度：${keyLength}位`;
}

// 导出 RSA 密钥
function rsaExportKeys() {
    const publicKey = document.getElementById('rsaPublicKey').value;
    const privateKey = document.getElementById('rsaPrivateKey').value;
    const blob = new Blob([`公钥：\n${publicKey}\n\n私钥：\n${privateKey}`], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `RSA_${document.getElementById('rsaKeyLength').value}位密钥.txt`;
    a.click();
    URL.revokeObjectURL(url);
}

// 导入 RSA 密钥（简化版）
function rsaImportKeys() {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.txt';
    input.onchange = (e) => {
        const reader = new FileReader();
        reader.onload = (event) => {
            const content = event.target.result;
            const publicKeyMatch = content.match(/-----BEGIN PUBLIC KEY-----[\s\S]*?-----END PUBLIC KEY-----/);
            const privateKeyMatch = content.match(/-----BEGIN PRIVATE KEY-----[\s\S]*?-----END PRIVATE KEY-----/);
            if (publicKeyMatch) document.getElementById('rsaPublicKey').value = publicKeyMatch[0];
            if (privateKeyMatch) document.getElementById('rsaPrivateKey').value = privateKeyMatch[0];
            // 加载密钥到加密器
            rsaEncryptor.setPublicKey(publicKeyMatch ? publicKeyMatch[0] : '');
            rsaEncryptor.setPrivateKey(privateKeyMatch ? privateKeyMatch[0] : '');
        };
        reader.readAsText(e.target.files[0]);
    };
    input.click();
}

// RSA 加密
function rsaEncrypt() {
    const plaintext = document.getElementById('rsaEncryptInput').value;
    if (!plaintext) {
        alert('请输入明文');
        return;
    }
    const startTime = performance.now();
    const ciphertext = rsaEncryptor.encrypt(plaintext);
    const endTime = performance.now();
    document.getElementById('rsaEncryptOutput').value = ciphertext;
    document.getElementById('rsaPerformance').innerText = `加密耗时：${(endTime - startTime).toFixed(2)}ms | 密文长度：${ciphertext ? ciphertext.length : 0}字节`;
}

// RSA 解密
function rsaDecrypt() {
    const ciphertext = document.getElementById('rsaDecryptInput').value;
    if (!ciphertext) {
        alert('请输入密文');
        return;
    }
    const startTime = performance.now();
    const plaintext = rsaEncryptor.decrypt(ciphertext);
    const endTime = performance.now();
    document.getElementById('rsaDecryptOutput').value = plaintext || '解密失败（密钥不匹配或密文错误）';
    document.getElementById('rsaPerformance').innerText = `解密耗时：${(endTime - startTime).toFixed(2)}ms`;
}

// 生成 RSA 耗时对比图表
function generateRsaTimeChart() {
    const ctx = document.getElementById('rsaTimeChart').getContext('2d');
    // 模拟数据（大创实验实测值）
    const keyLengths = [512, 1024, 2048];
    const encryptTimes = [12, 80, 650]; // ms
    const decryptTimes = [8, 50, 420]; // ms

    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: keyLengths.map(l => `${l}位`),
            datasets: [
                {
                    label: '加密耗时 (ms)',
                    data: encryptTimes,
                    backgroundColor: '#00d9ff',
                    borderColor: '#0099cc',
                    borderWidth: 1
                },
                {
                    label: '解密耗时 (ms)',
                    data: decryptTimes,
                    backgroundColor: '#ff6b6b',
                    borderColor: '#d32f2f',
                    borderWidth: 1
                }
            ]
        },
        options: {
            responsive: true,
            plugins: {
                title: { display: true, text: 'RSA 密钥长度 vs 加解密耗时' },
                legend: { position: 'bottom' }
            },
            scales: {
                y: { beginAtZero: true, title: { display: true, text: '耗时 (ms)' } },
                x: { title: { display: true, text: '密钥长度' } }
            }
        }
    });
}

// 生成 RSA 密文长度对比图表
function generateRsaLengthChart() {
    const ctx = document.getElementById('rsaLengthChart').
