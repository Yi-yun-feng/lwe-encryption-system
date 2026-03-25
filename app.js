let currentAlgorithm = 'rsa';
let rsaCrypt = null;
let lwe = null;
let lweKeys = null;

function updateUI() {
    currentAlgorithm = document.getElementById('algorithm').value;
    document.getElementById('encryptResult').style.display = 'none';
    document.getElementById('decryptResult').style.display = 'none';
    document.getElementById('keyStatus').textContent = '⚠️ 请重新生成密钥（已切换算法）';
    document.getElementById('publicKeyInfo').style.display = 'none';
    document.getElementById('secretKeyInfo').style.display = 'none';
    rsaCrypt = null;
    lweKeys = null;
}

function generateKey() {
    const statusDiv = document.getElementById('keyStatus');
    const pubInfo = document.getElementById('publicKeyInfo');
    const secInfo = document.getElementById('secretKeyInfo');
    
    if(currentAlgorithm === 'rsa') {
        rsaCrypt = new JSEncrypt();
        rsaCrypt.getKey(() => {
            statusDiv.textContent = '✅ RSA 密钥对生成成功！';
            statusDiv.style.color = 'green';
            pubInfo.style.display = 'block';
            secInfo.style.display = 'block';
        });
    } else {
        lwe = new LWE(64, 997, 3.0);
        lweKeys = lwe.keyGen();
        statusDiv.textContent = '✅ LWE 密钥对生成成功！';
        statusDiv.style.color = 'green';
        pubInfo.style.display = 'block';
        secInfo.style.display = 'block';
    }
}

function encrypt() {
    const text = document.getElementById('plainText').value;
    if(!text) { alert('⚠️ 请输入要加密的内容！'); return; }
    
    const resultDiv = document.getElementById('encryptResult');
    try {
        if(currentAlgorithm === 'rsa') {
            if(!rsaCrypt) { alert('⚠️ 请先生成密钥！'); return; }
            const encrypted = rsaCrypt.encrypt(text);
            resultDiv.textContent = encrypted;
        } else {
            if(!lweKeys) { alert('⚠️ 请先生成密钥！'); return; }
            const encrypted = lwe.encryptString(lweKeys.publicKey, text);
            resultDiv.textContent = encrypted;
        }
        resultDiv.style.display = 'block';
        resultDiv.classList.remove('error');
    } catch(e) {
        resultDiv.textContent = '❌ 错误：' + e.message;
        resultDiv.classList.add('error');
        resultDiv.style.display = 'block';
    }
}

function decrypt() {
    const text = document.getElementById('cipherText').value;
    if(!text) { alert('⚠️ 请输入要解密的内容！'); return; }
    
    const resultDiv = document.getElementById('decryptResult');
    try {
        if(currentAlgorithm === 'rsa') {
            if(!rsaCrypt) { alert('⚠️ 请先生成密钥！'); return; }
            const decrypted = rsaCrypt.decrypt(text);
            resultDiv.textContent = decrypted;
        } else {
            if(!lweKeys) { alert('⚠️ 请先生成密钥！'); return; }
            const decrypted = lwe.decryptString(lweKeys.secretKey, text);
            resultDiv.textContent = decrypted;
        }
        resultDiv.style.display = 'block';
        resultDiv.classList.remove('error');
    } catch(e) {
        resultDiv.textContent = '❌ 错误：' + e.message;
        resultDiv.classList.add('error');
        resultDiv.style.display = 'block';
    }
}
