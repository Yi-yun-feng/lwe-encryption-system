// 生成密钥对
function generateKeys() {
    const encryptor = new JSEncrypt({default_key_size: 2048});
    encryptor.generateKey();
    
    const publicKey = encryptor.getPublicKey();
    const privateKey = encryptor.getPrivateKey();
    
    localStorage.setItem('publicKey', publicKey);
    localStorage.setItem('privateKey', privateKey);
    
    document.getElementById('publicKey').value = publicKey;
    document.getElementById('privateKey').value = privateKey;
    
    alert('✅ 密钥对生成成功！');
}

// 加密
function encrypt() {
    const input = document.getElementById('encryptInput').value;
    const publicKey = localStorage.getItem('publicKey');
    
    if (!publicKey) {
        alert('❌ 请先生成密钥对！');
        return;
    }
    
    if (!input.trim()) {
        alert('❌ 请输入要加密的内容！');
        return;
    }
    
    const encryptor = new JSEncrypt();
    encryptor.setPublicKey(publicKey);
    const encrypted = encryptor.encrypt(input);
    
    document.getElementById('encryptOutput').value = encrypted || '加密失败';
}

// 解密
function decrypt() {
    const input = document.getElementById('decryptInput').value;
    const privateKey = localStorage.getItem('privateKey');
    
    if (!privateKey) {
        alert('❌ 请先生成密钥对！');
        return;
    }
    
    if (!input.trim()) {
        alert('❌ 请输入要解密的内容！');
        return;
    }
    
    const encryptor = new JSEncrypt();
    encryptor.setPrivateKey(privateKey);
    const decrypted = encryptor.decrypt(input);
    
    document.getElementById('decryptOutput').value = decrypted || '❌ 解密失败';
}

// 导出密钥
function exportKeys() {
    const publicKey = localStorage.getItem('publicKey');
    const privateKey = localStorage.getItem('privateKey');
    
    if (!publicKey || !privateKey) {
        alert('❌ 没有可导出的密钥！');
        return;
    }
    
    const keys = { publicKey, privateKey };
    const blob = new Blob([JSON.stringify(keys, null, 2)], {type: 'application/json'});
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'keys_' + new Date().toISOString().slice(0,10) + '.json';
    a.click();
    URL.revokeObjectURL(url);
}

// 导入密钥
function importKeys() {
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
                if (keys.publicKey && keys.privateKey) {
                    localStorage.setItem('publicKey', keys.publicKey);
                    localStorage.setItem('privateKey', keys.privateKey);
                    document.getElementById('publicKey').value = keys.publicKey;
                    document.getElementById('privateKey').value = keys.privateKey;
                    alert('✅ 密钥导入成功！');
                } else {
                    alert('❌ 密钥文件格式错误！');
                }
            } catch (err) {
                alert('❌ 文件读取失败！');
            }
        };
        reader.readAsText(file);
    };
    input.click();
}

// 页面加载时恢复密钥显示
window.onload = function() {
    const publicKey = localStorage.getItem('publicKey');
    const privateKey = localStorage.getItem('privateKey');
    if (publicKey) document.getElementById('publicKey').value = publicKey;
    if (privateKey) document.getElementById('privateKey').value = privateKey;
};
