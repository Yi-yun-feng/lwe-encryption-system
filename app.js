function decrypt() {
    const decryptInput = document.getElementById('decryptInput').value;
    const privateKey = localStorage.getItem('privateKey');
    
    if (!privateKey) {
        alert('请先生成密钥对！');
        return;
    }
    
    const decryptor = new JSEncrypt();
    decryptor.setPrivateKey(privateKey);
    const decrypted = decryptor.decrypt(decryptInput);
    
    document.getElementById('decryptOutput').value = decrypted || '解密失败';
}
