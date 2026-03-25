// LWE 加密算法 JavaScript 实现
class LWE {
    constructor(n = 64, q = 997, sigma = 3.0) {
        this.n = n;
        this.q = q;
        this.sigma = sigma;
    }

    // 高斯随机采样
    _gaussianRandom() {
        let u = 0, v = 0;
        while(u === 0) u = Math.random();
        while(v === 0) v = Math.random();
        return Math.sqrt(-2.0 * Math.log(u)) * Math.cos(2.0 * Math.PI * v);
    }

    // 采样误差
    _sampleError() {
        return Math.round(this._gaussianRandom() * this.sigma) % this.q;
    }

    // 生成密钥对
    keyGen() {
        const s = Array.from({length: this.n}, () => Math.floor(Math.random() * 2));
        const A = Array.from({length: this.n}, () => 
            Array.from({length: this.n}, () => Math.floor(Math.random() * this.q))
        );
        const e = Array.from({length: this.n}, () => this._sampleError());
        
        const b = [];
        for(let i = 0; i < this.n; i++) {
            let sum = e[i];
            for(let j = 0; j < this.n; j++) {
                sum += A[i][j] * s[j];
            }
            b.push(sum % this.q);
        }
        
        return { publicKey: { A, b }, secretKey: s };
    }

    // 加密单个字节
    encrypt(publicKey, message) {
        const { A, b } = publicKey;
        const r = Array.from({length: this.n}, () => Math.floor(Math.random() * 2));
        
        const u = [];
        for(let j = 0; j < this.n; j++) {
            let sum = 0;
            for(let i = 0; i < this.n; i++) {
                sum += A[i][j] * r[i];
            }
            u.push(sum % this.q);
        }
        
        let v = 0;
        for(let i = 0; i < this.n; i++) {
            v += b[i] * r[i];
        }
        v = (v + message * Math.floor(this.q / 2)) % this.q;
        
        return { u, v };
    }

    // 解密单个字节
    decrypt(secretKey, ciphertext) {
        const { u, v } = ciphertext;
        const s = secretKey;
        
        let dotProduct = 0;
        for(let i = 0; i < this.n; i++) {
            dotProduct += s[i] * u[i];
        }
        let val = (v - dotProduct) % this.q;
        if(val < 0) val += this.q;
        
        if(val > this.q / 4 && val < 3 * this.q / 4) {
            return 1;
        }
        return 0;
    }

    // 加密字符串
    encryptString(publicKey, text) {
        const bytes = new TextEncoder().encode(text);
        const encrypted = Array.from(bytes).map(b => this.encrypt(publicKey, b));
        return JSON.stringify(encrypted);
    }

    // 解密字符串
    decryptString(secretKey, encryptedJson) {
        const encrypted = JSON.parse(encryptedJson);
        const bytes = encrypted.map(c => this.decrypt(secretKey, c));
        return new TextDecoder().decode(new Uint8Array(bytes));
    }
}
