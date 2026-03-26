/**
 * LWE (Learning With Errors) 后量子加密算法完整实现
 * 基于格密码学，抗量子计算攻击，教学演示级实现
 * 作者：Yi-yun-feng
 */
class LWE {
    /**
     * 构造函数，初始化LWE核心参数
     * @param {number} n 格维度（安全参数，越大越安全，性能越低，教学推荐256）
     * @param {BigInt} q 模数（大素数，推荐4093n）
     * @param {number} sigma 离散高斯分布标准差（错误项参数，推荐3）
     */
    constructor(n = 256, q = 4093n, sigma = 3) {
        this.n = n;
        this.q = q;
        this.sigma = sigma;
        this.m = 2 * n; // 公钥矩阵行数，平衡安全性与性能
        this.privateKey = null; // 私钥 s (n维向量)
        this.publicKey = null;  // 公钥 {A, b} (A: m×n矩阵, b: m维向量)
    }

    /**
     * 辅助函数：模q运算，确保结果为正
     * @param {BigInt} x 输入数值
     * @returns {BigInt} x mod q
     */
    mod(x) {
        let res = x % this.q;
        return res < 0n ? res + this.q : res;
    }

    /**
     * 辅助函数：离散高斯分布采样（生成错误项e）
     * @returns {BigInt} 采样得到的小整数错误项
     */
    sampleGaussian() {
        let u1 = Math.random();
        let u2 = Math.random();
        // Box-Muller 算法生成正态分布
        let z = Math.sqrt(-2 * Math.log(u1)) * Math.cos(2 * Math.PI * u2);
        let sample = Math.round(z * this.sigma);
        return BigInt(sample);
    }

    /**
     * 辅助函数：生成指定范围的随机整数
     * @param {BigInt} min 最小值
     * @param {BigInt} max 最大值
     * @returns {BigInt} 随机数
     */
    randomInt(min, max) {
        const range = max - min + 1n;
        const randomBytes = new Uint32Array(1);
        crypto.getRandomValues(randomBytes);
        const randomNum = BigInt(randomBytes[0]);
        return min + (randomNum % range);
    }

    /**
     * 密钥生成算法
     * @returns {Object} {publicKey, privateKey}
     */
    generateKeyPair() {
        // 1. 生成私钥s：n维向量，每个元素为0或1（二进制私钥，简化实现，不降低安全性）
        const s = [];
        for (let i = 0; i < this.n; i++) {
            s.push(BigInt(Math.random() > 0.5 ? 1 : 0));
        }
        this.privateKey = s;

        // 2. 生成公钥矩阵A：m×n矩阵，每个元素在[0, q-1]均匀随机
        const A = [];
        for (let i = 0; i < this.m; i++) {
            const row = [];
            for (let j = 0; j < this.n; j++) {
                row.push(this.randomInt(0n, this.q - 1n));
            }
            A.push(row);
        }

        // 3. 生成错误向量e：m维向量，从离散高斯分布采样
        const e = [];
        for (let i = 0; i < this.m; i++) {
            e.push(this.sampleGaussian());
        }

        // 4. 计算b = A*s + e mod q
        const b = [];
        for (let i = 0; i < this.m; i++) {
            let sum = 0n;
            for (let j = 0; j < this.n; j++) {
                sum += A[i][j] * s[j];
            }
            sum += e[i];
            b.push(this.mod(sum));
        }

        this.publicKey = { A, b };
        return { publicKey: this.publicKey, privateKey: this.privateKey };
    }

    /**
     * 单比特加密算法（明文为0或1）
     * @param {number} bit 明文比特（0或1）
     * @param {Object} publicKey 公钥（可选，默认使用实例内公钥）
     * @returns {Object} 密文 {u, v}
     */
    encryptBit(bit, publicKey = this.publicKey) {
        if (!publicKey) throw new Error("请先生成公钥或传入公钥");
        if (bit !== 0 && bit !== 1) throw new Error("单比特加密仅支持0或1");

        const { A, b } = publicKey;
        const qHalf = this.q / 2n;

        // 1. 生成随机向量r：m维向量，每个元素为0或1
        const r = [];
        for (let i = 0; i < this.m; i++) {
            r.push(BigInt(Math.random() > 0.5 ? 1 : 0));
        }

        // 2. 计算u = r^T * A mod q
        const u = [];
        for (let j = 0; j < this.n; j++) {
            let sum = 0n;
            for (let i = 0; i < this.m; i++) {
                sum += r[i] * A[i][j];
            }
            u.push(this.mod(sum));
        }

        // 3. 计算v = r^T * b + bit * floor(q/2) mod q
        let v = 0n;
        for (let i = 0; i < this.m; i++) {
            v += r[i] * b[i];
        }
        v += BigInt(bit) * qHalf;
        v = this.mod(v);

        return { u, v };
    }

    /**
     * 单比特解密算法
     * @param {Object} ciphertext 密文 {u, v}
     * @param {Array} privateKey 私钥（可选，默认使用实例内私钥）
     * @returns {number} 明文比特（0或1）
     */
    decryptBit(ciphertext, privateKey = this.privateKey) {
        if (!privateKey) throw new Error("请先生成私钥或传入私钥");
        const { u, v } = ciphertext;
        const qHalf = this.q / 2n;
        const qQuarter = this.q / 4n;

        // 计算 v - u^T * s mod q
        let sum = 0n;
        for (let j = 0; j < this.n; j++) {
            sum += u[j] * privateKey[j];
        }
        const res = this.mod(v - sum);

        // 判决：距离0近则为0，距离q/2近则为1
        const distance0 = res < qHalf ? res : this.q - res;
        const distance1 = res < qHalf ? qHalf - res : res - qHalf;

        return distance0 < distance1 ? 0 : 1;
    }

    /**
     * 字符串加密算法
     * @param {string} plaintext 明文文本
     * @param {Object} publicKey 公钥（可选）
     * @returns {Array} 密文数组（每个元素为单比特密文）
     */
    encryptString(plaintext, publicKey = this.publicKey) {
        if (!publicKey) throw new Error("请先生成公钥或传入公钥");
        // 字符串转UTF-8字节数组，再转二进制比特串
        const encoder = new TextEncoder();
        const bytes = encoder.encode(plaintext);
        const bitArray = [];
        for (const byte of bytes) {
            for (let i = 7; i >= 0; i--) {
                bitArray.push((byte >> i) & 1);
            }
        }
        // 逐比特加密
        const ciphertextArray = [];
        for (const bit of bitArray) {
            ciphertextArray.push(this.encryptBit(bit, publicKey));
        }
        return ciphertextArray;
    }

    /**
     * 字符串解密算法
     * @param {Array} ciphertextArray 密文数组
     * @param {Array} privateKey 私钥（可选）
     * @returns {string} 明文文本
     */
    decryptString(ciphertextArray, privateKey = this.privateKey) {
        if (!privateKey) throw new Error("请先生成私钥或传入私钥");
        // 逐比特解密
        const bitArray = [];
        for (const ciphertext of ciphertextArray) {
            bitArray.push(this.decryptBit(ciphertext, privateKey));
        }
        // 比特串转回字节数组，再转回字符串
        const bytes = [];
        for (let i = 0; i < bitArray.length; i += 8) {
            let byte = 0;
            for (let j = 0; j < 8; j++) {
                byte = (byte << 1) | bitArray[i + j];
            }
            bytes.push(byte);
        }
        const decoder = new TextDecoder();
        return decoder.decode(new Uint8Array(bytes));
    }
}

// 全局暴露，供页面调用
window.LWE = LWE;
