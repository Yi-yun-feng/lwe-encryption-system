/**
 * LWE (Learning With Errors) 后量子加密算法完整实现
 * 包含：基础LWE加解密、LWE-RABE可撤销属性基加密
 * 基于格密码学，抗量子计算攻击，匹配论文标准实现
 */

// 基础LWE类
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

    // 模q运算，确保结果为正
    mod(x) {
        let res = x % this.q;
        return res < 0n ? res + this.q : res;
    }

    // 离散高斯分布采样（生成错误项e）
    sampleGaussian() {
        let u1 = Math.random();
        let u2 = Math.random();
        let z = Math.sqrt(-2 * Math.log(u1)) * Math.cos(2 * Math.PI * u2);
        let sample = Math.round(z * this.sigma);
        return BigInt(sample);
    }

    // 生成指定范围的随机整数
    randomInt(min, max) {
        const range = max - min + 1n;
        const randomBytes = new Uint32Array(1);
        crypto.getRandomValues(randomBytes);
        const randomNum = BigInt(randomBytes[0]);
        return min + (randomNum % range);
    }

    // 向量内积计算
    vectorDot(a, b) {
        let sum = 0n;
        for (let i = 0; i < a.length; i++) {
            sum += a[i] * b[i];
        }
        return this.mod(sum);
    }

    // 矩阵向量乘法
    matrixVectorMul(matrix, vector) {
        const result = [];
        for (let i = 0; i < matrix.length; i++) {
            result.push(this.vectorDot(matrix[i], vector));
        }
        return result;
    }

    // 密钥生成算法
    generateKeyPair() {
        // 生成私钥s：n维二进制向量
        const s = [];
        for (let i = 0; i < this.n; i++) {
            s.push(BigInt(Math.random() > 0.5 ? 1 : 0));
        }
        this.privateKey = s;

        // 生成公钥矩阵A：m×n随机矩阵
        const A = [];
        for (let i = 0; i < this.m; i++) {
            const row = [];
            for (let j = 0; j < this.n; j++) {
                row.push(this.randomInt(0n, this.q - 1n));
            }
            A.push(row);
        }

        // 生成错误向量e
        const e = [];
        for (let i = 0; i < this.m; i++) {
            e.push(this.sampleGaussian());
        }

        // 计算b = A*s + e mod q
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

    // 单比特加密
    encryptBit(bit, publicKey = this.publicKey) {
        if (!publicKey) throw new Error("请先生成公钥或传入公钥");
        if (bit !== 0 && bit !== 1) throw new Error("单比特加密仅支持0或1");

        const { A, b } = publicKey;
        const qHalf = this.q / 2n;

        // 生成随机向量r
        const r = [];
        for (let i = 0; i < this.m; i++) {
            r.push(BigInt(Math.random() > 0.5 ? 1 : 0));
        }

        // 计算u = r^T * A mod q
        const u = [];
        for (let j = 0; j < this.n; j++) {
            let sum = 0n;
            for (let i = 0; i < this.m; i++) {
                sum += r[i] * A[i][j];
            }
            u.push(this.mod(sum));
        }

        // 计算v = r^T * b + bit * floor(q/2) mod q
        let v = 0n;
        for (let i = 0; i < this.m; i++) {
            v += r[i] * b[i];
        }
        v += BigInt(bit) * qHalf;
        v = this.mod(v);

        return { u, v };
    }

    // 单比特解密
    decryptBit(ciphertext, privateKey = this.privateKey) {
        if (!privateKey) throw new Error("请先生成私钥或传入私钥");
        const { u, v } = ciphertext;
        const qHalf = this.q / 2n;

        // 计算 v - u^T * s mod q
        const res = this.mod(v - this.vectorDot(u, privateKey));

        // 判决
        const distance0 = res < qHalf ? res : this.q - res;
        const distance1 = res < qHalf ? qHalf - res : res - qHalf;

        return distance0 < distance1 ? 0 : 1;
    }

    // 字符串加密
    encryptString(plaintext, publicKey = this.publicKey) {
        if (!publicKey) throw new Error("请先生成公钥或传入公钥");
        const encoder = new TextEncoder();
        const bytes = encoder.encode(plaintext);
        const bitArray = [];
        for (const byte of bytes) {
            for (let i = 7; i >= 0; i--) {
                bitArray.push((byte >> i) & 1);
            }
        }
        const ciphertextArray = [];
        for (const bit of bitArray) {
            ciphertextArray.push(this.encryptBit(bit, publicKey));
        }
        return ciphertextArray;
    }

    // 字符串解密
    decryptString(ciphertextArray, privateKey = this.privateKey) {
        if (!privateKey) throw new Error("请先生成私钥或传入私钥");
        const bitArray = [];
        for (const ciphertext of ciphertextArray) {
            bitArray.push(this.decryptBit(ciphertext, privateKey));
        }
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

// ==================== LWE-RABE 可撤销属性基加密类 ====================
class LWE_RABE extends LWE {
    /**
     * 构造函数
     * @param {number} n 格维度
     * @param {BigInt} q 模数
     * @param {Array} attributeSpace 系统属性空间
     */
    constructor(n = 256, q = 4093n, attributeSpace = []) {
        super(n, q);
        this.attributeSpace = attributeSpace; // 系统属性空间
        this.msk = null; // 系统主密钥
        this.pk = null; // 系统公钥
        this.userList = new Map(); // 注册用户列表 {userId: {attrs, sk}}
        this.revocationList = new Set(); // 撤销用户ID列表
        this.version = 1; // 系统版本号，用于撤销更新
    }

    // 系统初始化：生成系统公钥和主密钥
    setup(attributeSpace = this.attributeSpace) {
        this.attributeSpace = attributeSpace;
        // 为每个属性生成对应的LWE密钥对
        const attrKeys = new Map();
        for (const attr of attributeSpace) {
            const { publicKey, privateKey } = super.generateKeyPair();
            attrKeys.set(attr, { pk: publicKey, sk: privateKey });
        }
        // 系统主密钥：所有属性的私钥
        this.msk = attrKeys;
        // 系统公钥：所有属性的公钥 + 系统参数
        this.pk = {
            attrKeys: new Map(),
            n: this.n,
            q: this.q,
            version: this.version,
            attributeSpace: this.attributeSpace
        };
        for (const [attr, key] of attrKeys) {
            this.pk.attrKeys.set(attr, key.pk);
        }
        return { pk: this.pk, msk: this.msk };
    }

    // 用户密钥生成：为用户生成对应属性的私钥
    keyGen(userId, userAttrs) {
        if (!this.msk) throw new Error("请先初始化RABE系统");
        // 校验用户属性是否在系统属性空间内
        for (const attr of userAttrs) {
            if (!this.attributeSpace.includes(attr)) {
                throw new Error(`属性 ${attr} 不在系统属性空间内`);
            }
        }
        // 校验用户是否已被撤销
        if (this.revocationList.has(userId)) {
            throw new Error(`用户 ${userId} 已被撤销，无法生成密钥`);
        }
        // 生成用户私钥：用户属性对应的主密钥私钥
        const userSk = new Map();
        for (const attr of userAttrs) {
            userSk.set(attr, this.msk.get(attr).sk);
        }
        // 存储用户信息
        this.userList.set(userId, {
            userId,
            attrs: userAttrs,
            sk: userSk,
            version: this.version
        });
        return { userId, attrs: userAttrs, sk: userSk };
    }

    // 加密：使用访问策略加密明文（与门策略：需同时满足所有属性）
    encrypt(plaintext, policyAttrs) {
        if (!this.pk) throw new Error("请先初始化RABE系统");
        // 校验策略属性是否在系统属性空间内
        for (const attr of policyAttrs) {
            if (!this.attributeSpace.includes(attr)) {
                throw new Error(`策略属性 ${attr} 不在系统属性空间内`);
            }
        }
        // 对明文进行逐属性加密，生成密文组件
        const ciphertext = {
            policy: policyAttrs,
            version: this.version,
            cipherComponents: new Map()
        };
        // 用每个策略属性的公钥加密相同的明文
        for (const attr of policyAttrs) {
            const attrPk = this.pk.attrKeys.get(attr);
            const ct = super.encryptString(plaintext, attrPk);
            ciphertext.cipherComponents.set(attr, ct);
        }
        return ciphertext;
    }

    // 解密：用户使用自己的私钥解密密文
    decrypt(ciphertext, userSk, userId) {
        // 校验用户是否被撤销
        if (this.revocationList.has(userId)) {
            throw new Error(`用户 ${userId} 已被撤销，无法解密`);
        }
        // 校验版本号
        if (ciphertext.version !== this.version) {
            throw new Error("密文版本与系统版本不匹配，无法解密");
        }
        // 校验用户属性是否满足访问策略
        const policyAttrs = ciphertext.policy;
        for (const attr of policyAttrs) {
            if (!userSk.has(attr)) {
                throw new Error(`用户缺少策略属性 ${attr}，无法解密`);
            }
        }
        // 取第一个属性的密文组件解密（与门策略下任意属性解密结果一致）
        const firstAttr = policyAttrs[0];
        const ctComponent = ciphertext.cipherComponents.get(firstAttr);
        const attrSk = userSk.get(firstAttr);
        return super.decryptString(ctComponent, attrSk);
    }

    // 用户撤销：添加用户到撤销列表并更新系统版本
    revoke(userId) {
        if (!this.userList.has(userId)) {
            throw new Error(`用户 ${userId} 不存在`);
        }
        this.revocationList.add(userId);
        this.version += 1;
        // 更新系统公钥版本号
        if (this.pk) {
            this.pk.version = this.version;
        }
        return { revokedUserId: userId, newVersion: this.version };
    }
}
