/**
 * LWE-RABE 核心算法实现（大创项目版）
 * 包含：离散高斯噪声采样、属性基加密、用户撤销、访问策略验证
 * 作者：大创项目组
 * 版本：1.0（适配教学与实验）
 */
class LWE {
    /**
     * 构造函数初始化 LWE 核心参数
     * @param {number} n 格维度（安全参数）
     * @param {BigInt} q 模数（大质数）
     * @param {number} sigma 离散高斯噪声标准差
     */
    constructor(n = 16, q = 101n, sigma = 2.0) {
        this.n = n;
        this.q = q;
        this.sigma = sigma;
        this.m = 2 * n; // 公钥矩阵行数（平衡安全性与性能）
        this.privateKey = null; // 私钥 s (n维二进制向量)
        this.publicKey = null;  // 公钥 {A, b} (A: m×n矩阵, b: m维向量)
        this.attributeSpace = ["A", "B", "C", "D", "E"]; // 默认属性空间
        this.userList = new Map(); // 注册用户 {userId: {attrs, sk, version}}
        this.revocationList = new Set(); // 撤销用户ID
        this.systemVersion = 1; // 系统版本（用于撤销）
    }

    // 模q运算，确保结果为正
    mod(x) {
        let res = x % this.q;
        return res < 0n ? res + this.q : res;
    }

    /**
     * 离散高斯噪声采样（Box-Muller 算法）
     * 核心：生成符合 N(0, σ²) 分布的整数噪声
     * @returns {BigInt} 噪声值
     */
    sampleGaussian() {
        // Box-Muller 变换生成标准正态分布
        let u1 = Math.random();
        let u2 = Math.random();
        let z = Math.sqrt(-2 * Math.log(u1)) * Math.cos(2 * Math.PI * u2);
        // 缩放至指定标准差并取整
        let sample = Math.round(z * this.sigma);
        return BigInt(sample);
    }

    // 生成指定范围的随机整数（密码学安全）
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

    /**
     * 系统初始化（Setup）
     * 生成主公钥（mpk）和主私钥（msk）
     * @returns {Object} {mpk, msk}
     */
    setup() {
        // 为每个属性生成 LWE 密钥对
        const attrKeys = new Map();
        for (const attr of this.attributeSpace) {
            // 生成属性对应的私钥 s
            const s = [];
            for (let i = 0; i < this.n; i++) {
                s.push(BigInt(Math.random() > 0.5 ? 1 : 0));
            }
            // 生成公钥矩阵 A
            const A = [];
            for (let i = 0; i < this.m; i++) {
                const row = [];
                for (let j = 0; j < this.n; j++) {
                    row.push(this.randomInt(0n, this.q - 1n));
                }
                A.push(row);
            }
            // 生成噪声向量 e
            const e = [];
            for (let i = 0; i < this.m; i++) {
                e.push(this.sampleGaussian());
            }
            // 计算 b = A·s + e mod q
            const b = this.matrixVectorMul(A, s).map((val, idx) => this.mod(val + e[idx]));
            // 存储属性密钥对
            attrKeys.set(attr, {
                sk: s,
                pk: { A, b }
            });
        }
        // 系统主密钥 = 所有属性私钥
        const msk = attrKeys;
        // 系统主公钥 = 所有属性公钥 + 系统参数
        const mpk = {
            attrKeys: new Map(),
            n: this.n,
            q: this.q,
            sigma: this.sigma,
            version: this.systemVersion,
            attributeSpace: this.attributeSpace
        };
        for (const [attr, key] of attrKeys) {
            mpk.attrKeys.set(attr, key.pk);
        }
        // 保存全局密钥
        this.privateKey = msk;
        this.publicKey = mpk;
        return { mpk, msk };
    }

    /**
     * 用户密钥生成（KeyGen）
     * @param {string} userId 用户ID
     * @param {Array} userAttrs 用户属性列表
     * @returns {Object} 用户私钥
     */
    keyGen(userId, userAttrs) {
        // 校验属性合法性
        for (const attr of userAttrs) {
            if (!this.attributeSpace.includes(attr)) {
                throw new Error(`属性 ${attr} 不在系统属性空间内`);
            }
        }
        // 校验用户是否被撤销
        if (this.revocationList.has(userId)) {
            throw new Error(`用户 ${userId} 已被撤销，无法生成密钥`);
        }
        // 生成用户私钥：对应属性的私钥集合
        const userSk = new Map();
        for (const attr of userAttrs) {
            userSk.set(attr, this.privateKey.get(attr).sk);
        }
        // 存储用户信息
        this.userList.set(userId, {
            attrs: userAttrs,
            sk: userSk,
            version: this.systemVersion
        });
        return {
            userId,
            attrs: userAttrs,
            sk: userSk,
            version: this.systemVersion
        };
    }

    /**
     * 访问策略验证
     * 支持 AND/OR 策略，如 "AND(A,B)"、"OR(A,C)"
     * @param {string} policy 访问策略
     * @param {Array} userAttrs 用户属性
     * @returns {boolean} 是否满足策略
     */
    verifyPolicy(policy, userAttrs) {
        // 解析策略（简化版，适配教学场景）
        const policyType = policy.includes("AND") ? "AND" : "OR";
        const attrsInPolicy = policy.replace(/AND|OR|\(|\)/g, "").split(",").map(a => a.trim());
        // 验证策略
        if (policyType === "AND") {
            return attrsInPolicy.every(attr => userAttrs.includes(attr));
        } else {
            return attrsInPolicy.some(attr => userAttrs.includes(attr));
        }
    }

    /**
     * 加密（Encrypt）
     * @param {string|number} plaintext 明文（0/1 或字符串）
     * @param {string} policy 访问策略
     * @returns {Object|Array} 密文
     */
    encrypt(plaintext, policy) {
        if (!this.publicKey) throw new Error("请先执行系统初始化");
        // 解析策略属性
        const attrsInPolicy = policy.replace(/AND|OR|\(|\)/g, "").split(",").map(a => a.trim());
        // 选择策略属性对应的公钥（取第一个属性的公钥，简化版）
        const attrPk = this.publicKey.attrKeys.get(attrsInPolicy[0]);
        if (!attrPk) throw new Error(`策略属性 ${attrsInPolicy[0]} 不存在`);
        const { A, b } = attrPk;
        const qHalf = this.q / 2n;

        // 字符串转比特数组
        const encryptBit = (bit) => {
            // 生成随机向量 r
            const r = [];
            for (let i = 0; i < this.m; i++) {
                r.push(BigInt(Math.random() > 0.5 ? 1 : 0));
            }
            // 计算 u = r·A mod q
            const u = [];
            for (let j = 0; j < this.n; j++) {
                let sum = 0n;
                for (let i = 0; i < this.m; i++) {
                    sum += r[i] * A[i][j];
                }
                u.push(this.mod(sum));
            }
            // 计算 v = r·b + bit·⌊q/2⌋ mod q
            let v = 0n;
            for (let i = 0; i < this.m; i++) {
                v += r[i] * b[i];
            }
            v += BigInt(bit) * qHalf;
            v = this.mod(v);
            return { u, v, policy };
        };

        // 处理明文
        if (typeof plaintext === "number" && (plaintext === 0 || plaintext === 1)) {
            return encryptBit(plaintext);
        } else if (typeof plaintext === "string") {
            const encoder = new TextEncoder();
            const bytes = encoder.encode(plaintext);
            const bitArray = [];
            for (const byte of bytes) {
                for (let i = 7; i >= 0; i--) {
                    bitArray.push((byte >> i) & 1);
                }
            }
            return bitArray.map(bit => encryptBit(bit));
        } else {
            throw new Error("明文仅支持 0/1 或字符串");
        }
    }

    /**
     * 解密（Decrypt）
     * @param {Object|Array} ciphertext 密文
     * @param {string} userId 用户ID
     * @returns {string|number} 明文
     */
    decrypt(ciphertext, userId) {
        if (!this.userList.has(userId)) throw new Error(`用户 ${userId} 不存在`);
        const userInfo = this.userList.get(userId);
        // 校验用户版本
        if (userInfo.version !== this.systemVersion) {
            throw new Error(`用户 ${userId} 密钥版本过期（已被撤销）`);
        }
        const userAttrs = userInfo.attrs;
        const userSk = userInfo.sk;

        // 单比特解密
        const decryptBit = (ct) => {
            // 验证访问策略
            if (!this.verifyPolicy(ct.policy, userAttrs)) {
                throw new Error("用户属性不满足访问策略");
            }
            // 选择策略属性对应的私钥
            const attrsInPolicy = ct.policy.replace(/AND|OR|\(|\)/g, "").split(",").map(a => a.trim());
            const sk = userSk.get(attrsInPolicy[0]);
            if (!sk) throw new Error(`用户无属性 ${attrsInPolicy[0]} 的私钥`);
            // 解密
            const qHalf = this.q / 2n;
            const res = this.mod(ct.v - this.vectorDot(ct.u, sk));
            // 判决
            const distance0 = res < qHalf ? res : this.q - res;
            const distance1 = res < qHalf ? qHalf - res : res - qHalf;
            return distance0 < distance1 ? 0 : 1;
        };

        // 处理密文
        if (Array.isArray(ciphertext)) {
            // 字符串密文解密
            const bitArray = [];
            for (const ct of ciphertext) {
                bitArray.push(decryptBit(ct));
            }
            // 比特数组转字符串
            const bytes = [];
            for (let i = 0; i < bitArray.length; i += 8) {
                let byte = 0;
                for (let j = 0; j < 8; j++) {
                    if (i + j >= bitArray.length) break;
                    byte = (byte << 1) | bitArray[i + j];
                }
                bytes.push(byte);
            }
            return new TextDecoder().decode(new Uint8Array(bytes));
        } else {
            // 单比特密文解密
            return decryptBit(ciphertext);
        }
    }

    /**
     * 用户撤销（Revoke）
     * @param {string} userId 待撤销用户ID
     */
    revokeUser(userId) {
        if (!this.userList.has(userId)) throw new Error(`用户 ${userId} 不存在`);
        this.revocationList.add(userId);
    }

    /**
     * 更新系统密钥（用于撤销）
     * 增量更新，仅更新版本号，简化版（实际应更新公钥）
     */
    updateKeys() {
        this.systemVersion++;
        // 更新主公钥版本
        this.publicKey.version = this.systemVersion;
        // 非撤销用户更新版本
        for (const [userId, userInfo] of this.userList) {
            if (!this.revocationList.has(userId)) {
                userInfo.version = this.systemVersion;
            }
        }
    }

    /**
     * 生成离散高斯噪声采样数据（用于可视化）
     * @param {number} count 采样次数
     * @returns {Array} 采样值数组
     */
    generateNoiseSamples(count = 50) {
        const samples = [];
        for (let i = 0; i < count; i++) {
            samples.push(Number(this.sampleGaussian()));
        }
        return samples;
    }
}

// 全局 LWE 实例
let globalLwe = null;
