// ---------- 模拟 LWE 状态 ----------
let lwePublicKey = null;
let lweSecretKey = null;
let storedDocs = [];  // { id, title, ciphertext, keywordCiphers, rawKeywords }

function mockLWEEncrypt(data) {
    return "LWE_CIPHER_" + btoa(data + Date.now() + Math.random()).substring(0, 24);
}
function mockGenTrapdoor(keyword) {
    return "TRAP_" + btoa(keyword + (lweSecretKey || "demo")).substring(0, 20);
}
function mockMatch(trapdoor, keywordCipher) {
    return trapdoor.includes(keywordCipher.slice(5,10)) || keywordCipher.includes(trapdoor.slice(5,10));
}

// ---------- 视图渲染 ----------
const views = {
    home: () => `
        <div class="hero">
            <div class="badge"><i class="fas fa-shield-alt"></i> 后量子密码学 · 国家级大创</div>
            <h1>基于LWE的轻量化<br>可搜索加密系统</h1>
            <p style="font-size:1.1rem;">在密文上直接检索关键词，抵抗量子攻击。轻量化设计适配云端与边缘设备。</p>
            <div style="margin-top:1.5rem; display:flex; gap:12px;">
                <button class="btn btn-primary" data-nav="keygen">开始使用 · 生成密钥</button>
                <button class="btn btn-outline" data-nav="upload">加密上传文档</button>
            </div>
        </div>
        <h2>核心技术特色</h2>
        <div class="grid-2">
            <div class="card"><i class="fas fa-chart-simple"></i><h3>轻量化LWE参数</h3><p>n=256, q≈2^16，128-bit安全，效率提升约50%</p></div>
            <div class="card"><i class="fas fa-magnifying-glass-chart"></i><h3>可搜索加密</h3><p>支持陷门检索，保护查询隐私</p></div>
            <div class="card"><i class="fas fa-chart-line"></i><h3>内置性能对比</h3><p>实时对比不同方案的检索效率</p></div>
        </div>
    `,
    keygen: () => `
        <div class="card">
            <h2>LWE密钥对模拟生成</h2>
            <button id="doGenKeys" class="btn btn-primary">生成新LWE密钥对</button>
            <div id="keyStatusArea" class="result-area" style="margin-top:1rem;">⚠️ 未生成密钥</div>
            <div class="status-msg">实际环境采用Regev加密方案，公钥(A, b)，私钥s。</div>
        </div>
    `,
    upload: () => `
        <div class="card">
            <h2>加密上传文档</h2>
            <input type="text" id="docTitle" placeholder="文档标题">
            <textarea id="docContent" rows="4" placeholder="文档内容"></textarea>
            <input type="text" id="docKeywords" placeholder="关键词 (英文逗号分隔)">
            <button id="uploadBtn" class="btn btn-primary">加密并上传</button>
            <div id="uploadResult" class="result-area"></div>
            <div class="status-msg">已存储文档: <span id="docCount">0</span></div>
        </div>
    `,
    search: () => `
        <div class="card">
            <h2>密文检索</h2>
            <input type="text" id="searchKeyword" placeholder="输入关键词">
            <button id="searchBtn" class="btn btn-primary">生成陷门并检索</button>
            <div id="searchResultArea" class="result-area">🔍 检索结果显示于此</div>
        </div>
    `,
    compare: () => `
        <div class="card">
            <h2>性能对比实验</h2>
            <canvas id="performanceChart" width="400" height="200" style="max-height:320px; width:100%;"></canvas>
            <button id="runCompare" class="btn btn-primary">更新对比图表</button>
            <div class="status-msg">* 数据模拟：本方案相比基础LWE检索时间降低约45%</div>
        </div>
    `
};

function renderView(viewId) {
    document.getElementById("mainContent").innerHTML = views[viewId]();
    attachEvents(viewId);
}

function attachEvents(viewId) {
    if (viewId === "keygen") {
        document.getElementById("doGenKeys")?.addEventListener("click", () => {
            lwePublicKey = "LWE_PUB_" + Math.random().toString(36).slice(2);
            lweSecretKey = "LWE_SEC_" + Math.random().toString(36).slice(2);
            document.getElementById("keyStatusArea").innerHTML = `✅ 密钥生成成功！<br>公钥: ${lwePublicKey}<br>私钥已保存`;
        });
    }
    if (viewId === "upload") {
        const updateCount = () => document.getElementById("docCount").innerText = storedDocs.length;
        updateCount();
        document.getElementById("uploadBtn")?.addEventListener("click", () => {
            const title = document.getElementById("docTitle").value.trim();
            const content = document.getElementById("docContent").value.trim();
            const kwStr = document.getElementById("docKeywords").value.trim();
            if (!title || !content) return alert("请填写标题和内容");
            if (!lweSecretKey) return alert("请先生成密钥对");
            const docCipher = mockLWEEncrypt(content);
            let keywords = kwStr ? kwStr.split(/[,，]+/).map(k=>k.trim()) : ["默认"];
            const keywordCiphers = keywords.map(k => mockLWEEncrypt(k));
            storedDocs.push({ id: storedDocs.length+1, title, ciphertext: docCipher, keywordCiphers, rawKeywords: keywords });
            document.getElementById("uploadResult").innerHTML = `✅ 文档“${title}”已加密上传`;
            document.getElementById("docTitle").value = "";
            document.getElementById("docContent").value = "";
            document.getElementById("docKeywords").value = "";
            updateCount();
        });
    }
    if (viewId === "search") {
        document.getElementById("searchBtn")?.addEventListener("click", () => {
            const keyword = document.getElementById("searchKeyword").value.trim();
            const resultDiv = document.getElementById("searchResultArea");
            if (!keyword) return resultDiv.innerHTML = "请输入关键词";
            if (!lweSecretKey) return resultDiv.innerHTML = "请先生成密钥对";
            if (storedDocs.length === 0) return resultDiv.innerHTML = "暂无文档，请先上传";
            const trapdoor = mockGenTrapdoor(keyword);
            const matched = storedDocs.filter(doc =>
                doc.keywordCiphers.some(kc => mockMatch(trapdoor, kc))
            );
            if (matched.length === 0) {
                resultDiv.innerHTML = `未找到匹配文档。<br>陷门: ${trapdoor}`;
            } else {
                let html = `<div>找到 ${matched.length} 个文档：</div><ul>`;
                matched.forEach(d => html += `<li><strong>${d.title}</strong> (密文: ${d.ciphertext.substring(0,20)}...)</li>`);
                html += `</ul>`;
                resultDiv.innerHTML = html;
            }
        });
    }
    if (viewId === "compare") {
        const renderChart = () => {
            const ctx = document.getElementById('performanceChart')?.getContext('2d');
            if (!ctx) return;
            if (window.myChart) window.myChart.destroy();
            window.myChart = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: ['100', '300', '500', '800', '1000'],
                    datasets: [
                        { label: '明文检索', data: [12,35,58,94,118], borderColor: '#94a3b8' },
                        { label: 'RSA-SE', data: [15,42,70,112,142], borderColor: '#f97316' },
                        { label: '基础LWE-SE', data: [42,128,210,340,430], borderColor: '#ef4444' },
                        { label: '本方案(轻量化)', data: [22,66,108,175,222], borderColor: '#2563eb', borderWidth: 3 }
                    ]
                },
                options: { responsive: true, plugins: { legend: { position: 'top' } } }
            });
        };
        renderChart();
        document.getElementById("runCompare")?.addEventListener("click", renderChart);
    }
}

// 导航与初始化
function init() {
    const menuBtn = document.getElementById("menuToggle");
    const sideNav = document.getElementById("sideNav");
    const overlay = document.getElementById("overlay");
    menuBtn.onclick = () => { sideNav.classList.add("open"); overlay.classList.add("show"); };
    overlay.onclick = () => { sideNav.classList.remove("open"); overlay.classList.remove("show"); };
    document.querySelectorAll('.sidenav a').forEach(link => {
        link.addEventListener("click", (e) => {
            e.preventDefault();
            const navId = link.getAttribute("data-nav");
            if (navId) renderView(navId);
            sideNav.classList.remove("open");
            overlay.classList.remove("show");
        });
    });
    renderView("home");
}
init();
