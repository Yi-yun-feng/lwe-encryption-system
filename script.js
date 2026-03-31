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

// ---------- 页面交互 ----------
function updateDocCount() {
    document.getElementById("docCount").innerText = storedDocs.length;
}

// 密钥生成
document.getElementById("doGenKeys").addEventListener("click", () => {
    lwePublicKey = "LWE_PUB_" + Math.random().toString(36).slice(2);
    lweSecretKey = "LWE_SEC_" + Math.random().toString(36).slice(2);
    document.getElementById("keyStatusArea").innerHTML = `✅ 密钥生成成功！<br>公钥: ${lwePublicKey}<br>私钥已保存`;
});

// 加密上传
document.getElementById("uploadBtn").addEventListener("click", () => {
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
    updateDocCount();
});

// 密文检索
document.getElementById("searchBtn").addEventListener("click", () => {
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

// 性能对比图表
let chart;
function renderChart() {
    const ctx = document.getElementById('performanceChart').getContext('2d');
    if (chart) chart.destroy();
    chart = new Chart(ctx, {
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
}
document.getElementById("runCompare").addEventListener("click", renderChart);
renderChart();

// 侧边导航与滚动
const menuBtn = document.getElementById("menuToggle");
const sideNav = document.getElementById("sideNav");
const overlay = document.getElementById("overlay");
menuBtn.onclick = () => { sideNav.classList.add("open"); overlay.classList.add("show"); };
overlay.onclick = () => { sideNav.classList.remove("open"); overlay.classList.remove("show"); };
document.querySelectorAll('.sidenav a').forEach(link => {
    link.addEventListener("click", (e) => {
        e.preventDefault();
        const targetId = link.getAttribute("href").substring(1);
        const target = document.getElementById(targetId);
        if (target) target.scrollIntoView({ behavior: "smooth" });
        sideNav.classList.remove("open");
        overlay.classList.remove("show");
    });
});

// 初始化文档计数
updateDocCount();
