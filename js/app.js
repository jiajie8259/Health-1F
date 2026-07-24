// ============================================================================
// 健康記事 · app.js
// ============================================================================
import { initializeApp } from "https://www.gstatic.com/firebasejs/10.12.2/firebase-app.js";
import {
  getFirestore, collection, doc, addDoc, updateDoc, deleteDoc,
  onSnapshot, query, orderBy, where, getDocs, getDoc, setDoc, serverTimestamp
} from "https://www.gstatic.com/firebasejs/10.12.2/firebase-firestore.js";
import { firebaseConfig, appConfig } from "./firebase-config.js";

const app = initializeApp(firebaseConfig);
const db = getFirestore(app);
// 注意：附件改為壓縮後以 base64 存進 Firestore（見下方 fileToAttachment），
// 不使用 Firebase Storage —— 因為自 2026/2/3 起 Storage 必須升級到 Blaze
// 付費方案（需連結信用卡）才能使用，Spark 免費方案已不支援。

// ----------------------------------------------------------------------------
// Constants
// ----------------------------------------------------------------------------
const CATEGORY_LABELS = { symptom: "症狀", visit: "就診", exam: "檢查", med: "用藥", note: "備註" };
const CATEGORY_ICONS = { symptom: "🩹", visit: "🏥", exam: "🔬", med: "💊", note: "📝" };
const STATUS_LABELS = { active: "治療中", tracking: "追蹤中", done: "已完成" };
const PERSON_LABELS = { mother: "媽媽", father: "爸爸", other: "其他" };
const ATTACH_MAX_BYTES = 700 * 1024; // 單一附件上限（base64 編碼後），確保單一 Firestore 文件不超過大小限制
const ATTACHMENTS_COLLECTION = "attachments";

const KEYWORDS = {
  symptom: ["痛", "癢", "腫", "咳嗽", "發燒", "頭暈", "噁心", "嘔吐", "疲倦", "喘", "麻", "酸", "拉肚子", "便秘", "失眠", "食慾", "水腫", "出血", "紅疹"],
  visit: ["看診", "掛號", "門診", "醫生", "醫師", "醫院", "診所", "回診", "急診", "轉診"],
  exam: ["檢查", "抽血", "X光", "X 光", "超音波", "報告", "斷層", "核磁共振", "MRI", "CT", "心電圖", "內視鏡"],
  med: ["藥", "服用", "劑量", "mg", "顆", "錠", "針劑", "打針", "副作用"]
};

// Sensitive pattern redaction: Taiwan ID, phone numbers, common NHI-card-like long digit runs
const SENSITIVE_PATTERNS = [
  { re: /\b[A-Za-z][12]\d{8}\b/g, label: "身分證字號" },
  { re: /\b09\d{2}[- ]?\d{3}[- ]?\d{3}\b/g, label: "手機號碼" },
  { re: /\b0\d{1,2}[- ]?\d{3,4}[- ]?\d{4}\b/g, label: "電話號碼" }
];

function redact(text) {
  if (!text) return { text: "", hits: 0 };
  let hits = 0;
  let out = text;
  // 先處理有明確欄位標籤的識別資料（健保匯出報告常見：病患姓名、病歷號碼、出生日期）
  const LABELED = [
    /(病患姓名|受檢者姓名|姓名)\s*[:：]\s*\S+/g,
    /(病歷號碼|病歷号碼|病歷編號)\s*[:：]\s*\S+/g,
    /(出生日期)\s*[:：]\s*[\d/\-]+/g
  ];
  LABELED.forEach(re => {
    out = out.replace(re, (m, label) => { hits++; return `${label}：████`; });
  });
  for (const p of SENSITIVE_PATTERNS) {
    out = out.replace(p.re, (m) => { hits++; return "█".repeat(Math.min(m.length, 10)); });
  }
  return { text: out, hits };
}

// ----------------------------------------------------------------------------
// Small utilities
// ----------------------------------------------------------------------------
const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

function toast(msg) {
  const t = $("#toast");
  t.textContent = msg;
  t.classList.add("show");
  setTimeout(() => t.classList.remove("show"), 2200);
}

async function sha256Hex(str) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, "0")).join("");
}

function todayStr() {
  const d = new Date();
  return d.toISOString().slice(0, 10);
}

function fmtDateLabel(dateStr) {
  const d = new Date(dateStr + "T00:00:00");
  const wd = ["日", "一", "二", "三", "四", "五", "六"][d.getDay()];
  return `${d.getFullYear()}年${d.getMonth() + 1}月${d.getDate()}日（週${wd}）`;
}
function fmtShortDate(dateStr) {
  const d = new Date(dateStr + "T00:00:00");
  return `${d.getMonth() + 1}/${d.getDate()}`;
}

// ============================================================================
// Auth gate (password hash stored in Firestore settings/access)
// ============================================================================
const ACCESS_DOC = () => doc(db, appConfig.settingsCollection, "access");
let lockMode = "enter"; // "enter" | "set"

async function initLockScreen() {
  const snap = await getDoc(ACCESS_DOC());
  const confirmInput = $("#lock-input-confirm");
  if (!snap.exists()) {
    lockMode = "set";
    $("#lock-title").textContent = "設定密碼";
    $("#lock-sub").textContent = "第一次使用，請設定一組全家共用的密碼";
    $("#lock-submit").textContent = "設定密碼並進入";
    confirmInput.style.display = "block";
  } else {
    lockMode = "enter";
    $("#lock-title").textContent = "輸入密碼";
    $("#lock-sub").textContent = "請輸入家人共用密碼";
    $("#lock-submit").textContent = "進入";
    confirmInput.style.display = "none";
  }

  if (localStorage.getItem("hj_unlocked") === "1" && snap.exists()) {
    unlockApp();
  }
}

async function handleLockSubmit() {
  const pw = $("#lock-input").value.trim();
  const err = $("#lock-error");
  err.textContent = "";
  if (!pw) { err.textContent = "請輸入密碼"; return; }

  if (lockMode === "set") {
    const pw2 = $("#lock-input-confirm").value.trim();
    if (pw.length < 4) { err.textContent = "密碼至少 4 碼"; return; }
    if (pw !== pw2) { err.textContent = "兩次輸入的密碼不一致"; return; }
    const hash = await sha256Hex(pw);
    await setDoc(ACCESS_DOC(), { hash, createdAt: serverTimestamp() });
    localStorage.setItem("hj_unlocked", "1");
    unlockApp();
  } else {
    const snap = await getDoc(ACCESS_DOC());
    const hash = await sha256Hex(pw);
    if (snap.exists() && snap.data().hash === hash) {
      localStorage.setItem("hj_unlocked", "1");
      unlockApp();
    } else {
      err.textContent = "密碼錯誤，請再試一次";
    }
  }
}

function unlockApp() {
  $("#lock-screen").style.display = "none";
  $("#app-shell").classList.add("active");
  initUserIdentity();
  startRecordsListener();
}

$("#lock-submit").addEventListener("click", handleLockSubmit);
$("#lock-input").addEventListener("keydown", (e) => { if (e.key === "Enter" && lockMode === "enter") handleLockSubmit(); });
$("#lock-input-confirm").addEventListener("keydown", (e) => { if (e.key === "Enter") handleLockSubmit(); });
$("#lock-app-btn").addEventListener("click", () => {
  localStorage.removeItem("hj_unlocked");
  location.reload();
});

// ============================================================================
// User identity (localStorage-based, shared pattern across family apps)
// ============================================================================
function initUserIdentity() {
  let name = localStorage.getItem("hj_user_name");
  if (!name) {
    name = prompt("第一次使用，請輸入你的稱呼（例如：小明）") || "家人";
    localStorage.setItem("hj_user_name", name);
  }
  $("#user-name-label").textContent = name;
  $("#user-avatar").textContent = name.slice(0, 1);
}
function currentUser() { return localStorage.getItem("hj_user_name") || "家人"; }

// ============================================================================
// Records state + Firestore listener
// ============================================================================
let allRecords = [];
let currentView = "timeline";
let activeCategoryFilters = new Set();
let activeStatusFilters = new Set();
let activePersonFilters = new Set();
let searchTerm = "";
let conditionFilter = null; // { person, cond } | null — 左側病症索引篩選
let selectedTimelineDate = null; // 橫向時間軸目前選取的日期

function startRecordsListener() {
  const q = query(collection(db, appConfig.recordsCollection), orderBy("date", "desc"));
  onSnapshot(q, (snap) => {
    allRecords = snap.docs.map(d => ({ id: d.id, ...d.data() }));
    renderAll();
  }, (err) => {
    console.error(err);
    toast("讀取資料發生問題，請確認 Firebase 設定");
  });
}

// 從標題推導「病症/主題」關鍵字：NHI 匯入的標題常是「機構｜診斷」，取後半段；
// 用藥標題是「機構｜用藥（疾病）」，取括號內容。手動/GPT 紀錄則直接用標題本身。
function deriveConditionKey(record) {
  let t = (record.title || "").trim();
  const barIdx = t.indexOf("｜");
  if (barIdx >= 0) t = t.slice(barIdx + 1).trim();
  const medMatch = t.match(/^用藥（(.+)）$/);
  if (medMatch) t = medMatch[1];
  return t || "其他";
}

function filteredRecords() {
  return allRecords.filter(r => {
    if (activeCategoryFilters.size && !activeCategoryFilters.has(r.category)) return false;
    if (activeStatusFilters.size && !activeStatusFilters.has(r.status)) return false;
    if (activePersonFilters.size && !activePersonFilters.has(r.person || "other")) return false;
    if (conditionFilter) {
      if ((r.person || "other") !== conditionFilter.person) return false;
      if (deriveConditionKey(r) !== conditionFilter.cond) return false;
    }
    if (searchTerm) {
      const hay = [r.title, r.description, (r.tags || []).join(" "), CATEGORY_LABELS[r.category], PERSON_LABELS[r.person]].join(" ").toLowerCase();
      if (!hay.includes(searchTerm.toLowerCase())) return false;
    }
    return true;
  });
}

function renderAll() {
  renderConditionSidebar();
  renderRings();
  renderCounts();
  if (currentView === "timeline") renderTimeline(); else renderList();
}

// ----------------------------------------------------------------------------
// Condition-index sidebar (病症索引) — derived from records, per person
// ----------------------------------------------------------------------------
let conditionEntries = [];
function renderConditionSidebar() {
  const el = $("#condition-sidebar");
  if (!el) return;
  const byPerson = {};
  allRecords.forEach(r => {
    const p = r.person || "other";
    const key = deriveConditionKey(r);
    byPerson[p] = byPerson[p] || {};
    byPerson[p][key] = (byPerson[p][key] || 0) + 1;
  });
  conditionEntries = [];
  const order = ["mother", "father", "other"];
  let html = "";
  order.filter(p => byPerson[p]).forEach(p => {
    const conditions = Object.entries(byPerson[p]).sort((a, b) => b[1] - a[1]);
    html += `<div class="condition-person-block">
      <div class="condition-person-name"><span class="person-pill ${p}">${PERSON_LABELS[p]}</span></div>`;
    conditions.forEach(([cond, count]) => {
      const i = conditionEntries.length;
      conditionEntries.push({ person: p, cond });
      const active = conditionFilter && conditionFilter.person === p && conditionFilter.cond === cond;
      html += `<div class="condition-item ${active ? "active" : ""}" data-i="${i}" title="${escapeHtml(cond)}">
        <span>${escapeHtml(cond)}</span><span class="count">${count}</span></div>`;
    });
    html += `</div>`;
  });
  if (!html) html = `<div class="condition-empty-hint">尚無資料，新增或匯入紀錄後，這裡會自動列出每位家人的病症索引。</div>`;
  if (conditionFilter) html += `<button class="condition-clear-btn" id="condition-clear-btn">✕ 清除病症篩選</button>`;
  el.innerHTML = html;
  el.querySelectorAll(".condition-item").forEach(item => {
    item.addEventListener("click", () => {
      const entry = conditionEntries[Number(item.dataset.i)];
      conditionFilter = (conditionFilter && conditionFilter.person === entry.person && conditionFilter.cond === entry.cond) ? null : entry;
      renderAll();
    });
  });
  const clearBtn = $("#condition-clear-btn");
  if (clearBtn) clearBtn.addEventListener("click", () => { conditionFilter = null; renderAll(); });
}

// ----------------------------------------------------------------------------
// Health rings (signature element)
// ----------------------------------------------------------------------------
function renderRings() {
  const total = allRecords.length || 1;
  const c = { active: 0, tracking: 0, done: 0 };
  allRecords.forEach(r => { if (c[r.status] !== undefined) c[r.status]++; });
  $("#count-active").textContent = c.active;
  $("#count-tracking").textContent = c.tracking;
  $("#count-done").textContent = c.done;

  const rings = [
    { r: 44, color: "var(--status-active)", pct: c.active / total },
    { r: 33, color: "var(--status-tracking)", pct: c.tracking / total },
    { r: 22, color: "var(--status-done)", pct: c.done / total }
  ];
  let svg = "";
  rings.forEach(ring => {
    const circ = 2 * Math.PI * ring.r;
    const dash = Math.max(circ * ring.pct, ring.pct > 0 ? 4 : 0);
    svg += `<circle cx="50" cy="50" r="${ring.r}" fill="none" stroke="var(--divider-soft)" stroke-width="7"/>`;
    svg += `<circle cx="50" cy="50" r="${ring.r}" fill="none" stroke="${ring.color}" stroke-width="7"
      stroke-dasharray="${dash} ${circ}" stroke-linecap="round"
      transform="rotate(-90 50 50)" />`;
  });
  svg += `<text x="50" y="54" text-anchor="middle" font-size="15" font-weight="800" fill="var(--text-primary)">${allRecords.length}</text>`;
  $("#rings-svg").innerHTML = svg;
}

function renderCounts() {
  const n = filteredRecords().length;
  let text = n === 0 ? "尚無紀錄" : `共 ${n} 筆紀錄`;
  if (conditionFilter) text += `｜篩選中：${PERSON_LABELS[conditionFilter.person]} · ${conditionFilter.cond}`;
  $("#record-count-sub").textContent = text;
}

// ----------------------------------------------------------------------------
// Timeline view
// ----------------------------------------------------------------------------
function renderTimeline() {
  const el = $("#timeline-view");
  const recs = filteredRecords();
  if (!recs.length) {
    el.innerHTML = emptyStateHtml();
    return;
  }
  const groups = {};
  recs.forEach(r => { (groups[r.date] = groups[r.date] || []).push(r); });
  const dates = Object.keys(groups).sort((a, b) => b.localeCompare(a)); // 最新在左

  if (!selectedTimelineDate || !groups[selectedTimelineDate]) selectedTimelineDate = dates[0];

  const stripHtml = dates.map(date => {
    const items = groups[date];
    const cats = [...new Set(items.map(i => i.category))];
    const active = date === selectedTimelineDate;
    return `
      <div class="h-timeline-marker ${active ? "active" : ""}" data-date="${date}">
        <div class="date-label">${fmtShortDate(date)}</div>
        <div class="h-dots">${cats.slice(0, 4).map(c => `<span class="dot" style="background:var(--c-${c})"></span>`).join("")}</div>
        <div class="h-count">${items.length}筆</div>
      </div>`;
  }).join("");

  const detailItems = groups[selectedTimelineDate] || [];
  const detailHtml = `
    <div class="timeline-date-label">${fmtDateLabel(selectedTimelineDate)}</div>
    ${detailItems.map(cardHtml).join("")}
  `;

  el.innerHTML = `
    <div class="h-timeline" id="h-timeline">${stripHtml}</div>
    <div class="h-timeline-detail">${detailHtml}</div>
  `;

  el.querySelectorAll(".h-timeline-marker").forEach(m => {
    m.addEventListener("click", () => {
      selectedTimelineDate = m.dataset.date;
      renderTimeline();
    });
  });
  const activeMarker = el.querySelector(".h-timeline-marker.active");
  if (activeMarker) activeMarker.scrollIntoView({ inline: "center", block: "nearest" });

  el.querySelectorAll(".record-card").forEach(card => {
    card.addEventListener("click", () => openEditModal(card.dataset.id));
  });
}

function cardHtml(r) {
  const tags = (r.tags || []).slice(0, 3).map(t => `<span class="tag-pill">${escapeHtml(t)}</span>`).join("");
  const attachCount = r.attachmentCount || 0;
  return `
    <div class="record-card" data-id="${r.id}">
      <div class="record-icon ${r.category}">${CATEGORY_ICONS[r.category] || "📝"}</div>
      <div class="record-body">
        <div class="record-top">
          <div class="record-title">${escapeHtml(r.title || "（未命名）")}</div>
          <div class="record-time">${r.time || ""}</div>
        </div>
        ${r.description ? `<div class="record-desc">${escapeHtml(r.description)}</div>` : ""}
        <div class="record-meta">
          <span class="person-pill ${r.person || "other"}">${PERSON_LABELS[r.person] || "其他"}</span>
          <span class="status-pill ${r.status}">${r.status === "done" ? '<span class="check-mark">✓</span>' : ""}${STATUS_LABELS[r.status] || ""}</span>
          ${tags}
          ${attachCount ? `<span class="attach-badge">📎 ${attachCount}</span>` : ""}
        </div>
      </div>
    </div>`;
}

function emptyStateHtml() {
  return `<div class="empty-state"><div class="emoji">🗒️</div><p>目前沒有符合條件的紀錄，點右下角「＋」新增第一筆吧</p></div>`;
}

// ----------------------------------------------------------------------------
// List view
// ----------------------------------------------------------------------------
function renderList() {
  const el = $("#list-view");
  const recs = filteredRecords();
  if (!recs.length) { el.innerHTML = emptyStateHtml(); return; }
  el.innerHTML = `
    <table class="list-table">
      <thead><tr><th>家人</th><th>日期</th><th>分類</th><th>標題</th><th>狀態</th><th>標籤</th></tr></thead>
      <tbody>
        ${recs.map(r => `
          <tr data-id="${r.id}">
            <td><span class="person-pill ${r.person || "other"}">${PERSON_LABELS[r.person] || "其他"}</span></td>
            <td>${r.date}${r.time ? " " + r.time : ""}</td>
            <td><span class="list-cat-dot" style="background:var(--c-${r.category})"></span>${CATEGORY_LABELS[r.category] || ""}</td>
            <td>${escapeHtml(r.title || "")}</td>
            <td><span class="status-pill ${r.status}">${STATUS_LABELS[r.status] || ""}</span></td>
            <td>${(r.tags || []).map(t => `<span class="tag-pill">${escapeHtml(t)}</span>`).join(" ")}</td>
          </tr>
        `).join("")}
      </tbody>
    </table>`;
  el.querySelectorAll("tr[data-id]").forEach(row => {
    row.addEventListener("click", () => openEditModal(row.dataset.id));
  });
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

// ----------------------------------------------------------------------------
// View toggle / filters / search wiring
// ----------------------------------------------------------------------------
$$(".view-toggle button").forEach(btn => {
  btn.addEventListener("click", () => {
    $$(".view-toggle button").forEach(b => b.classList.remove("active"));
    btn.classList.add("active");
    currentView = btn.dataset.view;
    $("#timeline-view").style.display = currentView === "timeline" ? "" : "none";
    $("#list-view").style.display = currentView === "list" ? "" : "none";
    renderAll();
  });
});

$$("#category-chips .chip").forEach(chip => {
  chip.addEventListener("click", () => {
    const cat = chip.dataset.cat;
    chip.classList.toggle("active");
    if (activeCategoryFilters.has(cat)) activeCategoryFilters.delete(cat); else activeCategoryFilters.add(cat);
    renderAll();
  });
});
$$("#status-chips .chip").forEach(chip => {
  chip.addEventListener("click", () => {
    const st = chip.dataset.status;
    chip.classList.toggle("active");
    if (activeStatusFilters.has(st)) activeStatusFilters.delete(st); else activeStatusFilters.add(st);
    renderAll();
  });
});
$$("#person-chips .chip").forEach(chip => {
  chip.addEventListener("click", () => {
    const p = chip.dataset.person;
    chip.classList.toggle("active");
    if (activePersonFilters.has(p)) activePersonFilters.delete(p); else activePersonFilters.add(p);
    renderAll();
  });
});
$("#search-input").addEventListener("input", (e) => {
  searchTerm = e.target.value.trim();
  renderAll();
});

// ============================================================================
// Navigation (routes)
// ============================================================================
function setRoute(route) {
  $$('.nav-item').forEach(n => n.classList.toggle("active", n.dataset.route === route));
  $("#page-timeline").style.display = route === "timeline" ? "" : "none";
  $("#page-import").style.display = route === "import" ? "" : "none";
  $("#fab-add").style.display = route === "timeline" ? "flex" : "none";
}
$$('.nav-item').forEach(item => item.addEventListener("click", () => setRoute(item.dataset.route)));

// ============================================================================
// Add / Edit modal
// ============================================================================
let editingId = null;
let formAttachments = [];
let formCategory = "symptom";
let formStatus = "tracking";
let formPerson = "mother";

function openAddModal() {
  editingId = null;
  formAttachments = [];
  formCategory = "symptom";
  formStatus = "tracking";
  formPerson = localStorage.getItem("hj_last_person") || "mother";
  $("#modal-title").textContent = "新增紀錄";
  $("#delete-record-btn").style.display = "none";
  $("#f-date").value = todayStr();
  $("#f-time").value = "";
  $("#f-title").value = "";
  $("#f-desc").value = "";
  $("#f-tags").value = "";
  syncCategoryButtons();
  syncStatusButtons();
  syncPersonButtons();
  renderAttachList();
  $("#record-modal").classList.add("active");
}

async function openEditModal(id) {
  const r = allRecords.find(x => x.id === id);
  if (!r) return;
  editingId = id;
  formAttachments = [];
  formCategory = r.category || "symptom";
  formStatus = r.status || "tracking";
  formPerson = r.person || "mother";
  $("#modal-title").textContent = "編輯紀錄";
  $("#delete-record-btn").style.display = "inline-block";
  $("#f-date").value = r.date || todayStr();
  $("#f-time").value = r.time || "";
  $("#f-title").value = r.title || "";
  $("#f-desc").value = r.description || "";
  $("#f-tags").value = (r.tags || []).join(", ");
  syncCategoryButtons();
  syncStatusButtons();
  syncPersonButtons();
  renderAttachList();
  $("#record-modal").classList.add("active");

  // 附件存在獨立的 attachments 集合，開啟編輯視窗時才查詢載入
  try {
    const snap = await getDocs(query(collection(db, ATTACHMENTS_COLLECTION), where("recordId", "==", id)));
    formAttachments = snap.docs.map(d => ({ id: d.id, saved: true, ...d.data() }));
    if (editingId === id) renderAttachList();
  } catch (err) {
    console.error(err);
  }
}

function closeModal() { $("#record-modal").classList.remove("active"); }
$("#modal-close-btn").addEventListener("click", closeModal);
$("#cancel-record-btn").addEventListener("click", closeModal);
$("#fab-add").addEventListener("click", openAddModal);

function syncCategoryButtons() {
  $$("#f-category button").forEach(b => b.classList.toggle("active", b.dataset.cat === formCategory));
}
function syncStatusButtons() {
  $$("#f-status button").forEach(b => b.classList.toggle("active", b.dataset.status === formStatus));
}
function syncPersonButtons() {
  $$("#f-person button").forEach(b => b.classList.toggle("active", b.dataset.person === formPerson));
}
$$("#f-category button").forEach(b => b.addEventListener("click", () => { formCategory = b.dataset.cat; syncCategoryButtons(); }));
$$("#f-status button").forEach(b => b.addEventListener("click", () => { formStatus = b.dataset.status; syncStatusButtons(); }));
$$("#f-person button").forEach(b => b.addEventListener("click", () => { formPerson = b.dataset.person; localStorage.setItem("hj_last_person", formPerson); syncPersonButtons(); }));

function fmtBytes(n) {
  if (!n) return "";
  if (n < 1024) return `${n} B`;
  return `${(n / 1024).toFixed(0)} KB`;
}

function renderAttachList() {
  const el = $("#attach-list");
  el.innerHTML = formAttachments.map((a, i) => `
    <div class="attach-row">
      <a href="${a.dataUrl}" target="_blank" rel="noopener">${escapeHtml(a.name)}</a>
      <span class="upload-progress">${fmtBytes(a.size)}</span>
      <button class="attach-remove" data-i="${i}" type="button">移除</button>
    </div>`).join("");
  el.querySelectorAll(".attach-remove").forEach(btn => {
    btn.addEventListener("click", async () => {
      const i = Number(btn.dataset.i);
      const a = formAttachments[i];
      if (a.saved && a.id) {
        try { await deleteDoc(doc(db, ATTACHMENTS_COLLECTION, a.id)); } catch (e) { console.warn(e); }
      }
      formAttachments.splice(i, 1);
      renderAttachList();
    });
  });
}

// 讀檔為 data URL
function readFileAsDataUrl(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result);
    reader.onerror = reject;
    reader.readAsDataURL(file);
  });
}

// base64 字元數換算實際位元組數（粗估）
function base64ByteSize(dataUrl) {
  const commaIdx = dataUrl.indexOf(",");
  const b64 = commaIdx >= 0 ? dataUrl.slice(commaIdx + 1) : dataUrl;
  return Math.floor(b64.length * 0.75);
}

// 圖片壓縮：縮小尺寸並轉 JPEG，降低 base64 大小
function compressImage(file, maxDim, quality) {
  return new Promise((resolve, reject) => {
    const img = new Image();
    const reader = new FileReader();
    reader.onload = () => { img.src = reader.result; };
    reader.onerror = reject;
    img.onload = () => {
      let { width, height } = img;
      if (width > maxDim || height > maxDim) {
        const scale = maxDim / Math.max(width, height);
        width = Math.round(width * scale);
        height = Math.round(height * scale);
      }
      const canvas = document.createElement("canvas");
      canvas.width = width; canvas.height = height;
      const ctx = canvas.getContext("2d");
      ctx.drawImage(img, 0, 0, width, height);
      resolve(canvas.toDataURL("image/jpeg", quality));
    };
    img.onerror = reject;
    reader.readAsDataURL(file);
  });
}

// 將檔案轉為可存進 Firestore 的附件物件（含大小限制）
async function fileToAttachment(file) {
  if (file.type.startsWith("image/")) {
    let dataUrl = await compressImage(file, 1600, 0.75);
    if (base64ByteSize(dataUrl) > ATTACH_MAX_BYTES) dataUrl = await compressImage(file, 1100, 0.6);
    if (base64ByteSize(dataUrl) > ATTACH_MAX_BYTES) dataUrl = await compressImage(file, 800, 0.5);
    const size = base64ByteSize(dataUrl);
    if (size > ATTACH_MAX_BYTES) throw new Error("TOO_LARGE");
    return { name: file.name, type: "image/jpeg", dataUrl, size };
  } else {
    const dataUrl = await readFileAsDataUrl(file);
    const size = base64ByteSize(dataUrl);
    if (size > ATTACH_MAX_BYTES) throw new Error("TOO_LARGE");
    return { name: file.name, type: file.type, dataUrl, size };
  }
}

$("#upload-btn").addEventListener("click", () => $("#attach-input").click());
$("#attach-input").addEventListener("change", async (e) => {
  const files = Array.from(e.target.files || []);
  if (!files.length) return;
  $("#upload-progress").textContent = "處理中…";
  for (const file of files) {
    try {
      const attachment = await fileToAttachment(file);
      formAttachments.push(attachment);
    } catch (err) {
      if (err && err.message === "TOO_LARGE") {
        toast(`「${file.name}」檔案太大（上限約 ${Math.round(ATTACH_MAX_BYTES / 1024)}KB），請先壓縮後再上傳`);
      } else {
        console.error(err);
        toast("附件處理失敗");
      }
    }
  }
  $("#upload-progress").textContent = "";
  e.target.value = "";
  renderAttachList();
});

$("#save-record-btn").addEventListener("click", async () => {
  const date = $("#f-date").value || todayStr();
  const time = $("#f-time").value || "";
  const title = $("#f-title").value.trim();
  const descRaw = $("#f-desc").value.trim();
  const tags = $("#f-tags").value.split(",").map(t => t.trim()).filter(Boolean);

  if (!title) { toast("請輸入標題"); return; }

  const { text: description, hits } = redact(descRaw);
  const { text: safeTitle } = redact(title);

  const payload = {
    date, time, title: safeTitle, description,
    tags, category: formCategory, status: formStatus, person: formPerson,
    attachmentCount: formAttachments.length,
    createdBy: currentUser(),
    updatedAt: serverTimestamp()
  };

  try {
    let recordId = editingId;
    if (editingId) {
      await updateDoc(doc(db, appConfig.recordsCollection, editingId), payload);
    } else {
      payload.source = "manual";
      payload.createdAt = serverTimestamp();
      const newDoc = await addDoc(collection(db, appConfig.recordsCollection), payload);
      recordId = newDoc.id;
    }
    // 儲存尚未寫入 Firestore 的新附件（已存在的附件不需重寫）
    const newAttachments = formAttachments.filter(a => !a.saved);
    for (const a of newAttachments) {
      await addDoc(collection(db, ATTACHMENTS_COLLECTION), {
        recordId, name: a.name, type: a.type, dataUrl: a.dataUrl, size: a.size,
        createdAt: serverTimestamp()
      });
    }
    if (hits > 0) toast(`已儲存（偵測到 ${hits} 處疑似敏感資料已自動遮蔽）`);
    else toast("已儲存");
    closeModal();
  } catch (err) {
    console.error(err);
    toast("儲存失敗，請確認 Firebase 設定");
  }
});

$("#delete-record-btn").addEventListener("click", async () => {
  if (!editingId) return;
  if (!confirm("確定要刪除這筆紀錄嗎？此操作無法復原。")) return;
  try {
    const attSnap = await getDocs(query(collection(db, ATTACHMENTS_COLLECTION), where("recordId", "==", editingId)));
    await Promise.all(attSnap.docs.map(d => deleteDoc(doc(db, ATTACHMENTS_COLLECTION, d.id))));
    await deleteDoc(doc(db, appConfig.recordsCollection, editingId));
    toast("已刪除");
    closeModal();
  } catch (err) {
    console.error(err);
    toast("刪除失敗");
  }
});

// ============================================================================
// GPT import
// ============================================================================
let draftEntries = [];

function guessCategory(text) {
  for (const cat of Object.keys(KEYWORDS)) {
    if (KEYWORDS[cat].some(kw => text.includes(kw))) return cat;
  }
  return "note";
}

function guessDate(text, fallbackDate) {
  let m = text.match(/(\d{4})[-/](\d{1,2})[-/](\d{1,2})/);
  if (m) return `${m[1]}-${String(m[2]).padStart(2, "0")}-${String(m[3]).padStart(2, "0")}`;
  m = text.match(/(\d{1,2})[-/](\d{1,2})/);
  if (m && fallbackDate) {
    const y = fallbackDate.slice(0, 4);
    return `${y}-${String(m[1]).padStart(2, "0")}-${String(m[2]).padStart(2, "0")}`;
  }
  if (text.includes("今天")) return fallbackDate || todayStr();
  if (text.includes("昨天") && fallbackDate) {
    const d = new Date(fallbackDate); d.setDate(d.getDate() - 1);
    return d.toISOString().slice(0, 10);
  }
  return fallbackDate || todayStr();
}

// Flatten a ChatGPT conversations.json export (mapping tree) into ordered messages
function flattenChatGptExport(json) {
  const conversations = Array.isArray(json) ? json : [json];
  const messages = [];
  conversations.forEach(conv => {
    const mapping = conv.mapping;
    if (!mapping) return;
    Object.values(mapping).forEach(node => {
      const msg = node.message;
      if (!msg || !msg.content || !msg.content.parts) return;
      const text = msg.content.parts.filter(p => typeof p === "string").join("\n").trim();
      if (!text) return;
      const role = msg.author && msg.author.role;
      if (role !== "user" && role !== "assistant") return;
      const ts = msg.create_time ? new Date(msg.create_time * 1000) : null;
      messages.push({ role, text, date: ts ? ts.toISOString().slice(0, 10) : null });
    });
  });
  return messages;
}

function buildDraftsFromMessages(messages) {
  let fallbackDate = messages.find(m => m.date)?.date || todayStr();
  const drafts = [];
  messages.forEach((m, idx) => {
    if (m.role !== "user") return;
    const hitCategory = Object.keys(KEYWORDS).some(cat => KEYWORDS[cat].some(kw => m.text.includes(kw)));
    if (!hitCategory) return;
    const date = m.date || guessDate(m.text, fallbackDate);
    if (m.date) fallbackDate = m.date;
    const category = guessCategory(m.text);
    const reply = messages[idx + 1] && messages[idx + 1].role === "assistant" ? messages[idx + 1].text : "";
    const fullText = reply ? `${m.text}\n\n（AI 回覆參考）\n${reply}` : m.text;
    const { text: safeText, hits } = redact(fullText);
    drafts.push({
      date, category, status: "tracking", person: "other",
      title: m.text.slice(0, 24).replace(/\n/g, " "),
      description: safeText,
      tags: [],
      hits,
      include: true
    });
  });
  return drafts;
}

function buildDraftsFromPlainText(text) {
  const blocks = text.split(/\n\s*\n/).map(b => b.trim()).filter(Boolean);
  const fallbackDate = todayStr();
  return blocks.map(block => {
    const category = guessCategory(block);
    const date = guessDate(block, fallbackDate);
    const { text: safeText, hits } = redact(block);
    return {
      date, category, status: "tracking", person: "other",
      title: block.slice(0, 24).replace(/\n/g, " "),
      description: safeText,
      tags: [],
      hits,
      include: true
    };
  });
}

// 將 "2026-04-01"／"2026-04"／"2026" 統一補成完整日期，並標記是否為概略日期
function normalizeApproxDate(raw) {
  if (!raw) return { date: todayStr(), approx: true };
  const s = String(raw).trim();
  if (/^\d{4}-\d{2}-\d{2}$/.test(s)) return { date: s, approx: false };
  if (/^\d{4}-\d{2}$/.test(s)) return { date: `${s}-01`, approx: true };
  if (/^\d{4}$/.test(s)) return { date: `${s}-01-01`, approx: true };
  return { date: guessDate(s, todayStr()), approx: true };
}

// 偵測是否為「依家人分類」的結構化健康 JSON（例如 { people: { mother: {...}, father: {...} } }）
function looksLikeStructuredHealthJson(json) {
  return !!(json && typeof json === "object" && json.people && typeof json.people === "object");
}

function mapStructuredStatus(status) {
  const map = { completed: "done", follow_up: "tracking", observation: "tracking", pending: "active" };
  return map[status] || "tracking";
}

// 將結構化的個人時間軸（symptoms/medical_findings/treatment/...）組成可讀描述
function buildStructuredDescription(entry, approxDate) {
  const parts = [];
  const pushList = (label, arr) => {
    if (Array.isArray(arr) && arr.length) parts.push(`【${label}】\n` + arr.map(s => `・${s}`).join("\n"));
  };
  pushList("症狀", entry.symptoms);
  pushList("檢查/診斷", entry.medical_findings);
  pushList("治療方式", entry.treatment);
  if (Array.isArray(entry.options) && entry.options.length) {
    pushList("方案選項", entry.options.map(o => `${o.type || ""}${o.note ? "：" + o.note : ""}`));
  }
  pushList("相關病史", entry.history);
  pushList("AI 分析參考（僅供參考，非診斷）", entry.gpt_analysis);
  pushList("建議", entry.recommendation);
  pushList("日常照護", entry.daily_care);
  pushList("摘要", entry.summary);
  pushList("補充說明", entry.gpt_summary);
  if (approxDate) parts.unshift("（原始日期僅精確到月／年，請確認並視需要調整）");
  return parts.join("\n\n");
}

function buildDraftsFromStructuredJson(json) {
  const drafts = [];
  Object.entries(json.people).forEach(([personKey, personData]) => {
    const person = PERSON_LABELS[personKey] ? personKey : "other";
    const timeline = Array.isArray(personData.timeline) ? personData.timeline : [];
    timeline.forEach(entry => {
      const { date, approx } = normalizeApproxDate(entry.date);
      const combinedText = [entry.title, entry.category, ...(entry.symptoms || []), ...(entry.treatment || []), ...(entry.medical_findings || [])].join(" ");
      const category = guessCategory(combinedText);
      const status = mapStructuredStatus(entry.status);
      const description = buildStructuredDescription(entry, approx);
      const { text: safeDesc, hits } = redact(description);
      const tags = entry.category ? [entry.category] : [];
      drafts.push({
        date, category, status, person,
        title: (entry.title || entry.category || "健康紀錄").slice(0, 30),
        description: safeDesc, tags, hits, include: true
      });
    });
  });
  return drafts;
}

// ============================================================================
// 健保快易通資料匯入（門診／用藥／影像病理／檢驗檢查結果 HTML 匯出檔）
// ============================================================================
function nhiCellText(el) {
  return (el.textContent || "").replace(/\u00A0/g, " ").replace(/\s+/g, " ").trim();
}
function rocToIso(raw) {
  if (!raw) return null;
  const m = String(raw).trim().match(/^(\d{2,3})\/(\d{1,2})\/(\d{1,2})/);
  if (!m) return null;
  const y = parseInt(m[1], 10) + 1911;
  return `${y}-${String(m[2]).padStart(2, "0")}-${String(m[3]).padStart(2, "0")}`;
}

function detectNhiKind(doc) {
  const t = (doc.querySelector("title")?.textContent || "") + " " + (doc.body?.textContent || "").slice(0, 400);
  if (t.includes("門診資料")) return "visit";
  if (t.includes("用藥資料")) return "med";
  if (t.includes("影像或病理")) return "imaging";
  if (t.includes("檢驗檢查結果") || t.includes("檢驗檢查")) return "lab";
  return null;
}

function biggestListTable(doc) {
  const tables = [...doc.querySelectorAll("table.list")];
  if (!tables.length) return null;
  return tables.sort((a, b) => b.querySelectorAll("tr").length - a.querySelectorAll("tr").length)[0];
}

// ---- 門診資料 ----
function parseNhiVisitTable(doc) {
  const table = biggestListTable(doc);
  if (!table) return [];
  const rows = [...table.querySelectorAll("tr")];
  const groups = [];
  let current = null, subState = 0;
  rows.forEach(tr => {
    const tds = [...tr.children].filter(el => el.tagName === "TD");
    if (!tds.length || tds.length === 1) return;
    const texts = tds.map(nhiCellText);
    if (tds.length >= 10 && texts[0]) {
      if (current) groups.push(current);
      current = {
        institution: texts[1], date: rocToIso(texts[2]),
        mainDiagCode: texts[5], mainDiagName: texts[6],
        mainProcCode: texts[7], mainProcName: texts[8],
        subDiag: [], subProc: [], orders: []
      };
      subState = 1;
    } else if (tds.length >= 10 && !texts[0] && current) {
      if (subState === 1) {
        for (let i = 1; i < texts.length; i += 2) if (texts[i]) current.subDiag.push(`${texts[i]} ${texts[i + 1] || ""}`.trim());
        subState = 2;
      } else if (subState === 2) {
        for (let i = 1; i < texts.length; i += 2) if (texts[i]) current.subProc.push(`${texts[i]} ${texts[i + 1] || ""}`.trim());
        subState = 3;
      }
    } else if (tds.length === 4 && current) {
      if (texts[2]) current.orders.push(texts[2]);
    }
  });
  if (current) groups.push(current);
  return groups.filter(g => g.date);
}

// ---- 用藥資料 ----
function parseNhiMedTable(doc) {
  const table = biggestListTable(doc);
  if (!table) return [];
  const rows = [...table.querySelectorAll("tr")];
  const groups = [];
  let current = null;
  rows.forEach(tr => {
    const tds = [...tr.children].filter(el => el.tagName === "TD");
    if (!tds.length || tds.length === 1) return;
    const texts = tds.map(nhiCellText);
    if (tds.length === 9 && texts[0]) {
      if (current) groups.push(current);
      current = { institution: texts[1], date: rocToIso(texts[2]), dischargeDate: rocToIso(texts[3]), diseaseCode: texts[7], diseaseName: texts[8], drugs: [] };
    } else if (tds.length === 8 && current) {
      if (texts[2]) current.drugs.push({ code: texts[1], name: texts[2], drugClass: texts[3], days: texts[4], qty: texts[7] });
    }
  });
  if (current) groups.push(current);
  return groups.filter(g => g.date);
}

// ---- 影像或病理檢查資料 ----
function parseNhiImagingTable(doc) {
  const table = biggestListTable(doc);
  if (!table) return [];
  const rows = [...table.querySelectorAll("tr")];
  const groups = [];
  let current = null;
  rows.forEach(tr => {
    const tds = [...tr.children].filter(el => el.tagName === "TD");
    if (!tds.length) return;
    const texts = tds.map(nhiCellText);
    if (tds.length === 7) {
      if (current) groups.push(current);
      current = {
        institution: texts[1], visitDate: rocToIso(texts[2]), examDate: rocToIso(texts[3]) || rocToIso(texts[2]),
        orderCode: texts[5], orderName: texts[6], reportText: ""
      };
    } else if (tds.length === 1 && current) {
      const txt = nhiCellText(tds[0]);
      if (txt.length > 5) current.reportText = (current.reportText ? current.reportText + "\n" : "") + txt;
    }
  });
  if (current) groups.push(current);
  return groups.filter(g => g.examDate || g.visitDate);
}

// ---- 檢驗檢查結果 ----
function parseNhiLabTable(doc) {
  const table = biggestListTable(doc);
  if (!table) return [];
  const rows = [...table.querySelectorAll("tr")];
  const items = [];
  rows.forEach(tr => {
    const tds = [...tr.children].filter(el => el.tagName === "TD");
    if (tds.length < 10) return;
    const texts = tds.map(nhiCellText);
    if (!texts[1] && !texts[2]) return;
    items.push({
      institution: texts[1], examDate: rocToIso(texts[3]) || rocToIso(texts[2]),
      itemName: texts[7], value: texts[8], unit: texts[9], ref: texts[10]
    });
  });
  const groups = {};
  items.forEach(it => {
    if (!it.examDate) return;
    const key = `${it.institution}__${it.examDate}`;
    (groups[key] = groups[key] || { institution: it.institution, examDate: it.examDate, items: [] }).items.push(it);
  });
  return Object.values(groups);
}

// 常見英文報告全文對照（來自實際健保報告樣本，逐句人工核對翻譯）。
// 找到完全比對時會在原文後方附加中文參考翻譯，找不到的英文內容會保留原文並標註提醒。
const NHI_REPORT_TRANSLATIONS = [
  { en: "Purpose for Endoscopy : Ana mass", zh: "檢查目的：肛門腫塊" },
  { en: "Pre-medication : IV Conscious sedation by anesthesiologist; Fucon 20mg i.m.", zh: "術前用藥：由麻醉科醫師執行靜脈鎮靜；肌肉注射 Fucon 20mg" },
  { en: "Colonoscopic Findings : Up to 80cm from anal verge (to the cecum) showed: -Colon preparation regimen: BK -Colon preparation quality: BPPS 8 -Time from anus to cecum: 4 minutes 20 seconds. -Ileocecal valve: essentially normal. -Internal and external hemorrhoid.", zh: "大腸鏡檢查所見：內視鏡由肛門口深入約80公分（達盲腸），腸道清潔藥物：BK方案；腸道清潔品質：BPPS評分8分；由肛門至盲腸所需時間：4分20秒；迴盲瓣：大致正常；內痔合併外痔。" },
  { en: "Endoscopic diagnosis : Hemorrhoids, mixed", zh: "內視鏡診斷：混合痔（內外痔）" },
  { en: "Advice : Follow up", zh: "建議：門診追蹤" },
  { en: "Film of regular chest:P-A upright. There is tortuous of the aorta noted.The heart and mediastinum revealed essential negative.Evidence of exaggeration and coarse of lung markings over both lungs are seen.The bony thoracic cage and both hemidiaphragm are essential intact. Impression:There are tortuous of the aorta and exaggeration, coarse of lung markings over both lungs noted.",
    zh: "一般胸部X光（後前站立位）：主動脈可見迂曲；心臟及縱膈腔大致正常；雙側肺紋理增加且變粗；胸廓骨骼及雙側橫膈大致完整。診斷印象：主動脈迂曲，雙側肺紋理增加且變粗。" },
  { en: "Film of the ches:Left lateral view. Impression:Tortuous of aorta and exaggeration markings over lung fields are showed.",
    zh: "胸部X光（左側面）：診斷印象：主動脈迂曲，肺野紋理增加。" },
  { en: "C-T scan of brain,chest and abdomen,without enhancement revealed: The heart and mediastineal great vessels are essential negative.Prominent,coarse of bronchovascular markings over both lungs, evidence of bronchiectasis over left upper and focal pleural thickness over both lower,a granuloma over right middle are showed. There were no evidence of mediastineal LAP. The liver,spleen,pancreas and both kidneys are essential negative but hepatic cysts. The gallbladder is normal visualized without opaque stones. No significant abnormal findings of the visualized bowel loops or evidece of ascites,retroperitoneal lymph adenopathies were demonstrated. Old compression fracture of T12 and post-op with hysterectomy are showed. Impression:Chronic inflammatory process over both lungs,bronchiectasis over left upper and pleural thickness over left lower. Focal pleural thickness with granuloma over right middle. Hpatic cysts,old compressio fracture of T12 ad post hysterectomy.",
    zh: "腦部、胸部及腹部電腦斷層（未打顯影劑）：心臟及縱膈腔大血管大致正常；雙側肺支氣管血管紋理明顯增粗，左上肺可見支氣管擴張，雙下肺局部胸膜增厚，右中肺可見一處肉芽腫；未見縱膈腔淋巴腫大證據；肝、脾、胰臟及雙腎大致正常，但肝臟有囊腫；膽囊型態正常，未見顯影結石；腸道未見明顯異常，亦無腹水或後腹腔淋巴腫大證據；可見第12胸椎陳舊性壓迫性骨折，及子宮切除手術後改變。診斷印象：雙側肺部慢性發炎反應，左上肺支氣管擴張及左下肺胸膜增厚；右中肺局部胸膜增厚合併肉芽腫；肝囊腫；第12胸椎陳舊性壓迫性骨折；子宮切除術後狀態。" },
  { en: "CT scan of the chest without contrast enhancement shows: 1. Bronchiectases and subsegmental atelectases in LUL LLL and RML. 2. Multiple small (＜0.4cm) subpleural peribronchial and centrilobular nodules in both lungs. 3. Small mediastinal lymph nodes. 4. No pleural effusion. 5. Multiple calcified nodules in left neck. 6. Cysts in liver. No adrenal mass. 7. Old compression fracture at T11.",
    zh: "胸部電腦斷層（未打顯影劑）：1. 左上肺、左下肺及右中肺可見支氣管擴張及部分肺葉塌陷（肺不張）。2. 雙側肺野可見多處小於0.4公分之胸膜下、支氣管周圍及小葉中心結節。3. 縱膈腔淋巴結稍大但未達異常標準。4. 無肋膜積液。5. 左頸部可見多處鈣化結節。6. 肝臟囊腫，無腎上腺腫塊。7. 第11胸椎陳舊性壓迫性骨折。" },
  { en: "CT scan of the chest without contrast enhancement shows: - Bronchiectases and subsegmental atelectases in LUL LLL and RML. - Multiple small (＜0.4cm) subpleural peribronchial and centrilobular nodules in both lungs. - Small mediastinal lymph nodes. - No pleural effusion. - Multiple calcified nodules in left neck. - Cysts in liver. No adrenal mass. - Old compression fracture at T11.",
    zh: "胸部電腦斷層（未打顯影劑）：支氣管擴張及部分肺葉塌陷（左上肺、左下肺、右中肺）；雙側肺野多處小於0.4公分之胸膜下／支氣管周圍／小葉中心結節；縱膈腔淋巴結稍大但未達異常；無肋膜積液；左頸部多處鈣化結節；肝臟囊腫，無腎上腺腫塊；第11胸椎陳舊性壓迫性骨折。" },
  { en: "Bronchiectases and subsegmental atelectases. Multiple tiny nodules in both lungs suggest follow up. Calcified nodules in left neck.",
    zh: "支氣管擴張及部分肺葉塌陷；雙側肺野多發小結節，建議追蹤；左頸部鈣化結節。" },
  { en: "＞ Clear bilateral costophrenic angle. ＞ Normal heart size. ＞ Clear bilateral lung field. ＞ Intact bony structure. Stationary soft tissue mass, with several nodular calcifications in it, at left side of the neck, is noted.",
    zh: "雙側肋膈角清晰；心臟大小正常；雙側肺野清晰；骨骼結構完整。左頸部可見穩定（無變化）之軟組織腫塊，內含多處結節狀鈣化。" },
  { en: "＞ Clear bilateral lung field.", zh: "雙側肺野清晰。" },
  { en: "Sinus rhythm……normal P axis, V-rate 50- 99 Abnormal R-wave progression, early transition……QRS area＞0 in V2 Repol abnrm suggests ischemia, diffuse leads……ST-T neg, ant/lat/inf Prolonged QT interval……QTc ＞500mS",
    zh: "竇性心律，P波軸正常，心室率50-99；R波遞增異常（過早轉位）；復極異常，提示瀰漫性導程缺血徵象（前壁/側壁/下壁ST-T波呈負向）；QT間期延長，校正後QTc大於500毫秒。" },
  { en: "Sinus rhythm……normal P axis, V-rate 50- 99 Borderline T wave abnormalities……T/QRS ratio ＜ 1/20 or flat T",
    zh: "竇性心律，P波軸正常，心室率50-99；臨界性T波異常（T波/QRS波比小於1/20或T波平坦）。" },
  { en: "Sinus rhythm……normal P axis, V-rate 50- 99", zh: "竇性心律，P波軸正常，心室率50-99。" },
  { en: "＞ Nodular shadow(s) at right lower lung field.", zh: "右下肺野可見結節狀陰影。" },
  { en: "Supine chest AP: ＞ Nodular shadow(s) at right lower lung field. ＞ The heart size is within normal limit.",
    zh: "平躺姿勢胸部X光（前後向）：右下肺野可見結節狀陰影；心臟大小正常範圍內。" },
  { en: "boggy turbinates, left nasal cavity and NP mild mucopus, left VPG, good VF movement",
    zh: "鼻甲黏膜水腫（鬆軟腫脹）；左側鼻腔及鼻咽部有輕微黏膿性分泌物；左側聲帶溝；聲帶活動良好。" },
  { en: "anoscopy:prominent internal hemorrhoids with erythematous change and thromboses at 3, 7, and 11 o`clock directions of anus FOBT:",
    zh: "肛門鏡檢查：可見明顯內痔，合併發紅及血栓變化，位於肛門3點、7點、11點方向。糞便潛血檢查（FOBT）：（未附結果）" },
  { en: "[ Indications ] Anal bleeding,Anal mass [ Findings ] Hemorrhoids： internal, at 3, 7, 11 o ’clock direction, (grade 3) prolapsed internal, at 7 o ’clock direction [ Remarks ] Grade III hemorrhoid",
    zh: "【檢查適應症】肛門出血、肛門腫塊。【檢查所見】痔瘡：內痔位於3、7、11點方向（第三度），7點方向內痔脫垂。【備註】第三度痔瘡。" },
  { en: "Chest X ray shows: ＞ Normal heart size and configuration. ＞ Aortic tortuosity and Calcified aortic knob. ＞ No widening of the mediastinum. ＞ No definite active lung lesion. ＞ Mild bilateral apical pleural thickening. ＞ Clear cardiophrenic angles, bilateral. ＞ Degenerative change of spine with spur formation. ＞ Nodular shadow(s) over left lower neck region, without significant interval change.",
    zh: "胸部X光顯示：心臟大小及形態正常；主動脈迂曲並主動脈弓鈣化；縱膈腔無增寬；未見明確活動性肺部病灶；雙側肺尖輕度肋膜增厚；雙側心膈角清晰；脊椎退化性改變並骨刺形成；左頸下方結節狀陰影，與先前比較無明顯變化。" },
  { en: "No significant active lung lesion. Please clinical correlation.", zh: "無明顯活動性肺部病灶，建議配合臨床評估。" },
  { en: "Endoscope: EC-760R-V/M/7C727K169 Medication: Hyoscine-N-Butylbromide (Buscopan) 10 mg IV Preparation method: H:Bowklean Preparation Time: Split dose Preparation Quality: Fair Insertion Level: Cecum Sedation: Yes AntiPlatelet: Nil Complication: 1:none [ Symptoms ] Bowel habit change [ Endoscopic Findings ] The colonoscope was inserted to the cecum. The colon prepare was fair with some watery stool over A to S colon, which may mask small lesion. A 0.3cm Isp polyp was noted at A-colon, s/p biopsy. Internal hemorrhoid was also found. [ Diagnosis ] Colorectal polyp,A-colon,s/p biopsy Internal hemorrhoids,Anus [ Comment ] pending for pathology report",
    zh: "內視鏡型號：EC-760R-V/M/7C727K169。用藥：Buscopan 10毫克靜脈注射。清腸藥物：Bowklean，分次服用，清潔品質尚可。內視鏡到達盲腸，鎮靜：有。【症狀】排便習慣改變。【內視鏡檢查所見】大腸鏡已深入至盲腸，腸道清潔尚可，升結腸至乙狀結腸間有些許水便，可能遮蔽小病灶；升結腸處發現一顆0.3公分無蒂型息肉，已切片；另發現內痔。【診斷】升結腸大腸息肉（已切片）；肛門內痔。【備註】病理報告結果待確認。" },
  { en: "The specimen submitted consists of a tissue fragment, measuring 0.3 x 0.2 x 0.1 cm in size, fixed in formalin. Grossly, it is white and soft. All for section. MICROSCOPIC 1. Histologic type: Tubular adenoma 2. Histologic features: Tubular proliferation of adenomatous glands 3. Low-grade dysplasia: Present 4. High-grade dysplasia or invasive carcinoma: Absent 5. Margin: Cannot be assessed",
    zh: "送檢檢體為一小塊組織，大小約0.3×0.2×0.1公分，經福馬林固定，肉眼呈白色、質地柔軟，全部取材製片。顯微鏡檢查：1. 組織型態：管狀腺瘤。2. 組織特徵：腺瘤性腺體呈管狀增生。3. 低度分化不良：有。4. 高度分化不良或侵襲性癌：無。5. 邊緣：無法評估。" }
];

// 常見報告段落標題（找不到整段對照時，至少翻譯常見標題方便閱讀）
const NHI_LABEL_GLOSSARY = [
  ["Purpose for Endoscopy", "檢查目的"], ["Endoscope", "內視鏡型號"], ["Medication", "用藥"],
  ["Pre-medication", "術前用藥"], ["Colonoscopic Findings", "大腸鏡檢查所見"],
  ["Endoscopic Findings", "內視鏡檢查所見"], ["Endoscopic diagnosis", "內視鏡診斷"], ["Diagnosis", "診斷"],
  ["Advice", "建議"], ["Findings", "檢查所見"], ["Impression", "診斷印象"], ["Indications", "適應症"],
  ["Remarks", "備註"], ["Comment", "備註"], ["Symptoms", "症狀"], ["Technician", "技術員"],
  ["Reported by", "報告醫師"], ["Sedation", "鎮靜"], ["Complication", "併發症"]
];

function translateNhiReportText(text) {
  if (!text) return { text: "", translated: false, hasResidualEnglish: false };
  let out = text;
  let residualCheck = text;
  let translated = false;
  NHI_REPORT_TRANSLATIONS.forEach(({ en, zh }) => {
    if (out.includes(en)) {
      out = out.replace(en, `${en}\n〔中文參考翻譯〕${zh}`);
      residualCheck = residualCheck.split(en).join(""); // 已成功翻譯的段落從殘留英文檢查中移除
      translated = true;
    }
  });
  NHI_LABEL_GLOSSARY.forEach(([en, zh]) => {
    const re = new RegExp(`\\b${en}\\b\\s*:`, "g");
    out = out.replace(re, `${en}（${zh}）:`);
  });
  const hasResidualEnglish = /[A-Za-z]{4,}/.test(residualCheck);
  return { text: out, translated, hasResidualEnglish };
}

function extractDoctorTag(reportText) {
  const m = reportText.match(/(開單醫師|Reported by)\s*[:：]\s*([^\s　]+)/);
  return m ? `醫師:${m[2]}` : null;
}

// 合併同一天、同一機構、同一診斷碼的「門診」與「用藥」原始資料
// （健保「慢性病連續處方箋」會把同一次看診的每次調劑各記一筆 claim，
// 就醫日期卻都寫同一天，所以要合併回一筆紀錄，並保留調劑效期資訊）
function mergeNhiVisitAndMed(rawGroups) {
  const clusters = {};
  rawGroups.forEach(g => {
    const diagCode = g.kind === "visit" ? g.mainDiagCode : g.diseaseCode;
    const key = `${g.institution}::${g.date}::${diagCode}`;
    clusters[key] = clusters[key] || { institution: g.institution, date: g.date, diagCode, visits: [], meds: [] };
    if (g.kind === "visit") clusters[key].visits.push(g); else clusters[key].meds.push(g);
  });
  return Object.values(clusters);
}

function buildMergedNhiDraft(cluster, person) {
  const v = cluster.visits[0];
  const m = cluster.meds[0];
  const diagName = (v && v.mainDiagName) || (m && m.diseaseName) || "";

  const subDiag = new Set(), subProc = new Set(), orders = new Set();
  cluster.visits.forEach(g => {
    g.subDiag.forEach(s => subDiag.add(s));
    g.subProc.forEach(s => subProc.add(s));
    g.orders.forEach(o => orders.add(o));
  });

  const drugMap = new Map();
  cluster.meds.forEach(g => {
    g.drugs.forEach(d => {
      const dk = `${d.name}__${d.days}__${d.qty}`;
      if (!drugMap.has(dk)) drugMap.set(dk, { ...d, dischargeDates: [] });
      if (g.dischargeDate) drugMap.get(dk).dischargeDates.push(g.dischargeDate);
    });
  });

  const refillCount = Math.max(cluster.visits.length, cluster.meds.length);
  const parts = [];
  if (refillCount > 1) parts.push(`（本次為連續處方箋，健保資料顯示共 ${refillCount} 次調劑紀錄，已自動合併為一筆）`);
  if (diagName) parts.push(`【主診斷】${cluster.diagCode} ${diagName}`);
  if (subDiag.size) parts.push(`【次診斷】\n` + [...subDiag].map(s => `・${s}`).join("\n"));
  if (subProc.size) parts.push(`【次處置】\n` + [...subProc].map(s => `・${s}`).join("\n"));
  if (orders.size) parts.push(`【醫囑/處置項目】\n` + [...orders].map(s => `・${s}`).join("\n"));
  if (drugMap.size) {
    const drugLines = [...drugMap.values()].map(d => {
      let line = `・${d.name}${d.drugClass ? "（" + d.drugClass + "）" : ""} － 每次${d.days || "?"}天，總量${d.qty || "?"}`;
      if (d.dischargeDates.length) line += `\n　調劑效期：${d.dischargeDates.sort().join("、")}`;
      return line;
    });
    parts.push(`【用藥】\n` + drugLines.join("\n"));
  }
  const description = parts.join("\n\n");
  const { text: safeDesc, hits } = redact(description);
  const category = v ? "visit" : "med";
  const titlePrefix = v ? "" : "用藥（";
  const titleSuffix = v ? "" : "）";
  return {
    date: cluster.date, category, status: "done", person,
    title: `${cluster.institution}｜${titlePrefix}${diagName}${titleSuffix}`.slice(0, 36),
    description: safeDesc, tags: [cluster.institution].filter(Boolean), hits, include: true,
    sourceKey: `nhi:visit:${cluster.date}:${cluster.institution}:${cluster.diagCode}`
  };
}

function buildNhiImagingDrafts(doc, person) {
  return parseNhiImagingTable(doc).map(g => {
    const { text: translatedText, hasResidualEnglish } = translateNhiReportText(g.reportText);
    const { text: safeDesc, hits } = redact(translatedText);
    const doctorTag = extractDoctorTag(g.reportText);
    const tags = [g.institution, doctorTag].filter(Boolean);
    let description = safeDesc;
    if (hasResidualEnglish) description = "⚠️ 部分內容為英文原文，系統未能自動對照翻譯，建議自行確認或詢問醫師。\n\n" + description;
    return {
      date: g.examDate || g.visitDate, category: "exam", status: "done", person,
      title: `${g.institution}｜${g.orderName || "檢查報告"}`.slice(0, 36),
      description, tags, hits, include: true,
      sourceKey: `nhi:exam:${g.examDate || g.visitDate}:${g.institution}:${g.orderCode || g.orderName}`
    };
  });
}

function buildNhiLabDrafts(doc, person) {
  return parseNhiLabTable(doc).map(g => {
    const lines = g.items.map(it => `・${it.itemName}：${it.value}${it.unit && it.unit !== "無" ? " " + it.unit : ""}${it.ref && it.ref !== "[][]" && it.ref !== "[無][無]" ? "（參考值 " + it.ref + "）" : ""}`);
    const description = `【檢驗項目共 ${g.items.length} 項】\n${lines.join("\n")}`;
    const { text: safeDesc, hits } = redact(description);
    return {
      date: g.examDate, category: "exam", status: "done", person,
      title: `${g.institution}｜檢驗結果（${g.items.length}項）`.slice(0, 36),
      description: safeDesc, tags: [g.institution].filter(Boolean), hits, include: true,
      sourceKey: `nhi:lab:${g.examDate}:${g.institution}`
    };
  });
}

function renderDraftList() {
  const wrap = $("#import-summary");
  const list = $("#draft-list");
  if (!draftEntries.length) {
    wrap.style.display = "block";
    $("#import-summary-title").textContent = "沒有解析到可能相關的內容";
    $("#import-summary-desc").textContent = "可以嘗試直接貼上文字，或改用「新增紀錄」手動輸入。";
    list.innerHTML = "";
    return;
  }
  wrap.style.display = "block";
  const maskedCount = draftEntries.filter(d => d.hits > 0).length;
  const dupCount = draftEntries.filter(d => d.duplicate).length;
  $("#import-summary-title").textContent = `解析出 ${draftEntries.length} 筆候選紀錄`;
  const descBits = [];
  if (maskedCount) descBits.push(`${maskedCount} 筆偵測到疑似敏感資料已自動遮蔽`);
  if (dupCount) descBits.push(`${dupCount} 筆與現有資料重複，已預設不勾選`);
  $("#import-summary-desc").textContent = (descBits.length ? descBits.join("；") + "。" : "") + "請確認內容後勾選要儲存的項目，可個別調整日期、分類與標籤。";

  list.innerHTML = draftEntries.map((d, i) => `
    <div class="draft-card ${d.include ? "" : "skip"}" data-i="${i}">
      <div class="draft-top">
        <label class="draft-checkbox">
          <input type="checkbox" class="draft-include" data-i="${i}" ${d.include ? "checked" : ""}/>
          ${escapeHtml(d.title)}
        </label>
        <span style="display:flex; gap:6px;">
          ${d.duplicate ? '<span class="tag-pill" style="background:#E5E5EA;color:#6E6E73;">↺ 已存在，略過</span>' : ""}
          ${d.hits ? '<span class="tag-pill" style="background:#FFE8CC;color:#7A4A00;">⚠ 已遮蔽敏感資料</span>' : ""}
        </span>
      </div>
      <div class="draft-fields">
        <select class="draft-person" data-i="${i}">
          ${Object.keys(PERSON_LABELS).map(p => `<option value="${p}" ${p === (d.person || "other") ? "selected" : ""}>${PERSON_LABELS[p]}</option>`).join("")}
        </select>
        <input type="date" class="draft-date" data-i="${i}" value="${d.date}" />
        <select class="draft-cat" data-i="${i}">
          ${Object.keys(CATEGORY_LABELS).map(c => `<option value="${c}" ${c === d.category ? "selected" : ""}>${CATEGORY_LABELS[c]}</option>`).join("")}
        </select>
        <select class="draft-status" data-i="${i}">
          ${Object.keys(STATUS_LABELS).map(s => `<option value="${s}" ${s === d.status ? "selected" : ""}>${STATUS_LABELS[s]}</option>`).join("")}
        </select>
        <input type="text" class="draft-tags" data-i="${i}" placeholder="標籤，用逗號分隔" value="${(d.tags || []).join(", ")}" />
      </div>
      <div class="draft-text">${escapeHtml(d.description)}</div>
    </div>
  `).join("");

  list.querySelectorAll(".draft-include").forEach(cb => cb.addEventListener("change", () => {
    const i = Number(cb.dataset.i); draftEntries[i].include = cb.checked; renderDraftList();
  }));
  list.querySelectorAll(".draft-person").forEach(sel => sel.addEventListener("change", () => {
    draftEntries[Number(sel.dataset.i)].person = sel.value;
  }));
  list.querySelectorAll(".draft-date").forEach(inp => inp.addEventListener("change", () => {
    draftEntries[Number(inp.dataset.i)].date = inp.value;
  }));
  list.querySelectorAll(".draft-cat").forEach(sel => sel.addEventListener("change", () => {
    draftEntries[Number(sel.dataset.i)].category = sel.value;
  }));
  list.querySelectorAll(".draft-status").forEach(sel => sel.addEventListener("change", () => {
    draftEntries[Number(sel.dataset.i)].status = sel.value;
  }));
  list.querySelectorAll(".draft-tags").forEach(inp => inp.addEventListener("change", () => {
    draftEntries[Number(inp.dataset.i)].tags = inp.value.split(",").map(t => t.trim()).filter(Boolean);
  }));
}

$("#parse-btn").addEventListener("click", () => {
  const raw = $("#import-textarea").value.trim().replace(/^\uFEFF/, "");
  if (!raw) { toast("請先貼上或上傳對話內容"); return; }
  try {
    const json = JSON.parse(raw);
    if (looksLikeStructuredHealthJson(json)) {
      draftEntries = buildDraftsFromStructuredJson(json);
    } else {
      const messages = flattenChatGptExport(json);
      draftEntries = buildDraftsFromMessages(messages);
      if (!draftEntries.length && !messages.length) {
        toast("這個 JSON 不是 ChatGPT 匯出格式，也不是家人健康 JSON 格式，請確認檔案內容");
      }
    }
  } catch {
    draftEntries = buildDraftsFromPlainText(raw);
  }
  renderDraftList();
});

$("#clear-import-btn").addEventListener("click", () => {
  $("#import-textarea").value = "";
  draftEntries = [];
  $("#import-summary").style.display = "none";
});

$("#select-all-btn").addEventListener("click", () => {
  const allOn = draftEntries.every(d => d.include);
  draftEntries.forEach(d => d.include = !allOn);
  renderDraftList();
});

$("#save-drafts-btn").addEventListener("click", async () => {
  const toSave = draftEntries.filter(d => d.include);
  if (!toSave.length) { toast("尚未勾選任何項目"); return; }
  let ok = 0;
  for (const d of toSave) {
    try {
      const payload = {
        date: d.date, time: "", title: d.title, description: d.description,
        tags: d.tags || [], category: d.category, status: d.status, person: d.person || "other",
        attachmentCount: 0, source: d.sourceKey ? "nhi-import" : "gpt-import", createdBy: currentUser(),
        createdAt: serverTimestamp(), updatedAt: serverTimestamp()
      };
      if (d.sourceKey) payload.sourceKey = d.sourceKey;
      await addDoc(collection(db, appConfig.recordsCollection), payload);
      ok++;
    } catch (err) { console.error(err); }
  }
  toast(`已匯入 ${ok} 筆紀錄`);
  draftEntries = [];
  $("#import-summary").style.display = "none";
  $("#import-textarea").value = "";
  $("#nhi-file-status").textContent = "";
  setRoute("timeline");
});

// File / drag-drop wiring for import page
const dropzone = $("#dropzone");
dropzone.addEventListener("click", () => $("#file-input").click());
dropzone.addEventListener("dragover", (e) => { e.preventDefault(); dropzone.classList.add("drag"); });
dropzone.addEventListener("dragleave", () => dropzone.classList.remove("drag"));
dropzone.addEventListener("drop", (e) => {
  e.preventDefault(); dropzone.classList.remove("drag");
  const file = e.dataTransfer.files[0];
  if (file) readImportFile(file);
});
$("#file-input").addEventListener("change", (e) => {
  const file = e.target.files[0];
  if (file) readImportFile(file);
});
function readImportFile(file) {
  const reader = new FileReader();
  reader.onload = () => { $("#import-textarea").value = String(reader.result).replace(/^\uFEFF/, ""); };
  reader.readAsText(file);
}

// ---- 健保快易通檔案 dropzone ----
let nhiFiles = [];
const nhiDropzone = $("#nhi-dropzone");
nhiDropzone.addEventListener("click", () => $("#nhi-file-input").click());
nhiDropzone.addEventListener("dragover", (e) => { e.preventDefault(); nhiDropzone.classList.add("drag"); });
nhiDropzone.addEventListener("dragleave", () => nhiDropzone.classList.remove("drag"));
nhiDropzone.addEventListener("drop", (e) => {
  e.preventDefault(); nhiDropzone.classList.remove("drag");
  addNhiFiles(e.dataTransfer.files);
});
$("#nhi-file-input").addEventListener("change", (e) => { addNhiFiles(e.target.files); e.target.value = ""; });
function addNhiFiles(fileList) {
  nhiFiles = nhiFiles.concat(Array.from(fileList));
  $("#nhi-file-status").textContent = nhiFiles.length ? `已選取 ${nhiFiles.length} 個檔案：${nhiFiles.map(f => f.name).join("、")}` : "";
}

function readFileAsText(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result).replace(/^\uFEFF/, ""));
    reader.onerror = reject;
    reader.readAsText(file);
  });
}

async function fetchExistingNhiSourceKeys() {
  try {
    const snap = await getDocs(query(collection(db, appConfig.recordsCollection), where("source", "==", "nhi-import")));
    return new Set(snap.docs.map(d => d.data().sourceKey).filter(Boolean));
  } catch (err) {
    console.error(err);
    return new Set();
  }
}

$("#nhi-clear-old-btn").addEventListener("click", async () => {
  const person = $("#nhi-person").value;
  const personLabel = PERSON_LABELS[person] || person;
  if (!confirm(`確定要刪除「${personLabel}」所有健保快易通匯入的紀錄嗎？\n\n手動新增和 GPT 對話匯入的紀錄不會受影響，但已刪除的健保資料無法復原。刪除後請重新選取檔案並按「解析健保資料」重新匯入。`)) return;
  $("#nhi-clear-status").textContent = "刪除中…";
  try {
    const snap = await getDocs(query(
      collection(db, appConfig.recordsCollection),
      where("source", "==", "nhi-import"),
      where("person", "==", person)
    ));
    await Promise.all(snap.docs.map(d => deleteDoc(doc(db, appConfig.recordsCollection, d.id))));
    $("#nhi-clear-status").textContent = `已刪除 ${snap.docs.length} 筆「${personLabel}」的舊健保匯入紀錄，可以重新匯入了`;
    toast(`已刪除 ${snap.docs.length} 筆舊資料`);
  } catch (err) {
    console.error(err);
    $("#nhi-clear-status").textContent = "";
    toast("刪除失敗，請稍後再試");
  }
});

$("#nhi-parse-btn").addEventListener("click", async () => {
  if (!nhiFiles.length) { toast("請先選取或拖曳健保快易通匯出的 HTML 檔案"); return; }
  const person = $("#nhi-person").value;
  $("#nhi-file-status").textContent = "解析中…";
  let visitMedRaw = []; // 門診／用藥原始資料，先收集齊全再合併，避免同一天的連續處方被拆成好幾筆
  let otherDrafts = []; // 影像/病理、檢驗結果不需要合併，直接轉成候選紀錄
  let unrecognized = [];
  for (const file of nhiFiles) {
    try {
      const text = await readFileAsText(file);
      const doc = new DOMParser().parseFromString(text, "text/html");
      const kind = detectNhiKind(doc);
      if (kind === "visit") parseNhiVisitTable(doc).forEach(g => visitMedRaw.push({ ...g, kind: "visit" }));
      else if (kind === "med") parseNhiMedTable(doc).forEach(g => visitMedRaw.push({ ...g, kind: "med" }));
      else if (kind === "imaging") otherDrafts = otherDrafts.concat(buildNhiImagingDrafts(doc, person));
      else if (kind === "lab") otherDrafts = otherDrafts.concat(buildNhiLabDrafts(doc, person));
      else unrecognized.push(file.name);
    } catch (err) {
      console.error(err);
      unrecognized.push(file.name);
    }
  }
  const mergedDrafts = mergeNhiVisitAndMed(visitMedRaw).map(cluster => buildMergedNhiDraft(cluster, person));
  let allDrafts = mergedDrafts.concat(otherDrafts);
  if (unrecognized.length) toast(`無法辨識檔案格式：${unrecognized.join("、")}`);

  const existingKeys = await fetchExistingNhiSourceKeys();
  allDrafts.forEach(d => {
    if (d.sourceKey && existingKeys.has(d.sourceKey)) { d.duplicate = true; d.include = false; }
  });
  allDrafts.sort((a, b) => (a.date || "").localeCompare(b.date || ""));

  draftEntries = allDrafts;
  $("#nhi-file-status").textContent = `已解析 ${nhiFiles.length} 個檔案，共 ${allDrafts.length} 筆候選紀錄`;
  nhiFiles = [];
  renderDraftList();
});

// ============================================================================
// Boot
// ============================================================================
initLockScreen();
