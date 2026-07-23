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
let searchTerm = "";

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

function filteredRecords() {
  return allRecords.filter(r => {
    if (activeCategoryFilters.size && !activeCategoryFilters.has(r.category)) return false;
    if (activeStatusFilters.size && !activeStatusFilters.has(r.status)) return false;
    if (searchTerm) {
      const hay = [r.title, r.description, (r.tags || []).join(" "), CATEGORY_LABELS[r.category]].join(" ").toLowerCase();
      if (!hay.includes(searchTerm.toLowerCase())) return false;
    }
    return true;
  });
}

function renderAll() {
  renderRings();
  renderCounts();
  if (currentView === "timeline") renderTimeline(); else renderList();
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
  $("#record-count-sub").textContent = n === 0 ? "尚無紀錄" : `共 ${n} 筆紀錄`;
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
  const dates = Object.keys(groups).sort((a, b) => b.localeCompare(a));

  el.innerHTML = dates.map(date => `
    <div class="timeline-group">
      <div class="timeline-date-label">${fmtDateLabel(date)}</div>
      ${groups[date].map(cardHtml).join("")}
    </div>
  `).join("");

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
      <thead><tr><th>日期</th><th>分類</th><th>標題</th><th>狀態</th><th>標籤</th></tr></thead>
      <tbody>
        ${recs.map(r => `
          <tr data-id="${r.id}">
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

function openAddModal() {
  editingId = null;
  formAttachments = [];
  formCategory = "symptom";
  formStatus = "tracking";
  $("#modal-title").textContent = "新增紀錄";
  $("#delete-record-btn").style.display = "none";
  $("#f-date").value = todayStr();
  $("#f-time").value = "";
  $("#f-title").value = "";
  $("#f-desc").value = "";
  $("#f-tags").value = "";
  syncCategoryButtons();
  syncStatusButtons();
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
  $("#modal-title").textContent = "編輯紀錄";
  $("#delete-record-btn").style.display = "inline-block";
  $("#f-date").value = r.date || todayStr();
  $("#f-time").value = r.time || "";
  $("#f-title").value = r.title || "";
  $("#f-desc").value = r.description || "";
  $("#f-tags").value = (r.tags || []).join(", ");
  syncCategoryButtons();
  syncStatusButtons();
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
$$("#f-category button").forEach(b => b.addEventListener("click", () => { formCategory = b.dataset.cat; syncCategoryButtons(); }));
$$("#f-status button").forEach(b => b.addEventListener("click", () => { formStatus = b.dataset.status; syncStatusButtons(); }));

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
    tags, category: formCategory, status: formStatus,
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
      date, category, status: "tracking",
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
      date, category, status: "tracking",
      title: block.slice(0, 24).replace(/\n/g, " "),
      description: safeText,
      tags: [],
      hits,
      include: true
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
  $("#import-summary-title").textContent = `解析出 ${draftEntries.length} 筆候選紀錄`;
  $("#import-summary-desc").textContent = maskedCount
    ? `其中 ${maskedCount} 筆偵測到疑似敏感資料已自動遮蔽，請確認內容後再儲存。可勾選要儲存的項目、調整日期與分類。`
    : `請確認內容後勾選要儲存的項目，可個別調整日期、分類與標籤。`;

  list.innerHTML = draftEntries.map((d, i) => `
    <div class="draft-card ${d.include ? "" : "skip"}" data-i="${i}">
      <div class="draft-top">
        <label class="draft-checkbox">
          <input type="checkbox" class="draft-include" data-i="${i}" ${d.include ? "checked" : ""}/>
          ${escapeHtml(d.title)}
        </label>
        ${d.hits ? '<span class="tag-pill" style="background:#FFE8CC;color:#7A4A00;">⚠ 已遮蔽敏感資料</span>' : ""}
      </div>
      <div class="draft-fields">
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
  const raw = $("#import-textarea").value.trim();
  if (!raw) { toast("請先貼上或上傳對話內容"); return; }
  try {
    const json = JSON.parse(raw);
    const messages = flattenChatGptExport(json);
    draftEntries = buildDraftsFromMessages(messages);
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
      await addDoc(collection(db, appConfig.recordsCollection), {
        date: d.date, time: "", title: d.title, description: d.description,
        tags: d.tags || [], category: d.category, status: d.status,
        attachmentCount: 0, source: "gpt-import", createdBy: currentUser(),
        createdAt: serverTimestamp(), updatedAt: serverTimestamp()
      });
      ok++;
    } catch (err) { console.error(err); }
  }
  toast(`已匯入 ${ok} 筆紀錄`);
  draftEntries = [];
  $("#import-summary").style.display = "none";
  $("#import-textarea").value = "";
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
  reader.onload = () => { $("#import-textarea").value = reader.result; };
  reader.readAsText(file);
}

// ============================================================================
// Boot
// ============================================================================
initLockScreen();
