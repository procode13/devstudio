/**
 * ==========================================================================
 * DEVSTUDIO - JAVASCRIPT CONTROLLER
 * Features: Dual Moving Tracks, Modal Popups, Kotak Saran, Fitur Bagikan, & Security Suite
 * ==========================================================================
 */

/**
 * 0. MODUL KEAMANAN (SECURITY & SANITIZATION SUITE)
 * - Perlindungan Anti-XSS (DOM-based & CSS Injection)
 * - SHA-256 Hashing untuk Verifikasi Administrator (Zero Plaintext Passcode)
 * - Anti-Brute Force Rate Limiter & Lockout
 * - Anti-Spam Honeypot Verification & Submission Cooldown
 */

// Hash SHA-256 dari kode administrator rahasia (mencegah tereksposnya kode plaintext di source code)
const ADMIN_PASSCODE_HASH = "2ec40539c9778647e1a84d86a040225fd93422f4dcf9d8e73c03853a3d9bab2c";

// Regex standar untuk validasi format email yang aman
const VALID_EMAIL_REGEX = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+$/;


// State OTP Administrator (7 Kode Acak Huruf & Angka)
let currentAdminOtp = null;
let isSendingOtp = false;

// Fungsi Pembuat 7 Kode Acak (Huruf & Angka)
function generate7CharOtp() {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // 32 karakter bersih tanpa 0/O/1/I
  let res = "";
  if (window.crypto && window.crypto.getRandomValues) {
    const arr = new Uint8Array(7);
    window.crypto.getRandomValues(arr);
    for (let i = 0; i < 7; i++) {
      res += chars[arr[i] % chars.length];
    }
  } else {
    for (let i = 0; i < 7; i++) {
      res += chars[Math.floor(Math.random() * chars.length)];
    }
  }
  return res;
}

// Mengirim 7 kode acak ke email tujuan via FormSubmit AJAX API
async function sendOtpToEmail(targetEmail, code) {
  return fetch(`https://formsubmit.co/ajax/${encodeURIComponent(targetEmail)}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Accept": "application/json"
    },
    body: JSON.stringify({
      nama_pengirim: "DEVSTUDIO Security Auth",
      email_pengirim: targetEmail,
      kategori_pesan: "Kode Akses Administrator",
      _subject: `[DEVSTUDIO] Kode Akses Administrator: ${code}`,
      isi_pesan: `Halo Administrator DEVSTUDIO,\n\nPermintaan masuk ke Mode Pengelola telah dilakukan dari website.\nBerikut adalah 7 KODE ACAK verifikasi Anda:\n\n👉  ${code}  👈\n\nMasukkan 7 kode di atas ke pop-up verifikasi di website untuk mengatur proyek.\nKode ini hanya berlaku selama 10 menit.\nJika bukan Anda yang meminta kode ini, abaikan email ini.`,
      _template: "table",
      _captcha: "false"
    })
  }).then(r => r.json());
}


// Fungsi Cryptographic Hash SHA-256 berbasis Web Crypto API
async function computeSha256(str) {
  if (window.crypto && window.crypto.subtle) {
    try {
      const buffer = new TextEncoder().encode(str);
      const hashBuffer = await window.crypto.subtle.digest("SHA-256", buffer);
      return Array.from(new Uint8Array(hashBuffer))
        .map(b => b.toString(16).padStart(2, "0"))
        .join("");
    } catch (_) {}
  }
  // Fallback hash jika Web Crypto tidak aktif
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    hash = ((hash << 5) - hash) + str.charCodeAt(i);
    hash |= 0;
  }
  return String(hash);
}

// Verifikasi kode admin dengan proteksi brute force rate-limiting
async function verifyAdminPasscode(inputCode) {
  const clean = String(inputCode || "").trim();
  if (!clean) return false;

  const now = Date.now();
  const lockoutUntil = parseInt(sessionStorage.getItem("admin_lockout_until") || "0", 10);
  if (now < lockoutUntil) {
    const remainingSec = Math.ceil((lockoutUntil - now) / 1000);
    showToast(`🔒 Akses admin ditangguhkan sementara. Tunggu ${remainingSec} detik.`);
    return false;
  }

  const hashResult = await computeSha256(clean);
  if (hashResult === ADMIN_PASSCODE_HASH) {
    sessionStorage.removeItem("admin_failed_attempts");
    sessionStorage.removeItem("admin_lockout_until");
    return true;
  }

  // Jika kode salah dan berupa 6 digit angka, catat percobaan gagal
  if (/^\d{6}$/.test(clean)) {
    let failedAttempts = parseInt(sessionStorage.getItem("admin_failed_attempts") || "0", 10) + 1;
    sessionStorage.setItem("admin_failed_attempts", String(failedAttempts));

    if (failedAttempts >= 5) {
      sessionStorage.setItem("admin_lockout_until", String(now + 60000)); // 60 detik lockout
      showToast("🔒 Terlalu banyak percobaan kode gagal. Akses ditangguhkan 60 detik.");
    }
  }

  return false;
}

// Sanitasi URL untuk mencegah XSS melalui atribut href (misal javascript:... / data:...)
function sanitizeUrl(rawUrl, fallback = "#") {
  if (!rawUrl || typeof rawUrl !== "string") return fallback;
  const trimmed = rawUrl.trim();
  if (/^(https?:\/\/|mailto:)/i.test(trimmed)) {
    return trimmed;
  }
  if (/^#[a-zA-Z0-9_-]+$/.test(trimmed)) {
    return trimmed;
  }
  return fallback;
}

// Sanitasi URL gambar untuk mencegah CSS Injection pada background-image
function sanitizeCssUrl(rawUrl) {
  if (!rawUrl || typeof rawUrl !== "string") return "";
  const trimmed = rawUrl.trim();
  if (/^(https?:\/\/|data:image\/(png|jpe?g|gif|webp|svg\+xml);base64,)/i.test(trimmed)) {
    return trimmed.replace(/['"()\\]/g, "");
  }
  return "";
}

// Sanitasi teks umum (menghilangkan bracket HTML untuk mencegah stored XSS)
function sanitizeText(raw, maxLen = 1000) {
  if (!raw) return "";
  return String(raw)
    .trim()
    .replace(/[<>]/g, "")
    .slice(0, maxLen);
}

// 1. DATA PROYEK DEFAULT
const defaultProjects = [
  {
    id: "01",
    title: "VoxelCraft Raymarching Engine",
    theme: "theme-mint",
    version: "v1.4.2",
    year: "2025",
    image: "https://images.unsplash.com/photo-1618005182384-a83a8bd57fbe?auto=format&fit=crop&w=800&q=80",
    summary: "Real-time sparse voxel octree (SVO) raymarching engine built in C++20 and Vulkan 1.3 featuring dynamic volumetric lighting and destructible terrain physics.",
    tags: ["C++20", "Vulkan 1.3", "Compute Shaders", "SIMD", "GLM"],
    github: "https://github.com/example/voxelcraft-engine",
    demo: "https://example.com/voxelcraft-engine",
    features: [
      "Hierarchical DDA traversal running 100% on GPU compute shaders.",
      "64-bit morton code compression saving over 75% memory footprint.",
      "Screen-space temporal reprojection (TAA) for volumetric god rays."
    ]
  },
  {
    id: "02",
    title: "Null-Drift Tactics Arena",
    theme: "theme-sky",
    version: "v0.9.8",
    year: "2026",
    image: "https://images.unsplash.com/photo-1542751371-adc38448a05e?auto=format&fit=crop&w=800&q=80",
    summary: "Deterministic 2D zero-gravity combat title featuring sub-tick input sampling, custom GGRS rollback netcode, and particle physics.",
    tags: ["Godot 4.3", "C#", "GDScript", "GGRS Rollback", "UDP"],
    github: "https://github.com/example/nulldrift-tactics",
    demo: "https://example.com/nulldrift-tactics",
    features: [
      "Bitwise deterministic fixed-point math engine preventing network desyncs.",
      "State serializer packaging 100% of game state into 128 bytes per tick.",
      "Predictive physics pipeline concealing network jitter up to 140ms."
    ]
  },
  {
    id: "03",
    title: "CyberRogue: Neon Protocol",
    theme: "theme-mint",
    version: "v1.2.0",
    year: "2026",
    image: "https://images.unsplash.com/photo-1550745165-9bc0b252726f?auto=format&fit=crop&w=800&q=80",
    summary: "Fast-paced isometric cyberpunk roguelite with procedurally synthesized dungeon layouts, responsive dodge-dash combat, and dynamic lighting.",
    tags: ["Unity 6", "C#", "URP", "Procedural Gen", "FMOD"],
    github: "https://github.com/example/cyberrogue-protocol",
    demo: "https://example.com/cyberrogue-protocol",
    features: [
      "Procedural room generation using graph grammar and wave function collapse.",
      "Custom animation state machine with frame-perfect hitboxes and cancel windows.",
      "Dynamic adaptive audio mixing reacting to in-game intensity."
    ]
  },
  {
    id: "04",
    title: "Aetherial: Echoes of Void",
    theme: "theme-blue",
    version: "v0.7.5",
    year: "2025",
    image: "https://images.unsplash.com/photo-1538481199705-c710c4e965fc?auto=format&fit=crop&w=800&q=80",
    summary: "Atmospheric third-person action RPG exploring stylized desolate ruins with fluid swordplay, physics-driven grappling hooks, and boss behavior trees.",
    tags: ["Unreal Engine 5", "C++", "Nanite", "Lumen", "Behavior Trees"],
    github: "https://github.com/example/aetherial-echoes",
    demo: "https://example.com/aetherial-echoes",
    features: [
      "Motion matching locomotion pipeline for hyper-fluid character movement.",
      "Custom inverse kinematics (IK) foot-placement across irregular terrain.",
      "Utility-based boss AI decision making with sensory memory systems."
    ]
  },
  {
    id: "05",
    title: "ShaderNode Visual Studio",
    theme: "theme-blue",
    version: "v2.1.0",
    year: "2026",
    image: "https://images.unsplash.com/photo-1550751827-4bd374c3f58b?auto=format&fit=crop&w=800&q=80",
    summary: "Desktop node-based shader authoring tool compiling visual graphs directly into optimized WGSL and SPIR-V bytecodes in real time.",
    tags: ["Rust", "WGPU", "WGSL", "Tauri v2", "TypeScript"],
    github: "https://github.com/example/shadernode-studio",
    demo: "https://example.com/shadernode-studio",
    features: [
      "Topological DAG sorting with automated dead-code branch elimination.",
      "Multi-target AST compilation targeting WebGPU, Vulkan, and DirectX 12.",
      "Hot-reloading shader preview cache without garbage collection pauses."
    ]
  },
  {
    id: "06",
    title: "MemTrace Linux Kernel Profiler",
    theme: "theme-cyan",
    version: "v3.0.1",
    year: "2025",
    image: "https://images.unsplash.com/photo-1526374965328-7f61d4dc18c5?auto=format&fit=crop&w=800&q=80",
    summary: "Zero-overhead eBPF-powered heap allocation profiler and cacheline fragmentation analyzer for high-frequency game servers.",
    tags: ["C", "eBPF", "Linux Kernel", "Dear ImGui", "Python"],
    github: "https://github.com/example/memtrace-cli",
    demo: "https://example.com/memtrace-cli",
    features: [
      "Kernel ring-buffer telemetry intercepting heap allocations without ptrace pauses.",
      "Lock-free atomic flamegraph synthesizer computing callstacks in real-time.",
      "Hardware counter telemetry detecting CPU false-sharing on L1/L2 cache lines."
    ]
  },
  {
    id: "07",
    title: "ChronoTransport High-Speed UDP",
    theme: "theme-mint",
    version: "v1.1.4",
    year: "2025",
    image: "https://images.unsplash.com/photo-1558494949-ef010cbdcc31?auto=format&fit=crop&w=800&q=80",
    summary: "High-throughput binary UDP transport protocol tailored for multiplayer game state synchronization with client-side delta compression.",
    tags: ["Go", "C++", "UDP", "WebRTC", "Cryptography"],
    github: "https://github.com/example/chronotransport",
    demo: "https://example.com/chronotransport",
    features: [
      "XOR delta snapshot compression achieving up to 82% bandwidth savings.",
      "ChaCha20-Poly1305 packet authentication with anti-replay sliding window.",
      "SIMD-accelerated packet serialization designed for high-tickrate servers."
    ]
  },
  {
    id: "08",
    title: "NeuralResonator Audio AI",
    theme: "theme-sky",
    version: "v0.4.0",
    year: "2026",
    image: "https://images.unsplash.com/photo-1598488035139-bdbb2231ce04?auto=format&fit=crop&w=800&q=80",
    summary: "Experimental real-time neural audio resynthesis engine generating procedural acoustic impulses and sci-fi foley via 1D ConvNets.",
    tags: ["Python", "PyTorch", "C++20", "JUCE 7", "ONNX Runtime"],
    github: "https://github.com/example/neural-resonator",
    demo: "https://example.com/neural-resonator",
    features: [
      "Quantized 8-bit ONNX neural model executing directly inside the audio thread.",
      "Phase vocoder spectral masking for sharp acoustic transient preservation.",
      "Hardware-accelerated FFT convolution using KissFFT and platform SIMD."
    ]
  }
];

// LOCAL STORAGE PROYEK: Membaca & Menyimpan Data Proyek secara Bersih & Valid
const STORAGE_KEY_PROJECTS = "devstudio_projects_clean_v1";

// Otomatis hapus semua sisa cache corrupt lama dari browser pengunjung
(function purgeCorruptStorage() {
  try {
    const keysToRemove = [];
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i);
      if (k && (k.startsWith("devstudio_projects_v") || k === "devstudio_projects" || k === "devstudio_custom_projects_v2")) {
        keysToRemove.push(k);
      }
    }
    keysToRemove.forEach(k => localStorage.removeItem(k));
  } catch (_) {}
})();

function loadProjects() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY_PROJECTS);
    if (raw) {
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed) && parsed.length > 0) {
        // Cek apakah ada data rusak (misal judul mengandung koma / URL / teks CSV berantakan)
        const isCorrupt = parsed.some(p => !p.title || p.title.includes("http") || p.title.includes(",") || !p.summary || p.summary.length < 5);
        if (isCorrupt) {
          console.warn("Mendeteksi data corrupt di localStorage, mereset ke default murni.");
          localStorage.removeItem(STORAGE_KEY_PROJECTS);
          return JSON.parse(JSON.stringify(defaultProjects));
        }

        return parsed.map(p => ({
          id: p.id ? String(p.id).replace(/[^a-zA-Z0-9_-]/g, "") : String(Date.now()).slice(-4),
          title: sanitizeText(p.title || "Proyek Studio", 120),
          version: sanitizeText(p.version || "v1.0.0", 30),
          year: sanitizeText(p.year || "2026", 10),
          theme: ["theme-mint", "theme-blue", "theme-sky", "theme-cyan"].includes(p.theme) ? p.theme : "theme-mint",
          image: sanitizeCssUrl(p.image) || defaultProjects[0].image,
          summary: sanitizeText(p.summary || "", 1500),
          features: Array.isArray(p.features) ? p.features.map(f => sanitizeText(f, 300)).filter(Boolean) : [],
          tags: Array.isArray(p.tags) ? p.tags.map(t => sanitizeText(t, 40)).filter(Boolean) : [],
          github: sanitizeUrl(p.github, "#"),
          demo: sanitizeUrl(p.demo, "#")
        }));
      }
    }
  } catch (e) {
    console.error("Gagal membaca storage proyek, fallback ke default aman:", e);
  }
  return JSON.parse(JSON.stringify(defaultProjects));
}

let projects = loadProjects();

function saveProjects(newProjects) {
  projects = newProjects;
  try {
    localStorage.setItem(STORAGE_KEY_PROJECTS, JSON.stringify(projects));
  } catch (e) {
    console.error("Gagal menyimpan storage proyek:", e);
  }
  renderMarquees();
  renderAdminProjectList();
}

// 1b. LOADER NATIVE MICROSOFT EXCEL (.XLSX) VIA SHEETJS
async function loadProjectsFromExcel(fileOrUrl) {
  if (typeof XLSX === "undefined") return;
  try {
    let workbook;
    if (fileOrUrl instanceof File || fileOrUrl instanceof Blob) {
      const data = await fileOrUrl.arrayBuffer();
      workbook = XLSX.read(data, { type: "array" });
    } else {
      const res = await fetch("proyek.xlsx", { cache: "no-store" });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.arrayBuffer();
      workbook = XLSX.read(data, { type: "array" });
    }

    const firstSheetName = workbook.SheetNames[0];
    const worksheet = workbook.Sheets[firstSheetName];
    const rows = XLSX.utils.sheet_to_json(worksheet, { defval: "" });

    if (!Array.isArray(rows) || rows.length === 0) return;

    const parsed = [];
    rows.forEach((row, idx) => {
      const getVal = (keys) => {
        for (const k of keys) {
          for (const rowKey of Object.keys(row)) {
            if (rowKey.toLowerCase().trim() === k.toLowerCase().trim() && row[rowKey] !== undefined) {
              return String(row[rowKey]).trim();
            }
          }
        }
        return "";
      };

      const title = getVal(["judul", "title", "nama"]);
      if (!title) return;

      const year = getVal(["tahun", "year"]) || "2026";
      let theme = getVal(["tema", "theme"]) || "mint";
      if (!theme.startsWith("theme-")) theme = `theme-${theme}`;
      if (!["theme-mint", "theme-blue", "theme-sky", "theme-cyan"].includes(theme)) theme = "theme-mint";

      const rawImg = getVal(["gambar", "image", "foto", "url"]);
      const defaultImg = (defaultProjects[idx] && defaultProjects[idx].image) || defaultProjects[0].image;
      const image = sanitizeCssUrl(rawImg) || defaultImg;

      const summary = getVal(["ringkasan", "summary", "deskripsi"]) || "Proyek game kreatif studio.";

      let features = [];
      const rawFitur = getVal(["fitur", "features", "feature"]);
      if (rawFitur) {
        features = rawFitur.split(/[|\n]/).map(f => sanitizeText(f.trim(), 300)).filter(Boolean);
      }
      if (features.length === 0 && defaultProjects[idx]) {
        features = defaultProjects[idx].features || [];
      }
      if (features.length === 0) {
        features = [
          "Arsitektur modular berperforma tinggi teroptimasi.",
          "Desain visual adaptif dengan sistem rendering modern."
        ];
      }

      const rawTags = getVal(["tags", "kategori", "tag"]);
      const tags = rawTags ? rawTags.split(/[,;]/).map(t => sanitizeText(t.trim(), 40)).filter(Boolean) : ["Game", "Studio"];

      const demo = sanitizeUrl(getVal(["demo", "link", "play"]), "#");
      const github = sanitizeUrl(getVal(["github", "repo", "source"]), "#");

      parsed.push({
        id: String(idx + 1).padStart(2, "0"),
        title: sanitizeText(title, 120),
        version: (defaultProjects[idx] && defaultProjects[idx].version) || "v1.0.0",
        year: sanitizeText(year, 10),
        theme,
        image,
        summary: sanitizeText(summary, 1500),
        tags,
        github,
        demo,
        features
      });
    });

    if (parsed.length > 0) {
      projects = parsed;
      try {
        localStorage.setItem(STORAGE_KEY_PROJECTS, JSON.stringify(projects));
      } catch (_) {}
      renderMarquees();
      renderAdminProjectList();
      showToast(`✓ Berhasil memuat ${projects.length} proyek dari Microsoft Excel!`);
      console.log(`✓ Berhasil memuat ${projects.length} proyek dari proyek.xlsx`);
    }
  } catch (err) {
    console.info("Info: Menggunakan data default proyek bawaan:", err.message);
  }
}

// Inisialisasi pemuatan proyek.xlsx jika tersedia secara online
if (typeof window !== "undefined") {
  window.addEventListener("DOMContentLoaded", () => {
    loadProjectsFromExcel();
  });
}

// Event Listener tombol Impor Excel di panel Admin
const btnImportExcel = document.getElementById("btn-import-excel");
const inputImportExcel = document.getElementById("admin-import-excel");

if (btnImportExcel && inputImportExcel) {
  btnImportExcel.addEventListener("click", () => {
    inputImportExcel.click();
  });

  inputImportExcel.addEventListener("change", (e) => {
    const file = e.target.files && e.target.files[0];
    if (file) {
      loadProjectsFromExcel(file);
      e.target.value = "";
    }
  });
}








// 2. DOM REFERENCES
// Modal Verifikasi OTP Email (admin-dev)
const adminOtpModal = document.getElementById("admin-otp-modal");
const adminOtpCloseBtn = document.getElementById("admin-otp-close-btn");
const adminOtpForm = document.getElementById("admin-otp-form");
const adminOtpInput = document.getElementById("admin-otp-input");
const adminOtpError = document.getElementById("admin-otp-error");
const adminOtpSubmitBtn = document.getElementById("admin-otp-submit-btn");
const otpEmailTargetText = document.getElementById("otp-email-target-text");

const track1 = document.getElementById("marquee-track-1");
const track2 = document.getElementById("marquee-track-2");

const modalBackdrop = document.getElementById("project-modal");
const modalCloseBtn = document.getElementById("modal-close-btn");
const modalBanner = document.getElementById("modal-card-banner");
const modalTitle = document.getElementById("modal-title");
const modalCategory = document.getElementById("modal-category");
const modalDesc = document.getElementById("modal-desc");
const modalFeatures = document.getElementById("modal-features");
const modalTags = document.getElementById("modal-tags");
const modalCodeBtn = document.getElementById("modal-code-btn");
const modalDemoBtn = document.getElementById("modal-demo-btn");
const modalShareBtn = document.getElementById("modal-share-btn");

const saranForm = document.getElementById("saran-form");
const saranNamaInput = document.getElementById("saran-nama");
const saranEmailInput = document.getElementById("saran-email");
const saranKategoriInput = document.getElementById("saran-kategori");
const saranPesanInput = document.getElementById("saran-pesan");
const saranSubmitBtn = document.getElementById("saran-submit-btn");

// Share Modal Elements
const shareModal = document.getElementById("share-modal");
const shareCloseBtn = document.getElementById("share-close-btn");
const shareTargetTitle = document.getElementById("share-target-title");
const shareTargetUrl = document.getElementById("share-target-url");
const copyLinkBtn = document.getElementById("copy-link-btn");
const toastEl = document.getElementById("toast-notification");

// Admin Mode Elements
const adminFloatingBar = document.getElementById("admin-floating-bar");
const openAdminPanelBtn = document.getElementById("open-admin-panel-btn");
const logoutAdminBtn = document.getElementById("logout-admin-btn");

const adminModal = document.getElementById("admin-modal");
const adminModalCloseBtn = document.getElementById("admin-modal-close-btn");

const tabBtnList = document.getElementById("tab-btn-list");
const tabBtnForm = document.getElementById("tab-btn-form");
const btnResetDefault = document.getElementById("btn-reset-default");

const adminTabList = document.getElementById("admin-tab-list");
const adminTabForm = document.getElementById("admin-tab-form");

const adminRecipientEmailInput = document.getElementById("admin-recipient-email-input");
const btnSaveRecipientEmail = document.getElementById("btn-save-recipient-email");

const adminProjectsList = document.getElementById("admin-projects-list");
const adminTotalCount = document.getElementById("admin-total-count");

const adminProjectForm = document.getElementById("admin-project-form");
const formEditId = document.getElementById("admin-form-edit-id");
const formModeTitle = document.getElementById("admin-form-mode-title");

const formTitle = document.getElementById("form-title");
const formVersion = document.getElementById("form-version");
const formYear = document.getElementById("form-year");
const formTheme = document.getElementById("form-theme");
const formImage = document.getElementById("form-image");
const formImageFile = document.getElementById("form-image-file");
const formFileName = document.getElementById("form-file-name");
const formImagePreview = document.getElementById("form-image-preview");
const formSummary = document.getElementById("form-summary");
const formTags = document.getElementById("form-tags");
const formGithub = document.getElementById("form-github");
const formDemo = document.getElementById("form-demo");
const formFeatures = document.getElementById("form-features");
const formCancelBtn = document.getElementById("form-cancel-btn");

// Social Share Links
const shareWa = document.getElementById("share-wa");
const shareX = document.getElementById("share-x");
const shareTelegram = document.getElementById("share-telegram");
const shareLinkedin = document.getElementById("share-linkedin");

let currentActiveProject = null;

/**
 * 3. CREATE MOVING CARD ELEMENT (DENGAN BACKGROUND FOTO)
 */
function createCardElement(item) {
  const card = document.createElement("div");
  card.className = `proyek-card-frame ${item.theme}`;
  const safeImg = sanitizeCssUrl(item.image) || defaultProjects[0].image;
  card.style.backgroundImage = `url('${safeImg}')`;
  card.tabIndex = 0;
  card.setAttribute("role", "button");
  card.setAttribute("aria-label", `Buka detail ${escapeHtml(item.title)}`);

  card.innerHTML = `
    <!-- Top Meta: Hanya Tahun -->
    <div class="card-top-tag">
      ${item.year ? `<span class="card-tag-badge">${escapeHtml(item.year)}</span>` : ''}
    </div>

    <!-- Bottom Meta: Hanya Judul Proyek -->
    <div class="card-bottom-info">
      <span class="card-project-name" title="${escapeHtml(item.title)}">
        ${escapeHtml(item.title)}
      </span>
    </div>
  `;

  // Click card to open detail modal
  card.addEventListener("click", () => openModal(item));
  card.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      openModal(item);
    }
  });

  return card;
}

/**
 * 4. RENDER BOTH MOVING MARQUEES
 * - Track 1 (My Proyek Part 1) -> Bergerak ke Kiri
 * - Track 2 (My Proyek Part 2) -> Bergerak ke Kanan
 */
function duplicateForSeamlessLoop(list) {
  if (!list || list.length === 0) return [];
  let mult = 2;
  while (list.length * mult < 12) {
    mult += 2;
  }
  let res = [];
  for (let i = 0; i < mult; i++) {
    res = res.concat(list);
  }
  return res;
}

function renderMarquees() {
  let list1 = [];
  let list2 = [];

  if (projects.length <= 4) {
    list1 = [...projects];
    list2 = [...projects].reverse();
  } else {
    list1 = projects.filter((_, idx) => idx % 2 === 0);
    list2 = projects.filter((_, idx) => idx % 2 !== 0);
  }

  // Track 1 (Bergerak ke Kiri)
  if (track1) {
    track1.innerHTML = "";
    const items1 = duplicateForSeamlessLoop(list1);
    items1.forEach(item => track1.appendChild(createCardElement(item)));
  }

  // Track 2 (Bergerak ke Kanan)
  if (track2) {
    track2.innerHTML = "";
    const items2 = duplicateForSeamlessLoop(list2);
    items2.forEach(item => track2.appendChild(createCardElement(item)));
  }
}

/**
 * 5. MODAL POPUP (DENGAN BANNER FOTO)
 */
function openModal(item) {
  currentActiveProject = item;

  // Banner dengan foto proyek terproteksi sanitasi
  const safeImg = sanitizeCssUrl(item.image);
  modalBanner.style.backgroundImage = safeImg ? `url('${safeImg}')` : "";
  modalBanner.innerHTML = `
    <div class="modal-banner-overlay">
      <span>${escapeHtml(item.title)}</span>
    </div>
  `;

  modalTitle.textContent = item.title;
  modalCategory.textContent = [item.version, item.year ? `(${item.year})` : ""].filter(Boolean).join(" ");
  modalDesc.textContent = item.summary;

  modalFeatures.innerHTML = "";
  item.features.forEach(f => {
    const li = document.createElement("li");
    li.textContent = f;
    modalFeatures.appendChild(li);
  });

  modalTags.innerHTML = "";
  item.tags.forEach(t => {
    const span = document.createElement("span");
    span.className = "modal-tag";
    span.textContent = t;
    modalTags.appendChild(span);
  });

  // Sanitasi protokol URL untuk mencegah eksekusi javascript: / data:
  modalCodeBtn.href = sanitizeUrl(item.github, "#");
  modalDemoBtn.href = sanitizeUrl(item.demo, "#");
  modalCodeBtn.setAttribute("rel", "noopener noreferrer");
  modalDemoBtn.setAttribute("rel", "noopener noreferrer");

  modalBackdrop.classList.add("active");
  modalBackdrop.setAttribute("aria-hidden", "false");
  document.body.style.overflow = "hidden";
  modalCloseBtn.focus();
}

function closeModal() {
  modalBackdrop.classList.remove("active");
  modalBackdrop.setAttribute("aria-hidden", "true");
  document.body.style.overflow = "";
}

modalCloseBtn.addEventListener("click", closeModal);
modalBackdrop.addEventListener("click", (e) => {
  if (e.target === modalBackdrop) closeModal();
});

// Modal Share Button
if (modalShareBtn) {
  modalShareBtn.addEventListener("click", () => {
    if (currentActiveProject) {
      openShareDialog(
        currentActiveProject.title, 
        `${window.location.origin}${window.location.pathname}#proyek-${currentActiveProject.id}`
      );
    }
  });
}

/**
 * 6. FITUR BAGIKAN (SHARE SYSTEM)
 */
function openShareDialog(title, url) {
  const shareTitle = title || "Creative DEVSTUDIO — Portfolio & Proyek";
  const shareUrl = url || window.location.href;

  // Coba Web Share API bawaan browser jika ada (sangat bagus di HP / Browser modern)
  if (navigator.share) {
    navigator.share({
      title: shareTitle,
      text: `Lihat proyek keren "${shareTitle}" di Creative DEVSTUDIO!`,
      url: shareUrl
    }).catch(() => {
      // Jika dibatalkan atau gagal, buka modal dialog sebagai fallback
      showFallbackShareModal(shareTitle, shareUrl);
    });
    return;
  }

  showFallbackShareModal(shareTitle, shareUrl);
}

function showFallbackShareModal(title, url) {
  if (!shareModal) return;

  shareTargetTitle.textContent = title;
  shareTargetUrl.value = url;

  // Update direct share links
  const encodedUrl = encodeURIComponent(url);
  const encodedText = encodeURIComponent(`Lihat proyek keren "${title}" di Creative DEVSTUDIO:\n${url}`);

  if (shareWa) shareWa.href = `https://api.whatsapp.com/send?text=${encodedText}`;
  if (shareX) shareX.href = `https://twitter.com/intent/tweet?text=${encodedText}`;
  if (shareTelegram) shareTelegram.href = `https://t.me/share/url?url=${encodedUrl}&text=${encodeURIComponent(title)}`;
  if (shareLinkedin) shareLinkedin.href = `https://www.linkedin.com/sharing/share-offsite/?url=${encodedUrl}`;

  shareModal.classList.add("active");
  shareModal.setAttribute("aria-hidden", "false");
}

function closeShareDialog() {
  if (!shareModal) return;
  shareModal.classList.remove("active");
  shareModal.setAttribute("aria-hidden", "true");
}

if (shareCloseBtn) {
  shareCloseBtn.addEventListener("click", closeShareDialog);
}

if (shareModal) {
  shareModal.addEventListener("click", (e) => {
    if (e.target === shareModal) closeShareDialog();
  });
}

// Salin tautan ke clipboard
if (copyLinkBtn) {
  copyLinkBtn.addEventListener("click", () => {
    const textToCopy = shareTargetUrl.value;
    navigator.clipboard.writeText(textToCopy).then(() => {
      showToast("✓ Tautan berhasil disalin ke papan klip!");
      copyLinkBtn.textContent = "Tersalin! ✓";
      setTimeout(() => {
        copyLinkBtn.textContent = "Salin";
      }, 2000);
    }).catch(() => {
      shareTargetUrl.select();
      document.execCommand("copy");
      showToast("✓ Tautan berhasil disalin!");
    });
  });
}

// Toast Notifikasi
function showToast(message) {
  if (!toastEl) return;
  toastEl.textContent = message;
  toastEl.classList.add("show");
  setTimeout(() => {
    toastEl.classList.remove("show");
  }, 2800);
}

// Global button to share the whole site
window.shareWebsite = function() {
  openShareDialog("Creative DEVSTUDIO — Portfolio & Proyek", window.location.href);
};

window.addEventListener("keydown", (e) => {
  if (e.key === "Escape") {
    if (typeof closeSaweriaModal === "function" && document.getElementById("saweria-modal-backdrop") && document.getElementById("saweria-modal-backdrop").classList.contains("active")) {
      closeSaweriaModal();
    } else if (adminModal && adminModal.classList.contains("active")) {
      closeAdminModal();
    } else if (shareModal && shareModal.classList.contains("active")) {
      closeShareDialog();
    } else if (modalBackdrop && modalBackdrop.classList.contains("active")) {
      closeModal();
    }
  }
});

/**
 * 7. KOTAK PESAN / FORM KONTAK (TERKIRIM LANGSUNG KE EMAIL & DILENGKAPI PROTEKSI ANTI-SPAM)
 */
const STORAGE_KEY_RECIPIENT_EMAIL = "devstudio_recipient_email";

function getRecipientEmail() {
  return localStorage.getItem(STORAGE_KEY_RECIPIENT_EMAIL) || "raffaadi07@gmail.com";
}

function setRecipientEmail(email) {
  const clean = String(email || "").trim();
  if (!clean || !VALID_EMAIL_REGEX.test(clean) || clean.length > 100) return false;
  localStorage.setItem(STORAGE_KEY_RECIPIENT_EMAIL, clean);
  return true;
}

function triggerAdminOtpFlow() {
  const targetEmail = getRecipientEmail();
  const otpCode = generate7CharOtp();
  currentAdminOtp = {
    code: otpCode,
    expiresAt: Date.now() + 10 * 60 * 1000 // 10 menit
  };

  // Log bantuan untuk pengujian lokal / console jika dibuka via file://
  console.log("%c[DEVSTUDIO ADMIN 2FA]", "background: #181920; color: #10b981; font-size: 14px; font-weight: bold; padding: 4px 8px; border-radius: 4px;", `Kode Verifikasi Anda: ${otpCode}`);

  showToast(`📧 Mengirim 7 kode verifikasi ke ${targetEmail}...`);
  openAdminOtpModal(targetEmail);

  if (window.location.protocol === "file:") {
    console.info("Pengujian lokal file:// terdeteksi: FormSubmit memerlukan server HTTP/HTTPS untuk mengirim email langsung. Kode ditampilkan di console (F12):", otpCode);
  }

  sendOtpToEmail(targetEmail, otpCode).then((data) => {
    if (data.success === "true" || data.success === true) {
      showToast(`✓ 7 kode verifikasi berhasil dikirim ke ${targetEmail}!`);
    } else {
      console.warn("Notice pengiriman FormSubmit:", data);
      if (window.location.protocol === "file:") {
        showToast(`💡 Buka Console (F12) untuk melihat kode verifikasi: ${otpCode}`);
      }
    }
  }).catch((err) => {
    console.warn("Gagal mengirim email OTP:", err);
    if (window.location.protocol === "file:") {
      showToast(`💡 Buka Console (F12) untuk melihat kode verifikasi: ${otpCode}`);
    }
  });
}

// Deteksi Kata Kunci "admin-dev" saat mengetik di input "Nama Anda"
if (saranNamaInput) {
  saranNamaInput.addEventListener("input", (e) => {
    const val = (e.target.value || "").trim().toLowerCase();
    if (val === "admin-dev") {
      e.target.value = "";
      triggerAdminOtpFlow();
    }
  });

  saranNamaInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      const val = (e.target.value || "").trim().toLowerCase();
      if (val === "admin-dev") {
        e.preventDefault();
        e.target.value = "";
        triggerAdminOtpFlow();
      }
    }
  });
}

// Form Submit: Mengirim Pesan Pengunjung Langsung ke Email (dengan Proteksi Honeypot & Rate Limiting)
if (saranForm) {
  saranForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const namaInput = document.getElementById("saran-nama");
    const emailInput = document.getElementById("saran-email");
    const kategoriInput = document.getElementById("saran-kategori");
    const pesanInput = document.getElementById("saran-pesan");
    const submitBtn = document.getElementById("saran-submit-btn") || saranForm.querySelector("button[type='submit']");

    const rawNama = namaInput ? namaInput.value.trim() : "";

    // CEK KATA KUNCI "admin-dev" SAAT SUBMIT
    if (rawNama.toLowerCase() === "admin-dev") {
      namaInput.value = "";
      triggerAdminOtpFlow();
      return;
    }

    // 1. Proteksi Anti-Spam Honeypot (Perangkap Bot Scraper Otomatis)
    const honeyField = document.getElementById("saran-security-honey");
    if (honeyField && honeyField.value.trim() !== "") {
      console.warn("Spam bot submission silently blocked.");
      showToast("✓ Pesan Anda berhasil dikirim!");
      saranForm.reset();
      return;
    }

    // 2. Proteksi Rate-Limiting / Cooldown Pengiriman Pesan
    const LAST_SUBMIT_KEY = "devstudio_last_contact_submit";
    const lastSubmitTime = parseInt(sessionStorage.getItem(LAST_SUBMIT_KEY) || "0", 10);
    const now = Date.now();
    const COOLDOWN_MS = 15000; // Jeda aman 15 detik
    if (now - lastSubmitTime < COOLDOWN_MS) {
      const remainingSec = Math.ceil((COOLDOWN_MS - (now - lastSubmitTime)) / 1000);
      showToast(`⏳ Harap tunggu ${remainingSec} detik sebelum mengirim pesan kembali.`);
      return;
    }

    const nama = sanitizeText(rawNama || "Pengunjung", 100);
    const emailPengirim = emailInput ? emailInput.value.trim() : "";
    const kategori = sanitizeText((kategoriInput && kategoriInput.value) || "Pesan Umum", 80);
    const pesan = sanitizeText((pesanInput && pesanInput.value.trim()) || "", 3000);

    if (!emailPengirim || !pesan) {
      alert("Silakan lengkapi email dan isi pesan Anda.");
      if (!emailPengirim && emailInput) emailInput.focus();
      else if (pesanInput) pesanInput.focus();
      return;
    }

    if (!VALID_EMAIL_REGEX.test(emailPengirim)) {
      alert("Format email yang Anda masukkan tidak valid. Contoh: nama@domain.com");
      if (emailInput) emailInput.focus();
      return;
    }

    if (pesan.length < 5) {
      alert("Isi pesan terlalu singkat. Harap tuliskan pesan minimal 5 karakter.");
      if (pesanInput) pesanInput.focus();
      return;
    }

    // Catat timestamp pengiriman untuk mencegah pengiriman beruntun
    sessionStorage.setItem(LAST_SUBMIT_KEY, String(Date.now()));

    const targetEmail = getRecipientEmail();

    // Indikator loading kirim
    if (submitBtn) {
      submitBtn.disabled = true;
      submitBtn.innerHTML = `<span>Mengirim pesan ke ${escapeHtml(targetEmail)}...</span> <span>⏳</span>`;
    }

    // Mengirim ke endpoint FormSubmit AJAX API secara asinkron (Direct to Email)
    fetch(`https://formsubmit.co/ajax/${encodeURIComponent(targetEmail)}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Accept": "application/json"
      },
      body: JSON.stringify({
        nama_pengirim: nama,
        email_pengirim: emailPengirim,
        kategori_pesan: kategori,
        isi_pesan: pesan,
        _subject: `[DEVSTUDIO] ${kategori} dari ${nama}`,
        _template: "table",
        _captcha: "false"
      })
    })
    .then(res => res.json())
    .then(data => {
      if (data.success === "true" || data.success === true) {
        showToast("📬 Pesan Anda berhasil dikirim ke email kami! Terima kasih.");
        saranForm.reset();
      } else {
        // Fallback langsung ke mailto
        showToast("✓ Membuka aplikasi email untuk mengirim pesan...");
        window.location.href = `mailto:${targetEmail}?subject=${encodeURIComponent('[DEVSTUDIO ' + kategori + '] dari ' + nama)}&body=${encodeURIComponent(pesan + '\n\n---\nDari: ' + nama + '\nEmail Balasan: ' + emailPengirim)}`;
        saranForm.reset();
      }
    })
    .catch(() => {
      // Fallback mailto jika offline atau browser memblokir fetch
      showToast("✓ Membuka aplikasi email untuk mengirim pesan...");
      window.location.href = `mailto:${targetEmail}?subject=${encodeURIComponent('[DEVSTUDIO ' + kategori + '] dari ' + nama)}&body=${encodeURIComponent(pesan + '\n\n---\nDari: ' + nama + '\nEmail Balasan: ' + emailPengirim)}`;
      saranForm.reset();
    })
    .finally(() => {
      if (submitBtn) {
        submitBtn.disabled = false;
        submitBtn.innerHTML = `<span>Kirim Pesan Sekarang</span> <span>✉</span>`;
      }
    });
  });
}

/**
 * 8. MODE ADMIN — KELOLA PROYEK
 */


function openAdminOtpModal(email) {
  if (!adminOtpModal) return;
  adminOtpModal.style.display = "flex";
  adminOtpModal.classList.add("active");
  adminOtpModal.setAttribute("aria-hidden", "false");
  document.body.style.overflow = "hidden";
  if (otpEmailTargetText) otpEmailTargetText.textContent = email;
  if (adminOtpError) adminOtpError.style.display = "none";
  if (adminOtpInput) {
    adminOtpInput.value = "";
    setTimeout(() => adminOtpInput.focus(), 150);
  }
}

function closeAdminOtpModal() {
  if (!adminOtpModal) return;
  adminOtpModal.classList.remove("active");
  adminOtpModal.style.display = "none";
  adminOtpModal.setAttribute("aria-hidden", "true");
  document.body.style.overflow = "";
}

if (adminOtpCloseBtn) {
  adminOtpCloseBtn.addEventListener("click", closeAdminOtpModal);
}

if (adminOtpModal) {
  adminOtpModal.addEventListener("click", (e) => {
    if (e.target === adminOtpModal) closeAdminOtpModal();
  });
}

if (adminOtpForm) {
  adminOtpForm.addEventListener("submit", (e) => {
    e.preventDefault();
    const inputVal = (adminOtpInput ? adminOtpInput.value : "").trim().toUpperCase();

    if (!currentAdminOtp) {
      if (adminOtpError) {
        adminOtpError.textContent = "Belum ada kode verifikasi aktif. Ketik 'admin-dev' untuk meminta kode.";
        adminOtpError.style.display = "block";
      }
      return;
    }

    if (Date.now() > currentAdminOtp.expiresAt) {
      if (adminOtpError) {
        adminOtpError.textContent = "Kode verifikasi telah kedaluwarsa. Ketik kembali 'admin-dev' di formulir pesan.";
        adminOtpError.style.display = "block";
      }
      return;
    }

    if (inputVal === currentAdminOtp.code) {
      // COCOK!
      currentAdminOtp = null;
      closeAdminOtpModal();
      activateAdminMode();
      showToast("🔓 Kode 7 Karakter Cocok! Selamat datang di Mode Pengelola.");
    } else {
      // TOLAK!
      if (adminOtpError) {
        adminOtpError.textContent = "❌ Kode tidak cocok! Akses ditolak. Periksa kembali email Anda.";
        adminOtpError.style.display = "block";
      }
    }
  });
}

function activateAdminMode() {
  sessionStorage.setItem("devstudio_admin_active", "true");
  if (adminFloatingBar) {
    adminFloatingBar.style.display = "block";
  }
  openAdminModal();
  showToast("🛡️ Sesi Administrator Terverifikasi: Mode Pengelola Aktif!");
}

function logoutAdminMode() {
  sessionStorage.removeItem("devstudio_admin_active");
  if (adminFloatingBar) {
    adminFloatingBar.style.display = "none";
  }
  closeAdminModal();
  showToast("🔒 Mode Administrator Ditutup.");
}

function openAdminModal() {
  if (!adminModal) return;
  adminModal.classList.add("active");
  adminModal.setAttribute("aria-hidden", "false");
  document.body.style.overflow = "hidden";
  if (adminRecipientEmailInput) {
    adminRecipientEmailInput.value = getRecipientEmail();
  }
  switchAdminTab("list");
  renderAdminProjectList();
}

function closeAdminModal() {
  if (!adminModal) return;
  adminModal.classList.remove("active");
  adminModal.setAttribute("aria-hidden", "true");
  document.body.style.overflow = "";
}

function switchAdminTab(tabName) {
  if (tabName === "list") {
    if (tabBtnList) tabBtnList.classList.add("active");
    if (tabBtnForm) tabBtnForm.classList.remove("active");
    if (adminTabList) adminTabList.style.display = "block";
    if (adminTabForm) adminTabForm.style.display = "none";
  } else if (tabName === "form") {
    if (tabBtnList) tabBtnList.classList.remove("active");
    if (tabBtnForm) tabBtnForm.classList.add("active");
    if (adminTabList) adminTabList.style.display = "none";
    if (adminTabForm) adminTabForm.style.display = "block";
  }
}

function resetFormToNew() {
  if (!adminProjectForm) return;
  adminProjectForm.reset();
  if (formEditId) formEditId.value = "";
  if (formModeTitle) formModeTitle.textContent = "➕ Tambah Proyek Baru";
  if (formVersion) formVersion.value = "v1.0.0";
  if (formYear) formYear.value = new Date().getFullYear().toString();
  if (formTheme) formTheme.value = "theme-mint";
  if (formImageFile) formImageFile.value = "";
  if (formFileName) {
    formFileName.textContent = "Klik tombol untuk memilih gambar (PNG/JPG/WebP)";
    formFileName.style.color = "var(--text-dim)";
  }
  if (formImagePreview) {
    formImagePreview.style.backgroundImage = "";
    formImagePreview.innerHTML = `<span style="color: var(--text-dim); font-size: 12px;">Masukkan URL foto di atas untuk melihat pratinjau</span>`;
  }
}

function renderAdminProjectList() {
  if (!adminProjectsList) return;
  if (adminTotalCount) adminTotalCount.textContent = projects.length;

  const filtered = projects;

  if (filtered.length === 0) {
    adminProjectsList.innerHTML = `
      <div style="text-align: center; padding: 40px; color: var(--text-dim); background: #181920; border-radius: var(--radius-md);">
        Belum ada proyek. Silakan klik tombol <strong>➕ Tambah Proyek Baru</strong> di atas.
      </div>
    `;
    return;
  }

  adminProjectsList.innerHTML = "";
  filtered.forEach((p) => {
    const itemEl = document.createElement("div");
    itemEl.className = "admin-project-item";

    itemEl.innerHTML = `
      <div class="admin-proj-left">
        <div class="admin-proj-thumb" style="background-image: url('${p.image}');"></div>
        <div class="admin-proj-info">
          <div class="admin-proj-title-row">
            <span class="admin-proj-title" title="${escapeHtml(p.title)}">${escapeHtml(p.title)}</span>
            <span style="font-size: 11px; color: var(--text-dim); font-family: monospace; background: rgba(255, 255, 255, 0.06); padding: 2px 6px; border-radius: 4px;">${escapeHtml(p.version || 'v1.0.0')} (${escapeHtml(p.year || '2026')})</span>
          </div>
          <div class="admin-proj-sub" title="${escapeHtml(p.summary)}">
            ${escapeHtml(p.summary)}
          </div>
          <div style="font-size: 11px; color: var(--mint-base); margin-top: 2px;">
            ${p.tags ? p.tags.slice(0, 4).map(t => `#${escapeHtml(t)}`).join(" ") : ""}
          </div>
        </div>
      </div>
      <div class="admin-proj-actions">
        <button type="button" class="btn-admin-edit" data-id="${p.id}" title="Edit proyek ini">✏️ Edit</button>
        <button type="button" class="btn-admin-delete" data-id="${p.id}" title="Hapus proyek ini">🗑️ Hapus</button>
      </div>
    `;

    // Button event listeners
    const editBtn = itemEl.querySelector(".btn-admin-edit");
    if (editBtn) {
      editBtn.addEventListener("click", () => editProject(p.id));
    }

    const deleteBtn = itemEl.querySelector(".btn-admin-delete");
    if (deleteBtn) {
      deleteBtn.addEventListener("click", () => deleteProject(p.id));
    }

    adminProjectsList.appendChild(itemEl);
  });
}

function editProject(id) {
  const p = projects.find(item => item.id === id);
  if (!p) return;

  if (formEditId) formEditId.value = p.id;
  if (formModeTitle) formModeTitle.textContent = `✏️ Edit Proyek: ${p.title}`;
  if (formTitle) formTitle.value = p.title || "";
  if (formVersion) formVersion.value = p.version || "v1.0.0";
  if (formYear) formYear.value = p.year || "2026";
  if (formTheme) formTheme.value = p.theme || "theme-mint";
  if (formImage) formImage.value = p.image || "";
  if (formImageFile) formImageFile.value = "";
  if (formFileName) {
    formFileName.textContent = p.image ? `File/URL aktif terpasang` : "Klik tombol untuk memilih gambar (PNG/JPG/WebP)";
    formFileName.style.color = p.image ? "var(--mint-base)" : "var(--text-dim)";
  }
  if (formSummary) formSummary.value = p.summary || "";
  if (formTags) formTags.value = Array.isArray(p.tags) ? p.tags.join(", ") : (p.tags || "");
  if (formGithub) formGithub.value = p.github || "";
  if (formDemo) formDemo.value = p.demo || "";
  if (formFeatures) formFeatures.value = Array.isArray(p.features) ? p.features.join("\n") : (p.features || "");

  if (formImagePreview) {
    if (p.image) {
      formImagePreview.style.backgroundImage = `url('${p.image}')`;
      formImagePreview.innerHTML = "";
    } else {
      formImagePreview.style.backgroundImage = "";
      formImagePreview.innerHTML = `<span style="color: var(--text-dim); font-size: 12px;">Foto kosong</span>`;
    }
  }

  switchAdminTab("form");
}

function deleteProject(id) {
  const p = projects.find(item => item.id === id);
  if (!p) return;

  const confirmed = confirm(`Apakah Anda yakin ingin menghapus proyek "${p.title}"?`);
  if (!confirmed) return;

  const updatedProjects = projects.filter(item => item.id !== id);
  saveProjects(updatedProjects);



  showToast(`🗑️ Proyek "${p.title}" berhasil dihapus.`);
}

// Live Image Preview in Form
if (formImage) {
  formImage.addEventListener("input", () => {
    const url = formImage.value.trim();
    if (formImagePreview) {
      if (url) {
        formImagePreview.style.backgroundImage = `url('${url}')`;
        formImagePreview.innerHTML = "";
      } else {
        formImagePreview.style.backgroundImage = "";
        formImagePreview.innerHTML = `<span style="color: var(--text-dim); font-size: 12px;">Masukkan URL foto di atas untuk melihat pratinjau</span>`;
      }
    }
  });
}

// Upload/Pilih File Gambar Langsung dari Folder Komputer
if (formImageFile) {
  formImageFile.addEventListener("change", (e) => {
    const file = e.target.files && e.target.files[0];
    if (!file) return;

    if (formFileName) {
      formFileName.textContent = `✓ ${file.name} (${Math.round(file.size / 1024)} KB)`;
      formFileName.style.color = "var(--mint-base)";
    }

    const reader = new FileReader();
    reader.onload = function(evt) {
      const dataUrl = evt.target.result;
      if (formImage) {
        formImage.value = dataUrl;
      }
      if (formImagePreview) {
        formImagePreview.style.backgroundImage = `url('${dataUrl}')`;
        formImagePreview.innerHTML = "";
      }
    };
    reader.readAsDataURL(file);
  });
}

// Admin Form Submit (Save New or Edited Project)
if (adminProjectForm) {
  adminProjectForm.addEventListener("submit", (e) => {
    e.preventDefault();

    const title = sanitizeText(formTitle ? formTitle.value : "", 120);
    const version = sanitizeText(formVersion ? formVersion.value : "v1.0.0", 30);
    const year = sanitizeText(formYear ? formYear.value : "2026", 10);
    const theme = ["theme-mint", "theme-blue", "theme-sky", "theme-cyan"].includes(formTheme ? formTheme.value : "") ? formTheme.value : "theme-mint";
    const image = sanitizeCssUrl(formImage ? formImage.value : "");
    const summary = sanitizeText(formSummary ? formSummary.value : "", 1500);
    const tagsRaw = formTags ? formTags.value.trim() : "";
    const github = sanitizeUrl(formGithub ? formGithub.value : "", "");
    const demo = sanitizeUrl(formDemo ? formDemo.value : "", "");
    const featuresRaw = formFeatures ? formFeatures.value.trim() : "";

    if (!title || !image || !summary) {
      alert("Harap isi Judul, URL Foto, dan Deskripsi Ringkas proyek secara valid.");
      return;
    }

    const tags = tagsRaw
      ? tagsRaw.split(",").map(t => sanitizeText(t, 40)).filter(Boolean)
      : ["Portfolio", "Proyek"];

    const features = featuresRaw
      ? featuresRaw.split("\n").map(f => sanitizeText(f, 300)).filter(Boolean)
      : ["Fitur performa tinggi teroptimasi.", "Arsitektur modular dan scalable."];

    const editId = formEditId ? formEditId.value : "";

    if (editId) {
      // Update existing project
      const index = projects.findIndex(item => item.id === editId);
      if (index !== -1) {
        const updatedProj = {
          ...projects[index],
          title,
          version,
          year,
          theme,
          image,
          summary,
          tags,
          github: github || `https://github.com/example/${title.toLowerCase().replace(/[^a-z0-9]/g, '-')}`,
          demo: demo || `https://example.com/${title.toLowerCase().replace(/[^a-z0-9]/g, '-')}`,
          features
        };
        projects[index] = updatedProj;
        saveProjects([...projects]);

        showToast(`✓ Proyek "${title}" berhasil diperbarui! Klik "Simpan ke Excel" untuk mengunduh CSV terbaru.`);
      }
    } else {
      // Add new project
      const newId = String(Date.now()).slice(-4);
      const newProj = {
        id: newId,
        title,
        version: version || "v1.0.0",
        year: year || "2026",
        theme,
        image,
        summary,
        tags,
        github: github || `https://github.com/example/${title.toLowerCase().replace(/[^a-z0-9]/g, '-')}`,
        demo: demo || `https://example.com/${title.toLowerCase().replace(/[^a-z0-9]/g, '-')}`,
        features
      };

      saveProjects([newProj, ...projects]);

      showToast(`✓ Proyek baru "${title}" berhasil ditambahkan! Klik "Simpan ke Excel" untuk mengunduh CSV terbaru.`);
    }

    switchAdminTab("list");
  });
}

// Form Cancel Button
if (formCancelBtn) {
  formCancelBtn.addEventListener("click", () => {
    switchAdminTab("list");
  });
}

// Reset Projects to Default
if (btnResetDefault) {
  btnResetDefault.addEventListener("click", () => {
    const ok = confirm("PERINGATAN: Apakah Anda yakin ingin mereset semua proyek kembali ke daftar bawaan awal?");
    if (ok) {
      saveProjects(JSON.parse(JSON.stringify(defaultProjects)));
      showToast("🔄 Semua proyek berhasil dikembalikan ke default!");
    }
  });
}

// Sub-tabs navigation in Admin
if (tabBtnList) {
  tabBtnList.addEventListener("click", () => switchAdminTab("list"));
}

if (tabBtnForm) {
  tabBtnForm.addEventListener("click", () => {
    resetFormToNew();
    switchAdminTab("form");
  });
}

// Admin Floating Bar buttons
if (openAdminPanelBtn) {
  openAdminPanelBtn.addEventListener("click", openAdminModal);
}

if (logoutAdminBtn) {
  logoutAdminBtn.addEventListener("click", () => {
    const ok = confirm("Keluar dari Mode Admin?");
    if (ok) logoutAdminMode();
  });
}

// Admin Modal Close events
if (adminModalCloseBtn) {
  adminModalCloseBtn.addEventListener("click", closeAdminModal);
}

if (adminModal) {
  adminModal.addEventListener("click", (e) => {
    if (e.target === adminModal) closeAdminModal();
  });
}

// Simpan Pengaturan Email Penerima Pesan di Mode Admin
if (btnSaveRecipientEmail) {
  btnSaveRecipientEmail.addEventListener("click", () => {
    const email = adminRecipientEmailInput ? adminRecipientEmailInput.value.trim() : "";
    if (!email || !email.includes("@")) {
      alert("Harap masukkan alamat email yang valid (contoh: nama@gmail.com).");
      return;
    }
    setRecipientEmail(email);
    showToast(`✓ Email penerima berhasil disimpan: ${email}`);
  });
}

// Restore admin mode if previously logged in during this session
if (sessionStorage.getItem("devstudio_admin_active") === "true") {
  if (adminFloatingBar) adminFloatingBar.style.display = "block";
}

// Saweria Centered Modal Entrance Popup & Floating Reopen Button
const saweriaModalBackdrop = document.getElementById("saweria-modal-backdrop");
const saweriaModalClose = document.getElementById("saweria-modal-close");
const btnSaweriaDismiss = document.getElementById("btn-saweria-dismiss");
const saweriaFloatingBtn = document.getElementById("saweria-floating-btn");

function closeSaweriaModal() {
  if (!saweriaModalBackdrop) return;
  saweriaModalBackdrop.classList.remove("active");
  document.body.style.overflow = "";
  // Tampilkan tombol lingkaran Saweria di pojok kanan bawah setelah notif ditutup
  if (saweriaFloatingBtn) {
    saweriaFloatingBtn.style.display = "flex";
  }
}

function openSaweriaModal() {
  if (!saweriaModalBackdrop) return;
  saweriaModalBackdrop.classList.add("active");
  document.body.style.overflow = "hidden";
  // Sembunyikan tombol lingkaran saat modal sedang terbuka
  if (saweriaFloatingBtn) {
    saweriaFloatingBtn.style.display = "none";
  }
}

if (saweriaModalBackdrop) {
  // Munculkan notifikasi modal besar di tengah layar sesaat setelah masuk ke halaman web
  setTimeout(openSaweriaModal, 800);

  if (saweriaModalClose) {
    saweriaModalClose.addEventListener("click", closeSaweriaModal);
  }

  if (btnSaweriaDismiss) {
    btnSaweriaDismiss.addEventListener("click", closeSaweriaModal);
  }

  saweriaModalBackdrop.addEventListener("click", (e) => {
    if (e.target === saweriaModalBackdrop) closeSaweriaModal();
  });
}

if (saweriaFloatingBtn) {
  saweriaFloatingBtn.addEventListener("click", openSaweriaModal);
}

/**
 * 9. UTILITIES
 */
function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// Initial Boot
renderMarquees();

// Inisialisasi awal sistem proyek selesai
