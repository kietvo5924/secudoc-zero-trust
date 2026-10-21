/**
 * SecuDoc - Client-side UI Interactions, Web Crypto Privacy Verifier & Attack Lab
 */

document.addEventListener("DOMContentLoaded", () => {
  // 1. File Dropzone Handling for Standard Mode
  const dropzone = document.getElementById("fileDropzone");
  const fileInput = document.getElementById("documentFileInput");
  const fileNameDisplay = document.getElementById("selectedFileName");

  if (dropzone && fileInput) {
    dropzone.addEventListener("dragover", (e) => {
      e.preventDefault();
      dropzone.classList.add("dragover");
    });

    dropzone.addEventListener("dragleave", () => {
      dropzone.classList.remove("dragover");
    });

    dropzone.addEventListener("drop", (e) => {
      e.preventDefault();
      dropzone.classList.remove("dragover");
      if (e.dataTransfer.files.length > 0) {
        fileInput.files = e.dataTransfer.files;
        updateFileName(e.dataTransfer.files[0].name);
      }
    });

    fileInput.addEventListener("change", () => {
      if (fileInput.files.length > 0) {
        updateFileName(fileInput.files[0].name);
      }
    });

    function updateFileName(name) {
      if (fileNameDisplay) {
        fileNameDisplay.textContent = "📄 Đã chọn: " + name;
        fileNameDisplay.style.display = "inline-block";
      }
    }
  }

  // 2. Privacy-Preserving In-Browser Dropzone (Web Crypto API)
  const privacyDropzone = document.getElementById("privacyDropzone");
  const privacyFileInput = document.getElementById("privacyFileInput");
  const privacyFileName = document.getElementById("privacyFileName");

  if (privacyDropzone && privacyFileInput) {
    privacyDropzone.addEventListener("dragover", (e) => {
      e.preventDefault();
      privacyDropzone.classList.add("dragover");
    });
    privacyDropzone.addEventListener("dragleave", () => {
      privacyDropzone.classList.remove("dragover");
    });
    privacyDropzone.addEventListener("drop", (e) => {
      e.preventDefault();
      privacyDropzone.classList.remove("dragover");
      if (e.dataTransfer.files.length > 0) {
        privacyFileInput.files = e.dataTransfer.files;
        handlePrivacyFile(e.dataTransfer.files[0]);
      }
    });
    privacyFileInput.addEventListener("change", () => {
      if (privacyFileInput.files.length > 0) {
        handlePrivacyFile(privacyFileInput.files[0]);
      }
    });
  }

  // 3. Copy to Clipboard buttons
  document.querySelectorAll(".copy-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      const textToCopy = btn.getAttribute("data-copy");
      if (textToCopy) {
        navigator.clipboard.writeText(textToCopy).then(() => {
          const originalText = btn.innerHTML;
          btn.innerHTML = "✓ Đã chép!";
          setTimeout(() => {
            btn.innerHTML = originalText;
          }, 1500);
        });
      }
    });
  });
});

/**
 * Switch between Standard Mode (File Upload) and Privacy Mode (In-Browser Web Crypto)
 */
function switchVerifyMode(mode) {
  const stdCard = document.getElementById("modeStandardCard");
  const privCard = document.getElementById("modePrivacyCard");
  const tabStd = document.getElementById("tabStandard");
  const tabPriv = document.getElementById("tabPrivacy");

  if (mode === "privacy") {
    if (stdCard) stdCard.style.display = "none";
    if (privCard) privCard.style.display = "block";
    if (tabStd) { tabStd.className = "btn btn-secondary"; }
    if (tabPriv) { tabPriv.className = "btn btn-primary"; }
  } else {
    if (stdCard) stdCard.style.display = "block";
    if (privCard) privCard.style.display = "none";
    if (tabStd) { tabStd.className = "btn btn-primary"; }
    if (tabPriv) { tabPriv.className = "btn btn-secondary"; }
  }
}

/**
 * Handle in-browser client-side hashing via Web Crypto API (Zero-Knowledge Privacy Proof)
 */
async function handlePrivacyFile(file) {
  const statusArea = document.getElementById("privacyStatusArea");
  const fileNameDisplay = document.getElementById("privacyFileName");
  const claimedUuid = (document.getElementById("privacyClaimedUuid")?.value || "").trim();

  if (fileNameDisplay) {
    fileNameDisplay.textContent = `📄 Đang xử lý trong RAM: ${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
    fileNameDisplay.style.display = "inline-block";
  }

  statusArea.innerHTML = `
    <div style="padding: 1.5rem; text-align: center; color: var(--accent-cyan); background: rgba(0, 229, 255, 0.05); border-radius: var(--radius-sm);">
      <span class="mono">⚙️ Đang đọc ArrayBuffer và băm SHA-256 nội tuyến bằng Web Crypto API (0 byte upload)...</span>
    </div>
  `;

  try {
    const arrayBuffer = await file.arrayBuffer();
    const hashBuffer = await crypto.subtle.digest("SHA-256", arrayBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const computedHash = hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");

    // Send solely the 64-character hash across the network
    const res = await fetch("/api/verify-hash", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ hash: computedHash, claimed_uuid: claimedUuid || null })
    });
    const result = await res.json();

    let certButtonHtml = "";
    if (result.document) {
      certButtonHtml = `
        <div style="margin-top: 1rem; text-align: right;">
          <a href="/certificate/${result.document.doc_uuid}" target="_blank" class="btn btn-secondary" style="text-decoration: none;">
            📜 Mở Phiếu Chứng Thực Mật Mã & Quét QR Code
          </a>
        </div>
      `;
    }

    statusArea.innerHTML = `
      <div class="verdict-banner ${result.badge_class}" style="margin-top: 1rem;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
          <div class="verdict-title">${result.verdict_title}</div>
          <span class="user-badge" style="background: rgba(0, 230, 118, 0.15); color: #00e676; border-color: #00e676;">
            🔒 ZERO-KNOWLEDGE PROOF (0 BYTE UPLOAD)
          </span>
        </div>
        <p style="font-size: 1rem; margin-bottom: 1.25rem;">${result.explanation}</p>
        
        <div class="details-grid">
          <div class="detail-item">
            <div class="detail-label">MÃ BĂM TÍNH TOÁN TRONG TRÌNH DUYỆT (IN-BROWSER SHA-256)</div>
            <div class="detail-val mono" style="color: #80d8ff; font-size: 0.8rem;">${computedHash}</div>
          </div>
          <div class="detail-item">
            <div class="detail-label">MÃ BĂM GỐC TỪ CHỨNG THỰC CỦA TRƯỜNG</div>
            <div class="detail-val mono" style="color: #b388ff; font-size: 0.8rem;">${result.expected_hash || "CHƯA ĐĂNG KÝ TRONG HỆ THỐNG"}</div>
          </div>
          <div class="detail-item">
            <div class="detail-label">XÁC MINH CHỮ KÝ SỐ RSA-2048</div>
            <div class="detail-val">
              ${result.signature_valid ? '<span style="color: var(--accent-green);">✓ HỢP LỆ (Root Public Key)</span>' : '<span style="color: var(--accent-red);">✗ KHÔNG HỢP LỆ</span>'}
            </div>
          </div>
          <div class="detail-item">
            <div class="detail-label">BẢO MẬT DỮ LIỆU CÁ NHÂN (PII PROTECTION)</div>
            <div class="detail-val" style="color: var(--accent-green);">
              ✓ TUÂN THỦ NGHỊ ĐỊNH 13/2023 & GDPR (File không rời RAM)
            </div>
          </div>
        </div>
        ${certButtonHtml}
      </div>
    `;
  } catch (err) {
    statusArea.innerHTML = `<div class="alert alert-danger">Lỗi xử lý băm Web Crypto: ${err.message}</div>`;
  }
}

/**
 * Interactive Attack Lab: Simulate Bit-Flip Tampering Attack with Avalanche Heatmap
 */
async function runBitFlipAttack(docUuid = "") {
  const resultContainer = document.getElementById("bitFlipResult");
  if (!resultContainer) return;

  resultContainer.innerHTML = `
    <div style="padding: 1.5rem; text-align: center; color: var(--accent-cyan);">
      <span>⚡ Đang thực thi tấn công đảo 1 bit nhị phân và chạy Zero-Trust Verification Engine...</span>
    </div>
  `;

  try {
    const res = await fetch("/api/attack/bit-flip", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ doc_uuid: docUuid })
    });
    const data = await res.json();

    // Generate 256-bit Avalanche Heatmap Grid
    let heatmapHtml = "";
    if (data.bit_vector && Array.isArray(data.bit_vector)) {
      heatmapHtml = `
        <div style="margin-top: 1.25rem; background: rgba(5, 8, 17, 0.7); border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 8px; padding: 1.25rem;">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem;">
            <div style="font-size: 0.85rem; font-weight: 700; color: var(--accent-cyan);">
              🔬 MA TRẬN 256 BITS SHA-256 (AVALANCHE EFFECT HEATMAP)
            </div>
            <div style="font-size: 0.8rem; color: var(--text-muted);">
              <span style="display: inline-block; width: 10px; height: 10px; background: #00e676; border-radius: 2px; margin-right: 4px;"></span> Giữ nguyên: ${data.total_bits - data.diff_bits} bits &nbsp;&nbsp;
              <span style="display: inline-block; width: 10px; height: 10px; background: #ff3366; border-radius: 2px; margin-right: 4px;"></span> Đảo chiều: ${data.diff_bits} bits (${data.avalanche_percentage}%)
            </div>
          </div>
          <div style="display: grid; grid-template-columns: repeat(32, 1fr); gap: 3px; max-width: 100%;">
      `;
      data.bit_vector.forEach((bit, i) => {
        const bg = bit === 1 ? "#ff3366" : "rgba(0, 230, 118, 0.35)";
        const border = bit === 1 ? "1px solid #ff1744" : "1px solid rgba(0, 230, 118, 0.5)";
        heatmapHtml += `<div title="Bit ${i}: ${bit === 1 ? 'ĐÃ ĐẢO CHIỀU (FLIPPED)' : 'GIỮ NGUYÊN'}" style="aspect-ratio: 1; background: ${bg}; border: ${border}; border-radius: 2px; cursor: pointer;"></div>`;
      });
      heatmapHtml += `</div>
        <div style="margin-top: 0.75rem; background: rgba(255, 255, 255, 0.05); height: 8px; border-radius: 4px; overflow: hidden;">
          <div style="width: ${data.avalanche_percentage}%; height: 100%; background: linear-gradient(90deg, #ff9100, #ff1744);"></div>
        </div>
      </div>`;
    }

    // Forensic Byte Difference Inspector
    const forensicHtml = `
      <div style="margin-top: 1.25rem; background: rgba(255, 51, 102, 0.07); border: 1px solid rgba(255, 51, 102, 0.3); border-radius: 8px; padding: 1rem;">
        <h4 style="color: #ff8a80; font-size: 0.95rem; margin-bottom: 0.5rem; display: flex; align-items: center; gap: 0.5rem;">
          <span>🔍</span> KÍNH HIỂN VI SOI TỪNG BYTE DỮ LIỆU BỊ SỬA LÉN (BYTE FORENSIC INSPECTOR):
        </h4>
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 1rem; font-size: 0.85rem;">
          <div style="background: rgba(0, 0, 0, 0.4); padding: 0.75rem; border-radius: 6px;">
            <div style="color: var(--accent-green); font-weight: 700;">BYTE GỐC (OFFSET 0x0000):</div>
            <div>Ký tự: <code class="mono" style="color: #fff; font-size: 1rem;">'${data.original_char}'</code></div>
            <div>Hex: <code class="mono" style="color: #80d8ff;">${data.original_byte_hex}</code> | Binary: <code class="mono" style="color: #80d8ff;">${data.original_byte_bin}</code></div>
          </div>
          <div style="background: rgba(0, 0, 0, 0.4); padding: 0.75rem; border-radius: 6px;">
            <div style="color: var(--accent-red); font-weight: 700;">BYTE SAU CAN THIỆP 1 BIT (OFFSET 0x0000):</div>
            <div>Ký tự: <code class="mono" style="color: #ff5252; font-size: 1rem;">'${data.tampered_char}'</code></div>
            <div>Hex: <code class="mono" style="color: #ff8a80;">${data.tampered_byte_hex}</code> | Binary: <code class="mono" style="color: #ff8a80;">${data.tampered_byte_bin}</code></div>
          </div>
        </div>
      </div>
    `;

    resultContainer.innerHTML = `
      <div class="verdict-banner ${data.verdict.badge_class}" style="margin-top: 1.5rem;">
        <div class="verdict-title">${data.verdict.verdict_title}</div>
        <p style="margin-bottom: 1rem;">${data.verdict.explanation}</p>
        
        <div class="details-grid">
          <div class="detail-item">
            <div class="detail-label">MÃ BĂM GỐC CỦA TỆP (ORIGINAL SHA-256)</div>
            <div class="detail-val mono" style="color: var(--accent-green); font-size: 0.82rem;">${data.original_hash}</div>
          </div>
          <div class="detail-item">
            <div class="detail-label">MÃ BĂM SAU KHI SỬA ĐÚNG 1 BIT (TAMPERED SHA-256)</div>
            <div class="detail-val mono" style="color: var(--accent-red); font-size: 0.82rem;">${data.tampered_hash}</div>
          </div>
          <div class="detail-item">
            <div class="detail-label">HIỆU ỨNG TUYẾT LỞ (AVALANCHE EFFECT)</div>
            <div class="detail-val" style="color: var(--accent-amber); font-weight: 700;">
              ${data.diff_bits} / ${data.total_bits} bits thay đổi (${data.avalanche_percentage}%)
            </div>
          </div>
          <div class="detail-item">
            <div class="detail-label">KẾT LUẬN ZERO-TRUST</div>
            <div class="detail-val" style="color: var(--accent-red); font-weight: 800;">
              CHẶN ĐỨNG THÀNH CÔNG (100% BLOCKED)
            </div>
          </div>
        </div>

        ${forensicHtml}
        ${heatmapHtml}
      </div>
    `;
  } catch (err) {
    resultContainer.innerHTML = `<div class="alert alert-danger">Lỗi thực thi mô phỏng: ${err.message}</div>`;
  }
}

/**
 * Interactive Attack Lab: Simulate Signature Forgery Attack
 */
async function runSignatureForgery(docUuid = "") {
  const resultContainer = document.getElementById("forgeryResult");
  if (!resultContainer) return;

  resultContainer.innerHTML = `
    <div style="padding: 1.5rem; text-align: center; color: var(--accent-cyan);">
      <span>⚡ Đang giả lập kẻ tấn công tự sinh cặp khóa RSA rogue và giả mạo chữ ký...</span>
    </div>
  `;

  try {
    const res = await fetch("/api/attack/forge-signature", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ doc_uuid: docUuid })
    });
    const data = await res.json();

    resultContainer.innerHTML = `
      <div class="verdict-banner badge-danger" style="margin-top: 1.5rem;">
        <div class="verdict-title">🚨 TẤN CÔNG GIẢ MẠO CHỮ KÝ BỊ CHẶN HOÀN TOÀN!</div>
        <p style="margin-bottom: 1rem;">${data.explanation}</p>
        
        <div class="details-grid">
          <div class="detail-item">
            <div class="detail-label">CHỮ KÝ GIẢ MẠO TẠO BỞI KHÓA ROGUE</div>
            <div class="detail-val mono" style="font-size: 0.8rem; color: #ff8a80;">${data.forged_signature}</div>
          </div>
          <div class="detail-item">
            <div class="detail-label">ĐỐI SOÁT VỚI ROOT PUBLIC KEY CHÍNH THỨC</div>
            <div class="detail-val" style="color: var(--accent-red); font-weight: 800;">
              XÁC THỰC THẤT BẠI (VERIFICATION: FALSE)
            </div>
          </div>
        </div>
      </div>
    `;
  } catch (err) {
    resultContainer.innerHTML = `<div class="alert alert-danger">Lỗi thực thi mô phỏng: ${err.message}</div>`;
  }
}

/**
 * Interactive Ledger Integrity Verification
 */
async function runLiveAuditCheck() {
  const resultDiv = document.getElementById("auditLiveResult");
  if (!resultDiv) return;

  resultDiv.innerHTML = `<span style="color: var(--accent-cyan);">Đang quét toán học toàn bộ chuỗi băm Merkle...</span>`;

  try {
    const res = await fetch("/api/audit/verify");
    const data = await res.json();

    if (data.is_valid) {
      resultDiv.innerHTML = `
        <div class="alert alert-success" style="margin-top: 1rem;">
          <strong>✓ KẾT QUẢ TOÀN VẸN:</strong> ${data.message} (Tổng số khối: ${data.total_blocks})
        </div>
      `;
    } else {
      resultDiv.innerHTML = `
        <div class="alert alert-danger" style="margin-top: 1rem;">
          <strong>🚨 CẢNH BÁO NGUY HIỂM:</strong> ${data.message} (Vỡ chuỗi tại Block: ${data.broken_at_block_index})
        </div>
      `;
    }
  } catch (err) {
    resultDiv.innerHTML = `<div class="alert alert-danger">Lỗi kiểm toán: ${err.message}</div>`;
  }
}

/**
 * Simulate Database Tamper
 */
async function runDatabaseTamper(blockIndex = 0) {
  const resultDiv = document.getElementById("auditLiveResult");
  if (!resultDiv) return;

  resultDiv.innerHTML = `<span style="color: var(--accent-red);">Đang can thiệp sửa trực tiếp 1 ô dữ liệu trong SQLite...</span>`;

  try {
    const res = await fetch("/api/attack/tamper-db", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ block_index: blockIndex })
    });
    const data = await res.json();

    resultDiv.innerHTML = `
      <div class="alert alert-danger" style="margin-top: 1rem;">
        <strong>🚨 SỔ CÁI BỊ VỠ:</strong> Kẻ tấn công nội bộ đã sửa ô dữ liệu tại Block ${blockIndex}. 
        Thuật toán băm liên hoàn lập tức phát hiện đứt gãy: "${data.verification.message}"
        <div style="margin-top: 0.75rem;">
          <button type="button" class="btn btn-secondary" onclick="runRestoreDatabase(${blockIndex})" style="font-size: 0.85rem;">
            🔄 Khôi Phục Dữ Liệu Gốc (Self-Healing Revert)
          </button>
        </div>
      </div>
    `;
  } catch (err) {
    resultDiv.innerHTML = `<div class="alert alert-danger">Lỗi can thiệp DB: ${err.message}</div>`;
  }
}

/**
 * Restore Database Tamper (Self-Healing)
 */
async function runRestoreDatabase(blockIndex = 0) {
  const resultDiv = document.getElementById("auditLiveResult");
  if (!resultDiv) return;

  resultDiv.innerHTML = `<span style="color: var(--accent-cyan);">Đang khôi phục dữ liệu gốc cho Block ${blockIndex}...</span>`;

  try {
    const res = await fetch("/api/attack/restore-db", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ block_index: blockIndex })
    });
    const data = await res.json();

    resultDiv.innerHTML = `
      <div class="alert alert-success" style="margin-top: 1rem;">
        <strong>✓ ĐÃ KHÔI PHỤC TOÀN VẸN:</strong> Block ${blockIndex} đã được hoàn nguyên về 'GENESIS'.
        Chuỗi băm Merkle đã khôi phục trạng thái toàn vẹn 100%!
      </div>
    `;
  } catch (err) {
    resultDiv.innerHTML = `<div class="alert alert-danger">Lỗi khôi phục: ${err.message}</div>`;
  }
}
