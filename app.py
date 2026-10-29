import hashlib
import hmac
import json
import secrets
from datetime import datetime
from pathlib import Path

import pandas as pd
import streamlit as st

# 1. App settings
st.set_page_config(
    page_title="File Integrity Checker",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)
APP_DIR = Path(__file__).resolve().parent
BASELINE_PATH = APP_DIR / "baseline.json"
KEY_PATH = APP_DIR / ".baseline_key"
HISTORY_PATH = APP_DIR / "scan_history.jsonl"
CHUNK_SIZE = 1024 * 1024

# 2. Cybersecurity Pro theme
st.markdown("""
<style>
.stApp {
    background: radial-gradient(ellipse at 75% 0%, rgba(39,91,180,.18), transparent 35%),
                linear-gradient(135deg,#06101d 0%,#08172a 55%,#07111f 100%);
    color: #e7f0ff;
}
[data-testid="stHeader"] { background: rgba(6,16,29,.88); }
.block-container { max-width: 1600px; padding-top: 1.6rem; padding-bottom: 2.8rem; }
h1,h2,h3,h4,p,label { color: #e7f0ff; }
h1,h2,h3 { letter-spacing: -.35px; }
[data-testid="stSidebar"] {
    background: linear-gradient(180deg,#08172a 0%,#06101d 100%);
    border-right: 1px solid #173251;
}
.brand { display:flex; align-items:center; gap:12px; padding:8px 5px 18px; }
.brand-icon {
    width:48px; height:48px; display:flex; align-items:center; justify-content:center;
    border-radius:15px; font-size:27px; background:linear-gradient(135deg,#1677ff,#7257ff);
    box-shadow:0 7px 24px rgba(47,129,247,.28);
}
.brand-title { color:#f4f8ff; font-size:19px; font-weight:800; line-height:1.15; }
.brand-caption { color:#8eabd0; font-size:11px; letter-spacing:1.4px; margin-top:5px; }
.sidebar-note {
    color:#9bb3d1; font-size:12px; line-height:1.5; background:#0b1b30;
    border:1px solid #1b3859; padding:12px; border-radius:12px; margin-top:14px;
}
.hero {
    overflow:hidden; padding:27px 30px; border-radius:20px; border:1px solid #1c4774;
    background:radial-gradient(ellipse at 90% 20%,rgba(47,129,247,.25),transparent 40%),
               linear-gradient(120deg,#0c1d34,#0a2140 60%,#101c48);
    box-shadow:0 12px 34px rgba(0,0,0,.18); margin-bottom:22px;
}
.hero-kicker { color:#80b8ff; font-size:11px; font-weight:800; letter-spacing:2.2px; margin-bottom:9px; }
.hero-title { color:#f6f9ff; font-size:clamp(27px,3vw,38px); line-height:1.18; font-weight:850; margin:0; }
.hero-title span { color:#5ca5ff; }
.hero-subtitle { color:#b7cbea; font-size:14px; margin-top:10px; }
.hero-chip {
    display:inline-block; margin-top:16px; padding:6px 10px; border-radius:999px;
    background:rgba(32,217,154,.10); border:1px solid rgba(32,217,154,.25);
    color:#65edbd; font-size:11px; font-weight:700;
}
[data-testid="stMetric"] {
    background:linear-gradient(145deg,#0d2037,#0a192b); border:1px solid #1b3859;
    border-radius:16px; padding:17px 18px; box-shadow:0 5px 18px rgba(0,0,0,.12);
}
[data-testid="stMetricLabel"] { color:#a7bedb; font-weight:650; }
[data-testid="stMetricValue"] { color:#f2f7ff; font-weight:800; }
.section-label { color:#9dbce3; font-size:11px; font-weight:800; letter-spacing:1.6px; margin:10px 0 8px; }
.panel { background:linear-gradient(145deg,#0c1d32,#0a192b); border:1px solid #1b3859; border-radius:16px; padding:18px; }
.panel-title { color:#eff6ff; font-size:16px; font-weight:750; margin-bottom:5px; }
.panel-copy { color:#9bb3d1; font-size:12px; line-height:1.55; }
.stButton > button,.stDownloadButton > button { border-radius:10px; min-height:42px; font-weight:700; border:1px solid #28568a; }
.stButton > button[kind="primary"] { background:linear-gradient(100deg,#2478f7,#6755f5); color:#fff; border:1px solid #4588ff; }
.stButton > button[kind="primary"]:hover { filter:brightness(1.12); border-color:#8ab8ff; }
.stButton > button:not([kind="primary"]),.stDownloadButton > button { background:#102642; color:#e6f0ff; }
.stButton > button:not([kind="primary"]):hover,.stDownloadButton > button:hover { background:#163454; color:#fff; border-color:#4789d8; }
.stTextInput input,.stTextArea textarea,[data-baseweb="select"] > div { background:#0a192b; color:#e7f0ff; border-color:#294563; border-radius:9px; }
[data-testid="stAlert"] { border-radius:12px; border:1px solid #294563; }
[data-testid="stTable"],[data-testid="stDataFrame"] { border:1px solid #1b3859; border-radius:12px; overflow:hidden; }
[data-testid="stExpander"] { background:#0b1b30; border:1px solid #1b3859; border-radius:12px; }
hr { border-color:#1b3859; }
.footer { color:#7894b7; font-size:11px; text-align:center; padding-top:12px; }
@media(max-width:768px) { .block-container { padding:1rem .8rem 2rem; } .hero { padding:21px; } }
/* UI Enhancement: Smooth interactions and polished panels */
.stButton > button {
    border-radius: 12px;
    font-weight: 700;
    transition: all 0.2s ease-in-out;
}

.stButton > button:hover {
    transform: translateY(-2px);
    box-shadow: 0 6px 18px rgba(22, 163, 255, 0.25);
}

[data-testid="stMetric"] {
    background: linear-gradient(135deg, rgba(22, 99, 180, 0.16), rgba(80, 60, 180, 0.12));
    border: 1px solid rgba(80, 160, 255, 0.25);
    border-radius: 14px;
    padding: 14px;
}

[data-testid="stExpander"] {
    border: 1px solid rgba(80, 160, 255, 0.25);
    border-radius: 12px;
}
</style>
""", unsafe_allow_html=True)

# 3. Hashing and baseline security
def calculate_hash(file_path):
    sha256 = hashlib.sha256()
    with file_path.open("rb") as file:
        for chunk in iter(lambda: file.read(CHUNK_SIZE), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def get_signing_key():
    if not KEY_PATH.exists():
        try:
            with KEY_PATH.open("xb") as file:
                file.write(secrets.token_bytes(32))
        except FileExistsError:
            pass
    key = KEY_PATH.read_bytes()
    if len(key) != 32:
        raise ValueError("Invalid signing key. Restore the original .baseline_key or create a new trusted baseline.")
    return key


def sign_data(data):
    message = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hmac.new(get_signing_key(), message, hashlib.sha256).hexdigest()


def read_text_snapshot(file_path, max_bytes=200000):
    try:
        if file_path.stat().st_size > max_bytes:
            return None
        return file_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None


def scan_folder(folder_text):
    root = Path(folder_text).expanduser().resolve()
    if not root.is_dir():
        raise ValueError("The selected folder does not exist.")
    if root == APP_DIR:
        raise ValueError("Choose a specific folder, such as sample_files, instead of the whole project folder.")
    hashes, errors = {}, []
    for path in root.rglob("*"):
        try:
            if path.is_symlink() or not path.is_file():
                continue
            hashes[path.relative_to(root).as_posix()] = calculate_hash(path)
        except (OSError, ValueError) as error:
            errors.append(f"{path}: {error}")
    return root, hashes, errors


def save_baseline(root, hashes):
    snapshots = {}
    for name in hashes:
        content = read_text_snapshot(root / name)
        if content is not None:
            snapshots[name] = content
    data = {
        "folder": str(root),
        "created_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "algorithm": "SHA-256",
        "files": hashes,
        "text_snapshots": snapshots,
    }
    data["signature"] = sign_data(data)
    temp_path = BASELINE_PATH.with_suffix(".tmp")
    try:
        temp_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        temp_path.replace(BASELINE_PATH)
    finally:
        if temp_path.exists():
            temp_path.unlink(missing_ok=True)


def load_baseline():
    if not BASELINE_PATH.exists():
        return None
    if not KEY_PATH.exists():
        raise ValueError("Signing key is missing. The baseline cannot be verified.")
    data = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
    signature = data.pop("signature", None)
    if not isinstance(signature, str):
        raise ValueError("Baseline signature is missing.")
    expected = sign_data(data)
    if not hmac.compare_digest(signature, expected):
        raise ValueError("BASELINE TAMPERING DETECTED! The baseline signature is invalid.")
    if not isinstance(data.get("files"), dict):
        raise ValueError("Invalid baseline file list.")
    return data

# 4. Scan history
def record_scan(entry):
    with HISTORY_PATH.open("a", encoding="utf-8") as file:
        file.write(json.dumps(entry) + "\n")


def read_history():
    entries = []
    if not HISTORY_PATH.exists():
        return entries
    with HISTORY_PATH.open("r", encoding="utf-8") as file:
        for line in file:
            try:
                item = json.loads(line)
                if isinstance(item, dict):
                    entries.append(item)
            except json.JSONDecodeError:
                continue
    return entries

# 5. Styled results table
def color_status(value):
    colors = {
        "UNCHANGED": "background-color:#064e3b;color:#d1fae5;font-weight:bold;",
        "MODIFIED": "background-color:#7f1d1d;color:#fff1f2;font-weight:bold;",
        "NEW": "background-color:#1e40af;color:#dbeafe;font-weight:bold;",
        "DELETED": "background-color:#374151;color:#f3f4f6;font-weight:bold;",
    }
    return colors.get(str(value).upper(), "background-color:#0b1b30;color:#e7f0ff;")


def style_results_table(df):
    other_columns = [column for column in df.columns if column != "Status"]
    return (
        df.style.map(color_status, subset=["Status"])
        .set_properties(subset=other_columns, **{"background-color": "#0b1b30", "color": "#e7f0ff"})
        .set_table_styles([
            {"selector": "table", "props": [("background-color", "#0b1b30"), ("color", "#e7f0ff"), ("border-collapse", "collapse"), ("width", "100%")]},
            {"selector": "th", "props": [("background-color", "#102642"), ("color", "#f4f8ff"), ("border", "1px solid #1b3859"), ("padding", "11px"), ("text-align", "left")]},
            {"selector": "td", "props": [("border", "1px solid #1b3859"), ("padding", "10px")]},
        ])
    )

# 6. Sidebar navigation and controls
with st.sidebar:
    st.markdown("""
    <div class="brand">
      <div class="brand-icon">🛡️</div>
      <div><div class="brand-title">File Integrity<br>Checker</div>
      <div class="brand-caption">SECURITY SUITE</div></div>
    </div>
    """, unsafe_allow_html=True)
    st.caption("Secure  •  Monitor  •  Verify")
    st.markdown("---")
    page = st.radio(
        "NAVIGATION",
        ["🔎  Integrity Scanner", "🕘  Scan History", "🛡️  Security"],
        label_visibility="collapsed",
        key="main_navigation",
    )
    st.markdown("---")
    st.markdown("#### ⚙️ Scan Controls")
    folder = st.text_input("Folder to monitor", value=str(APP_DIR / "sample_files"),
                           help="Choose the specific folder whose files you want to monitor.")
    st.markdown("""
    <div class="sidebar-note"><strong>Quick start</strong><br>
    1. Select your target folder.<br>2. Create a trusted baseline.<br>3. Scan again after file changes.</div>
    """, unsafe_allow_html=True)
    if st.button("↻ Refresh Dashboard", use_container_width=True):
        st.rerun()
    st.markdown("""
    <div class="sidebar-note"><strong style="color:#65edbd;">● Local security status</strong><br>
    SHA-256 file fingerprints<br>HMAC-SHA256 baseline verification</div>
    """, unsafe_allow_html=True)

# 7. Shared header
st.markdown("""
<div class="hero">
  <div class="hero-kicker">SECURITY OPERATIONS / FILE MONITORING</div>
  <div class="hero-title">File Integrity <span>Checker</span></div>
  <div class="hero-subtitle">Monitor files. Verify fingerprints. Detect unexpected changes.</div>
  <div class="hero-chip">● SHA-256 + HMAC-SHA256 PROTECTION</div>
</div>
""", unsafe_allow_html=True)

# 8. Integrity scanner
if page == "🔎  Integrity Scanner":
    st.markdown('<div class="section-label">INTEGRITY MONITORING</div>', unsafe_allow_html=True)
    st.subheader("Scanner overview")
    st.write("Compare current file fingerprints against your signed trusted baseline.")
    action1, action2, status_col = st.columns([1, 1, 1.05])
    with action1:
        create_clicked = st.button("＋  Create Trusted Baseline", type="primary", use_container_width=True)
    with action2:
        scan_clicked = st.button("⌕  Check File Integrity", use_container_width=True)
    with status_col:
        baseline_exists = BASELINE_PATH.exists()
        st.markdown(f"""
        <div class="panel" style="padding:11px 14px;min-height:42px;">
          <div style="color:#9bb3d1;font-size:11px;">BASELINE STATUS</div>
          <div style="color:{'#20d99a' if baseline_exists else '#ffbf69'};font-weight:750;">
            {'Baseline file exists' if baseline_exists else 'Not created yet'}
          </div>
        </div>
        """, unsafe_allow_html=True)

    if create_clicked:
        try:
            root, hashes, errors = scan_folder(folder)
            if errors:
                st.error("Some files could not be read. Baseline was not created.")
                for error in errors:
                    st.write(error)
            elif not hashes:
                st.warning("No files found. Add files to your folder first.")
            else:
                save_baseline(root, hashes)
                st.success(f"Trusted baseline created for {len(hashes)} file(s).")
                st.info("The baseline contains SHA-256 hashes and eligible text snapshots.")
        except (OSError, ValueError, json.JSONDecodeError) as error:
            st.error(f"Could not create baseline: {error}")

    if scan_clicked:
        try:
            baseline = load_baseline()
            if baseline is None:
                st.warning("Please create a trusted baseline before scanning.")
            else:
                root, current, errors = scan_folder(folder)
                if str(root) != baseline.get("folder"):
                    st.error("The selected folder differs from the baseline folder.")
                elif errors:
                    st.error("The scan is incomplete because some files could not be read.")
                    for error in errors:
                        st.write(error)
                else:
                    original = baseline["files"]
                    results = []
                    for name in sorted(set(original) | set(current)):
                        old_hash, new_hash = original.get(name), current.get(name)
                        if old_hash is None:
                            status = "NEW"
                        elif new_hash is None:
                            status = "DELETED"
                        elif old_hash != new_hash:
                            status = "MODIFIED"
                        else:
                            status = "UNCHANGED"
                        results.append({
                            "File": name, "Status": status,
                            "Original SHA-256": old_hash or "-",
                            "Current SHA-256": new_hash or "-",
                        })

                    df = pd.DataFrame(results, columns=["File", "Status", "Original SHA-256", "Current SHA-256"])
                    counts = df["Status"].value_counts()
                    unchanged = int(counts.get("UNCHANGED", 0))
                    modified = int(counts.get("MODIFIED", 0))
                    new_files = int(counts.get("NEW", 0))
                    deleted = int(counts.get("DELETED", 0))

                    st.markdown('<div class="section-label">LATEST SCAN / SUMMARY</div>', unsafe_allow_html=True)
                    m1, m2, m3, m4 = st.columns(4)
                    m1.metric("✓ Unchanged", unchanged)
                    m2.metric("⚠ Modified", modified)
                    m3.metric("＋ New files", new_files)
                    m4.metric("⌫ Deleted", deleted)

                    if modified or new_files or deleted:
                        st.error("Changes detected. Review the file results below.")
                    else:
                        st.success("All monitored files match the trusted baseline.")

                    st.markdown('<div class="section-label">FILE ANALYSIS</div>', unsafe_allow_html=True)
                    st.subheader("File results")
                    st.caption("SHA-256 fingerprints are shown for comparison.")
                    st.table(style_results_table(df))

                    modified_names = df.loc[df["Status"] == "MODIFIED", "File"].tolist()
                    if modified_names:
                        st.markdown('<div class="section-label">CHANGE INVESTIGATION</div>', unsafe_allow_html=True)
                        st.subheader("Before vs. after text comparison")
                        snapshots = baseline.get("text_snapshots", {})
                        for name in modified_names:
                            with st.expander(f"📝 {name}", expanded=True):
                                before_text = snapshots.get(name)
                                after_text = read_text_snapshot(root / name)
                                if before_text is None or after_text is None:
                                    st.info("Text comparison is unavailable. The file may be binary, too large, or absent from the original text snapshots.")
                                    continue
                                before_col, after_col = st.columns(2)
                                with before_col:
                                    st.markdown("**Original content**")
                                    st.text_area("Original content", value=before_text, height=240, disabled=True,
                                                 key=f"before_{name}", label_visibility="collapsed")
                                with after_col:
                                    st.markdown("**Current content**")
                                    st.text_area("Current content", value=after_text, height=240, disabled=True,
                                                 key=f"after_{name}", label_visibility="collapsed")
                    else:
                        st.info("No modified files to compare. Modify a text file and scan again to test comparison.")

                    st.download_button("↓  Download CSV Report", data=df.to_csv(index=False).encode("utf-8"),
                                       file_name="integrity_report.csv", mime="text/csv", use_container_width=True)

                    record_scan({
                        "timestamp": datetime.now().astimezone().isoformat(timespec="seconds"),
                        "folder": str(root), "total": len(results), "unchanged": unchanged,
                        "modified": modified, "new": new_files, "deleted": deleted,
                    })
                    st.caption("Baseline created: " + baseline.get("created_at", "Unknown"))
        except (OSError, ValueError, json.JSONDecodeError) as error:
            st.error(f"Scan failed: {error}")

# 9. Scan history
elif page == "🕘  Scan History":
    st.markdown('<div class="section-label">AUDIT TRAIL</div>', unsafe_allow_html=True)
    st.subheader("Previous scans")
    st.write("Review scan summaries recorded by this application.")
    history = read_history()
    if history:
        history_df = pd.DataFrame(history)
        if "timestamp" in history_df.columns:
            history_df = history_df.sort_values("timestamp", ascending=False)
        if not history_df.empty:
            latest = history_df.iloc[0]
            c1, c2, c3 = st.columns(3)
            c1.metric("Recorded scans", len(history_df))
            c2.metric("Latest scan total", int(latest.get("total", 0)))
            c3.metric("Latest modified", int(latest.get("modified", 0)))
        st.dataframe(history_df, use_container_width=True, hide_index=True)
        st.download_button("↓  Download Scan History", data=history_df.to_csv(index=False).encode("utf-8"),
                           file_name="scan_history.csv", mime="text/csv")
    else:
        st.info("No scans recorded yet. Run an integrity scan to build your audit history.")

# 10. Security
else:
    st.markdown('<div class="section-label">TRUST & VERIFICATION</div>', unsafe_allow_html=True)
    st.subheader("Baseline security")
    st.write("Security mechanisms used by the File Integrity Checker.")
    sec1, sec2 = st.columns(2)
    with sec1:
        st.markdown("""
        <div class="panel"><div class="panel-title">🔐 HMAC-SHA256 signature</div>
        <div class="panel-copy">The baseline is signed with a separate local key. The signature is checked before scan results are trusted.</div></div>
        """, unsafe_allow_html=True)
    with sec2:
        st.markdown("""
        <div class="panel"><div class="panel-title">🔎 SHA-256 fingerprints</div>
        <div class="panel-copy">Each regular file is hashed in chunks and compared with the saved baseline to detect content changes.</div></div>
        """, unsafe_allow_html=True)

    st.markdown("### Verification status")
    try:
        verified_baseline = load_baseline()
        if verified_baseline is None:
            st.warning("No baseline exists yet. Create a trusted baseline from the Integrity Scanner.")
        else:
            st.success(f"Baseline signature verified successfully. {len(verified_baseline['files'])} file(s) are listed in the baseline.")
            st.caption("Baseline created: " + verified_baseline.get("created_at", "Unknown"))
    except (OSError, ValueError, json.JSONDecodeError) as error:
        st.error(f"Baseline verification failed: {error}")

    st.markdown("### Security practices")
    st.markdown("""
    - Keep `.baseline_key` private and separate from public repositories.
    - Keep a secure backup of the key and baseline if you need to preserve trust.
    - If the signing key is lost or replaced, create a new trusted baseline.
    - Treat a scan with file-read errors as incomplete; resolve errors before relying on results.
    """)
    st.warning("Do not publish `.baseline_key`, and do not commit it to GitHub.")

# 11. Footer
st.markdown("---")
st.markdown('<div class="footer">FILE INTEGRITY CHECKER • EDUCATIONAL CYBERSECURITY PROJECT • SHA-256 + HMAC-SHA256</div>', unsafe_allow_html=True)