
import hashlib
import hmac
import json
import secrets
from datetime import datetime
from pathlib import Path

import pandas as pd
import streamlit as st

# ---------------- CONFIGURATION ----------------
st.set_page_config(
    page_title="File Integrity Checker",
    page_icon="🛡️",
    layout="wide",
)

APP_DIR = Path(__file__).resolve().parent
BASELINE_PATH = APP_DIR / "baseline.json"
KEY_PATH = APP_DIR / ".baseline_key"
HISTORY_PATH = APP_DIR / "scan_history.jsonl"
CHUNK_SIZE = 1024 * 1024

# ---------------- PROFESSIONAL LIGHT UI ----------------
st.markdown("""
<style>
.stApp {
    background-color: #f5f8fc;
    color: #172b4d;
}
.block-container {
    max-width: 1200px;
    padding-top: 2rem;
}
.hero {
    background: linear-gradient(110deg, #173b72, #2878c8);
    color: white;
    padding: 26px;
    border-radius: 16px;
    margin-bottom: 20px;
}
.hero h1 { color: white; }
.hero p { color: #e5efff; }
div[data-testid="stMetric"] {
    background: white;
    border: 1px solid #dce5f1;
    padding: 16px;
    border-radius: 12px;
}
.stButton > button, .stDownloadButton > button {
    border-radius: 9px;
    min-height: 42px;
}
</style>
""", unsafe_allow_html=True)

st.markdown("""
<div class="hero">
    <h1>🛡️ File Integrity Checker</h1>
    <p>Security monitoring powered by SHA-256 cryptographic fingerprints</p>
</div>
""", unsafe_allow_html=True)

# ---------------- SECURITY HELPERS ----------------
def calculate_hash(file_path):
    """Calculate the SHA-256 hash of a file."""
    digest = hashlib.sha256()

    with open(file_path, "rb") as file:
        while True:
            chunk = file.read(CHUNK_SIZE)
            if not chunk:
                break
            digest.update(chunk)

    return digest.hexdigest()


def get_signing_key():
    """
    Load or create a local HMAC key.
    Keep this key separate from the baseline file.
    """
    if not KEY_PATH.exists():
        KEY_PATH.write_bytes(secrets.token_bytes(32))

    key = KEY_PATH.read_bytes()

    if len(key) != 32:
        raise ValueError(
            "The signing key is invalid. Restore a trusted key backup."
        )

    return key


def sign_data(data, key):
    """Sign canonical JSON data using HMAC-SHA256."""
    message = json.dumps(
        data, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")

    return hmac.new(key, message, hashlib.sha256).hexdigest()


def save_baseline(folder, hashes):
    key = get_signing_key()

    data = {
        "folder": str(folder),
        "created_at": datetime.now().astimezone().isoformat(
            timespec="seconds"
        ),
        "algorithm": "SHA-256",
        "files": hashes,
    }

    data["signature"] = sign_data(data, key)

    temp_path = BASELINE_PATH.with_suffix(".tmp")
    temp_path.write_text(
        json.dumps(data, indent=2), encoding="utf-8"
    )
    temp_path.replace(BASELINE_PATH)


def load_verified_baseline():
    if not BASELINE_PATH.exists():
        return None

    if not KEY_PATH.exists():
        raise ValueError(
            "Signing key is missing. The baseline cannot be trusted."
        )

    data = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))

    signature = data.pop("signature", None)
    if not isinstance(signature, str):
        raise ValueError("Baseline signature is missing.")

    expected = sign_data(data, get_signing_key())

    if not hmac.compare_digest(signature, expected):
        raise ValueError(
            "BASELINE TAMPERING DETECTED! Do not trust this baseline. "
            "Restore a trusted backup before continuing."
        )

    if not isinstance(data.get("files"), dict):
        raise ValueError("Baseline file list is invalid.")

    return data


# ---------------- FILE SCANNING ----------------
def scan_folder(folder_text):
    root = Path(folder_text).expanduser().resolve()

    if not root.is_dir():
        raise ValueError("The selected folder does not exist.")

    if root == APP_DIR or APP_DIR in root.parents:
        raise ValueError(
            "Choose a monitored folder outside the project folder."
        )

    if root in APP_DIR.parents:
        raise ValueError(
            "Choose a specific folder, not a parent of the project."
        )

    hashes = {}
    errors = []

    for path in root.rglob("*"):
        try:
            if path.is_symlink() or not path.is_file():
                continue

            relative = path.relative_to(root).as_posix()
            hashes[relative] = calculate_hash(path)

        except (OSError, ValueError) as error:
            errors.append(f"{path}: {error}")

    return root, hashes, errors


# ---------------- SCAN HISTORY ----------------
def record_scan(entry):
    with open(HISTORY_PATH, "a", encoding="utf-8") as file:
        file.write(json.dumps(entry) + "\n")


def read_history():
    entries = []

    if not HISTORY_PATH.exists():
        return entries

    with open(HISTORY_PATH, "r", encoding="utf-8") as file:
        for line in file:
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    return entries


# ---------------- SIDEBAR ----------------
st.sidebar.title("⚙️ Controls")
st.sidebar.caption("File integrity monitoring")

sample_folder = APP_DIR / "sample_files"

folder = st.sidebar.text_input(
    "Folder to monitor",
    value=str(sample_folder),
)

st.sidebar.info(
    "Create a baseline first. Scan again later to detect changes."
)

if st.sidebar.button("🔄 Refresh dashboard", use_container_width=True):
    st.rerun()

# ---------------- DASHBOARD ----------------
tab_scan, tab_history, tab_security = st.tabs(
    ["🔍 Integrity Scanner", "🕒 Scan History", "🔐 Security"]
)

with tab_scan:
    st.subheader("Integrity Monitoring")
    st.write(
        "Compare current files against their original trusted SHA-256 hashes."
    )

    col_a, col_b = st.columns(2)

    with col_a:
        create_clicked = st.button(
            "📌 Create Trusted Baseline",
            type="primary",
            use_container_width=True,
        )

    with col_b:
        scan_clicked = st.button(
            "🔍 Check File Integrity",
            use_container_width=True,
        )

    if create_clicked:
        try:
            root, hashes, errors = scan_folder(folder)

            if errors:
                st.error(
                    "Some files could not be read. "
                    "Baseline was not created."
                )
                for error in errors:
                    st.write(error)

            elif not hashes:
                st.warning(
                    "No files found. Add files to the monitored folder first."
                )

            else:
                save_baseline(root, hashes)
                st.success(
                    f"Trusted baseline created for {len(hashes)} files."
                )
                st.caption(
                    "Record a backup of the baseline and signing key "
                    "in a separate secure location."
                )

        except (OSError, ValueError, json.JSONDecodeError) as error:
            st.error(f"Could not create baseline: {error}")

    if scan_clicked:
        try:
            baseline = load_verified_baseline()

            if baseline is None:
                st.warning("Create a trusted baseline before scanning.")
                st.stop()

            root, current, errors = scan_folder(folder)

            if str(root) != baseline.get("folder"):
                st.error(
                    "Selected folder differs from the baseline folder."
                )
                st.stop()

            if errors:
                st.error(
                    "Scan incomplete. Fix file access errors before "
                    "trusting the results."
                )
                for error in errors:
                    st.write(error)
                st.stop()

            original = baseline["files"]
            results = []

            for name in sorted(set(original) | set(current)):
                old_hash = original.get(name)
                new_hash = current.get(name)

                if old_hash is None:
                    status = "NEW"
                elif new_hash is None:
                    status = "DELETED"
                elif old_hash != new_hash:
                    status = "MODIFIED"
                else:
                    status = "UNCHANGED"

                results.append({
                    "File": name,
                    "Status": status,
                    "Original SHA-256": old_hash or "-",
                    "Current SHA-256": new_hash or "-",
                })

            df = pd.DataFrame(results)
            counts = df["Status"].value_counts()

            unchanged = int(counts.get("UNCHANGED", 0))
            modified = int(counts.get("MODIFIED", 0))
            new_files = int(counts.get("NEW", 0))
            deleted = int(counts.get("DELETED", 0))

            st.markdown("### Scan Summary")
            m1, m2, m3, m4 = st.columns(4)
            m1.metric("Unchanged", unchanged)
            m2.metric("Modified", modified)
            m3.metric("New files", new_files)
            m4.metric("Deleted", deleted)

            if modified or new_files or deleted:
                st.error(
                    "⚠️ Changes detected. Review the results below."
                )
            else:
                st.success(
                    "✅ All monitored files match the trusted baseline."
                )

            def color_status(row):
                colors = {
                    "UNCHANGED": "background-color: #e4f7ec; color: #17663a",
                    "MODIFIED": "background-color: #fff0d8; color: #8a4b08",
                    "NEW": "background-color: #e6f0ff; color: #174ea6",
                    "DELETED": "background-color: #ffe5e5; color: #a51d2d",
                }
                return [
                    colors.get(row["Status"], "")
                    if column == "Status" else ""
                    for column in row.index
                ]

            st.dataframe(
                df.style.apply(color_status, axis=1),
                use_container_width=True,
                hide_index=True,
            )

            st.download_button(
                "📥 Download CSV Report",
                data=df.to_csv(index=False).encode("utf-8"),
                file_name="integrity_report.csv",
                mime="text/csv",
                use_container_width=True,
            )

            record_scan({
                "timestamp": datetime.now().astimezone().isoformat(
                    timespec="seconds"
                ),
                "folder": str(root),
                "total": len(results),
                "unchanged": unchanged,
                "modified": modified,
                "new": new_files,
                "deleted": deleted,
            })

            st.caption(
                f"Baseline created: {baseline.get('created_at', 'Unknown')}"
            )

        except (
            OSError, ValueError, json.JSONDecodeError
        ) as error:
            st.error(f"Scan failed: {error}")

with tab_history:
    st.subheader("Previous Scans")
    history = read_history()

    if history:
        history_df = pd.DataFrame(history).sort_values(
            "timestamp", ascending=False
        )
        st.dataframe(
            history_df,
            use_container_width=True,
            hide_index=True,
        )

        st.download_button(
            "📥 Download Scan History",
            data=history_df.to_csv(index=False).encode("utf-8"),
            file_name="scan_history.csv",
            mime="text/csv",
        )
    else:
        st.info(
            "No scans recorded yet. Run an integrity scan to build history."
        )

with tab_security:
    st.subheader("Baseline Security")
    st.write(
        "The baseline is signed with HMAC-SHA256. The signature is "
        "checked before the baseline is used."
    )

    st.markdown("""
    - **SHA-256:** detects differences in file contents.
    - **HMAC-SHA256:** detects changes to the baseline data when the key
      remains secret.
    - **Separate key file:** `.baseline_key` is kept apart from
      `baseline.json`.
    - **Scan history:** records scan summaries and timestamps.
    """)

    st.warning(
        "This is an educational prototype. A person with access to the "
        "computer may replace the key and baseline together or alter the "
        "history. Keep protected backups outside this folder."
    )

st.divider()
st.caption(
    "File Integrity Checker • Educational Cybersecurity Project • "
    "SHA-256 + HMAC-SHA256"
)
