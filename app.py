"""
🔐 Password Strength Analyzer
--------------------------------
A production-ready Streamlit app that uses the zxcvbn library to evaluate
password strength. Passwords are never stored, logged, or transmitted.
"""

import math
import secrets
import string
import re
from decimal import Decimal
from typing import Union

import streamlit as st
from zxcvbn import zxcvbn

# ─── Page configuration ───────────────────────────────────────────────────────
st.set_page_config(
    page_title="Password Strength Analyzer",
    page_icon="🔐",
    layout="centered",
)

# ─── Custom CSS ───────────────────────────────────────────────────────────────
st.markdown(
    """
    <style>
    /* Tighten up default Streamlit padding */
    .block-container { padding-top: 2rem; padding-bottom: 2rem; }

    /* Strength badge chips */
    .strength-badge {
        display: inline-block;
        padding: 0.25rem 0.85rem;
        border-radius: 99px;
        font-weight: 700;
        font-size: 0.95rem;
        letter-spacing: 0.03em;
    }
    .score-0 { background:#fde8e8; color:#c0392b; }
    .score-1 { background:#fdebd0; color:#d35400; }
    .score-2 { background:#fef9e7; color:#b7950b; }
    .score-3 { background:#e9f7ef; color:#1e8449; }
    .score-4 { background:#d5f5e3; color:#117a65; }

    /* Metric cards */
    .metric-card {
        background: #f7f8fa;
        border: 1px solid #e5e7eb;
        border-radius: 8px;
        padding: 0.65rem 1rem;
        font-size: 0.88rem;
        color: #374151;
    }
    .metric-card b { color: #1f2328; }

    /* Warning / tip pills */
    .warn-pill  { color: #7c5cd8; font-size: 0.87rem; }
    .tip-pill   { color: #3b82d4; font-size: 0.87rem; }
    </style>
    """,
    unsafe_allow_html=True,
)

# ─── Score metadata ────────────────────────────────────────────────────────────
SCORE_META = {
    0: ("Very Weak",   "score-0", 0.05),
    1: ("Weak",        "score-1", 0.25),
    2: ("Fair",        "score-2", 0.50),
    3: ("Strong",      "score-3", 0.75),
    4: ("Very Strong", "score-4", 1.00),
}

PROGRESS_COLORS = {
    0: "#e74c3c",
    1: "#e67e22",
    2: "#f1c40f",
    3: "#2ecc71",
    4: "#27ae60",
}

# ─── Helpers ──────────────────────────────────────────────────────────────────

def generate_password(length: int | None = None) -> str:
    """Generate a cryptographically secure random password (16–20 chars)."""
    if length is None:
        length = secrets.choice(range(16, 21))  # 16 to 20 inclusive

    alphabet = string.ascii_letters + string.digits + string.punctuation
    # Guarantee at least one character from each required class
    required = [
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits),
        secrets.choice(string.punctuation),
    ]
    rest = [secrets.choice(alphabet) for _ in range(length - len(required))]
    combined = required + rest
    secrets.SystemRandom().shuffle(combined)   # cryptographically secure shuffle
    return "".join(combined)


def detect_extra_weaknesses(password: str) -> list[str]:
    """
    Return a list of human-readable weakness strings for common patterns
    that zxcvbn may not surface explicitly in its warning text.
    """
    issues: list[str] = []

    if len(password) < 8:
        issues.append("Password is shorter than 8 characters.")

    # Repeated characters, e.g. "aaaa"
    if re.search(r"(.)\1{2,}", password):
        issues.append("Contains 3+ repeated characters in a row.")

    # Common sequential patterns
    sequences = ["123", "234", "345", "456", "567", "678", "789",
                 "abc", "bcd", "cde", "qwerty", "asdf", "zxcv"]
    lower_pw = password.lower()
    for seq in sequences:
        if seq in lower_pw:
            issues.append(f'Contains common sequence "{seq}".')
            break  # report once

    # Only digits
    if password.isdigit():
        issues.append("Password contains only numbers.")

    # Only letters
    if password.isalpha():
        issues.append("Password contains only letters.")

    return issues


def analyze_composition(password: str) -> dict:
    """Return character-class counts for the password."""
    return {
        "Length":    len(password),
        "Uppercase": sum(1 for c in password if c.isupper()),
        "Lowercase": sum(1 for c in password if c.islower()),
        "Digits":    sum(1 for c in password if c.isdigit()),
        "Symbols":   sum(1 for c in password if c in string.punctuation),
    }


def crack_time_label(seconds: Union[float, Decimal, str]) -> str:
    """
    Convert a zxcvbn crack-time estimate (Decimal/float seconds or a plain
    string like 'less than a second') to a concise human-readable label.
    zxcvbn returns crack times as decimal.Decimal, so we normalise to float.
    """
    if isinstance(seconds, str):
        return seconds
    seconds = float(seconds)  # normalise Decimal → float
    if seconds < 1:
        return "less than a second"
    minutes  = seconds / 60
    hours    = minutes / 60
    days     = hours / 24
    years    = days / 365.25
    if years >= 1_000_000:
        return f"{years/1_000_000:.1f} million years"
    if years >= 1_000:
        return f"{years/1_000:.1f} thousand years"
    if years >= 1:
        return f"{years:.1f} year{'s' if years >= 2 else ''}"
    if days >= 1:
        return f"{days:.1f} day{'s' if days >= 2 else ''}"
    if hours >= 1:
        return f"{hours:.1f} hour{'s' if hours >= 2 else ''}"
    if minutes >= 1:
        return f"{minutes:.1f} minute{'s' if minutes >= 2 else ''}"
    return f"{seconds:.0f} second{'s' if seconds >= 2 else ''}"


# ─── Session state initialisation ─────────────────────────────────────────────
if "generated_password" not in st.session_state:
    st.session_state.generated_password = ""

# ─── UI ───────────────────────────────────────────────────────────────────────
st.title("🔐 Password Strength Analyzer")
st.caption("Passwords are analyzed locally and **never stored, logged, or transmitted**.")

st.divider()

# ── Optional personal information ─────────────────────────────────────────────
with st.expander("➕ Add personal info for smarter analysis (optional)"):
    st.caption(
        "zxcvbn will check whether your password includes these details, "
        "making the analysis more relevant to you."
    )
    col_a, col_b, col_c = st.columns(3)
    with col_a:
        user_name  = st.text_input("Your name",       placeholder="e.g. Alice")
    with col_b:
        user_email = st.text_input("Email address",   placeholder="e.g. alice@example.com")
    with col_c:
        user_year  = st.text_input("Birth year",      placeholder="e.g. 1995")

# Build the user_inputs list — passed to zxcvbn to check personal details
user_inputs: list[str] = []
if user_name:
    user_inputs.append(user_name)
if user_email:
    # Split on @ and . to expose sub-parts as separate dictionary words
    user_inputs.extend(re.split(r"[@.]", user_email))
if user_year:
    user_inputs.append(user_year)

st.markdown("#### Enter a password to analyze")

# ── Password input row ─────────────────────────────────────────────────────────
show_pw  = st.checkbox("Show password", value=False)
input_type = "default" if show_pw else "password"

# If a password was just generated, pre-fill the text box via session state
default_val = st.session_state.generated_password

password = st.text_input(
    "Password",
    value=default_val,
    type=input_type,
    placeholder="Type or paste a password…",
    label_visibility="collapsed",
)

# ── Generate button ─────────────────────────────────────────────────────────────
if st.button("⚡ Generate strong password", use_container_width=True):
    st.session_state.generated_password = generate_password()
    st.rerun()  # Re-render so the generated password fills the input

# ─── Analysis ─────────────────────────────────────────────────────────────────
if not password:
    st.info("Enter a password above to see your strength analysis.")
    st.stop()

# Run zxcvbn — user_inputs lets it detect personal information in the password
result   = zxcvbn(password, user_inputs=user_inputs if user_inputs else [])
score    = result["score"]                      # 0–4
feedback = result["feedback"]                   # {warning, suggestions}
crack    = result["crack_times_seconds"]        # dict of scenario → float
guesses  = result.get("guesses", 0)

label, badge_class, progress_val = SCORE_META[score]

st.divider()

# ── Strength meter ─────────────────────────────────────────────────────────────
st.markdown(
    f'<span class="strength-badge {badge_class}">{label}</span>',
    unsafe_allow_html=True,
)
st.progress(progress_val)

# ── Crack-time summary ─────────────────────────────────────────────────────────
col1, col2 = st.columns(2)
with col1:
    online_time = crack_time_label(
        crack.get("online_no_throttling_10_per_second", "?")
    )
    st.metric("🌐 Crack time (online)", online_time,
              help="Unthrottled online attack — 10 guesses / second.")
with col2:
    offline_time = crack_time_label(
        crack.get("offline_slow_hashing_1e4_per_second", "?")
    )
    st.metric("💻 Crack time (offline, slow hash)", offline_time,
              help="Offline attack against a slow hash (bcrypt) — 10 000 guesses / second.")

# ── zxcvbn warning ────────────────────────────────────────────────────────────
if feedback.get("warning"):
    st.warning(f"⚠️ {feedback['warning']}")

# ── Suggestions from zxcvbn ───────────────────────────────────────────────────
if feedback.get("suggestions"):
    st.markdown("**Suggestions:**")
    for suggestion in feedback["suggestions"]:
        st.markdown(f"- {suggestion}")

# ─── Detailed breakdown ───────────────────────────────────────────────────────
with st.expander("🔍 Detailed breakdown", expanded=(score < 3)):

    composition = analyze_composition(password)
    extra_issues = detect_extra_weaknesses(password)

    # Character composition table
    st.markdown("**Character composition**")
    comp_cols = st.columns(len(composition))
    for col, (metric, count) in zip(comp_cols, composition.items()):
        col.markdown(
            f'<div class="metric-card"><b>{count}</b><br>{metric}</div>',
            unsafe_allow_html=True,
        )

    st.markdown("")  # spacer

    # Detected weaknesses
    if extra_issues:
        st.markdown("**Detected weaknesses**")
        for issue in extra_issues:
            st.markdown(f'<span class="warn-pill">⚠ {issue}</span>', unsafe_allow_html=True)
    else:
        st.success("No common structural weaknesses detected.")

    # All zxcvbn suggestions
    all_suggestions = list(feedback.get("suggestions", []))
    if all_suggestions:
        st.markdown("**Improvement tips**")
        for tip in all_suggestions:
            st.markdown(f'<span class="tip-pill">💡 {tip}</span>', unsafe_allow_html=True)

    st.divider()

    # Entropy / guesses estimate
    st.markdown("**Entropy estimate**")
    entropy_bits = math.log2(guesses) if guesses > 1 else 0
    st.markdown(
        f"Estimated guesses to crack: **{guesses:,}**  \n"
        f"Approximate entropy: **{entropy_bits:.1f} bits**"
    )

    # Full crack-time table
    st.markdown("**Crack-time estimates across attack scenarios**")
    scenario_labels = {
        "online_throttling_100_per_hour":        "Online (throttled, 100/hr)",
        "online_no_throttling_10_per_second":     "Online (unthrottled, 10/s)",
        "offline_slow_hashing_1e4_per_second":    "Offline — slow hash (10 k/s)",
        "offline_fast_hashing_1e10_per_second":   "Offline — fast hash (10 B/s)",
    }
    for key, desc in scenario_labels.items():
        val = crack.get(key, "?")
        st.markdown(
            f'<div class="metric-card" style="margin-bottom:0.35rem;">'
            f'<b>{desc}</b>: {crack_time_label(val)}'
            f"</div>",
            unsafe_allow_html=True,
        )

st.divider()
st.caption("Built with [Streamlit](https://streamlit.io) · Strength engine: [zxcvbn](https://github.com/dwolfhub/zxcvbn-python)")
