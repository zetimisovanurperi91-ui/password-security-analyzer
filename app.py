import hashlib
import math
import random
import string
import requests
import streamlit as st

# Streamlit Page Configuration
st.set_page_config(
    page_title="CryptoGuard & Password Analyzer",
    page_icon="🔐",
    layout="centered",
    initial_sidebar_state="collapsed",
)

# Custom Styles (Catppuccin / Modern dark vibe)
st.markdown(
    """
    <style>
    .main {
        background-color: #1e1e2e;
        color: #cdd6f4;
    }
    .stTextInput input {
        background-color: #313244;
        color: #cdd6f4;
        border-radius: 8px;
        border: 1px solid #45475a;
    }
    .stMetric {
        background-color: #313244;
        padding: 15px;
        border-radius: 10px;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    }
    </style>
""",
    unsafe_allow_html=True,
)


def calculate_entropy(password: str) -> float:
  """Calculates password entropy in bits."""
  if not password:
    return 0.0

  charset_size = 0
  if any(c in string.ascii_lowercase for c in password):
    charset_size += 26
  if any(c in string.ascii_uppercase for c in password):
    charset_size += 26
  if any(c in string.digits for c in password):
    charset_size += 10
  if any(c in string.punctuation for c in password):
    charset_size += 32

  if charset_size == 0:
    return 0.0

  entropy = len(password) * math.log2(charset_size)
  return round(entropy, 2)


def estimate_crack_time(entropy: float) -> str:
  """Estimates brute-force cracking time based on entropy."""
  guesses_per_second = 10**10
  if entropy == 0:
    return "Instant"

  total_combinations = 2**entropy
  seconds = total_combinations / guesses_per_second

  if seconds < 1:
    return "Instant (< 1 sec)"
  elif seconds < 60:
    return f"~{int(seconds)} sec"
  elif seconds < 3600:
    return f"~{int(seconds / 60)} min"
  elif seconds < 86400:
    return f"~{int(seconds / 3600)} hours"
  elif seconds < 31536000:
    return f"~{int(seconds / 86400)} days"
  elif seconds < 31536000 * 1000:
    return f"~{int(seconds / 31536000)} years"
  else:
    return "Centuries (ultra-secure)"


def check_pwned_api(password: str) -> int:
  """Checks password against HaveIBeenPwned API using k-anonymity."""
  sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
  prefix = sha1_hash[:5]
  suffix = sha1_hash[5:]

  url = f"https://api.pwnedpasswords.com/range/{prefix}"
  try:
    response = requests.get(url, timeout=5)
    if response.status_code != 200:
      return -1

    hashes = (line.split(":") for line in response.text.splitlines())
    for h, count in hashes:
      if h == suffix:
        return int(count)
    return 0
  except Exception:
    return -1


def generate_secure_password(
    length=16, use_upper=True, use_digits=True, use_symbols=True
) -> str:
  """Generates a cryptographically secure password."""
  chars = string.ascii_lowercase
  if use_upper:
    chars += string.ascii_uppercase
  if use_digits:
    chars += string.digits
  if use_symbols:
    chars += string.punctuation

  while True:
    pwd = "".join(random.choice(chars) for _ in range(length))
    has_lower = any(c in string.ascii_lowercase for c in pwd)
    has_upper = (
        not use_upper or any(c in string.ascii_uppercase for c in pwd)
    )
    has_digit = not use_digits or any(c in string.digits for c in pwd)
    has_symbol = not use_symbols or any(c in string.punctuation for c in pwd)

    if has_lower and has_upper and has_digit and has_symbol:
      return pwd


# --- App Interface ---
st.title("🔐 CryptoGuard: Password Analyzer & Generator")
st.markdown(
    "A tool to assess cryptographic strength, check database leaks, and"
    " generate secure passwords."
)

tab1, tab2 = st.tabs(["🔍 Password Analysis", "⚡ Password Generator"])

with tab1:
  st.subheader("Security Level Check")
  user_password = st.text_input(
      "Enter password to analyze",
      type="password",
      placeholder="Type your secret phrase here...",
  )

  if user_password:
    entropy = calculate_entropy(user_password)
    crack_time = estimate_crack_time(entropy)

    col1, col2, col3 = st.columns(3)
    with col1:
      st.metric(
          label="Length", value=f"{len(user_password)} chars", delta=None
      )
    with col2:
      st.metric(label="Entropy", value=f"{entropy} bits", delta=None)
    with col3:
      st.metric(label="Crack Time", value=crack_time, delta=None)

    strength_score = min(entropy / 128.0, 1.0)
    if entropy < 40:
      st.error(
          "⚠️ **Weak password!** This password can easily be guessed via"
          " brute-force."
      )
      st.progress(strength_score, text="Security Level: Low")
    elif entropy < 70:
      st.warning(
          "⚠️ **Medium password.** Recommended to add special characters and"
          " increase length."
      )
      st.progress(strength_score, text="Security Level: Medium")
    else:
      st.success("✨ **Great password!** High cryptographic strength.")
      st.progress(strength_score, text="Security Level: High")

    st.markdown("---")
    st.subheader("🌐 Leak Verification (HaveIBeenPwned)")
    with st.spinner("Checking anonymous hash against breach databases..."):
      pwned_count = check_pwned_api(user_password)

    if pwned_count > 0:
      st.error(
          f"🚨 **Warning!** This password was found in public data breaches"
          f" **{pwned_count} time(s)**! You should change it immediately."
      )
    elif pwned_count == 0:
      st.success(
          "✅ This password **was not found** in any known breach databases."
      )
    else:
      st.warning(
          "⚠️ Failed to connect to the leak check server (check your internet"
          " connection)."
      )

with tab2:
  st.subheader("Cryptographically Secure Password Generator")
  col_len, col_opt = st.columns([2, 1])

  with col_len:
    gen_length = st.slider(
        "Password Length", min_value=8, max_value=64, value=16
    )
  with col_opt:
    st.write("Options:")
    inc_upper = st.checkbox("Uppercase (A-Z)", value=True)
    inc_digits = st.checkbox("Digits (0-9)", value=True)
    inc_symbols = st.checkbox("Special chars (!@#)", value=True)

  if st.button("Generate Secure Password", type="primary"):
    new_password = generate_secure_password(
        length=gen_length,
        use_upper=inc_upper,
        use_digits=inc_digits,
        use_symbols=inc_symbols,
    )
    st.success("Done! Copy your new password:")
    st.code(new_password, language="")