"""Record High-Definition Animated WebP Demo Videos for New SecuDoc Features:
- Video 8: Signed Checkpoint & Full-Chain Rewrite Detection
- Video 9: Security Behavior Analytics with ML (Isolation Forest)
- Video 10: Least Privilege & PII Protection
"""
import os
import sys
import time
import threading
from pathlib import Path
from io import BytesIO
from PIL import Image

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

BASE_DIR = Path(__file__).resolve().parent.parent
OUTPUT_DIR = BASE_DIR / "video demo"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# Port for demo server
DEMO_PORT = 5005
BASE_URL = f"http://127.0.0.1:{DEMO_PORT}"


def start_flask_server():
    """Start SecuDoc Flask application in a daemon thread."""
    sys.path.insert(0, str(BASE_DIR))
    from src.web.app import create_app
    app = create_app({"DEMO_MODE": True})
    import logging
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)
    app.run(host="127.0.0.1", port=DEMO_PORT, debug=False, use_reloader=False)


def setup_driver():
    options = Options()
    options.add_argument("--headless=new")
    options.add_argument("--window-size=1920,1080")
    options.add_argument("--disable-gpu")
    options.add_argument("--no-sandbox")
    options.binary_location = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
    driver = webdriver.Chrome(options=options)
    driver.set_window_size(1920, 1080)
    return driver


def capture_frame(driver) -> Image.Image:
    """Capture current browser viewport as PIL Image."""
    png_data = driver.get_screenshot_as_png()
    return Image.open(BytesIO(png_data)).convert("RGB")


def save_webp_animation(frames: list[Image.Image], output_path: Path, duration_ms: int = 400):
    """Save a list of PIL Images as an animated WebP file."""
    if not frames:
        return
    print(f"Saving {len(frames)} frames to {output_path.name}...")
    # Resize slightly or optimize to keep high quality under reasonable size
    optimized_frames = []
    for f in frames:
        # Resize to standard 1600x900 for crisp text and optimal webp filesize
        resized = f.resize((1600, 900), Image.Resampling.LANCZOS)
        optimized_frames.append(resized)

    optimized_frames[0].save(
        output_path,
        save_all=True,
        append_images=optimized_frames[1:],
        duration=duration_ms,
        loop=0,
        quality=85,
        method=4
    )
    file_size_mb = output_path.stat().st_size / (1024 * 1024)
    print(f"Successfully generated {output_path.name} ({file_size_mb:.2f} MB)")


def record_video_8_signed_checkpoint(driver):
    """Video 8: Signed Checkpoint Creation, Verification, and Full-Chain Rewrite Attack Detection."""
    frames = []
    print("\n--- Recording Video 8: Signed Checkpoint & Full-Chain Rewrite Detection ---")

    # 1. Login as auditor
    driver.get(f"{BASE_URL}/login")
    time.sleep(1)
    frames.append(capture_frame(driver))

    u_input = driver.find_element(By.NAME, "username")
    p_input = driver.find_element(By.NAME, "password")
    u_input.clear()
    u_input.send_keys("auditor")
    p_input.clear()
    p_input.send_keys("AuditorPass2026!")
    frames.append(capture_frame(driver))

    driver.find_element(By.XPATH, "//button[@type='submit']").click()
    time.sleep(1.5)

    # 2. On Audit Page
    driver.get(f"{BASE_URL}/audit")
    time.sleep(1)
    for _ in range(2):
        frames.append(capture_frame(driver))

    # Scroll down to Checkpoint Panel
    driver.execute_script("window.scrollTo(0, 200);")
    time.sleep(0.5)
    frames.append(capture_frame(driver))

    # Click Create Signed Checkpoint
    try:
        btn_create = driver.find_element(By.XPATH, "//button[contains(text(), 'Tạo Checkpoint Mới')]")
        btn_create.click()
        time.sleep(2)
        frames.append(capture_frame(driver))
    except Exception as e:
        print("Create checkpoint button click:", e)

    # Click Verify Checkpoint
    try:
        btn_verify = driver.find_element(By.XPATH, "//button[contains(text(), 'Đối Soát Với Checkpoint')]")
        btn_verify.click()
        time.sleep(1.5)
        for _ in range(2):
            frames.append(capture_frame(driver))
    except Exception as e:
        print("Verify checkpoint button click:", e)

    # Scroll down to Adversarial Simulation Panel
    driver.execute_script("window.scrollTo(0, 1000);")
    time.sleep(0.8)
    for _ in range(2):
        frames.append(capture_frame(driver))

    # Execute Full-Chain Rewrite Attack
    try:
        btn_rewrite = driver.find_element(By.XPATH, "//button[contains(text(), 'Thực Thi Tấn Công Viết Lại Chuỗi')]")
        btn_rewrite.click()
        time.sleep(2)
        for _ in range(3):
            frames.append(capture_frame(driver))
    except Exception as e:
        print("Rewrite attack button click:", e)

    # Scroll to show rewrite attack result clearly
    driver.execute_script("window.scrollTo(0, 1200);")
    time.sleep(1)
    for _ in range(3):
        frames.append(capture_frame(driver))

    save_webp_animation(frames, OUTPUT_DIR / "Video_8_Signed_Checkpoint_Va_Chong_Gia_Mao_So_Cai.webp", duration_ms=600)


def record_video_9_security_behavior_analytics(driver):
    """Video 9: Security Behavior Analytics with ML (Isolation Forest vs Baseline)."""
    frames = []
    print("\n--- Recording Video 9: Security Behavior Analytics ML ---")

    driver.get(f"{BASE_URL}/audit")
    time.sleep(1)
    frames.append(capture_frame(driver))

    # Scroll directly to ML Analytics panel
    driver.execute_script("window.scrollTo(0, 450);")
    time.sleep(1)
    for _ in range(3):
        frames.append(capture_frame(driver))

    # Scroll slightly to show Benchmark Table
    driver.execute_script("window.scrollTo(0, 700);")
    time.sleep(1)
    for _ in range(4):
        frames.append(capture_frame(driver))

    # Scroll to show Security Event Telemetry table
    driver.execute_script("window.scrollTo(0, 1050);")
    time.sleep(1)
    for _ in range(3):
        frames.append(capture_frame(driver))

    save_webp_animation(frames, OUTPUT_DIR / "Video_9_Security_Behavior_Analytics_ML.webp", duration_ms=700)


def record_video_10_least_privilege_and_pii(driver):
    """Video 10: Least Privilege Authorization & PII Masking Protection."""
    frames = []
    print("\n--- Recording Video 10: Least Privilege & PII Protection ---")

    # 1. First, visit certificate view without login -> PII is masked
    # Find a valid document UUID from database
    import sqlite3
    conn = sqlite3.connect(str(BASE_DIR / "data" / "secudoc.db"))
    c = conn.cursor()
    row = c.execute("SELECT doc_uuid FROM documents LIMIT 1;").fetchone()
    conn.close()

    doc_uuid = row[0] if row else "00000000-0000-0000-0000-000000000000"

    driver.get(f"{BASE_URL}/logout")
    time.sleep(0.5)

    # Public View of Certificate: PII is masked
    driver.get(f"{BASE_URL}/certificate/{doc_uuid}")
    time.sleep(1.2)
    for _ in range(3):
        frames.append(capture_frame(driver))

    # 2. Login as Issuer to view authorized dashboard
    driver.get(f"{BASE_URL}/login")
    time.sleep(0.8)
    driver.find_element(By.NAME, "username").send_keys("issuer")
    driver.find_element(By.NAME, "password").send_keys("IssuerSecurePass2026!")
    frames.append(capture_frame(driver))
    driver.find_element(By.XPATH, "//button[@type='submit']").click()
    time.sleep(1.5)

    # 3. View Issuer Dashboard
    driver.get(f"{BASE_URL}/dashboard")
    time.sleep(1)
    for _ in range(3):
        frames.append(capture_frame(driver))

    # View certificate as authorized owner -> Full name visible
    driver.get(f"{BASE_URL}/certificate/{doc_uuid}")
    time.sleep(1.2)
    for _ in range(3):
        frames.append(capture_frame(driver))

    save_webp_animation(frames, OUTPUT_DIR / "Video_10_Least_Privilege_Va_Bao_Ve_Du_Lieu_PII.webp", duration_ms=650)


def main():
    print("Starting background Flask server...")
    srv_thread = threading.Thread(target=start_flask_server, daemon=True)
    srv_thread.start()
    time.sleep(2)

    print("Initializing Headless Chrome Driver...")
    driver = setup_driver()

    try:
        record_video_8_signed_checkpoint(driver)
        record_video_9_security_behavior_analytics(driver)
        record_video_10_least_privilege_and_pii(driver)
    finally:
        driver.quit()
        print("\nAll new video recordings completed successfully!")


if __name__ == "__main__":
    main()

