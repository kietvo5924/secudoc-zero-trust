"""SecuDoc Web Server Runner."""
import sys
from pathlib import Path

# Ensure project root is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

from src.web.app import create_app
from src.config import SERVER_HOST, SERVER_PORT, DEBUG

app = create_app()

if __name__ == "__main__":
    print("=" * 65)
    print("🛡️  SecuDoc - Cổng Thẩm Định Văn Bản Số Chống Giả Mạo")
    print(f"🌐 Server đang khởi chạy tại: http://{SERVER_HOST}:{SERVER_PORT}")
    print("=" * 65)
    app.run(host=SERVER_HOST, port=SERVER_PORT, debug=DEBUG)
