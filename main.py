# path: main.py
# Bu dosya, uygulamanın ana giriş noktasıdır.

import os
import sys

# Python PATH'ini ayarlama (GUI modüllerinin "core" modüllerini bulabilmesi için)
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.append(current_dir)

try:
    from Test.gui_main import MestegApp
except ImportError as e:
    print(f"Kritik Hata: gui_main modülü bulunamadi. Hata: {e}")
    sys.exit(1)


if __name__ == "__main__":
    app = MestegApp()
    app.mainloop()