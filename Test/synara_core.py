# path: Synara AI Security Test/Test/synara_core.py

# --- MİMARİ NOTU ---
# Bu dosya, Faz 1 dönüşümü sırasında parçalanmıştır.
# Yeni ana tarama motoru: core/engine.py
# Yeni raporlama: core/reporter.py
# Yeni tarayıcı modülleri: core/scanners/*

# Bu dosyanın ismi, eski çağrıları engellemek için korunmaktadır.
# Ancak GUI, artık 'core/engine.py' içindeki SynaraScannerEngine'i kullanmalıdır.

# Eski SynaraScanner sınıfı silinmiştir.
# Yeni mimari için gerekli importlar:
# Düzeltme: sys.path manipülasyonu sayesinde mutlak import artık çalışacaktır.
from core.engine import SynaraScannerEngine as SynaraScanner # GUI'nin import bağımlılığını korumak için

# Bu dosya, sadece eski isimlendirme bağımlılığını çözmek için tutulmuştur.