import sys
from pdfminer.high_level import extract_text

pdf_path = r"d:\Machine virtuelle\Python pour TI\Examen\penetration_testing_framework\Projet_testIntrusion.pdf"
out_path = r"d:\Machine virtuelle\Python pour TI\Examen\penetration_testing_framework\tools\Projet_testIntrusion.txt"

try:
    text = extract_text(pdf_path)
    with open(out_path, 'w', encoding='utf-8') as f:
        f.write(text)
    print(f"OK: wrote {out_path}")
except Exception as e:
    print("ERROR", e, file=sys.stderr)
    sys.exit(1)
