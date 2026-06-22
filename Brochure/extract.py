import fitz, os, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
out = r'd:\DD-CLONE\DealDirectSecure\Brochure\pages'
os.makedirs(out, exist_ok=True)

# La Vesta
doc = fitz.open(r'd:\DD-CLONE\DealDirectSecure\Brochure\La Vesta Full Brocher Horizental Design 16 Dec 2024-6.pdf')
print(f'La Vesta: {len(doc)} pages')
for i, page in enumerate(doc):
    text = page.get_text().strip().replace('\n', ' | ')
    short = text[:400] if text else "[image only]"
    print(f'  P{i+1}: {short}')
doc.close()

print("\n" + "="*80 + "\n")

# Little Earth
doc2 = fitz.open(r'd:\DD-CLONE\DealDirectSecure\Brochure\little-earth-Brochure.pdf')
print(f'Little Earth: {len(doc2)} pages')
for i, page in enumerate(doc2):
    if i >= 15: break
    pix = page.get_pixmap(dpi=150)
    pix.save(os.path.join(out, f'littleearth_p{i+1}.png'))
    text = page.get_text().strip().replace('\n', ' | ')
    short = text[:400] if text else "[image only]"
    print(f'  P{i+1} ({pix.width}x{pix.height}): {short}')
doc2.close()
print('Done')
