#!/usr/bin/env python3
"""PostLock:Boot launcher icon: golden padlock + green boot-bolt on deep navy."""
from PIL import Image, ImageDraw

S = 512

# ---- background: vertical navy gradient -----------------------------------
bg = Image.new("RGBA", (S, S), (0, 0, 0, 0))
top = (13, 27, 42)     # #0D1B2A
bot = (22, 40, 60)     # #16283C
for y in range(S):
    t = y / (S - 1)
    c = tuple(int(top[i] + (bot[i] - top[i]) * t) for i in range(3))
    bg.paste(c + (255,), (0, y, S, y + 1))

# ---- foreground: padlock + bolt -------------------------------------------
fg = Image.new("RGBA", (S, S), (0, 0, 0, 0))
d = ImageDraw.Draw(fg)

gold = (245, 183, 0, 255)        # #F5B700 shackle + body
gold_hi = (255, 214, 79, 255)    # #FFD64F body highlight edge
bolt = (74, 222, 128, 255)       # #4ADE80 boot bolt
bolt_hi = (187, 255, 208, 255)

# shackle: upper half arc, thick
arc_bbox = (176, 118, 336, 278)
d.arc(arc_bbox, 180, 360, fill=gold, width=36)
# shackle feet into the body
d.rectangle([176 - 18, 190, 176 + 18, 270], fill=gold)
d.rectangle([336 - 18, 190, 336 + 18, 270], fill=gold)

# body: rounded rect
body = (140, 250, 372, 448)
d.rounded_rectangle(body, radius=44, fill=gold)
# subtle top highlight band inside body
d.rounded_rectangle(
    (body[0] + 14, body[1] + 12, body[2] - 14, body[1] + 40),
    radius=18, fill=gold_hi)

# boot bolt (lightning) centered on the body
cx, cy = 256, 352
bolt_pts = [
    (cx + 26, cy - 78),
    (cx - 52, cy + 8),
    (cx - 4, cy + 8),
    (cx - 26, cy + 82),
    (cx + 58, cy - 12),
    (cx + 8, cy - 12),
]
d.polygon(bolt_pts, fill=bolt)
# inner glint
d.polygon([
    (cx + 26, cy - 78),
    (cx + 4, cy - 50),
    (cx + 16, cy - 50),
], fill=bolt_hi)

bg.alpha_composite(fg)

import os
base = os.path.dirname(os.path.abspath(__file__))
out_dir = os.path.join(base, "app/src/main/res")
os.makedirs(os.path.join(out_dir, "mipmap-xxxhdpi"), exist_ok=True)
os.makedirs(os.path.join(out_dir, "mipmap-anydpi-v26"), exist_ok=True)
os.makedirs(os.path.join(out_dir, "values"), exist_ok=True)

bg.save(os.path.join(out_dir, "mipmap-xxxhdpi", "ic_launcher_background.png"))
fg.save(os.path.join(out_dir, "mipmap-xxxhdpi", "ic_launcher_foreground.png"))

# adaptive icon xml (API 26+, minSdk 26 => sole launcher path)
with open(os.path.join(out_dir, "mipmap-anydpi-v26", "ic_launcher.xml"), "w") as f:
    f.write('''<?xml version="1.0" encoding="utf-8"?>
<adaptive-icon xmlns:android="http://schemas.android.com/apk/res/android">
    <background android:drawable="@mipmap/ic_launcher_background"/>
    <foreground android:drawable="@mipmap/ic_launcher_foreground"/>
</adaptive-icon>
''')

# drop a preview copy for review
bg.save(os.path.join(base, "icon_preview.png"))
print("icons written")
