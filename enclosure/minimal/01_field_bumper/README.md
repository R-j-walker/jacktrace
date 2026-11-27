# JackTrace Minimal — Concept 1: Field Bumper

An open-source, support-free 3D-printable enclosure for a minimal **Raspberry Pi 4 Model B + Waveshare 5" DSI Capacitive LCD** JackTrace build — featuring clamshell-captured side bumper rails, chimney airflow cooling, a recessed top USB-C plug bay, and a native flush recess for a stick-on **MagSafe** ring (sized for slim `~102 × 68 × 9 mm` magnetic power banks such as the Dbasne F91-D).

## Key Specs
- **Assembled Dimensions:** `137.6 × 93.0 × 38.5 mm` (`~47.5 mm` total with a `9 mm` MagSafe power bank attached)
- **Hardware Stack:** Direct-mounted Raspberry Pi 4B on the Waveshare 5" DSI LCD's built-in brass standoffs using the stock `50 mm` DSI ribbon (zero soldering, zero HATs, zero extra standoffs)
- **Print Bed Required:** Fits any `180 × 180 mm` printer (Prusa MINI, Bambu A1 Mini, Ender 3, etc.)
- **Supports Required:** **None** (all parts pre-oriented flat on `Z = 0` with `45°` self-supporting ceilings and locking ramps)

---

## Bill of Materials (BOM)

| Qty | Item | Notes |
| :---: | :--- | :--- |
| 1 | Raspberry Pi 4 Model B | Optional low-profile aluminum heatsinks up to `14 mm` tall fit inside |
| 1 | Waveshare 5" DSI Capacitive LCD (`800×480`) | Includes built-in Pi standoffs, `4× M2.5` screws, and `50 mm` DSI ribbon |
| 4 | **`M2.5 × 16 mm`** socket-head cap screws | Direct self-tapping into the front shell (`M2.5 × 14 mm` also works; toggle `use_heatset_inserts = true` in OpenSCAD for `M2.5×4×3.5` brass inserts) |
| 1 | Stick-on MagSafe metal ring *(optional)* | Standard `54–56 mm OD / 46 mm ID × 0.5–0.7 mm` steel sticker (with optional bottom anti-spin alignment pill) |
| 1 | Slim MagSafe USB-C power bank + `10–15 cm` right-angle USB-C cable *(optional)* | Tested geometry: Dbasne F91-D (`102 × 68 × 9 mm`); also fits `5V/3A` Anker MagGo / UGREEN MagSafe banks |
| 1 | Wrist lanyard *(optional)* | Clips through the `4.4 mm` tucked top-left bezel loop |

---

## Files

- **Shared Minimal Core:** [`../jacktrace_minimal_core.scad`](../jacktrace_minimal_core.scad) — single source of truth for LCD pocket, Pi 4B cutouts, MagSafe recess, and JackTrace branding
- **Parametric CAD:** [`jacktrace_field_bumper.scad`](jacktrace_field_bumper.scad)
- **Print-Ready STLs (`stl/`):**
  - `field_bumper_front.stl` (`132.8 × 95.8 × 14.0 mm`) — print flat on outer front bezel face
  - `field_bumper_back.stl` (`130.0 × 93.0 × 26.3 mm`) — print flat on outer rear MagSafe face
  - `field_bumper_rails.stl` (`45.9 × 38.1 × 60.5 mm`) — pair of left & right clamshell-captured side bumper rails (pre-oriented upright on flat base)

---

## Slicing Recommendations

- **Material:**
  - `front` & `back`: **PETG** (recommended for field durability/heat) or **PLA+** / **ASA**
  - `rails`: **TPU 95A** (for rubberized drop protection) **or** contrasting **PETG/PLA** (e.g., matte safety amber) — the clamshell-captured locking tabs require **zero flex**, so rigid filaments assemble cleanly without cracking!
- **Layer Height:** `0.20 mm` (clean `3-layer` `0.6 mm` logo & `0.7 mm` MagSafe recess)
- **Perimeters / Walls:** `3` walls (`1.2 mm` minimum) — gives strong M2.5 self-tapping bite
- **Infill:** `20%` gyroid or grid
- **Supports:** **OFF** (`0` supports needed)
- **Orientation Tip:** Every STL is already exported flat on `Z = 0` — do **not** run slicer "Auto-Orient".

---

## 2-Minute Assembly

1. **Pre-assemble LCD + Pi 4:** Connect the stock `50 mm` DSI ribbon between the Waveshare 5" DSI LCD and the Raspberry Pi 4B, and fasten the Pi 4B onto the LCD's 4 built-in rear brass standoffs using the 4× `M2.5` screws included with the screen. *(Tip: flash and insert your microSD card now — the card stays safely protected inside the enclosure.)*
2. **Seat into Front Shell:** Place `field_bumper_front` face-down on a clean surface and drop the assembled LCD + Pi 4 straight into the unobstructed front glass pocket (Ethernet/USB ports toward the right `+X` edge, Pi USB-C toward the top `-Y` alcove notch).
3. **Drop in Bumper Rails:** Set the left (scalloped) and right (port-framed) bumper rails into the recessed side saddles on `field_bumper_front` so their lower locking tabs seat into the shell seam pockets.
4. **Close & Fasten:** Lower `field_bumper_back` straight down over the Pi 4 and bumper rails (the 4 internal rear posts gently retain the LCD corners while capturing both bumper rails in place). Thread **4× `M2.5 × 16 mm`** screws into the recessed rear corners until snug — do not overtighten into plastic.
5. **Attach MagSafe Ring *(optional)*:** Peel and press a standard `55 mm` stick-on steel MagSafe ring directly into the flush rear ring groove (and press the horizontal anti-spin alignment pill into the `-X` pill recess if your sticker kit includes one). Snap on your MagSafe power bank with its USB-C port facing left (`-X`) and connect a short `10–15 cm` right-angle USB-C cable into the recessed top Pi 4 USB-C alcove.

---

## OpenSCAD Customization Parameters

Edit the top of [`jacktrace_field_bumper.scad`](jacktrace_field_bumper.scad) or override with `-D`:

- `enable_magsafe = true` — set `false` for a non-MagSafe back with classic upper-center rear cooling vents + lower rear `JACKTRACE` emblem & wordmark
- `use_heatset_inserts = false` — set `true` to enlarge the 4 front bosses from `2.25 mm` (M2.5 self-tap) to `3.6 mm` (`M2.5 × 4 × 3.5 mm` brass heat-set inserts)
- `expose_hdmi_audio = false` — set `true` to open the top edge for micro-HDMI 0/1 & 3.5 mm audio bench debugging
- `bumper_clear = 0.25` — adjust if your printer runs tighter/looser tolerances on the captured side bumper rails
