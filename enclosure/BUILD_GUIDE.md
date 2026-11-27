# JackTrace v2.0 — Extended-Grip Handheld Enclosure Build Guide (Option A)

This guide covers the **3D-printable rugged handheld enclosure**, **complete Bill of Materials (BOM)**, **safe simultaneous USB-C + PoE charging wiring**, and **reserved PoE voltage-sensing bay** for the JackTrace Raspberry Pi 4 network tester.

- **Parametric CAD source:** [`jacktrace_enclosure.scad`](jacktrace_enclosure.scad)
- **Print-ready STLs (support-free):**
  - [`stl/jacktrace_front.stl`](stl/jacktrace_front.stl) — Front bezel, unobstructed drop-in screen pocket, grip grooves, engraved logo, LED hole, lanyard loop
  - [`stl/jacktrace_lcd_clamps.stl`](stl/jacktrace_lcd_clamps.stl) — Pair of slim retaining bars that lock the Waveshare 5" DSI LCD solidly into the front shell
  - [`stl/jacktrace_back.stl`](stl/jacktrace_back.stl) — Extended-grip rear body, Pi 4 ports, cooling louvers, engraved rear emblem, USB-C & guarded power button cutouts, through-bolted Pi pillars, flush kickstand recess
  - [`stl/jacktrace_kickstand.stl`](stl/jacktrace_kickstand.stl) — Flush U-frame fold-out rear kickstand

---

## 1. Enclosure Dimensions & Features

| Specification | Value |
| :--- | :--- |
| **Overall Outer Size** | `173.3 × 96.0 × 63.3 mm` (`L × H × D`) |
| **Screen Pocket (Verified)** | `122.2 × 78.0 × 9.5 mm` (matched to your Waveshare 5" DSI LCD) |
| **Viewing Window** | `109.6 × 66.4 mm` (+3.25 mm X offset, 45° chamfered drop-protection lip) |
| **External Ports** | Right edge: `eth0` RJ45 + Dual USB 3.0 + Dual USB 2.0<br>Bottom-left: Recessed USB-C charging port<br>Top-left: Guarded 12 mm recessed power button |
| **MicroSD Slot** | Fully enclosed (dust-sealed; accessible by removing the 6 back screws) |
| **Cooling** | Rear intake/exhaust louver vents centered inside the U-kickstand + top convection exhaust slots + internal thermal divider separating Pi/PoE heat from the grip bay |
| **Extras** | Molded top-left lanyard/carabiner loop, flush fold-out rear kickstand (~55° stand angle), front status LED hole, 6× grip grooves |

---

## 2. Power & PoE Architecture (Zero Backfeed + Working TDR)

```text
                       ┌───────────────────────────┐
Wall Jack ──► Pi4 RJ45 ┤ (MagJack center taps)     │  ◄── No inline splitter = TDR works 100%
                       └────────────┬──────────────┘
                                    │ 4-pin PoE Header (48V isolated)
                                    ▼
                        Waveshare PoE HAT (C)  ──► [GPIO 5V pins 2 & 4 DISCONNECTED/ISOLATED]
                       (802.3af/at, isolated 5V/4A)
                                    │
                       [Optional: INA219 on 5V] ◄── Tier 1 active PoE power verification
                                    │
                                    ▼
                        ┌──────────────────────┐
External USB-C ────────►│ Dual Ideal Diode     │  ◄── Blocks backfeed (<30 mV drop)
(5.1kΩ CC breakout)     │ OR-ing (2× 10A 3-28V)│      USB-C + PoE together = 100% SAFE
                        └──────────┬───────────┘
                                   │ Single safe 5V rail (wired to PiSugar 5V IN)
                                   ▼
                          PiSugar 3 Plus       ──► Powers Pi 4 + 5" DSI LCD via pogo pins
                       (5000 mAh LiPo + I2C)       (Seamless UPS failover on unplug)
```

> **CRITICAL ELECTRICAL RULE — Isolate PoE HAT (C) GPIO 5V Pins!**
> Never allow both the **Waveshare PoE HAT (C)** and the **PiSugar 3 Plus** to drive the Raspberry Pi 4's 5 V GPIO rail simultaneously.
> Before mounting the PoE HAT (C), **isolate or remove GPIO pins 2 and 4 (5 V)** on the PoE HAT's 40-pin header (e.g. using a short 4-pin PoE-only stacking header on the 2×2 PoE pins + M2.5 standoffs, or clipping/bending/insulating pins 2 & 4 on the HAT's female header).
> The PoE HAT (C) receives its 48 V input solely through the **4-pin PoE header** and outputs isolated **5 V / 4 A** on its onboard USB-A power port, which routes cleanly into **Ideal Diode #1** → **PiSugar 3 Plus charging input**.

---

## 3. Bill of Materials (BOM)

### A. Core Electronics (Already Owned / Option A Stack)
| Qty | Component | Notes |
| :---: | :--- | :--- |
| 1 | **Raspberry Pi 4 Model B** | Existing unit |
| 1 | **Waveshare 5" DSI Capacitive LCD (800×480)** | Existing unit (`121.11 × 77.93 mm`, `113 × 68 mm` outer pitch) |
| 1 | **150 mm 15-pin DSI FFC Ribbon Cable** | Longer than the stock 50 mm ribbon to route cleanly around the PiSugar 3 Plus |
| 1 | **PiSugar 3 Plus** (5000 mAh LiPo, for Pi 4) | Bottom pogo-pin mount (~15 mm thick), 5 V/3 A out, I2C fuel gauge + RTC |
| 1 | **Waveshare PoE HAT (C)** (802.3af/at PoE+) | Isolated SMPS, onboard active fan, 5 V/4 A USB-A power output |

### B. Safe Dual-Input Charging & Controls (Left Grip Bay)
| Qty | Component | Approx. Cost | Notes |
| :---: | :--- | :---: | :--- |
| 2 | **Ideal Diode Anti-Backflow Module (3–28 V, 10 A / 15 A)** | £3–£5 | MOSFET ideal diode (e.g. `LM74610` / `XL0401`, `<30 mV` drop). Must be rated down to `3 V` so it operates cleanly at `5.0 V`. |
| 1 | **USB-C Female Breakout PCB (with 5.1 kΩ CC resistors)** | £2–£4 | Standard `~16 × 14 mm` board (e.g. Adafruit `#4090` or generic 6-pin USB-C breakout with `5.1 kΩ` CC1/CC2 pulldowns so USB-C PD chargers output 5 V). |
| 1 | **12 mm Panel-Mount Momentary Push Button** | £2–£4 | Fits the guarded `12.2 mm` top-left recess; wires to PiSugar external button pads (or Pi `GPIO3` + `GND` wake/shutdown). |
| 1 | **Short Right-Angle USB-A Male Pigtail (or direct 5 V wire)** | £2 | Connects Waveshare PoE HAT (C) 5 V USB-A power-out to Ideal Diode #1 input. |
| 1 | **Short Right-Angle USB-C Male Pigtail (or 5 V solder pads)** | £2 | Connects combined Ideal Diode cathode output to PiSugar 3 Plus USB-C (or micro-USB / 5 V pad) charging input. |
| 1 | **5 mm Status LED + 330 Ω Resistor** *(optional)* | £1 | Fits the front-left recessed `5.2 mm` hole (wire to Pi `GPIO` or PiSugar charging LED). |
| — | **20–22 AWG Silicone Wire + Heat Shrink** | £3 | Use `20 AWG` for all 5 V power paths (up to 3 A); `26–28 AWG` for I2C/button signals. |

### C. Reserved PoE Voltage-Sensing Bay (Optional — Decide Later)
The left grip bay includes a dedicated `41 × 78 × 54 mm` cavity with 10× M2.5 mounting standoffs reserved for either sensing tier:

- **Tier 1 — Active PoE Power Verify (~£4, zero isolation complexity):**
  - 1× **INA219** I2C breakout wired in series on the **isolated 5 V output** of the PoE HAT (C) (before Ideal Diode #1).
  - Measures: Live active 802.3af/at PoE delivery (`YES/NO`), live PoE `5 V` rail, draw (`A`), wattage (`W`), and active power source (`PoE` vs `USB-C` vs `Battery`).
- **Tier 2 — True Raw 48 V PoE Line Voltage (~£20, requires strict isolation):**
  - 1× **Adafruit INA228** (85 V, 20-bit I2C power monitor) on the PoE HAT's rectified primary 48 V bus
  - 1× **Adafruit ISO1540** I2C galvanic isolator (`2.5 kVrms` isolation)
  - 1× **B0503S-1W** isolated `5 V → 3.3 V` DC-DC module (powers the isolated primary side of the `ISO1540` + `INA228`)
  - > **SAFETY WARNING:** Never wire a non-isolated `INA228` straight to the Pi 4's I2C pins across the 48 V PoE primary bus — doing so defeats IEEE 802.3af/at isolation and creates a ground-loop fault hazard whenever a grounded USB-C charger is plugged in.

### D. Mechanical Fasteners & Padding
| Qty | Fastener | Purpose |
| :---: | :--- | :--- |
| 6 | **M3 × 55 mm Socket Head Cap Screws (SHCS)** | Closes back shell directly into the 6 self-tapping front shell bosses (`2.7 mm` bore; optional: set `use_heatset_inserts = true;` for M3 brass inserts) |
| 4 | **M2.5 × 6 mm Screws** | Bolts the 2× LCD Clamp Bars into the Waveshare 5" DSI LCD's 4 rear threaded M2.5 holes (`113 × 68 mm`) |
| 4 | **M2.5 × 8 mm Screws** | Bolts the 2× LCD Clamp Bars into the 4 exterior-rim M2.5 bosses in `jacktrace_front.stl` |
| 4 | **M2.5 × 12 mm Female-Female Brass Standoffs** + **4× M2.5 × 25 mm Screws** | Mounts Waveshare PoE HAT (C) onto Pi 4, then bolts the entire Pi stack from the OUTSIDE of `jacktrace_back.stl` through the 4 rear countersunk pillars |
| 2 | **M2 × 12 mm Screws** *(or two 14 mm lengths of 1.75 mm 3D-printer filament)* | Enclosed flush kickstand hinge pins |
| 2 | **M2 × 6 mm Screws** | Secures USB-C breakout PCB to the internal cradle |
| 1 | **2 mm Adhesive EVA Foam Pad (`65 × 50 mm`)** | Cushions between the rear of the LCD PCB and the flat PiSugar LiPo pouch |

---

## 4. Wiring Checklist

1. **External USB-C Breakout → Ideal Diode #2:**
   - `USB-C VBUS (+5V)` → `Ideal Diode #2 IN+`
   - `USB-C GND` → Common `GND` bus
2. **Waveshare PoE HAT (C) → Ideal Diode #1:**
   - **Isolate GPIO pins 2 & 4 (`5 V`)** on the PoE HAT (C) 40-pin header so PoE 5 V cannot reach the Pi's GPIO rail directly.
   - Connect `PoE HAT (C) USB-A +5V` → *(optional Tier 1 INA219 `VIN+ → VIN-`)* → `Ideal Diode #1 IN+`
   - Connect `PoE HAT (C) USB-A GND` → Common `GND` bus
3. **OR-ing Output → PiSugar 3 Plus:**
   - Tie `Ideal Diode #1 OUT+` and `Ideal Diode #2 OUT+` together → feed into `PiSugar 3 Plus` 5 V USB-C (or micro-USB / 5 V charge pad) input.
   - Tie `GND` to `PiSugar 3 Plus` charging `GND`.
4. **Bench Verification BEFORE Connecting the Pi 4:**
   - Plug in USB-C only → verify `~4.97–5.05 V` at OR-ing output and `0 V` backfed at PoE HAT USB-A port.
   - Plug in PoE Ethernet only (on a PoE switch) → verify `~5.0 V` at OR-ing output and `0 V` backfed at external USB-C port.
   - Plug in **BOTH USB-C and PoE simultaneously** → verify stable `~5.0 V` at OR-ing output, cool ideal diode boards, and PiSugar charging LED active.

---

## 5. Step-by-Step Assembly Sequence

1. **Mount the Waveshare 5" DSI LCD into `jacktrace_front.stl`:**
   - Place `jacktrace_front.stl` face-down on your desk. *(Optional: apply thin 0.5 mm foam tape around the inner 2.2 mm front bezel lip to cushion the glass.)*
   - Drop the Waveshare 5" DSI LCD **glass-first** straight into the unobstructed `122.2 × 78.0 mm` pocket.
   - Lay the two **LCD Clamp Bars** (`jacktrace_lcd_clamps.stl`) across the top and bottom edges of the display back:
     - Drive **4× M2.5 × 6 mm** screws through the outer holes (`±56.5, ±34.0`) into the Waveshare LCD's own rear threaded M2.5 holes.
     - Drive **4× M2.5 × 8 mm** screws through the two clamp ears (`±38.0, ±42.2`) into the 4 exterior-rim M2.5 bosses on `jacktrace_front.stl`.
   - The screen is now locked solidly to the front bezel while leaving the entire rear of the LCD open for cables.
2. **Pre-assemble the Pi 4 + PiSugar 3 Plus + PoE HAT (C) Stack:**
   - Mount **PiSugar 3 Plus** to the underside of the Pi 4 with its included pogo-pin M2.5 hardware.
   - Plug one end of the **150 mm 15-pin DSI ribbon** into the Pi 4's DSI port.
   - **Isolate GPIO pins 2 & 4 (`5 V`)** on the Waveshare PoE HAT (C), install `4× M2.5 × 12 mm` female-female standoffs on the Pi 4, and seat the PoE HAT (C) onto the 4-pin PoE header.
   - Stick the `2 mm` EVA foam pad to the back of the PiSugar 3 Plus battery.
3. **Install Left-Grip Hardware (`jacktrace_back.stl` & `jacktrace_front.stl`):**
   - Screw the USB-C breakout PCB onto the gusseted cradle inside `jacktrace_back.stl` (`2× M2 × 6 mm`).
   - Fit the 12 mm momentary power button into the guarded top-left recess of `jacktrace_back.stl`.
   - Screw the two Ideal Diode OR-ing boards onto the grip M2.5 standoffs, complete the power wiring in Section 4, and verify zero backfeed on the bench before connecting the Pi.
4. **Mount the Pi Stack into `jacktrace_back.stl`:**
   - Seat the Pi 4 + PiSugar + PoE HAT stack into `jacktrace_back.stl` so `eth0` RJ45 and both USB-A stacks align cleanly with the right-edge cutouts.
   - Insert **4× M2.5 × 25 mm** screws from the **outside** of the back shell through the 4 countersunk rear mounting tubes directly into the PoE HAT (C)'s top M2.5 brass standoffs.
5. **Connect DSI Ribbon, Close the Case & Install Kickstand:**
   - Plug the free end of the **150 mm DSI ribbon** into the Waveshare 5" DSI LCD (tucking the slack cleanly through the thermal divider notch).
   - Mate `jacktrace_front.stl` and `jacktrace_back.stl` along the interlocking perimeter lip and fasten the **6× M3 × 55 mm** screws from the back into the self-tapping front bosses.
   - Drop `jacktrace_kickstand.stl` into the rear U-channel and push two `14 mm` lengths of `1.75 mm` filament (or `2× M2 × 12 mm` screws) through the two hinge bores.

---

## 6. 3D Printing & Slicing Guide

All four STL files are **pre-oriented flat on `Z = 0`** and engineered for **100% support-free FDM printing**:

| Part | Orientation | Supports | Notes |
| :--- | :--- | :---: | :--- |
| `jacktrace_front.stl` | Screen face down (`Z = 0`) | **None** | All bevels/chamfers are 45°; clean textured PEI finish on front bezel |
| `jacktrace_lcd_clamps.stl` | Flat on bed (`Z = 0`) | **None** | Pair of 2.3 mm LCD retaining bars (~5 min print) |
| `jacktrace_back.stl` | Rear outer face down (`Z = 0`) | **None** | U-kickstand channels are `8.4 mm` wide and bridge cleanly; skip Auto-Orient |
| `jacktrace_kickstand.stl` | Flat on bed (`Z = 0`) | **None** | Strong continuous layer lines along both arms |

### Recommended Slicer Settings
- **Filament:** **PETG**, **ABS**, or **ASA** (matte black PETG-CF looks great and matches the concept renders). *Avoid standard PLA*, as Pi 4 + PoE converter warmth in a comms cabinet can soften PLA above ~55 °C.
- **Nozzle / Layer Height:** `0.4 mm` nozzle, `0.20 mm` layer height
- **Walls / Infill:** `3–4` wall loops (`1.2–1.6 mm`), `20–25%` Gyroid infill, `4–5` top/bottom layers
- **Bed Size Required:** At least `180 × 100 mm` (fits Prusa MINI, Bambu A1 Mini, Ender 3, Bambu P1/X1, Prusa MK3/MK4)

### Re-exporting Custom Tweaks from OpenSCAD
Edit any parameter at the top of [`jacktrace_enclosure.scad`](jacktrace_enclosure.scad) (e.g., `use_heatset_inserts = false`, `win_w`, `pwr_btn_d`, `led_d`), then run:

```powershell
$oscad = "C:\Program Files\OpenSCAD\openscad.com"
& $oscad -D 'part=\"front\"'     -o enclosure\stl\jacktrace_front.stl     enclosure\jacktrace_enclosure.scad
& $oscad -D 'part=\"back\"'      -o enclosure\stl\jacktrace_back.stl      enclosure\jacktrace_enclosure.scad
& $oscad -D 'part=\"kickstand\"' -o enclosure\stl\jacktrace_kickstand.stl enclosure\jacktrace_enclosure.scad
```
