// ============================================================================
// JackTrace v2.0 — Rugged Extended-Grip Handheld Enclosure (Option A)
// ============================================================================
// Target Hardware Stack:
//   - Waveshare 5" DSI Capacitive LCD (800x480, 121.11 x 77.93 mm)
//   - PiSugar 3 Plus (5000 mAh LiPo, pogo-pin bottom mount, ~15.5 mm stack)
//   - Raspberry Pi 4 Model B (85 x 56 mm, BCM54213PE TDR intact)
//   - Waveshare PoE HAT (C) (IEEE 802.3af/at isolated SMPS, 5V/4A USB-A out)
//   - Left Grip Bay: External USB-C input, Dual 10A Ideal Diode OR-ing,
//     guarded power switch, status LED, & reserved PoE voltage-sensing bay
//     (fits INA219 or isolated INA228 + ISO1540 + B0503S-1W).
//
// Verified Reference Coordinates:
//   XY origin (0, 0) = center of Waveshare 5" DSI LCD glass, directly
//   matched to the verified CK case STLs already test-fitted on your screen.
//
// Export via CLI:
//   openscad -D 'part="front"'      -o stl/jacktrace_front.stl      jacktrace_enclosure.scad
//   openscad -D 'part="back"'       -o stl/jacktrace_back.stl       jacktrace_enclosure.scad
//   openscad -D 'part="kickstand"'  -o stl/jacktrace_kickstand.stl  jacktrace_enclosure.scad
//   openscad -D 'part="lcd_clamps"' -o stl/jacktrace_lcd_clamps.stl jacktrace_enclosure.scad
// ============================================================================

part = "assembly"; // "front", "back", "kickstand", "lcd_clamps", "assembly", "exploded"

$fn = 48;

// ----------------------------------------------------------------------------
// 1. VERIFIED LCD & PI 4 REFERENCE DIMENSIONS (mm)
// ----------------------------------------------------------------------------
// Extracted from verified CK front/back STLs + official Waveshare/RPi drawings
lcd_pocket_w     = 122.2;   // 121.11 mm glass + ~0.55 mm clearance/side
lcd_pocket_h     = 78.0;    // 77.93 mm glass (CK uses 77.5..78.0)
lcd_pocket_depth = 9.5;     // Glass front to rear PCB mounting plane

// Active display viewing window (Waveshare active area: 108.0 x 64.8 mm)
// Offset +3.25 mm in X due to wider touch ribbon border on -X side
win_w            = 109.6;   // +0.8 mm margin/side for edge touch taps
win_h            = 66.4;    // +0.8 mm margin/side for edge touch taps
win_offset_x     = 3.25;
win_offset_y     = 0.0;

// Waveshare 5" DSI outer mounting holes: 113.0 x 68.0 mm pitch
lcd_mount_holes = [
    [-56.5, -34.0],
    [ 56.5, -34.0],
    [-56.5,  34.0],
    [ 56.5,  34.0]
];

// Raspberry Pi 4B mounting holes (58.0 x 49.0 mm pitch) relative to LCD center
pi_hole_x1 = -23.8;
pi_hole_x2 =  34.2;
pi_hole_y1 = -24.5;
pi_hole_y2 =  24.5;
pi_mount_holes = [
    [pi_hole_x1, pi_hole_y1],
    [pi_hole_x2, pi_hole_y1],
    [pi_hole_x1, pi_hole_y2],
    [pi_hole_x2, pi_hole_y2]
];
pi_pcb_x_min = pi_hole_x1 - 3.5;  // -27.3 mm
pi_pcb_x_max = pi_hole_x2 + 23.5; // +57.7 mm (total 85.0 mm)
pi_pcb_y_min = -28.0;             // 56.0 mm height
pi_pcb_y_max =  28.0;

// ----------------------------------------------------------------------------
// 2. Z-STACKUP (Z=0 is outer front face, Z=total_depth is outer back face)
// ----------------------------------------------------------------------------
front_wall        = 2.2;    // Protective front bezel thickness around glass
lcd_back_z        = front_wall + lcd_pocket_depth; // 11.7 mm (LCD rear PCB)
pisugar_gap       = 2.3;    // Clearance/foam pad behind LCD PCB
pisugar_z0        = lcd_back_z + pisugar_gap;      // 14.0 mm
pisugar_thickness = 15.5;   // PiSugar 3 Plus (5000 mAh LiPo + PCB + pogo pins)
pi_pcb_z0         = pisugar_z0 + pisugar_thickness;// 29.5 mm (Pi 4 bottom)
pi_pcb_t          = 1.6;
pi_pcb_top_z      = pi_pcb_z0 + pi_pcb_t;          // 31.1 mm (Pi 4 top)
poe_hat_clear_h   = 25.0;   // PoE HAT (C) standoffs + PCB + transformer + fan
fan_headroom      = 3.4;    // Airflow clearance above PoE HAT fan
back_wall         = 3.8;    // Rear wall (houses flush U-channel kickstand + hinge pin cleanly)

total_depth       = pi_pcb_top_z + poe_hat_clear_h + fan_headroom + back_wall; // 63.3 mm
split_z           = 14.2;   // Front/Back shell parting plane
lip_h             = 2.5;    // Interlocking tongue-and-groove overlap height
lip_clear         = 0.25;   // FDM fit tolerance on interlocking lip

// ----------------------------------------------------------------------------
// 3. OUTER ENCLOSURE DIMENSIONS (Extended Left-Grip Handheld)
// ----------------------------------------------------------------------------
wall_t            = 3.2;    // Rugged outer side wall thickness
right_edge_x      = 65.0;   // Clears LCD (+61.1) & Pi RJ45/USB (+59.7) + wall
left_grip_w       = 44.0;   // Internal grip bay width
left_edge_x       = -lcd_pocket_w/2 - left_grip_w - wall_t; // -108.3 mm
case_x_min        = left_edge_x;
case_x_max        = right_edge_x;
case_w            = case_x_max - case_x_min; // 173.3 mm
case_cx           = (case_x_min + case_x_max) / 2;

case_h            = 96.0;   // -48.0 .. +48.0 mm (clears 78 mm LCD + perimeter M3 bosses!)
case_y_min        = -case_h / 2;
case_y_max        =  case_h / 2;
corner_r          = 7.5;    // Comfortable handheld corner radius
outer_chamfer     = 2.5;    // 45-deg industrial front & rear chamfer

// ----------------------------------------------------------------------------
// 4. FASTENERS & HARDWARE OPTIONS
// ----------------------------------------------------------------------------
use_heatset_inserts = false; // false = direct M3 self-tap (2.7 mm), true = M3x5x4 brass inserts (4.5 mm)
m3_insert_d         = use_heatset_inserts ? 4.5 : 2.7;
m3_clear_d          = 3.4;
m3_head_d           = 6.2;
m3_head_depth       = 3.4;
m25_insert_d        = 3.8;  // M2.5 heat-set insert or 2.3 mm self-tap
m25_self_tap_d      = 2.35;

// NOTE ON VIEWING ORIENTATION (Right-Hand Rule):
//   Holding JackTrace looking at the FRONT SCREEN (-Z facing viewer) with the
//   Extended Grip on the LEFT (-X) and Ethernet/USB on the RIGHT (+X):
//     -Y = TOP edge    (Lanyard corner, Guarded Power Button, Status LED, Top Vents, Kickstand Hinge)
//     +Y = BOTTOM edge (Recessed USB-C Charging Port, Kickstand Foot)

// 6 perimeter case-closure screw locations (100% clear of 122.2 x 78.0 LCD pocket!)
case_screws = [
    [case_x_min + 7.5,  case_y_min + 15.0], // Top-left grip (clears lanyard corner on -Y)
    [case_x_min + 7.5,  case_y_max - 7.5],  // Bottom-left grip
    [-58.5,             case_y_min + 4.4],  // Top-center divider    (Y=-43.6, clears -39.0 LCD)
    [-58.5,             case_y_max - 4.4],  // Bottom-center divider (Y=+43.6, clears +39.0 LCD)
    [case_x_max - 6.5,  case_y_min + 4.4],  // Top-right             (Y=-43.6, clears -39.0 LCD)
    [case_x_max - 6.5,  case_y_max - 4.4]   // Bottom-right          (Y=+43.6, clears +39.0 LCD)
];

// ----------------------------------------------------------------------------
// 5. PORT & CONTROL CUTOUT PARAMETERS
// ----------------------------------------------------------------------------
// Right (+X) wall: Pi 4 RJ45 Ethernet + USB 3.0 + USB 2.0
// Port Z starts at pi_pcb_top_z (31.1 mm)
rj45_y_center =  17.75;  rj45_w = 18.6;  rj45_h = 15.6;
usb3_y_center =  -1.0;   usb3_w = 16.4;  usb3_h = 17.6;
usb2_y_center = -19.0;   usb2_w = 16.4;  usb2_h = 17.6;

// Bottom-left (+Y) wall: Recessed USB-C charging port (exits neatly downward!)
usbc_x        = -84.0;
usbc_z        =  28.0;
usbc_w        =  10.2;   // USB-C oval opening
usbc_h        =   4.4;
usbc_recess_w =  15.5;   // Plug overmold clearance recess
usbc_recess_h =   9.5;
usbc_recess_d =   2.0;

// Top-left (-Y) wall: Guarded 12 mm panel-mount power button
pwr_btn_x     = -84.0;
pwr_btn_z     =  32.0;
pwr_btn_d     =  12.2;   // Fits standard 12 mm threaded momentary push button
pwr_guard_d   =  19.0;   // Recessed finger guard prevents accidental bag press

// Front-left status LED hole (top-left above grip grooves, like concept renders)
led_x         = -84.0;
led_y         = -28.0;
led_d         =   5.2;   // Fits 5 mm LED bezel / light pipe (change to 3.2 for 3 mm)

// Lanyard loop on top-left corner (-X, -Y)
lanyard_slot_l = 12.0;
lanyard_slot_w =  4.5;

// Flush U-Frame Rear Kickstand (hinge near TOP -Y, opens downward toward BOTTOM +Y!)
// Sized cleanly around the 4 rear M2.5 Pi/PoE through-screws at (-23.8/+34.2, +-24.5)
ks_w           = 84.0;   // Outer width of U-frame (inner span ~68 mm)
ks_h           = 68.0;   // Length from hinge (-31) to foot (+37)
ks_arm_w       =  7.5;   // Arm width (8.4 mm pocket bridges cleanly support-free!)
ks_t           =  2.6;   // Kickstand thickness (sits flush inside 2.85 mm pocket)
ks_clear       =  0.45;  // Side/end fit clearance
ks_cx          =  5.5;   // Centered over Pi/PoE mounting zone
ks_hinge_y     = -31.0;  // Hinge axis near TOP-back (-Y) for stable ~55 deg upright lean
ks_pin_d       =  2.0;   // 1.75 mm filament pin OR M2 screw hinge (cleanly enclosed!)

// Dedicated M2.5 LCD-Clamp boss locations (100% OUTSIDE the 122.2 x 78.0 glass pocket!)
lcd_clamp_bosses = [
    [-38.0, -42.2],
    [ 38.0, -42.2],
    [-38.0,  42.2],
    [ 38.0,  42.2]
];

// Engraved Logo settings (0.6 mm = 3 layers @ 0.2 mm, crisp & bridge-free!)
logo_depth     = 0.6;

// ============================================================================
// UTILITY MODULES
// ============================================================================

module rrect_2d(w, h, r) {
    offset(r = r) offset(r = -r)
        square([w, h], center = true);
}

// Stadium / slot shape in 2D (supports both horizontal w>=h and vertical h>w!)
module stadium_2d(w, h) {
    r = min(w, h) / 2;
    hull() {
        if (w >= h) {
            translate([-(w/2 - r), 0]) circle(r = r);
            translate([ (w/2 - r), 0]) circle(r = r);
        } else {
            translate([0, -(h/2 - r)]) circle(r = r);
            translate([0,  (h/2 - r)]) circle(r = r);
        }
    }
}

// Chamfered outer shell prism from z0 to z1 with optional bottom/top 45-deg chamfers
module chamfered_box(x0, x1, y0, y1, z0, z1, r, ch_bot = 0, ch_top = 0) {
    w = x1 - x0;
    h = y1 - y0;
    cx = (x0 + x1) / 2;
    cy = (y0 + y1) / 2;
    translate([cx, cy, 0]) {
        hull() {
            if (ch_bot > 0) {
                translate([0, 0, z0])
                    linear_extrude(0.01) rrect_2d(w - 2*ch_bot, h - 2*ch_bot, max(1, r - ch_bot));
                translate([0, 0, z0 + ch_bot])
                    linear_extrude(0.01) rrect_2d(w, h, r);
            } else {
                translate([0, 0, z0])
                    linear_extrude(0.01) rrect_2d(w, h, r);
            }
            if (ch_top > 0) {
                translate([0, 0, z1 - ch_top])
                    linear_extrude(0.01) rrect_2d(w, h, r);
                translate([0, 0, z1 - 0.01])
                    linear_extrude(0.01) rrect_2d(w - 2*ch_top, h - 2*ch_top, max(1, r - ch_top));
            } else {
                translate([0, 0, z1 - 0.01])
                    linear_extrude(0.01) rrect_2d(w, h, r);
            }
        }
    }
}

// 2D line segment helper for crisp FDM-friendly vector icons (min stroke >= 1.2 mm)
module stroke_seg(p1, p2, w = 1.3) {
    hull() {
        translate(p1) circle(d = w, $fn = 16);
        translate(p2) circle(d = w, $fn = 16);
    }
}

// JackTrace "Pinout-Pulse" RJ45 Icon in 2D (centered at [0,0], ~24 x 22 mm, +Y up)
// Uses clean non-tangent polygons (zero pinch vertices) so CGAL extrusions are 100% manifold!
module jacktrace_icon_2d(s = 1.0) {
    scale([s, s]) {
        // 1. Outer rounded square bezel (22 x 20 mm, 1.4 mm stroke)
        difference() {
            rrect_2d(22.0, 20.0, 2.5);
            rrect_2d(19.2, 17.2, 1.4);
            // Break left & right edges cleanly for the horizontal TDR pulse line
            square([25.0, 4.0], center = true);
        }
        // 2. Inner RJ45 stepped jack cavity outline (single clean stepped polygon + offset!)
        difference() {
            polygon([
                [-7.6, -7.7], [ 7.6, -7.7],
                [ 7.6,  3.7], [ 4.6,  3.7],
                [ 4.6,  5.8], [ 2.6,  5.8],
                [ 2.6,  7.6], [-2.6,  7.6],
                [-2.6,  5.8], [-4.6,  5.8],
                [-4.6,  3.7], [-7.6,  3.7]
            ]);
            offset(delta = -1.3)
                polygon([
                    [-7.6, -7.7], [ 7.6, -7.7],
                    [ 7.6,  3.7], [ 4.6,  3.7],
                    [ 4.6,  5.8], [ 2.6,  5.8],
                    [ 2.6,  7.6], [-2.6,  7.6],
                    [-2.6,  5.8], [-4.6,  5.8],
                    [-4.6,  3.7], [-7.6,  3.7]
                ]);
            // Clear middle band for pulse waveform
            square([18.0, 4.0], center = true);
        }
        // 3. 6 bold RJ45 bottom contact pins (cleanly overlaps bottom bar by 0.5 mm)
        for (i = [-2.5 : 1 : 2.5]) {
            translate([i * 1.9, -5.4])
                square([0.95, 3.6], center = true);
        }
        // 4. Signature horizontal TDR pulse waveform + terminal node dot
        pts = [
            [-13.0,  0.0],
            [ -4.5,  0.0],
            [ -3.0,  2.2],
            [ -1.5, -2.6],
            [  0.2,  4.2],
            [  1.9, -2.8],
            [  3.4,  1.6],
            [  4.8,  0.0],
            [ 12.6,  0.0]
        ];
        for (k = [0 : len(pts) - 2]) {
            stroke_seg(pts[k], pts[k+1], w = 1.35);
        }
        // Terminal pulse dot on right
        translate([13.2, 0.0]) circle(d = 3.0, $fn = 24);
    }
}

// JackTrace wordmark in 2D (bold geometric sans-serif, centered at [0,0], +Y up)
module jacktrace_wordmark_2d(sz = 4.6) {
    text("JACKTRACE", size = sz, font = "Arial:style=Bold",
         halign = "center", valign = "center", spacing = 1.06);
}

// Lanyard ear integrated cleanly on TOP-LEFT corner (-X, -Y)
module lanyard_lug_solid(z0, z1, ch_bot = 0, ch_top = 0) {
    lx = case_x_min + 6.5;
    ly = case_y_min + 5.5;
    hull() {
        translate([lx - 4.5, ly - 4.5, z0 + ch_bot])
            cylinder(r = 7.5, h = (z1 - z0) - ch_bot - ch_top);
        translate([lx + 4.0, ly + 2.0, z0 + ch_bot])
            cylinder(r = 7.5, h = (z1 - z0) - ch_bot - ch_top);
        if (ch_bot > 0) {
            translate([lx - 4.5, ly - 4.5, z0])
                cylinder(r = 7.5 - ch_bot, h = 0.01);
            translate([lx + 4.0, ly + 2.0, z0])
                cylinder(r = 7.5 - ch_bot, h = 0.01);
        }
        if (ch_top > 0) {
            translate([lx - 4.5, ly - 4.5, z1 - 0.01])
                cylinder(r = 7.5 - ch_top, h = 0.01);
            translate([lx + 4.0, ly + 2.0, z1 - 0.01])
                cylinder(r = 7.5 - ch_top, h = 0.01);
        }
    }
}

module lanyard_slot_cut(z0, z1) {
    lx = case_x_min + 2.5;
    ly = case_y_min + 1.5;
    translate([lx, ly, z0 - 1])
        rotate([0, 0, -45])
            linear_extrude(z1 - z0 + 2)
                stadium_2d(lanyard_slot_l, lanyard_slot_w);
}

// ============================================================================
// PART 1: FRONT BEZEL SHELL (Prints face-down on Z=0, ZERO supports!)
// ============================================================================
module front_shell() {
    difference() {
        union() {
            // Main outer front shell body
            chamfered_box(case_x_min, case_x_max, case_y_min, case_y_max,
                          0, split_z, corner_r, ch_bot = outer_chamfer, ch_top = 0);

            // Lanyard corner reinforcement (front half)
            lanyard_lug_solid(0, split_z, ch_bot = outer_chamfer, ch_top = 0);

            // Interlocking inner alignment lip (protrudes +lip_h into back shell)
            translate([case_cx, 0, split_z - 0.1])
                linear_extrude(lip_h + 0.1)
                    difference() {
                        rrect_2d(case_w - 2*(wall_t/2 + lip_clear),
                                 case_h - 2*(wall_t/2 + lip_clear),
                                 corner_r - wall_t/2);
                        rrect_2d(case_w - 2*wall_t,
                                 case_h - 2*wall_t,
                                 corner_r - wall_t);
                    }
        }

        // --- Interior Cavity (Right LCD bay + Left Grip bay) ---
        // 1. LCD Glass & Display Pocket (exact verified 122.2 x 78.0 mm)
        translate([0, 0, front_wall])
            linear_extrude(split_z + lip_h + 2)
                square([lcd_pocket_w, lcd_pocket_h], center = true);

        // 2. Left Grip Cavity (leaves clean divider wall at X = -lcd_pocket_w/2)
        grip_x0 = case_x_min + wall_t;
        grip_x1 = -lcd_pocket_w/2 - 2.6;
        translate([(grip_x0 + grip_x1)/2, 0, front_wall + 1.2])
            linear_extrude(split_z + lip_h + 2)
                rrect_2d(grip_x1 - grip_x0, case_h - 2*wall_t, corner_r - wall_t);

        // Wire pass-through notch in divider rib (front half)
        translate([-lcd_pocket_w/2 - 1.3, 0, split_z - 5.0])
            cube([6.0, 26.0, 12.0], center = true);

        // 3. Chamfered Touchscreen Viewing Window (45 deg angled lip for easy edge taps!)
        translate([win_offset_x, win_offset_y, -0.1])
            hull() {
                linear_extrude(0.1)
                    rrect_2d(win_w + 2.4, win_h + 2.4, 2.5);
                translate([0, 0, front_wall + 0.2])
                    linear_extrude(0.1)
                        rrect_2d(win_w, win_h, 1.5);
            }

        // 4. Decorative + Ergonomic Left-Grip Grooves (below top-left LED, -Y = TOP!)
        for (i = [0 : 4]) {
            gy = -15.5 + i * 8.0;
            gw = (i == 0) ? 20.0 : 25.0;
            translate([led_x, gy, -0.05])
                hull() {
                    linear_extrude(0.05) stadium_2d(gw, 3.2);
                    translate([0, 0, 1.1])
                        linear_extrude(0.05) stadium_2d(gw - 1.6, 1.6);
                }
        }

        // 5. Engraved "JACKTRACE" wordmark on front left grip (bottom-left, reads upright!)
        //    Looking from -Z toward +Z with -Y=UP: +X is RIGHT, -Y is UP -> mirror([0,1,0]) maps 2D +Y to -Y!
        translate([led_x, 29.0, -0.05])
            linear_extrude(logo_depth + 0.05)
                mirror([0, 1, 0])
                    jacktrace_wordmark_2d(sz = 3.8);

        // 6. Front Status LED Hole + Subtle Chamfer (top-left above grooves)
        translate([led_x, led_y, -0.1]) {
            cylinder(d = led_d, h = front_wall + 3.0);
            cylinder(d1 = led_d + 1.8, d2 = led_d, h = 0.9);
        }

        // 7. Lanyard Slot Cutout
        lanyard_slot_cut(0, split_z + lip_h);

        // 8. 4× Recessed Rim Pockets + M2.5 Pilot Holes for LCD Retaining Clamp Ears
        //    Cuts down from split_z to lcd_back_z (11.7 mm) in the solid rim outside the glass
        //    so the two clamp bars drop in flush and bolt the LCD solidly to front_shell!
        for (pt = lcd_clamp_bosses) {
            side_sign = (pt[1] > 0) ? 1 : -1;
            // Open pocket from the LCD pocket edge out to inner wall (preserves outer wall & lip!)
            translate([pt[0] - 4.5, (side_sign > 0 ? 38.5 : -44.8), lcd_back_z])
                cube([9.0, 6.3, split_z + lip_h - lcd_back_z + 2.0]);
            // Self-tapping M2.5 pilot hole down into the rim
            translate([pt[0], pt[1], front_wall + 1.8])
                cylinder(d = m25_self_tap_d, h = lcd_back_z - front_wall + 1.0);
        }
    }

    // --- Internal Structural Bosses Added Back Inside Front Shell ---
    // NOTE: The 122.2 x 78.0 mm LCD glass pocket is kept 100% OPEN & UNOBSTRUCTED so the
    // Waveshare 5" DSI LCD drops face-down cleanly onto the 2.2 mm front bezel ledge!
    // (The 4 LCD clamp M2.5 pilot holes are machined directly into the top/bottom rims above.)

    // 1. 6× Perimeter Case Closure Screw Bosses (M3 self-tap or heat-set inserts)
    for (pt = case_screws) {
        difference() {
            translate([pt[0], pt[1], front_wall])
                cylinder(d = 7.4, h = split_z - front_wall);
            translate([pt[0], pt[1], split_z - 7.0])
                cylinder(d = m3_insert_d, h = 8.0);
        }
    }

    // 3. Universal Grip Telemetry / Ideal Diode Mounting Bosses on front grip floor
    //    6× M2.5 standoffs (4.5 mm tall), cleanly clear of LED hole and corner M3 bosses
    grip_standoffs = [
        [-94.0, -20.0], [-72.0, -20.0],
        [-94.0,   2.0], [-72.0,   2.0],
        [-94.0,  22.0], [-72.0,  22.0]
    ];
    for (pt = grip_standoffs) {
        difference() {
            translate([pt[0], pt[1], front_wall + 1.0])
                cylinder(d = 5.4, h = 4.5);
            translate([pt[0], pt[1], front_wall + 1.8])
                cylinder(d = m25_self_tap_d, h = 5.0);
        }
    }
}

// ============================================================================
// PART 2: BACK SHELL (Prints back-face-down on Z=0, ZERO supports!)
// ============================================================================
module back_shell() {
    difference() {
        union() {
            // Main outer back shell body
            chamfered_box(case_x_min, case_x_max, case_y_min, case_y_max,
                          split_z, total_depth, corner_r, ch_bot = 0, ch_top = outer_chamfer);

            // Lanyard corner reinforcement (back half)
            lanyard_lug_solid(split_z, total_depth, ch_bot = 0, ch_top = outer_chamfer);
        }

        // --- Interior Main Cavity ---
        // 1. Step pocket for interlocking front lip
        translate([case_cx, 0, split_z - 0.1])
            linear_extrude(lip_h + 0.3)
                rrect_2d(case_w - 2*(wall_t/2),
                         case_h - 2*(wall_t/2),
                         corner_r - wall_t/2);

        // 2. Main Hollow Interior (Pi + PoE HAT bay + Left Grip bay)
        translate([case_cx, 0, split_z + lip_h])
            linear_extrude(total_depth - back_wall - split_z - lip_h)
                rrect_2d(case_w - 2*wall_t,
                         case_h - 2*wall_t,
                         corner_r - wall_t);

        // --- Right Wall (+X): Pi 4 Ethernet RJ45 + USB 3.0 + USB 2.0 Cutouts ---
        // External beveled funnel makes bulky Cat6a snagless boots easy to latch
        for (port = [
            [rj45_y_center, rj45_w, rj45_h],
            [usb3_y_center, usb3_w, usb3_h],
            [usb2_y_center, usb2_w, usb2_h]
        ]) {
            py = port[0]; pw = port[1]; ph = port[2];
            pz = pi_pcb_top_z + ph/2 - 0.4;
            // Straight through cut
            translate([case_x_max - wall_t - 1.5, py - pw/2, pi_pcb_top_z - 0.4])
                cube([wall_t + 3.0, pw, ph]);
            // Subtle outer 1.0 mm entry chamfer
            translate([case_x_max - 1.0, py, pz])
                rotate([0, 90, 0])
                    linear_extrude(1.2, scale = 1.08)
                        square([ph, pw], center = true);
        }

        // --- Bottom-Left Wall (+Y): Recessed USB-C Charging Port ---
        // Through slot for USB-C tongue
        translate([usbc_x, case_y_max - wall_t - 2.0, usbc_z])
            rotate([-90, 0, 0])
                linear_extrude(wall_t + 3.0)
                    stadium_2d(usbc_w, usbc_h);
        // Outer recess for chunky USB-C cable overmolds
        translate([usbc_x, case_y_max - usbc_recess_d, usbc_z])
            rotate([-90, 0, 0])
                linear_extrude(usbc_recess_d + 0.2)
                    stadium_2d(usbc_recess_w, usbc_recess_h);

        // --- Top-Left Wall (-Y): Guarded 12 mm Power Button ---
        // Through-hole for 12 mm threaded switch barrel
        translate([pwr_btn_x, case_y_min - 1.0, pwr_btn_z])
            rotate([-90, 0, 0])
                cylinder(d = pwr_btn_d, h = wall_t + 4.0);
        // 1.5 mm protective chamfered recess prevents accidental bag press
        translate([pwr_btn_x, case_y_min - 0.1, pwr_btn_z])
            rotate([-90, 0, 0])
                cylinder(d1 = pwr_guard_d, d2 = pwr_guard_d - 2.0, h = 1.7);

        // --- Cooling Louver Vents (PoE HAT Fan + Top Convection) ---
        // Rear louver slots centered over PoE HAT / Pi 4 (sits cleanly INSIDE the U-kickstand!)
        for (i = [-4 : 4]) {
            vx = 4.0 + i * 6.2;
            translate([vx, 1.0, total_depth - back_wall - 1.0])
                linear_extrude(back_wall + 2.0)
                    stadium_2d(2.8, 30.0);
        }
        // Top (-Y) edge passive exhaust slots over Pi/PoE zone
        for (i = [-4 : 4]) {
            vx = 8.0 + i * 6.5;
            translate([vx, case_y_min - 1.0, total_depth - 12.0])
                rotate([-90, 0, 0])
                    linear_extrude(wall_t + 2.0)
                        stadium_2d(3.0, 8.0);
        }

        // --- Engraved Hero JACKTRACE Pinout-Pulse Emblem + Wordmark on Rear Grip Panel ---
        // Looking at +Z back face with -Y=UP: -X is RIGHT, +X is LEFT -> rotate 180 deg in XY
        // maps 2D (+X right, +Y up) cleanly to (-X right, -Y up) so it reads 100% upright!
        translate([-82.0, 0.0, total_depth - logo_depth]) {
            linear_extrude(logo_depth + 0.2)
                rotate([0, 0, 180]) {
                    translate([0,  6.5]) jacktrace_icon_2d(s = 1.05);
                    translate([0, -11.5]) jacktrace_wordmark_2d(sz = 4.5);
                }
        }

        // --- Flush U-Frame Kickstand Pocket (hinge near TOP -Y, opens downward toward +Y!) ---
        ks_pocket_d = ks_t + 0.25;
        ks_arm_cut  = ks_arm_w + 2*ks_clear;
        translate([ks_cx, ks_hinge_y, total_depth - ks_pocket_d]) {
            // Left vertical arm channel (extends +Y downward from hinge)
            translate([-ks_w/2 - ks_clear, -3.2 - ks_clear, 0])
                cube([ks_arm_cut, ks_h + 2*ks_clear + 3.2, ks_pocket_d + 1.0]);
            // Right vertical arm channel
            translate([ks_w/2 - ks_arm_w - ks_clear, -3.2 - ks_clear, 0])
                cube([ks_arm_cut, ks_h + 2*ks_clear + 3.2, ks_pocket_d + 1.0]);
            // Bottom crossbar channel (at +ks_h)
            translate([-ks_w/2 - ks_clear, ks_h - ks_arm_w - ks_clear, 0])
                cube([ks_w + 2*ks_clear, ks_arm_cut, ks_pocket_d + 1.0]);
            // Fingernail pull notch at bottom center (+Y)
            translate([0, ks_h + ks_clear + 1.5, 0])
                cylinder(d = 12.0, h = ks_pocket_d + 1.0);
            // Deeper recessed hinge knuckle pockets (only at top -Y ends of the two arms!)
            for (hx = [-ks_w/2 + ks_arm_w/2, ks_w/2 - ks_arm_w/2]) {
                translate([hx - ks_arm_cut/2, -4.0, -1.2])
                    cube([ks_arm_cut, 5.0, ks_pocket_d + 2.2], center = false);
            }
        }

        // Two short enclosed hinge-pin bores (1.75 mm filament or M2x12 screw)
        for (hx = [ks_cx - ks_w/2 - 4.5, ks_cx + ks_w/2 - ks_arm_w - 4.5]) {
            translate([hx, ks_hinge_y - 1.4, total_depth - (ks_t/2 + 0.45)])
                rotate([0, 90, 0])
                    cylinder(d = ks_pin_d + 0.25, h = ks_arm_w + 9.0);
        }

        // --- 6× Countersunk M3 Case Closure Screw Holes (45-deg self-supporting transition!) ---
        for (pt = case_screws) {
            // Clear shaft through back shell
            translate([pt[0], pt[1], split_z - 1.0])
                cylinder(d = m3_clear_d, h = total_depth - split_z + 2.0);
            // Countersink from rear face for M3 SHCS head + 45-deg conical ceiling (zero overhang!)
            translate([pt[0], pt[1], total_depth - m3_head_depth])
                cylinder(d = m3_head_d, h = m3_head_depth + 1.0);
            translate([pt[0], pt[1], total_depth - m3_head_depth - (m3_head_d - m3_clear_d)/2])
                cylinder(d1 = m3_clear_d, d2 = m3_head_d, h = (m3_head_d - m3_clear_d)/2 + 0.05);
        }

        // --- 4× Countersunk M2.5 Rear Through-Holes for Pi 4 / PoE HAT Stack ---
        // Lets you bolt the Pi 4 + PiSugar + PoE HAT assembly cleanly from the OUTSIDE of the back shell!
        for (pt = pi_mount_holes) {
            translate([pt[0], pt[1], total_depth - back_wall - 1.0])
                cylinder(d = 2.8, h = back_wall + 2.0);
            translate([pt[0], pt[1], total_depth - 2.6])
                cylinder(d = 5.2, h = 3.0);
            translate([pt[0], pt[1], total_depth - 2.6 - 1.2])
                cylinder(d1 = 2.8, d2 = 5.2, h = 1.25);
        }

        // --- Lanyard Slot Cutout ---
        lanyard_slot_cut(split_z, total_depth);
    }

    // --- Internal Structural Features Inside Back Shell ---
    // 1. 6× Full-height M3 Screw Tubes (guides long M3 screws cleanly to front shell bosses)
    for (pt = case_screws) {
        difference() {
            translate([pt[0], pt[1], split_z + lip_h])
                cylinder(d = 7.4, h = total_depth - back_wall - split_z - lip_h + 0.2);
            translate([pt[0], pt[1], split_z - 1.0])
                cylinder(d = m3_clear_d, h = total_depth - split_z + 2.0);
        }
    }

    // 2. 4× Raspberry Pi 4 / PoE HAT Top Mounting Tubes (Through-bolted from rear with M2.5x25!)
    //    Descend from rear inner wall down to top of PoE HAT (C) standoffs (Z = pi_pcb_top_z + 13.6)
    poe_top_mount_z = pi_pcb_top_z + 13.6; // ~44.7 mm
    for (pt = pi_mount_holes) {
        difference() {
            translate([pt[0], pt[1], poe_top_mount_z])
                cylinder(d = 6.4, h = (total_depth - back_wall) - poe_top_mount_z + 0.2);
            translate([pt[0], pt[1], poe_top_mount_z - 1.0])
                cylinder(d = 2.8, h = (total_depth - poe_top_mount_z) + 2.0);
        }
    }

    // 3. Internal Thermal & Wiring Divider Wall between Pi/PoE bay and Left Grip bay
    difference() {
        translate([-lcd_pocket_w/2 - 1.3, 0, (split_z + lip_h + total_depth - back_wall)/2])
            cube([2.4, case_h - 2*wall_t - 1.0, total_depth - back_wall - split_z - lip_h], center = true);
        // Generous upper/lower cable routing pass-throughs (5V PoE, I2C, DSI ribbon)
        translate([-lcd_pocket_w/2 - 1.3,  0.0, split_z + lip_h + 10.0])
            cube([6.0, 32.0, 22.0], center = true);
    }

    // 4. Self-Supporting 45-deg Gusseted USB-C Breakout Cradle (bottom-left +Y grip wall)
    //    PCB mounts flat at Z_asm = usbc_z + 2.5 (receptacle centered at Z_asm = usbc_z = 28.0 mm).
    //    45-deg gusset tapers from Z_asm = 33.5 toward the rear inner wall (Z_asm = 48.5), so when
    //    flipped for printing (back-face-down) it prints 100% support-free with zero overhang!
    difference() {
        hull() {
            // Flat PCB mounting platform (Z_asm = 30.5 .. 33.5 mm)
            translate([usbc_x, case_y_max - wall_t - 7.5, usbc_z + 4.0])
                cube([19.0, 15.0, 3.0], center = true);
            // 45-deg self-supporting taper anchor along the inner +Y wall toward the back floor
            translate([usbc_x, case_y_max - wall_t - 0.5, usbc_z + 20.5])
                cube([19.0, 1.0, 1.0], center = true);
        }
        // M2 mounting holes (12 mm pitch common on Adafruit/generic USB-C breakouts)
        for (dx = [-6.0, 6.0]) {
            translate([usbc_x + dx, case_y_max - wall_t - 8.0, usbc_z + 1.5])
                cylinder(d = 2.0, h = 10.0);
        }
    }

    // 5. Internal Grip Module Shelf / Standoffs on Rear Inner Wall
    //    Additional mounting points on the rear inner wall of the left grip for
    //    Dual Ideal Diode OR-ing boards or future Tier 2 ISO1540 + INA228 stack
    for (pt = [[-96.0, -18.0], [-76.0, -18.0], [-96.0, 12.0], [-76.0, 12.0]]) {
        difference() {
            translate([pt[0], pt[1], total_depth - back_wall - 5.0])
                cylinder(d = 5.6, h = 5.2);
            translate([pt[0], pt[1], total_depth - back_wall - 5.5])
                cylinder(d = m25_self_tap_d, h = 4.5);
        }
    }
}

// ============================================================================
// PART 3: FLUSH U-FRAME KICKSTAND (Prints flat on Z=0, ZERO supports!)
// ============================================================================
module kickstand() {
    knuckle_d = 4.2; // Thick 1.1 mm wall around 2.0 mm pin bore -> rock-solid single manifold!
    difference() {
        union() {
            // Left arm
            translate([-ks_w/2, -ks_h, 0])
                cube([ks_arm_w, ks_h + 2.4, ks_t]);
            // Right arm
            translate([ks_w/2 - ks_arm_w, -ks_h, 0])
                cube([ks_arm_w, ks_h + 2.4, ks_t]);
            // Bottom foot bar
            translate([-ks_w/2, -ks_h, 0])
                cube([ks_w, ks_arm_w, ks_t]);
            // Reinforced hinge knuckles (flat bottom on Z=0 so it prints cleanly support-free!)
            for (hx = [-ks_w/2 + ks_arm_w/2, ks_w/2 - ks_arm_w/2]) {
                intersection() {
                    translate([hx, 1.4, ks_t/2 + 0.45])
                        rotate([0, 90, 0])
                            cylinder(d = knuckle_d, h = ks_arm_w, center = true);
                    translate([hx, 1.4, 5.0])
                        cube([ks_arm_w + 1.0, 10.0, 10.0], center = true);
                }
            }
        }
        // Enclosed 2.0 mm hinge pin bores (fits 1.75 mm filament pin or M2 bolt)
        for (hx = [-ks_w/2 + ks_arm_w/2, ks_w/2 - ks_arm_w/2]) {
            translate([hx, 1.4, ks_t/2 + 0.45])
                rotate([0, 90, 0])
                    cylinder(d = ks_pin_d, h = ks_arm_w + 2.0, center = true);
        }
    }
}

// ============================================================================
// PART 4: 2× LCD RETAINING CLAMP BARS (Prints flat on Z=0, ZERO supports!)
// ============================================================================
// Bridges from the 2 exterior front-shell M2.5 bosses (+-38.0, 42.2) across to
// the Waveshare 5" DSI LCD's own rear M2.5 threaded holes (+-56.5, 34.0).
// Locks the display solidly to front_shell without blocking the drop-in glass!
module lcd_clamp_bar_single(side = 1) {
    // side = +1 for bottom (+Y), -1 for top (-Y)
    clamp_t = 2.3;
    y_lcd   = side * 34.0;
    y_case  = side * 42.2;
    difference() {
        linear_extrude(clamp_t) {
            union() {
                // Main horizontal bridge connecting both LCD corner holes
                hull() {
                    translate([-56.5, y_lcd]) circle(d = 6.6);
                    translate([ 56.5, y_lcd]) circle(d = 6.6);
                }
                // Left ear connecting to front-shell boss (-38.0, y_case)
                hull() {
                    translate([-38.0, y_lcd])  circle(d = 6.2);
                    translate([-38.0, y_case]) circle(d = 6.0);
                }
                // Right ear connecting to front-shell boss (+38.0, y_case)
                hull() {
                    translate([ 38.0, y_lcd])  circle(d = 6.2);
                    translate([ 38.0, y_case]) circle(d = 6.0);
                }
            }
        }
        // 2× M2.5 clearance holes for Waveshare LCD rear threaded bosses
        for (x = [-56.5, 56.5]) {
            translate([x, y_lcd, -0.5]) cylinder(d = 2.8, h = clamp_t + 1.0);
        }
        // 2× M2.5 clearance holes for front-shell rim bosses
        for (x = [-38.0, 38.0]) {
            translate([x, y_case, -0.5]) cylinder(d = 2.8, h = clamp_t + 1.0);
        }
    }
}

module lcd_clamps_print_pair() {
    // Two bars laid out cleanly side-by-side on Z=0 for a single 5-minute print
    translate([0, -25.0, 0]) lcd_clamp_bar_single(1);
    translate([0,  25.0, 0]) lcd_clamp_bar_single(-1);
}

// ============================================================================
// VISUALIZATION: INTERNAL HARDWARE GHOST MODELS (for clearance inspection)
// ============================================================================
module hardware_ghosts() {
    // 1. Waveshare 5" DSI LCD
    color([0.15, 0.15, 0.18, 0.7])
        translate([0, 0, front_wall + lcd_pocket_depth/2])
            cube([121.1, 77.9, lcd_pocket_depth], center = true);
    // Active screen area highlight
    color([0.05, 0.55, 0.75, 0.85])
        translate([win_offset_x, win_offset_y, front_wall - 0.1])
            cube([108.0, 64.8, 0.4], center = true);

    // 2. PiSugar 3 Plus (65 x 56 x 15 mm) under Pi 4
    color([0.95, 0.75, 0.15, 0.65])
        translate([pi_pcb_x_min + 32.5, 0, pisugar_z0 + pisugar_thickness/2])
            cube([65.0, 56.0, 15.0], center = true);

    // 3. Raspberry Pi 4B PCB (85 x 56 x 1.6 mm) + RJ45/USB jacks
    color([0.1, 0.55, 0.2, 0.75])
        translate([(pi_pcb_x_min + pi_pcb_x_max)/2, 0, pi_pcb_z0 + pi_pcb_t/2])
            cube([85.0, 56.0, pi_pcb_t], center = true);
    color([0.75, 0.75, 0.78, 0.85]) {
        // RJ45
        translate([pi_pcb_x_max - 9.0, rj45_y_center, pi_pcb_top_z + 6.8])
            cube([21.0, 16.0, 13.6], center = true);
        // USB 3.0 & 2.0
        translate([pi_pcb_x_max - 7.5, usb3_y_center, pi_pcb_top_z + 8.0])
            cube([17.5, 14.5, 16.0], center = true);
        translate([pi_pcb_x_max - 7.5, usb2_y_center, pi_pcb_top_z + 8.0])
            cube([17.5, 14.5, 16.0], center = true);
    }

    // 4. Waveshare PoE HAT (C): PCB (65 x 56.5 x 1.6 mm) + central fan/transformer (46 x 42 x 10 mm)
    color([0.1, 0.35, 0.8, 0.7])
        translate([pi_pcb_x_min + 32.5, 0, pi_pcb_top_z + 12.0 + 0.8])
            cube([65.0, 56.5, 1.6], center = true);
    color([0.18, 0.45, 0.9, 0.65])
        translate([pi_pcb_x_min + 32.5, 0, pi_pcb_top_z + 13.6 + 5.0])
            cube([46.0, 40.0, 10.0], center = true);

    // 5. Left Grip: Dual Ideal Diode Modules + Reserved PoE Sensing Bay
    color([0.85, 0.25, 0.25, 0.6]) {
        translate([-86.0, -24.0, 20.0]) cube([22.0, 16.0, 8.0], center = true);
        translate([-86.0,  -4.0, 20.0]) cube([22.0, 16.0, 8.0], center = true);
    }
    // Reserved PoE Voltage Sensor bay (INA228 + ISO1540 + B0503S)
    color([0.6, 0.2, 0.8, 0.5])
        translate([-86.0,  18.0, 42.0]) cube([30.0, 24.0, 14.0], center = true);
}

// ============================================================================
// PART SELECTOR (Print-oriented exports vs Assembly previews)
// ============================================================================
if (part == "front") {
    // Prints directly face-down on Z = 0, ZERO supports needed
    front_shell();
} else if (part == "back") {
    // Flipped so flat back outer face sits directly on Z = 0, ZERO supports needed
    rotate([180, 0, 0])
        translate([0, 0, -total_depth])
            back_shell();
} else if (part == "kickstand") {
    // Prints flat on Z = 0, ZERO supports needed
    kickstand();
} else if (part == "lcd_clamps") {
    // Prints both top & bottom LCD retaining clamp bars flat on Z = 0
    lcd_clamps_print_pair();
} else if (part == "assembly") {
    color([0.16, 0.17, 0.19]) front_shell();
    color([0.22, 0.24, 0.27]) back_shell();
    color([0.08, 0.55, 0.85])
        translate([ks_cx, ks_hinge_y, total_depth])
            rotate([180, 0, 0])
                kickstand();
} else if (part == "exploded") {
    color([0.16, 0.17, 0.19]) translate([0, 0, -25]) front_shell();
    color([0.08, 0.55, 0.85]) translate([0, 0, lcd_back_z + 3]) {
        lcd_clamp_bar_single(1);
        lcd_clamp_bar_single(-1);
    }
    hardware_ghosts();
    color([0.22, 0.24, 0.27, 0.45]) translate([0, 0, 28]) back_shell();
    color([0.08, 0.55, 0.85])
        translate([ks_cx, ks_hinge_y, total_depth + 42])
            rotate([180, 0, 0])
                kickstand();
} else if (part == "cutaway") {
    difference() {
        union() {
            color([0.16, 0.17, 0.19]) front_shell();
            color([0.22, 0.24, 0.27]) back_shell();
        }
        translate([-150, -100, -10]) cube([300, 100, 120], center = false);
    }
    hardware_ghosts();
}
