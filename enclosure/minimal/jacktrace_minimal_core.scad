// ============================================================================
// JackTrace Minimal — Shared Parametric OpenSCAD Core Library
// ============================================================================
// Clean-room, open-source single source of truth for all minimal JackTrace
// enclosures (Raspberry Pi 4 Model B + Waveshare 5" DSI Capacitive LCD,
// direct-mounted using the LCD's built-in brass standoffs and stock 50 mm
// DSI ribbon — zero soldering, zero HATs, zero extra standoffs).
//
// Coordinate System (Right-Hand Rule):
//   XY origin (0, 0) = center of Waveshare 5" DSI LCD glass.
//   Z = 0            = outer front bezel face; +Z goes toward the rear face.
//   Holding JackTrace upright looking at the FRONT SCREEN (-Z facing viewer):
//     +X = RIGHT  (Pi 4 RJ45 lower-right + USB 3.0 + USB 2.0)
//     -X = LEFT   (Wider LCD glass border, lanyard corner, power-bank USB-C side)
//     -Y = TOP    (Pi 4 native USB-C power port + ACT/PWR LEDs + exhaust vents)
//     +Y = BOTTOM (Front wordmark bezel + intake vents)
// ============================================================================

// ----------------------------------------------------------------------------
// 1. VERIFIED HARDWARE DIMENSIONS (mm)
// ----------------------------------------------------------------------------
// Waveshare 5" DSI Capacitive LCD (800x480)
JT_LCD_POCKET_W     = 122.2;   // 121.11 mm glass + ~0.55 mm clearance/side
JT_LCD_POCKET_H     =  78.0;   // 77.93 mm glass nominal
JT_LCD_DEPTH        =   9.5;   // Glass front to rear PCB/standoff mounting plane

// Active viewing window (Waveshare 5" DSI LCD active area = 108.0 x 64.8 mm).
// Physically calibrated from test-fit photos: active center sits at X = 0.0 mm,
// Y = -2.0 mm relative to the 121.1 x 77.9 mm glass outline. Adding a uniform
// +1.8 mm visible black glass border on all 4 sides (+ 1.0 mm front bevel)
// prevents any edge cutoff/parallax while keeping solid glass retention overlap.
JT_WIN_W            = 111.6;   // 108.0 + 2 * 1.8 mm uniform margin L/R
JT_WIN_H            =  68.4;   //  64.8 + 2 * 1.8 mm uniform margin T/B
JT_WIN_OFFSET_X     =   0.0;
JT_WIN_OFFSET_Y     =  -2.0;

// Waveshare 5" DSI 4 outer corner mounting pads (113.0 x 68.0 mm pitch)
JT_LCD_CORNER_HOLES = [
    [-56.5, -34.0],
    [ 56.5, -34.0],
    [-56.5,  34.0],
    [ 56.5,  34.0]
];

// Raspberry Pi 4 Model B (85.0 x 56.0 mm PCB, 58.0 x 49.0 mm mounting pattern)
// Mounted directly onto the Waveshare 5" DSI LCD's built-in brass standoffs,
// component-side facing +Z (toward the back cover).
JT_PI_HOLE_X1       = -23.2;
JT_PI_HOLE_X2       =  34.8;   // 58.0 mm pitch
JT_PI_HOLE_Y1       = -24.5;
JT_PI_HOLE_Y2       =  24.5;   // 49.0 mm pitch
JT_PI_MOUNT_HOLES   = [
    [JT_PI_HOLE_X1, JT_PI_HOLE_Y1],
    [JT_PI_HOLE_X2, JT_PI_HOLE_Y1],
    [JT_PI_HOLE_X1, JT_PI_HOLE_Y2],
    [JT_PI_HOLE_X2, JT_PI_HOLE_Y2]
];
JT_PI_PCB_X_MIN     = JT_PI_HOLE_X1 - 3.5;   // -26.7 mm (microSD edge)
JT_PI_PCB_X_MAX     = JT_PI_HOLE_X2 + 23.5;  // +58.3 mm (RJ45/USB edge, 85.0 mm total)
JT_PI_PCB_Y_MIN     = -28.0;                 // Top edge (USB-C / micro-HDMI / audio)
JT_PI_PCB_Y_MAX     =  28.0;                 // Bottom edge (40-pin GPIO)
JT_PI_PCB_T         =   1.6;

// Pi 4B right-edge (+X) port centerlines along Y (from -Y = -28.0 edge)
JT_USB2_Y           = -19.0;   // 9.0 mm from -Y edge (black USB 2.0)
JT_USB3_Y           =  -1.0;   // 27.0 mm from -Y edge (blue USB 3.0)
JT_RJ45_Y           =  17.75;  // 45.75 mm from -Y edge (Gigabit Ethernet)

// Pi 4B top-edge (-Y) port centerlines along X (from -X = -26.7 edge)
JT_USBC_X           = JT_PI_PCB_X_MIN + 11.2; // -15.5 mm (USB-C Power)
JT_LED_X            = JT_PI_PCB_X_MIN +  4.2; // -22.5 mm (PWR/ACT LEDs)
JT_HDMI0_X          = JT_PI_PCB_X_MIN + 26.0; //  -0.7 mm
JT_HDMI1_X          = JT_PI_PCB_X_MIN + 39.5; // +12.8 mm
JT_AUDIO_X          = JT_PI_PCB_X_MIN + 53.5; // +26.8 mm

// ----------------------------------------------------------------------------
// 2. DIRECT-MOUNT Z-STACKUP (Z = 0 front bezel -> Z = 38.5 mm rear face)
// ----------------------------------------------------------------------------
// Physically calibrated from real Waveshare 5" DSI LCD + Pi 4B test-fit:
//   Z =  0.0 ..  2.2 mm : Front bezel wall
//   Z =  2.2 .. 10.5 mm : LCD glass + backlight + blue rear PCB (~8.3 mm)
//   Z = 10.5 .. 16.3 mm : 8x Waveshare soldered brass M2.5 standoffs (~5.8 mm)
//   Z = 16.3 .. 17.9 mm : Raspberry Pi 4B PCB (1.6 mm) seated on inner 4 standoffs
//   Z = 17.9 .. 33.4 mm : Pi 4B tallest ports (stacked USB-A = 15.5 mm, RJ45 = 13.5 mm)
//   Z = 33.4 .. 35.5 mm : Internal clearance above USB-A (2.1 mm; fits <=14 mm heatsinks)
//   Z = 35.5 .. 38.5 mm : Solid 3.0 mm rear wall (2.3 mm left behind 0.7 mm MagSafe recess)
JT_FRONT_WALL       =  2.2;
JT_LCD_PCB_Z        = 10.5;                               // Rear face of blue LCD PCB
JT_LCD_STANDOFF_Z   = 16.3;                               // Top face of Waveshare's 8 built-in brass standoffs
JT_LCD_BACK_Z       = JT_LCD_STANDOFF_Z;                  // Mounting datum plane for Pi 4B & corner posts
JT_PI_PCB_Z0        = JT_LCD_STANDOFF_Z;                  // 16.3 mm (Pi 4B PCB bottom)
JT_PI_PCB_TOP_Z     = JT_PI_PCB_Z0 + JT_PI_PCB_T;         // 17.9 mm (Pi 4B PCB top)
JT_PI_PORTS_MAX_Z   = JT_PI_PCB_TOP_Z + 15.5;             // 33.4 mm (stacked USB-A top)
JT_BACK_INNER_Z     = 35.5;                               // 2.1 mm clearance above USB-A
JT_BACK_WALL        =  3.0;                               // Solid rear wall
JT_TOTAL_DEPTH      = JT_BACK_INNER_Z + JT_BACK_WALL;     // 38.5 mm total depth (~47.5 mm w/ 9 mm MagSafe bank)
JT_SPLIT_Z          = 12.2;                               // Front/back clamshell parting plane (encloses blue LCD PCB)

// ----------------------------------------------------------------------------
// 3. STANDARD STICK-ON MAGSAFE RING & POWER BANK GEOMETRY
// ----------------------------------------------------------------------------
// Standard Apple/Qi2 stick-on metal ring: ~54-55 mm OD, ~46 mm ID, 0.5-0.7 mm thick.
// Offset +14.0 mm in X so a landscape 102 x 68 x 9 mm slim MagSafe bank
// (e.g., Dbasne F91-D, ring ~35 mm from top & ~67 mm from bottom USB-C end)
// centers cleanly on the case back (X = -53..+49 mm, Y = -34..+34 mm) with its
// USB-C port facing -X right next to the Pi 4's top-left USB-C power input!
JT_MAGSAFE_CX       =  14.0;
JT_MAGSAFE_CY       =   0.0;
JT_MAGSAFE_OD       =  56.4;   // Fits 54-56 mm rings with gentle drop-in clearance
JT_MAGSAFE_ID       =  44.8;   // Fits 45.5-46 mm inner ring edges cleanly
JT_MAGSAFE_DEPTH    =   0.7;   // Flush recess for 0.5-0.7 mm adhesive metal rings
JT_MAGSAFE_PILL_DX  = -35.1;   // Horizontal anti-spin alignment bar toward -X
JT_MAGSAFE_PILL_L   =  12.5;
JT_MAGSAFE_PILL_W   =   5.2;

// ----------------------------------------------------------------------------
// 4. SHARED 2D & 3D GEOMETRY HELPERS
// ----------------------------------------------------------------------------
module jt_rrect_2d(w, h, r) {
    offset(r = r) offset(r = -r)
        square([w, h], center = true);
}

// Stadium / rounded slot in 2D (handles both horizontal w >= h and vertical h > w)
module jt_stadium_2d(w, h) {
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

// Chamfered rounded-rectangle prism from z0 to z1 with optional bottom/top 45-deg chamfers
module jt_chamfered_box(x0, x1, y0, y1, z0, z1, r, ch_bot = 0, ch_top = 0) {
    w  = x1 - x0;
    h  = y1 - y0;
    cx = (x0 + x1) / 2;
    cy = (y0 + y1) / 2;
    translate([cx, cy, 0]) {
        hull() {
            if (ch_bot > 0) {
                translate([0, 0, z0])
                    linear_extrude(0.01) jt_rrect_2d(w - 2*ch_bot, h - 2*ch_bot, max(1.0, r - ch_bot));
                translate([0, 0, z0 + ch_bot])
                    linear_extrude(0.01) jt_rrect_2d(w, h, r);
            } else {
                translate([0, 0, z0])
                    linear_extrude(0.01) jt_rrect_2d(w, h, r);
            }
            if (ch_top > 0) {
                translate([0, 0, z1 - ch_top])
                    linear_extrude(0.01) jt_rrect_2d(w, h, r);
                translate([0, 0, z1 - 0.01])
                    linear_extrude(0.01) jt_rrect_2d(w - 2*ch_top, h - 2*ch_top, max(1.0, r - ch_top));
            } else {
                translate([0, 0, z1 - 0.01])
                    linear_extrude(0.01) jt_rrect_2d(w, h, r);
            }
        }
    }
}

module jt_stroke_seg(p1, p2, w = 1.3) {
    hull() {
        translate(p1) circle(d = w, $fn = 16);
        translate(p2) circle(d = w, $fn = 16);
    }
}

// ----------------------------------------------------------------------------
// 5. SHARED BRANDING (Manifold CGAL-verified Pinout-Pulse Icon & Wordmark)
// ----------------------------------------------------------------------------
// Centered at [0, 0] in 2D (~24 x 22 mm at s = 1.0, +Y up)
module jt_icon_2d(s = 1.0) {
    scale([s, s]) {
        // Outer rounded square bezel
        difference() {
            jt_rrect_2d(22.0, 20.0, 2.5);
            jt_rrect_2d(19.2, 17.2, 1.4);
            square([25.0, 4.0], center = true);
        }
        // Stepped RJ45 cavity outline (clean polygon - offset, zero pinch vertices)
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
            square([18.0, 4.0], center = true);
        }
        // 6 bold RJ45 contact pins
        for (i = [-2.5 : 1 : 2.5]) {
            translate([i * 1.9, -5.4])
                square([0.95, 3.6], center = true);
        }
        // Horizontal TDR pulse waveform + terminal dot
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
            jt_stroke_seg(pts[k], pts[k+1], w = 1.35);
        }
        translate([13.2, 0.0]) circle(d = 3.0, $fn = 24);
    }
}

module jt_wordmark_2d(sz = 4.2) {
    text("JACKTRACE", size = sz, font = "Arial:style=Bold",
         halign = "center", valign = "center", spacing = 1.07);
}

// ----------------------------------------------------------------------------
// 6. SHARED CUTOUT & FEATURE MODULES
// ----------------------------------------------------------------------------

// Front LCD viewing window with clean 45-degree front bezel chamfer (cut from front shell)
module jt_lcd_window_cut(front_wall = JT_FRONT_WALL, bev = 1.2) {
    translate([JT_WIN_OFFSET_X, JT_WIN_OFFSET_Y, 0]) {
        // Straight through-window
        translate([0, 0, -0.5])
            linear_extrude(front_wall + 1.0)
                jt_rrect_2d(JT_WIN_W, JT_WIN_H, 1.5);
        // 45-deg front viewing bevel for smooth edge-touch taps
        hull() {
            translate([0, 0, -0.05])
                linear_extrude(0.05)
                    jt_rrect_2d(JT_WIN_W + 2*bev, JT_WIN_H + 2*bev, 1.5 + bev);
            translate([0, 0, bev])
                linear_extrude(0.05)
                    jt_rrect_2d(JT_WIN_W, JT_WIN_H, 1.5);
        }
    }
}

// Unobstructed drop-in LCD pocket (cut from front shell above front_wall)
module jt_lcd_pocket_cut(z0 = JT_FRONT_WALL, z1 = JT_SPLIT_Z + 1.0) {
    translate([0, 0, z0])
        linear_extrude(z1 - z0)
            jt_rrect_2d(JT_LCD_POCKET_W, JT_LCD_POCKET_H, 1.2);
}

// Pi 4B right-edge (+X) RJ45 + USB 3.0 + USB 2.0 port cutouts
// Cut cleanly from x_start outward to x_end, with exterior chamfer at x_face.
module jt_pi4_right_ports_cut(x_start = 56.0, x_end = 72.0, x_face = 65.0, port_bev = 1.2) {
    // 1. RJ45 Gigabit Ethernet (Y = +17.75, 17.8 mm wide x 15.6 mm tall)
    rj_w = 17.8; rj_z0 = JT_PI_PCB_TOP_Z - 0.3; rj_z1 = JT_PI_PCB_TOP_Z + 15.3;
    translate([x_start, JT_RJ45_Y - rj_w/2, rj_z0])
        cube([x_end - x_start, rj_w, rj_z1 - rj_z0]);
    // Generous exterior plug/latch chamfer on RJ45
    hull() {
        translate([x_face - port_bev, JT_RJ45_Y - rj_w/2, rj_z0])
            cube([0.05, rj_w, rj_z1 - rj_z0]);
        translate([x_face + 0.1, JT_RJ45_Y - rj_w/2 - port_bev, rj_z0 - port_bev])
            cube([0.05, rj_w + 2*port_bev, (rj_z1 - rj_z0) + 2*port_bev]);
    }

    // 2. USB 3.0 Dual-Stack (Y = -1.0, 16.0 mm wide x 17.2 mm tall)
    u_w = 16.0; u_z0 = JT_PI_PCB_TOP_Z - 0.3; u_z1 = JT_PI_PCB_TOP_Z + 16.9;
    translate([x_start, JT_USB3_Y - u_w/2, u_z0])
        cube([x_end - x_start, u_w, u_z1 - u_z0]);
    hull() {
        translate([x_face - port_bev, JT_USB3_Y - u_w/2, u_z0])
            cube([0.05, u_w, u_z1 - u_z0]);
        translate([x_face + 0.1, JT_USB3_Y - u_w/2 - port_bev, u_z0 - port_bev])
            cube([0.05, u_w + 2*port_bev, (u_z1 - u_z0) + 2*port_bev]);
    }

    // 3. USB 2.0 Dual-Stack (Y = -19.0, 16.0 mm wide x 17.2 mm tall)
    translate([x_start, JT_USB2_Y - u_w/2, u_z0])
        cube([x_end - x_start, u_w, u_z1 - u_z0]);
    hull() {
        translate([x_face - port_bev, JT_USB2_Y - u_w/2, u_z0])
            cube([0.05, u_w, u_z1 - u_z0]);
        translate([x_face + 0.1, JT_USB2_Y - u_w/2 - port_bev, u_z0 - port_bev])
            cube([0.05, u_w + 2*port_bev, (u_z1 - u_z0) + 2*port_bev]);
    }
}

// Pi 4B top-edge (-Y) recessed USB-C power plug alcove (support-free!)
// Pi PCB edge is at Y = -28.0 mm; outer top wall sits around Y = -46.5 mm.
// This alcove steps cleanly inward to Y = -30.5 mm (port mouth) and scoops the
// rear wall edge back to Y = -36.0 mm (2 mm clear of the 68 mm MagSafe power bank)
// so straight AND 90-degree USB-C plugs seat fully and unplug effortlessly!
module jt_pi4_top_usbc_alcove_back(y_outer = -46.5, z_back = JT_TOTAL_DEPTH, expose_hdmi_audio = false) {
    alcove_w = 24.0;  // Wide finger & overmold clearance (X = -27.5 .. -3.5)
    // 1. Open plug-insertion channel from outer top edge down to Y = -30.5 (port mouth wall)
    translate([JT_USBC_X - alcove_w/2, y_outer - 2.0, JT_SPLIT_Z - 1.0])
        cube([alcove_w, abs(y_outer - (-30.5)) + 2.0, (JT_BACK_INNER_Z - JT_SPLIT_Z) + 1.2]);
    // 2. Rear-wall thumb-scoop cutout from outer edge back to Y = -36.0 (2 mm clear of Y = -34 MagSafe bank!)
    //    Starts directly on the Z = z_back print bed -> ZERO overhangs, ZERO bridges!
    translate([JT_USBC_X, 0, JT_SPLIT_Z - 1.0])
        linear_extrude(z_back - JT_SPLIT_Z + 2.0)
            hull() {
                translate([0, -36.0 + 3.0]) jt_stadium_2d(alcove_w, 6.0);
                translate([0, y_outer - 2.0]) square([alcove_w + 2.0, 2.0], center = true);
            }
    // 3. Port mouth passing through Y = -30.5..-26.5 into Pi 4 USB-C jack + ACT/PWR LED light slot
    //    Pi 4 USB-C sits at Z = JT_PI_PCB_TOP_Z .. +3.3 (17.9 .. 21.2 mm) -> generous 11.5 mm mouth!
    translate([JT_USBC_X - 8.0, -32.0, JT_PI_PCB_TOP_Z - 2.6])
        cube([16.0, 6.0, 11.5]);
    translate([JT_LED_X - 2.2, -32.0, JT_PI_PCB_TOP_Z - 1.5])
        cube([4.4, 6.0, 6.0]);

    // Optional micro-HDMI 0/1 + 3.5 mm audio cutout for makers who want bench HDMI access
    if (expose_hdmi_audio) {
        translate([JT_HDMI0_X - 6.5, y_outer - 2.0, JT_PI_PCB_TOP_Z - 2.0])
            cube([41.0, abs(y_outer - (-26.5)) + 2.0, 11.5]);
    }
}

// Dust-sealing internal shroud walls flanking the top USB-C alcove inside back_shell
// Prints straight up from Z = JT_BACK_INNER_Z -> JT_SPLIT_Z (zero overhangs!)
module jt_pi4_top_usbc_shroud_walls(y_inner = -43.3) {
    alcove_w = 24.0;
    shroud_t = 2.0;
    y_stop   = -30.5;
    h_wall   = JT_BACK_INNER_Z - JT_SPLIT_Z + 0.2;
    for (sx = [-1, 1]) {
        wx = JT_USBC_X + sx * (alcove_w/2 + shroud_t/2);
        translate([wx - shroud_t/2, y_inner, JT_SPLIT_Z])
            cube([shroud_t, y_stop - y_inner, h_wall]);
    }
    // Inner backstop port bezel wall at Y = -30.5..-28.5 (with USB-C mouth cut cleanly afterward)
    translate([JT_USBC_X - (alcove_w/2 + shroud_t), y_stop, JT_SPLIT_Z])
        cube([alcove_w + 2*shroud_t, 2.0, h_wall]);
}

// Matching subtle rear-rim relief on FRONT shell (Z = 10.7..split_z) outside LCD glass
// (Y = -39.6..-46.5) for extra clearance below chunky USB-C plug overmolds.
module jt_pi4_top_usbc_relief_front(y_outer = -46.5) {
    translate([JT_USBC_X - 11.0, y_outer - 2.0, 10.7])
        cube([22.0, abs(y_outer - (-39.6)) + 2.0, JT_SPLIT_Z - 10.7 + 1.0]);
}

// 4 Internal LCD Corner Retaining Posts (in back shell, growing straight up from back inner wall)
// Meets the tops of the Waveshare 5" DSI LCD's 4 corner soldered brass standoffs (+-56.5, +-34.0)
// at Z = JT_LCD_STANDOFF_Z (16.3 mm) with +0.7 mm gentle clearance (z_tip = 17.0 mm) so the
// clamshell ALWAYS closes 100% flush with zero gap and zero glass stress!
module jt_lcd_retaining_posts(z_base = JT_BACK_INNER_Z, z_tip = JT_LCD_STANDOFF_Z + 0.7) {
    h = z_base - z_tip;
    for (p = JT_LCD_CORNER_HOLES) {
        translate([p[0], p[1], z_tip])
            difference() {
                cylinder(d1 = 6.4, d2 = 8.4, h = h);
                // Shallow center dimple to seat cleanly over the brass standoff rim
                translate([0, 0, -0.1])
                    cylinder(d = 3.2, h = 1.4);
            }
    }
}

// Flush Rear MagSafe Ring + Horizontal Anti-Rotation Pill Recess (cut into outer back face)
// Center default = (+14.0, 0.0) so a 102 x 68 mm MagSafe bank centers cleanly across the case.
module jt_magsafe_recess_cut(z_back = JT_TOTAL_DEPTH, cx = JT_MAGSAFE_CX, cy = JT_MAGSAFE_CY, include_pill = true) {
    // 1. Primary MagSafe ring groove (56.4 OD / 44.8 ID x 0.7 mm deep)
    translate([cx, cy, z_back - JT_MAGSAFE_DEPTH])
        linear_extrude(JT_MAGSAFE_DEPTH + 0.2)
            difference() {
                circle(d = JT_MAGSAFE_OD, $fn = 64);
                circle(d = JT_MAGSAFE_ID, $fn = 64);
            }
    // 2. Horizontal anti-spin alignment pill (keeps 100 g power bank locked in landscape!)
    if (include_pill) {
        translate([cx + JT_MAGSAFE_PILL_DX, cy, z_back - JT_MAGSAFE_DEPTH])
            linear_extrude(JT_MAGSAFE_DEPTH + 0.2)
                jt_stadium_2d(JT_MAGSAFE_PILL_L, JT_MAGSAFE_PILL_W);
    }
}

// ----------------------------------------------------------------------------
// 7. HARDWARE GHOST VISUALIZER (Assembly & Clearance Verification Only)
// ----------------------------------------------------------------------------
module jt_hardware_ghost(show_power_bank = true) {
    // Waveshare 5" DSI LCD Glass, Blue Rear PCB & 4 Corner Brass Standoffs
    color([0.10, 0.12, 0.16, 0.85])
        translate([0, 0, JT_FRONT_WALL])
            linear_extrude(2.2) square([121.1, 77.9], center = true);
    color([0.08, 0.36, 0.56, 0.85])
        translate([0, 0, JT_FRONT_WALL + 2.2])
            linear_extrude(JT_LCD_PCB_Z - (JT_FRONT_WALL + 2.2)) square([118.0, 74.0], center = true);
    color([0.82, 0.65, 0.25, 0.95])
        for (p = JT_LCD_CORNER_HOLES)
            translate([p[0], p[1], JT_LCD_PCB_Z])
                cylinder(d = 5.0, h = JT_LCD_STANDOFF_Z - JT_LCD_PCB_Z);
    color([0.82, 0.65, 0.25, 0.95])
        for (p = JT_PI_MOUNT_HOLES)
            translate([p[0], p[1], JT_LCD_PCB_Z])
                cylinder(d = 5.0, h = JT_LCD_STANDOFF_Z - JT_LCD_PCB_Z);

    // Raspberry Pi 4 Model B PCB + Connectors
    color([0.10, 0.58, 0.26, 0.85])
        translate([JT_PI_PCB_X_MIN, JT_PI_PCB_Y_MIN, JT_PI_PCB_Z0])
            cube([85.0, 56.0, JT_PI_PCB_T]);
    // RJ45
    color([0.78, 0.80, 0.84, 0.90])
        translate([JT_PI_PCB_X_MAX - 19.0, JT_RJ45_Y - 8.0, JT_PI_PCB_TOP_Z])
            cube([21.0, 16.0, 13.5]);
    // USB 3.0 & USB 2.0
    color([0.22, 0.48, 0.85, 0.90])
        translate([JT_PI_PCB_X_MAX - 15.0, JT_USB3_Y - 7.0, JT_PI_PCB_TOP_Z])
            cube([17.0, 14.0, 15.5]);
    color([0.78, 0.80, 0.84, 0.90])
        translate([JT_PI_PCB_X_MAX - 15.0, JT_USB2_Y - 7.0, JT_PI_PCB_TOP_Z])
            cube([17.0, 14.0, 15.5]);
    // Pi 4 USB-C Power Jack
    color([0.75, 0.77, 0.80, 0.95])
        translate([JT_USBC_X - 4.5, JT_PI_PCB_Y_MIN - 1.2, JT_PI_PCB_TOP_Z])
            cube([9.0, 7.5, 3.3]);
    // 40-pin GPIO
    color([0.18, 0.18, 0.20, 0.85])
        translate([JT_PI_HOLE_X1 - 2.5, JT_PI_PCB_Y_MAX - 6.0, JT_PI_PCB_TOP_Z])
            cube([51.0, 5.0, 11.2]);

    // Dbasne F91-D MagSafe Power Bank Ghost (102 x 68 x 9 mm, landscape)
    if (show_power_bank) {
        // Ring center is at X = +14; bank spans -53..+49 in X, -34..+34 in Y
        color([0.22, 0.24, 0.28, 0.45])
            translate([JT_MAGSAFE_CX - 16.0, 0, JT_TOTAL_DEPTH + 0.2])
                linear_extrude(9.0) jt_rrect_2d(102.0, 68.0, 7.0);
        // Bank USB-C port indicator on its -X short edge
        color([0.95, 0.62, 0.10, 0.9])
            translate([JT_MAGSAFE_CX - 67.5, -4.5, JT_TOTAL_DEPTH + 2.5])
                cube([2.0, 9.0, 4.0]);
    }
}
