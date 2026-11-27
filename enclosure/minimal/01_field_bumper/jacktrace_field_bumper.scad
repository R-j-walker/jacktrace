// ============================================================================
// JackTrace Minimal — Concept 1: "Field Bumper" Enclosure
// ============================================================================
// Open-source minimal enclosure for Raspberry Pi 4B + Waveshare 5" DSI LCD.
// Features:
//   - Ultra-compact 34 mm direct-mount clamshell (zero soldering, stock 50 mm DSI)
//   - Clamshell-captured scalloped side bumper rails (works in TPU, PETG, or PLA!)
//   - Native flush stick-on MagSafe ring + anti-spin pill recess (sized for a
//     landscape 102 x 68 x 9 mm slim bank such as the Dbasne F91-D)
//   - Top & bottom perimeter chimney vents (unobstructed when MagSafe bank is on)
//   - Top-edge recessed USB-C plug alcove (fits straight & 90-deg plugs cleanly)
//   - Tucked top-left lanyard corner loop & crisp debossed JACKTRACE branding
//   - 100% support-free FDM printing, assembled with 4x M2.5 x 16 mm screws
//
// Export via CLI:
//   openscad -D 'part="front"'   -o stl/field_bumper_front.stl   jacktrace_field_bumper.scad
//   openscad -D 'part="back"'    -o stl/field_bumper_back.stl    jacktrace_field_bumper.scad
//   openscad -D 'part="bumpers"' -o stl/field_bumper_rails.stl   jacktrace_field_bumper.scad
// ============================================================================

include <../jacktrace_minimal_core.scad>;

// ----------------------------------------------------------------------------
// USER PARAMETERS
// ----------------------------------------------------------------------------
part                = "assembly"; // "front", "back", "bumpers", "assembly", "exploded", "cutaway"
use_heatset_inserts = false;      // false = 2.25 mm direct M2.5 self-tap; true = 3.6 mm M2.5 inserts
enable_magsafe      = true;       // true = flush MagSafe ring recess + top/bottom vents; false = rear vent bank
expose_hdmi_audio   = false;      // true = open micro-HDMI 0/1 & 3.5 mm audio on top edge
bumper_clear        = 0.25;       // Print-fit clearance for clamshell-captured bumper rails
show_ghost          = true;       // Show Pi 4 + LCD + MagSafe power bank in assembly/cutaway views

$fn = 48;

// ----------------------------------------------------------------------------
// ENCLOSURE DIMENSIONS (mm)
// ----------------------------------------------------------------------------
// Main charcoal shell: 130.0 x 93.0 x 34.0 mm
// With left & right scalloped bumper rails: 138.0 x 93.0 x 34.0 mm
shell_x_half    = 65.0;                     // X = -65.0 .. +65.0 (130.0 mm)
shell_y_half    = 46.5;                     // Y = -46.5 .. +46.5 ( 93.0 mm)
shell_r         =  7.0;                     // Clean corner radius
outer_chamfer   =  1.6;                     // 45-deg industrial front & rear bevel
wall_x          =  3.9;                     // Side wall around 122.2 mm LCD pocket

// 4 Corner M2.5 closure screws (100% clear of 78 mm LCD pocket & 102x68 MagSafe bank!)
screw_pts = [
    [-55.0, -42.1],
    [ 55.0, -42.1],
    [-55.0,  42.1],
    [ 55.0,  42.1]
];
m25_tap_d       = use_heatset_inserts ? 3.6 : 2.25;
m25_clear_d     = 2.85;
m25_head_d      = 5.6;   // Fits M2.5 SHCS / BHCS cleanly inside flat rear face
screw_shelf_z   = 20.5;  // Counterbore shelf -> standard M2.5 x 16 mm screw gets ~7.5 mm bite!

// Side Bumper Rail Geometry (symmetrical Y = -30.5 .. +30.5 mm)
rail_y_half     = 30.5;                     // 61.0 mm vertical grip span
rail_recess_x   = 63.2;                     // Main shell steps inward to +-63.2 mm inside rail saddle
rail_outer_x    = 68.8;                     // Outer scalloped peak -> 137.6 mm total grip width
rail_tab_y0     = 28.9;                     // Clamshell locking tabs at Y = +-(28.9 .. 30.2), 100% clear of ports!
rail_tab_y1     = 30.2;
rail_tab_x_in   = 62.0;                     // Inward tongue depth (1.2 mm positive lock; 45-deg ramp ends at 27.7 > 27.4!)
rail_tab_z0     = JT_SPLIT_Z - 1.8;         // 10.4 mm (engages 1.8 mm into front shell)
rail_tab_z1     = JT_SPLIT_Z + 1.8;         // 14.0 mm (engages 1.8 mm into back shell)

// Interlocking front/back alignment lip
lip_h           = 1.8;
lip_clear       = 0.25;

// Branding depth (0.6 mm = 3 layers @ 0.2 mm)
logo_depth      = 0.6;

// ============================================================================
// HELPER MODULES
// ============================================================================

// Sleek tucked top-left corner lanyard lug (-X, -Y), kept slim on front_shell (Z = 0..12.2)
module lanyard_ear_solid(z0, z1, ch_bot = 0, ch_top = 0) {
    hull() {
        translate([-shell_x_half + 2.6, -shell_y_half + 2.6, z0 + ch_bot])
            cylinder(r = 5.4, h = (z1 - z0) - ch_bot - ch_top);
        translate([-shell_x_half + 8.0, -shell_y_half + 8.0, z0 + ch_bot])
            cylinder(r = 5.4, h = (z1 - z0) - ch_bot - ch_top);
    }
}

module lanyard_hole_cut(z0, z1) {
    translate([-shell_x_half + 2.0, -shell_y_half + 2.0, z0 - 1.0])
        cylinder(d = 4.4, h = (z1 - z0) + 2.0);
}

// Recessed side saddle & locking-tab pocket cut from main shell (+X and -X)
module bumper_shell_recess_cut(z0, z1, is_front = true) {
    for (sx = [-1, 1]) {
        // 1. Main side saddle step (X = +-63.2 outward, Y = -30.5..+30.5)
        translate([sx > 0 ? rail_recess_x : -(shell_x_half + 5.0), -rail_y_half, z0 - 0.5])
            cube([shell_x_half + 5.0 - rail_recess_x, 2 * rail_y_half, (z1 - z0) + 1.0]);

        // 2. Clamshell-capture locking-tab slots at top & bottom of rail (+-28.9..30.2)
        //    Upper slot & left center slot include extra -Y room for the 45-deg self-supporting print ramp!
        tab_z0 = is_front ? (rail_tab_z0 - bumper_clear) : (JT_SPLIT_Z - 0.2);
        tab_z1 = is_front ? (JT_SPLIT_Z + 0.2)           : (rail_tab_z1 + bumper_clear);
        tab_ramp = (rail_recess_x - rail_tab_x_in) + 0.4; // 1.6 mm ramp clearance
        // Lower end slot (-Y)
        translate([sx > 0 ? (rail_tab_x_in - bumper_clear) : -(rail_recess_x + 1.0), -(rail_tab_y1 + bumper_clear), tab_z0])
            cube([rail_recess_x - rail_tab_x_in + 1.0 + bumper_clear, (rail_tab_y1 - rail_tab_y0) + 2*bumper_clear, tab_z1 - tab_z0]);
        // Upper end slot (+Y, widened downward to clear the 45-deg print ramp cleanly above port edge 27.3!)
        u_y0 = max(27.35, rail_tab_y0 - tab_ramp - bumper_clear);
        translate([sx > 0 ? (rail_tab_x_in - bumper_clear) : -(rail_recess_x + 1.0), u_y0, tab_z0])
            cube([rail_recess_x - rail_tab_x_in + 1.0 + bumper_clear, (rail_tab_y1 + bumper_clear) - u_y0, tab_z1 - tab_z0]);
        if (sx < 0) {
            // Extra center locking tab slot on left (-X) side (includes 45-deg ramp clearance at -Y end!)
            c_y0 = -11.8 - tab_ramp - bumper_clear;
            c_y1 =  11.8 + bumper_clear;
            translate([-(rail_recess_x + 1.0), c_y0, tab_z0])
                cube([rail_recess_x - rail_tab_x_in + 1.0 + bumper_clear, c_y1 - c_y0, tab_z1 - tab_z0]);
        }
    }
}

// Perimeter chimney cooling vents (top + bottom edges, completely outside MagSafe bank!)
module chimney_vents_cut() {
    // Top exhaust slots (+X side of top edge, clear of USB-C alcove & corner screws)
    for (vx = [10.0 : 5.5 : 43.0]) {
        translate([vx, -shell_y_half - 2.0, 25.0])
            rotate([-90, 0, 0])
                linear_extrude(12.0)
                    jt_stadium_2d(2.6, 12.0);
    }
    // Bottom intake slots (centered along bottom edge, clear of corner screws)
    for (vx = [-38.5 : 5.5 : 38.5]) {
        translate([vx, shell_y_half - 10.0, 25.0])
            rotate([-90, 0, 0])
                linear_extrude(12.0)
                    jt_stadium_2d(2.4, 11.0);
    }
}

// ============================================================================
// PART 1: FRONT BEZEL SHELL (Z = 0.0 .. 12.2 mm)
// ============================================================================
module front_shell() {
    difference() {
        union() {
            // Outer chamfered shell body (Z = 0..12.2)
            jt_chamfered_box(-shell_x_half, shell_x_half, -shell_y_half, shell_y_half,
                             0, JT_SPLIT_Z, shell_r, ch_bot = outer_chamfer, ch_top = 0);
            // Tucked top-left lanyard lug
            lanyard_ear_solid(0, JT_SPLIT_Z, ch_bot = outer_chamfer, ch_top = 0);

            // Top & bottom interlocking alignment tongue along horizontal rails
            // (Clear of top USB-C alcove and side bumper pockets!)
            for (seg = [[-48.0, -30.5], [1.0, 48.0]]) {
                translate([seg[0], -shell_y_half + 1.5, JT_SPLIT_Z - 0.1])
                    cube([seg[1] - seg[0], 1.6, lip_h + 0.1]);
            }
            translate([-48.0, shell_y_half - 3.1, JT_SPLIT_Z - 0.1])
                cube([96.0, 1.6, lip_h + 0.1]);
        }

        // 1. Unobstructed drop-in Waveshare 5" DSI LCD glass pocket
        jt_lcd_pocket_cut(JT_FRONT_WALL, JT_SPLIT_Z + 1.0);

        // 2. Active viewing window with 45-deg front bezel chamfer (calibrated even 1.8 mm glass margin)
        jt_lcd_window_cut(JT_FRONT_WALL, 1.0);

        // 3. Recessed side bumper rail saddles & clamshell locking slots
        bumper_shell_recess_cut(0, JT_SPLIT_Z, is_front = true);

        // 4. Subtle rear-rim clearance for chunky USB-C plug overmolds (invisible from front!)
        jt_pi4_top_usbc_relief_front(-shell_y_half);

        // 5. Lanyard hole
        lanyard_hole_cut(0, JT_SPLIT_Z);

        // 6. 4x M2.5 self-tapping (or heat-set) blind bores at corners
        //    Blind bottom at Z = 3.8 mm (3.8 mm solid front bezel; 8.4 mm thread engagement!)
        for (p = screw_pts) {
            translate([p[0], p[1], 3.8])
                cylinder(d = m25_tap_d, h = JT_SPLIT_Z - 3.8 + 0.5);
        }

        // 7. Engraved front "JACKTRACE" wordmark centered on lower bezel (Z = 0, Y = 33.2..44.9)
        //    Right-hand rule on Z=0 (-Z viewer, -Y up): mirror([0,1,0]) reads upright!
        translate([0, 39.2, -0.05])
            linear_extrude(logo_depth + 0.05)
                mirror([0, 1, 0])
                    jt_wordmark_2d(sz = 4.2);
    }
}

// ============================================================================
// PART 2: BACK SHELL (Z = 12.2 .. 34.0 mm)
// ============================================================================
module back_shell() {
    difference() {
        union() {
            // Outer chamfered shell body (Z = 12.2..34.0)
            jt_chamfered_box(-shell_x_half, shell_x_half, -shell_y_half, shell_y_half,
                             JT_SPLIT_Z, JT_TOTAL_DEPTH, shell_r, ch_bot = 0, ch_top = outer_chamfer);
        }

        // 1. Main interior electronics cavity (fits Pi 4B + heatsinks up to 14 mm tall)
        //    Preserves solid corner regions for the 4 M2.5 screw tubes AND the top USB-C shroud!
        difference() {
            translate([0, 0, JT_SPLIT_Z - 0.5])
                linear_extrude(JT_BACK_INNER_Z - JT_SPLIT_Z + 0.5)
                    jt_rrect_2d(2 * (shell_x_half - wall_x), 2 * (shell_y_half - 3.2), 4.0);
            // Keep solid cylindrical reinforcement bosses around the 4 corner M2.5 screws
            for (p = screw_pts) {
                translate([p[0], p[1], JT_SPLIT_Z - 1.0])
                    cylinder(d = 9.0, h = JT_BACK_INNER_Z - JT_SPLIT_Z + 2.0);
            }
            // Keep dust-sealing shroud walls around the top USB-C alcove!
            jt_pi4_top_usbc_shroud_walls(y_inner = -(shell_y_half - 3.2));
        }

        // 2. Interlocking alignment groove matching front_shell tongues
        for (seg = [[-48.0 - lip_clear, -30.5 + lip_clear], [1.0 - lip_clear, 48.0 + lip_clear]]) {
            translate([seg[0], -shell_y_half + 1.5 - lip_clear, JT_SPLIT_Z - 0.2])
                cube([seg[1] - seg[0], 1.6 + 2*lip_clear, lip_h + 0.4]);
        }
        translate([-48.0 - lip_clear, shell_y_half - 3.1 - lip_clear, JT_SPLIT_Z - 0.2])
            cube([96.0 + 2*lip_clear, 1.6 + 2*lip_clear, lip_h + 0.4]);

        // 3. Recessed side bumper rail saddles & clamshell locking slots
        bumper_shell_recess_cut(JT_SPLIT_Z, JT_TOTAL_DEPTH, is_front = false);

        // 4. Right-edge (+X) Pi 4 RJ45 + USB 3.0 + USB 2.0 port cutouts
        jt_pi4_right_ports_cut(x_start = 56.0, x_end = shell_x_half + 5.0,
                               x_face = rail_recess_x, port_bev = 1.0);

        // 5. Top-edge (-Y) recessed Pi 4 USB-C power alcove (support-free!)
        jt_pi4_top_usbc_alcove_back(y_outer = -shell_y_half, z_back = JT_TOTAL_DEPTH,
                                    expose_hdmi_audio = expose_hdmi_audio);

        // 6. Cooling vents:
        //    - MagSafe enabled: top & bottom perimeter chimney vents (never blocked by bank!)
        //    - MagSafe disabled: perimeter vents + sleek upper-rear passive vent bank
        chimney_vents_cut();
        if (!enable_magsafe) {
            for (vx = [-36.0 : 5.5 : 36.0]) {
                translate([vx, -16.0, JT_BACK_INNER_Z - 1.0])
                    linear_extrude(JT_BACK_WALL + 2.0)
                        jt_stadium_2d(2.4, 15.0);
            }
        }

        // 7. Recessed M2.5 corner screw counterbores with 45-deg self-supporting print ceilings!
        //    Back shell prints flat on Z = JT_TOTAL_DEPTH (bed) growing toward Z = JT_SPLIT_Z.
        for (p = screw_pts) {
            // Clearance bore from shelf to split seam
            translate([p[0], p[1], JT_SPLIT_Z - 0.5])
                cylinder(d = m25_clear_d, h = (screw_shelf_z - JT_SPLIT_Z) + 1.0);
            // 45-deg conical print ceiling (transitions 5.6 mm -> 2.85 mm with zero supports!)
            cone_h = (m25_head_d - m25_clear_d) / 2;
            translate([p[0], p[1], screw_shelf_z - cone_h])
                cylinder(d1 = m25_clear_d, d2 = m25_head_d, h = cone_h + 0.05);
            // Outer counterbore recess from shelf to rear face
            translate([p[0], p[1], screw_shelf_z])
                cylinder(d = m25_head_d, h = (JT_TOTAL_DEPTH - screw_shelf_z) + 1.0);
        }

        // 9. Flush MagSafe Stick-On Ring + Anti-Spin Pill Recess + Subtle Rear Emblem
        if (enable_magsafe) {
            jt_magsafe_recess_cut(z_back = JT_TOTAL_DEPTH,
                                  cx = JT_MAGSAFE_CX, cy = JT_MAGSAFE_CY,
                                  include_pill = true);
            // Subtle Pinout-Pulse RJ45 emblem debossed cleanly inside the empty 44.8 mm ring center!
            // Right-hand rule on rear face (+Z viewer, -Y up): rotate([0,0,180]) reads upright!
            translate([JT_MAGSAFE_CX, JT_MAGSAFE_CY, JT_TOTAL_DEPTH - 0.5])
                linear_extrude(0.6)
                    rotate([0, 0, 180])
                        jt_icon_2d(s = 1.05);
        } else {
            // Centered emblem & wordmark on lower rear panel when MagSafe is off
            translate([0, 10.0, JT_TOTAL_DEPTH - logo_depth])
                linear_extrude(logo_depth + 0.1)
                    rotate([0, 0, 180])
                        jt_icon_2d(s = 0.95);
            translate([0, 26.5, JT_TOTAL_DEPTH - logo_depth])
                linear_extrude(logo_depth + 0.1)
                    rotate([0, 0, 180])
                        jt_wordmark_2d(sz = 4.4);
        }
    }

    // Internal LCD corner retaining posts (4x, print straight up from back inner wall, zero supports!)
    // Ends at Z = JT_LCD_STANDOFF_Z + 0.7 (17.0 mm) to meet the LCD's 4 brass corner standoffs cleanly!
    jt_lcd_retaining_posts(z_base = JT_BACK_INNER_Z + 0.2, z_tip = JT_LCD_STANDOFF_Z + 0.7);
}

// ============================================================================
// PART 3: SCALLOPED CLAMSHELL-CAPTURED SIDE BUMPER RAILS (Left & Right)
// ============================================================================
// Works identically in flexible TPU OR rigid PETG/PLA!
// Slides straight in along Z during assembly; captured in X, Y, and Z when the
// 4 corner M2.5 screws tighten. Prints upright on its flat Y = -rail_y_half end
// with 45-deg self-supporting transitions (100% support-free!).
module single_bumper_rail(is_right = false) {
    sx      = is_right ? 1 : -1;
    x_in    = rail_recess_x + bumper_clear;   // 63.45 mm inner mating face
    x_mid   = rail_outer_x - 1.4;             // 67.4 mm base rail body (4.0 mm thick solid bed base!)
    ch_z    = 2.6;                            // Rounded-chamfer front & back wrap bevels
    y_span  = rail_y_half - bumper_clear;     // 30.25 mm half-height

    difference() {
        union() {
            // 1. Base ergonomic rail body: FLAT bottom/top ends (Y = +-y_span) for rock-solid
            //    upright FDM bed adhesion (~4.0 x 29 mm contact patch, zero overhang, zero brim!)
            hull() {
                // Inner flush base against shell saddle
                translate([sx > 0 ? x_in : -(x_in + 0.05), -y_span, outer_chamfer])
                    cube([0.05, 2 * y_span, JT_TOTAL_DEPTH - 2 * outer_chamfer]);
                // Full-width shoulder gripping front & rear chamfers
                translate([sx > 0 ? (x_in + 1.6) : -(x_in + 1.6 + 0.05), -y_span, 0.2])
                    cube([0.05, 2 * y_span, JT_TOTAL_DEPTH - 0.4]);
                // Outer smooth grip face
                translate([sx > 0 ? x_mid : -(x_mid + 0.05), -y_span, ch_z])
                    cube([0.05, 2 * y_span, JT_TOTAL_DEPTH - 2 * ch_z]);
            }

            // 2. Three ergonomic tactile palm scallops on the solid LEFT (-X) grip rail!
            //    (Right rail stays sleek & continuously framed around the RJ45/USB-A port window.)
            if (!is_right) {
                for (sy_pos = [-17.5, 0.0, 17.5]) {
                    hull() {
                        translate([-(x_mid - 0.5 + 0.05), sy_pos - 7.5, ch_z + 1.0])
                            cube([0.05, 15.0, JT_TOTAL_DEPTH - 2*(ch_z + 1.0)]);
                        translate([-(rail_outer_x + 0.05), sy_pos - 3.2, ch_z + 3.2])
                            cube([0.05, 6.4, JT_TOTAL_DEPTH - 2*(ch_z + 3.2)]);
                    }
                }
            }

            // 3. Inward clamshell-captured locking tongues (45-deg self-supporting ramps for Y-up print!)
            tab_w = (x_in - rail_tab_x_in) + 0.2;
            // Lower end tab (sits directly on the build plate at Y = -y_span -> zero overhang!)
            translate([sx > 0 ? rail_tab_x_in : -x_in - 0.2, -rail_tab_y1, rail_tab_z0])
                cube([tab_w, rail_tab_y1 - rail_tab_y0, rail_tab_z1 - rail_tab_z0]);
            // Upper end tab with clean 45-deg ramp starting at Y = 27.5 (> 27.4 port cutout -> zero clip!)
            hull() {
                translate([sx > 0 ? rail_tab_x_in : -x_in - 0.2, rail_tab_y0, rail_tab_z0])
                    cube([tab_w, rail_tab_y1 - rail_tab_y0, rail_tab_z1 - rail_tab_z0]);
                translate([sx > 0 ? (x_in - 0.05) : -(x_in + 0.05), rail_tab_y0 - tab_w, rail_tab_z0])
                    cube([0.1, 0.1, rail_tab_z1 - rail_tab_z0]);
            }
            // Extra center locking tab on LEFT (-X) rail (45-deg underside ramp)
            if (!is_right) {
                hull() {
                    translate([-x_in - 0.2, -11.8, rail_tab_z0])
                        cube([tab_w, 23.6, rail_tab_z1 - rail_tab_z0]);
                    translate([-(x_in + 0.05), -11.8 - tab_w, rail_tab_z0])
                        cube([0.1, 0.1, rail_tab_z1 - rail_tab_z0]);
                }
            }
        }

        // 4. Right rail port bay cutout (clean chamfered frame around RJ45 + USB 3.0 + USB 2.0!)
        if (is_right) {
            pz0 = JT_PI_PCB_TOP_Z - 0.8;  // 12.5 mm
            pz1 = JT_PI_PCB_TOP_Z + 17.5; // 30.8 mm (18.3 mm clear port height)
            py0 = -27.3;
            py1 =  27.3;
            // Straight opening through rail
            translate([x_in - 1.0, py0, pz0])
                cube([10.0, py1 - py0, pz1 - pz0]);
            // Crisp exterior 45-deg chamfer framing the dark charcoal port bezel
            hull() {
                translate([x_mid - 1.4, py0, pz0])
                    cube([0.05, py1 - py0, pz1 - pz0]);
                translate([x_mid + 0.6, py0 - 1.4, pz0 - 1.4])
                    cube([0.05, (py1 - py0) + 2.8, (pz1 - pz0) + 2.8]);
            }
        }
    }
}

// ============================================================================
// PRINT-ORIENTED LAYOUTS & VISUALIZATION MODES
// ============================================================================

if (part == "front") {
    // Prints flat on outer front bezel face (Z = 0), 100% support-free!
    front_shell();
}
else if (part == "back") {
    // Flipped 180 deg around X so outer flat rear face (Z = 34.0) lies on Z = 0 print bed!
    translate([0, 0, JT_TOTAL_DEPTH])
        rotate([180, 0, 0])
            back_shell();
}
else if (part == "bumpers") {
    // Both left & right bumper rails standing upright on their flat Y = -rail_y_half base (Z = 0)!
    // Zero overhangs, zero supports — works in TPU, PETG, or PLA.
    y_base = rail_y_half - bumper_clear;
    // Left rail
    translate([-18, -JT_TOTAL_DEPTH/2, y_base])
        rotate([-90, 0, 0])
            translate([rail_recess_x, 0, 0])
                single_bumper_rail(is_right = false);
    // Right rail
    translate([18, -JT_TOTAL_DEPTH/2, y_base])
        rotate([-90, 0, 0])
            translate([-rail_recess_x, 0, 0])
                single_bumper_rail(is_right = true);
}
else if (part == "assembly") {
    color([0.22, 0.24, 0.27]) front_shell();
    color([0.26, 0.28, 0.31]) back_shell();
    color([0.93, 0.58, 0.10]) single_bumper_rail(is_right = false);
    color([0.93, 0.58, 0.10]) single_bumper_rail(is_right = true);
    if (show_ghost) jt_hardware_ghost(show_power_bank = enable_magsafe);
}
else if (part == "exploded") {
    color([0.22, 0.24, 0.27]) translate([0, 0, -28]) front_shell();
    color([0.26, 0.28, 0.31]) translate([0, 0,  28]) back_shell();
    color([0.93, 0.58, 0.10]) translate([-18, 0,  0]) single_bumper_rail(is_right = false);
    color([0.93, 0.58, 0.10]) translate([ 18, 0,  0]) single_bumper_rail(is_right = true);
    jt_hardware_ghost(show_power_bank = false);
    // Floating MagSafe bank behind back shell
    if (enable_magsafe) {
        color([0.22, 0.24, 0.28, 0.55])
            translate([JT_MAGSAFE_CX - 16.0, 0, JT_TOTAL_DEPTH + 44])
                linear_extrude(9.0) jt_rrect_2d(102.0, 68.0, 7.0);
    }
}
else if (part == "cutaway") {
    difference() {
        union() {
            color([0.22, 0.24, 0.27]) front_shell();
            color([0.26, 0.28, 0.31]) back_shell();
            color([0.93, 0.58, 0.10]) single_bumper_rail(is_right = false);
            color([0.93, 0.58, 0.10]) single_bumper_rail(is_right = true);
        }
        // Section through Y = 0 (showing Pi 4, LCD, USB-A, MagSafe recess & side rails)
        translate([-100, -100, -5]) cube([200, 100, 60]);
    }
    if (show_ghost) jt_hardware_ghost(show_power_bank = enable_magsafe);
}
