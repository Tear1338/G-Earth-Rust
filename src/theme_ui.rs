//! Original G-Earth 1.5.4-beta-29 Bootstrap/JavaFX theme visuals, logos, icons, and layout primitives.
use eframe::egui;
use std::collections::HashMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppTheme {
    GEarth,
    GEarthDark,
    Tanji,
}

#[derive(Clone, Copy, Debug)]
pub struct ThemePalette {
    pub titlebar_bg: egui::Color32,
    pub content_bg: egui::Color32,
    pub outer_border: egui::Color32,
    pub group_border: egui::Color32,
    pub tab_inactive_text: egui::Color32,
    pub tab_hover_bg: egui::Color32,
    pub tab_active_bg: egui::Color32,
    pub tab_active_text: egui::Color32,
    pub tab_active_border: egui::Color32,
    pub table_header_bg: egui::Color32,
    pub table_header_text: egui::Color32,
    pub table_row_alt_bg: egui::Color32,
    pub table_row_blue: egui::Color32,
    pub table_row_active: egui::Color32,
    pub table_row_inactive: egui::Color32,
    pub table_grid_line: egui::Color32,
    pub primary_accent: egui::Color32,
    pub text_muted: egui::Color32,
}

impl AppTheme {
    pub const ALL: [Self; 3] = [Self::GEarth, Self::GEarthDark, Self::Tanji];

    pub fn name(self) -> &'static str {
        match self {
            Self::GEarth => "G-Earth",
            Self::GEarthDark => "G-Earth Dark",
            Self::Tanji => "Tanji",
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            Self::Tanji => "Tanji",
            Self::GEarth | Self::GEarthDark => "G-Earth",
        }
    }

    pub fn from_settings(theme: Option<&str>, dark_mode: bool) -> Self {
        match theme {
            Some("G-Earth Dark") => Self::GEarthDark,
            Some("Tanji") => Self::Tanji,
            Some("G-Earth") => Self::GEarth,
            _ if dark_mode => Self::GEarthDark,
            _ => Self::GEarth,
        }
    }

    pub fn is_dark(self) -> bool {
        matches!(self, Self::GEarthDark)
    }

    pub fn palette(self) -> ThemePalette {
        match self {
            Self::GEarth => ThemePalette {
                titlebar_bg: egui::Color32::from_rgb(0xf4, 0xf4, 0xf4),
                content_bg: egui::Color32::WHITE,
                outer_border: egui::Color32::from_rgb(0xce, 0xce, 0xce),
                group_border: egui::Color32::from_rgb(0x88, 0x88, 0x88),
                tab_inactive_text: egui::Color32::from_rgb(0x33, 0x7a, 0xb7),
                tab_hover_bg: egui::Color32::from_rgb(0xee, 0xee, 0xee),
                tab_active_bg: egui::Color32::WHITE,
                tab_active_text: egui::Color32::from_rgb(0x33, 0x33, 0x33),
                tab_active_border: egui::Color32::from_rgb(0xdd, 0xdd, 0xdd),
                table_header_bg: egui::Color32::from_rgb(0xf7, 0xf7, 0xf7),
                table_header_text: egui::Color32::from_rgb(0x44, 0x44, 0x44),
                table_row_alt_bg: egui::Color32::from_rgb(0xfa, 0xfa, 0xfa),
                table_row_blue: egui::Color32::from_rgb(0xf0, 0xff, 0xff),
                table_row_active: egui::Color32::WHITE,
                table_row_inactive: egui::Color32::from_rgb(0xcc, 0xcc, 0xcc),
                table_grid_line: egui::Color32::from_rgb(0xcc, 0xcc, 0xcc),
                primary_accent: egui::Color32::from_rgb(0x33, 0x7a, 0xb7),
                text_muted: egui::Color32::from_rgb(0x55, 0x55, 0x55),
            },
            Self::GEarthDark => ThemePalette {
                titlebar_bg: egui::Color32::from_rgb(0x22, 0x22, 0x22),
                content_bg: egui::Color32::from_rgb(0x33, 0x33, 0x33),
                outer_border: egui::Color32::from_rgb(0x22, 0x22, 0x22),
                group_border: egui::Color32::from_rgb(0x88, 0x88, 0x88),
                tab_inactive_text: egui::Color32::from_rgb(0x5d, 0x83, 0xb4),
                tab_hover_bg: egui::Color32::from_rgb(0x44, 0x44, 0x44),
                tab_active_bg: egui::Color32::from_rgb(0x33, 0x33, 0x33),
                tab_active_text: egui::Color32::from_rgb(0xee, 0xee, 0xee),
                tab_active_border: egui::Color32::from_rgb(0x11, 0x11, 0x11),
                table_header_bg: egui::Color32::from_rgb(0x28, 0x28, 0x28),
                table_header_text: egui::Color32::from_rgb(0xe8, 0xe8, 0xe8),
                table_row_alt_bg: egui::Color32::from_rgb(0x38, 0x38, 0x38),
                table_row_blue: egui::Color32::from_rgb(0x3d, 0x5b, 0x69),
                table_row_active: egui::Color32::from_rgb(0x52, 0x52, 0x52),
                table_row_inactive: egui::Color32::from_rgb(0x5e, 0x5e, 0x5e),
                table_grid_line: egui::Color32::from_rgb(0x78, 0x78, 0x78),
                primary_accent: egui::Color32::from_rgb(0x5d, 0x83, 0xb4),
                text_muted: egui::Color32::from_rgb(0xb8, 0xb8, 0xb8),
            },
            Self::Tanji => ThemePalette {
                titlebar_bg: egui::Color32::from_rgb(0xf4, 0xf2, 0xee),
                content_bg: egui::Color32::from_rgb(0xff, 0xfe, 0xfc),
                outer_border: egui::Color32::from_rgb(0xff, 0xa5, 0x00),
                group_border: egui::Color32::from_rgb(0x88, 0x88, 0x88),
                tab_inactive_text: egui::Color32::from_rgb(0xb7, 0x77, 0x14),
                tab_hover_bg: egui::Color32::from_rgb(0xee, 0xee, 0xee),
                tab_active_bg: egui::Color32::from_rgb(0xff, 0xfe, 0xfc),
                tab_active_text: egui::Color32::from_rgb(0x33, 0x33, 0x33),
                tab_active_border: egui::Color32::from_rgb(0xdd, 0xdd, 0xdd),
                table_header_bg: egui::Color32::from_rgb(0xf7, 0xf5, 0xf0),
                table_header_text: egui::Color32::from_rgb(0x44, 0x44, 0x44),
                table_row_alt_bg: egui::Color32::from_rgb(0xfc, 0xf9, 0xf4),
                table_row_blue: egui::Color32::from_rgb(0xff, 0xf0, 0xe3),
                table_row_active: egui::Color32::WHITE,
                table_row_inactive: egui::Color32::from_rgb(0xcc, 0xcc, 0xcc),
                table_grid_line: egui::Color32::from_rgb(0xcc, 0xcc, 0xcc),
                primary_accent: egui::Color32::from_rgb(0xb7, 0x77, 0x14),
                text_muted: egui::Color32::from_rgb(0x55, 0x55, 0x55),
            },
        }
    }

    pub fn visuals(self) -> egui::Visuals {
        let p = self.palette();
        match self {
            Self::GEarth => {
                let mut v = egui::Visuals::light();
                let focus = egui::Color32::from_rgb(0x66, 0xaf, 0xe9);
                let border = egui::Color32::from_rgb(0xcc, 0xcc, 0xcc);
                let hover_bg = egui::Color32::from_rgb(0xe6, 0xe6, 0xe6);
                let hover_border = egui::Color32::from_rgb(0xac, 0xac, 0xac);
                v.window_fill = p.content_bg;
                v.panel_fill = p.content_bg;
                v.extreme_bg_color = egui::Color32::WHITE;
                v.faint_bg_color = p.table_header_bg;
                v.override_text_color = Some(egui::Color32::from_rgb(0x1f, 0x1f, 0x1f));
                v.hyperlink_color = p.primary_accent;
                v.window_rounding = egui::Rounding::same(6.0);
                v.window_stroke = egui::Stroke::new(1.0_f32, p.outer_border);
                v.selection.bg_fill = egui::Color32::from_rgb(0xd9, 0xed, 0xf7);
                v.selection.stroke = egui::Stroke::new(1.0_f32, focus);
                v.widgets.noninteractive.bg_fill = p.content_bg;
                v.widgets.noninteractive.bg_stroke = egui::Stroke::new(1.0_f32, border);
                v.widgets.noninteractive.rounding = egui::Rounding::same(4.0);
                v.widgets.inactive.bg_fill = egui::Color32::WHITE;
                v.widgets.inactive.weak_bg_fill = egui::Color32::WHITE;
                v.widgets.inactive.bg_stroke = egui::Stroke::new(1.0_f32, border);
                v.widgets.inactive.fg_stroke = egui::Stroke::new(1.0_f32, egui::Color32::BLACK);
                v.widgets.inactive.rounding = egui::Rounding::same(4.0);
                v.widgets.hovered.bg_fill = hover_bg;
                v.widgets.hovered.weak_bg_fill = hover_bg;
                v.widgets.hovered.bg_stroke = egui::Stroke::new(1.0_f32, hover_border);
                v.widgets.hovered.fg_stroke = egui::Stroke::new(1.0_f32, egui::Color32::BLACK);
                v.widgets.hovered.rounding = egui::Rounding::same(4.0);
                v.widgets.active.bg_fill = hover_bg;
                v.widgets.active.weak_bg_fill = hover_bg;
                v.widgets.active.bg_stroke = egui::Stroke::new(1.0_f32, focus);
                v.widgets.active.fg_stroke = egui::Stroke::new(1.0_f32, egui::Color32::BLACK);
                v.widgets.active.rounding = egui::Rounding::same(4.0);
                v.widgets.open.bg_fill = egui::Color32::WHITE;
                v.widgets.open.bg_stroke = egui::Stroke::new(1.0_f32, focus);
                v.widgets.open.rounding = egui::Rounding::same(4.0);
                v
            }
            Self::GEarthDark => {
                let mut v = egui::Visuals::dark();
                let focus = egui::Color32::from_rgb(0x66, 0xaf, 0xe9);
                let border = egui::Color32::from_rgb(0x88, 0x88, 0x88);
                let btn_bg = egui::Color32::from_rgb(0x26, 0x26, 0x26);
                let input_bg = egui::Color32::from_rgb(0x36, 0x36, 0x36);
                let text = egui::Color32::from_rgb(0xf0, 0xf0, 0xf0);
                v.window_fill = p.content_bg;
                v.panel_fill = p.content_bg;
                v.extreme_bg_color = input_bg;
                v.faint_bg_color = p.table_header_bg;
                v.override_text_color = Some(text);
                v.hyperlink_color = egui::Color32::from_rgb(0x6e, 0xa8, 0xfe);
                v.window_rounding = egui::Rounding::same(6.0);
                v.window_stroke = egui::Stroke::new(1.0_f32, p.outer_border);
                v.selection.bg_fill = egui::Color32::from_rgb(0x28, 0x60, 0x90);
                v.selection.stroke = egui::Stroke::new(1.0_f32, focus);
                v.widgets.noninteractive.bg_fill = p.content_bg;
                v.widgets.noninteractive.bg_stroke = egui::Stroke::new(1.0_f32, border);
                v.widgets.noninteractive.rounding = egui::Rounding::same(4.0);
                v.widgets.inactive.bg_fill = btn_bg;
                v.widgets.inactive.weak_bg_fill = btn_bg;
                v.widgets.inactive.bg_stroke = egui::Stroke::new(1.0_f32, border);
                v.widgets.inactive.fg_stroke = egui::Stroke::new(1.0_f32, text);
                v.widgets.inactive.rounding = egui::Rounding::same(4.0);
                v.widgets.hovered.bg_fill = input_bg;
                v.widgets.hovered.weak_bg_fill = input_bg;
                v.widgets.hovered.bg_stroke = egui::Stroke::new(1.0_f32, border);
                v.widgets.hovered.fg_stroke = egui::Stroke::new(1.0_f32, text);
                v.widgets.hovered.rounding = egui::Rounding::same(4.0);
                v.widgets.active.bg_fill = input_bg;
                v.widgets.active.weak_bg_fill = input_bg;
                v.widgets.active.bg_stroke = egui::Stroke::new(1.0_f32, focus);
                v.widgets.active.fg_stroke = egui::Stroke::new(1.0_f32, text);
                v.widgets.active.rounding = egui::Rounding::same(4.0);
                v.widgets.open.bg_fill = btn_bg;
                v.widgets.open.bg_stroke = egui::Stroke::new(1.0_f32, focus);
                v.widgets.open.rounding = egui::Rounding::same(4.0);
                v
            }
            Self::Tanji => {
                let mut v = egui::Visuals::light();
                let focus = egui::Color32::from_rgb(0xe9, 0xb3, 0x65);
                let border = egui::Color32::from_rgb(0xcc, 0xcc, 0xcc);
                let hover_bg = egui::Color32::from_rgb(0xee, 0xe8, 0xdf);
                let hover_border = egui::Color32::from_rgb(0xb7, 0x77, 0x14);
                v.window_fill = p.content_bg;
                v.panel_fill = p.content_bg;
                v.extreme_bg_color = egui::Color32::WHITE;
                v.faint_bg_color = p.table_header_bg;
                v.override_text_color = Some(egui::Color32::from_rgb(0x1f, 0x1f, 0x1f));
                v.hyperlink_color = p.primary_accent;
                v.window_rounding = egui::Rounding::same(6.0);
                v.window_stroke = egui::Stroke::new(1.0_f32, p.outer_border);
                v.selection.bg_fill = egui::Color32::from_rgb(0xf6, 0xe4, 0xc1);
                v.selection.stroke = egui::Stroke::new(1.0_f32, focus);
                v.widgets.noninteractive.bg_fill = p.content_bg;
                v.widgets.noninteractive.bg_stroke = egui::Stroke::new(1.0_f32, border);
                v.widgets.noninteractive.rounding = egui::Rounding::same(4.0);
                v.widgets.inactive.bg_fill = egui::Color32::WHITE;
                v.widgets.inactive.weak_bg_fill = egui::Color32::WHITE;
                v.widgets.inactive.bg_stroke = egui::Stroke::new(1.0_f32, border);
                v.widgets.inactive.fg_stroke = egui::Stroke::new(1.0_f32, egui::Color32::BLACK);
                v.widgets.inactive.rounding = egui::Rounding::same(4.0);
                v.widgets.hovered.bg_fill = hover_bg;
                v.widgets.hovered.weak_bg_fill = hover_bg;
                v.widgets.hovered.bg_stroke = egui::Stroke::new(1.0_f32, hover_border);
                v.widgets.hovered.fg_stroke = egui::Stroke::new(1.0_f32, egui::Color32::BLACK);
                v.widgets.hovered.rounding = egui::Rounding::same(4.0);
                v.widgets.active.bg_fill = hover_bg;
                v.widgets.active.weak_bg_fill = hover_bg;
                v.widgets.active.bg_stroke = egui::Stroke::new(1.0_f32, focus);
                v.widgets.active.fg_stroke = egui::Stroke::new(1.0_f32, egui::Color32::BLACK);
                v.widgets.active.rounding = egui::Rounding::same(4.0);
                v.widgets.open.bg_fill = egui::Color32::WHITE;
                v.widgets.open.bg_stroke = egui::Stroke::new(1.0_f32, focus);
                v.widgets.open.rounding = egui::Rounding::same(4.0);
                v
            }
        }
    }
}

pub struct ThemeLogos {
    pub gearth_large: Option<egui::TextureHandle>,
    pub gearth_small: Option<egui::TextureHandle>,
    pub tanji_large: Option<egui::TextureHandle>,
    pub tanji_small: Option<egui::TextureHandle>,
    pub btn_fire: Option<egui::TextureHandle>,
    pub btn_exit: Option<egui::TextureHandle>,
    pub btn_delete: Option<egui::TextureHandle>,
    pub btn_reload: Option<egui::TextureHandle>,
    pub btn_edit: Option<egui::TextureHandle>,
    pub btn_pause: Option<egui::TextureHandle>,
    pub btn_resume: Option<egui::TextureHandle>,
    pub flags: HashMap<&'static str, egui::TextureHandle>,
}

impl ThemeLogos {
    pub fn load(ctx: &egui::Context) -> Self {
        let mut flags = HashMap::new();
        for (code, bytes) in [
            (
                "de",
                include_bytes!("../resources/ui/flags/DE.png").as_slice(),
            ),
            (
                "en",
                include_bytes!("../resources/ui/flags/EN.png").as_slice(),
            ),
            (
                "es",
                include_bytes!("../resources/ui/flags/ES.png").as_slice(),
            ),
            (
                "fi",
                include_bytes!("../resources/ui/flags/FI.png").as_slice(),
            ),
            (
                "fr",
                include_bytes!("../resources/ui/flags/FR.png").as_slice(),
            ),
            (
                "it",
                include_bytes!("../resources/ui/flags/IT.png").as_slice(),
            ),
            (
                "nl",
                include_bytes!("../resources/ui/flags/NL.png").as_slice(),
            ),
            (
                "pt",
                include_bytes!("../resources/ui/flags/PT.png").as_slice(),
            ),
            (
                "tr",
                include_bytes!("../resources/ui/flags/TR.png").as_slice(),
            ),
        ] {
            if let Some(tex) = load_png_texture(ctx, &format!("flag_{code}"), bytes) {
                flags.insert(code, tex);
            }
        }
        Self {
            gearth_large: load_png_texture(
                ctx,
                "gearth_logo_large",
                include_bytes!("../resources/themes/gearth_logo.png"),
            ),
            gearth_small: load_png_texture(
                ctx,
                "gearth_logo_small",
                include_bytes!("../resources/themes/gearth_small.png"),
            ),
            tanji_large: load_png_texture(
                ctx,
                "tanji_logo_large",
                include_bytes!("../resources/themes/tanji_logo.png"),
            ),
            tanji_small: load_png_texture(
                ctx,
                "tanji_logo_small",
                include_bytes!("../resources/themes/tanji_small.png"),
            ),
            btn_fire: load_png_texture(
                ctx,
                "btn_fire",
                include_bytes!("../resources/ui/ButtonFire.png"),
            ),
            btn_exit: load_png_texture(
                ctx,
                "btn_exit",
                include_bytes!("../resources/ui/ButtonExit.png"),
            ),
            btn_delete: load_png_texture(
                ctx,
                "btn_delete",
                include_bytes!("../resources/ui/ButtonDelete.png"),
            ),
            btn_reload: load_png_texture(
                ctx,
                "btn_reload",
                include_bytes!("../resources/ui/ButtonReload.png"),
            ),
            btn_edit: load_png_texture(
                ctx,
                "btn_edit",
                include_bytes!("../resources/ui/ButtonEdit.png"),
            ),
            btn_pause: load_png_texture(
                ctx,
                "btn_pause",
                include_bytes!("../resources/ui/ButtonPause.png"),
            ),
            btn_resume: load_png_texture(
                ctx,
                "btn_resume",
                include_bytes!("../resources/ui/ButtonResume.png"),
            ),
            flags,
        }
    }

    pub fn large(&self, theme: AppTheme) -> Option<&egui::TextureHandle> {
        match theme {
            AppTheme::Tanji => self.tanji_large.as_ref(),
            AppTheme::GEarth | AppTheme::GEarthDark => self.gearth_large.as_ref(),
        }
    }

    pub fn small(&self, theme: AppTheme) -> Option<&egui::TextureHandle> {
        match theme {
            AppTheme::Tanji => self.tanji_small.as_ref(),
            AppTheme::GEarth | AppTheme::GEarthDark => self.gearth_small.as_ref(),
        }
    }

    pub fn flag(&self, code: &str) -> Option<&egui::TextureHandle> {
        self.flags.get(code).or_else(|| self.flags.get("en"))
    }
}

fn load_png_texture(ctx: &egui::Context, name: &str, bytes: &[u8]) -> Option<egui::TextureHandle> {
    let icon = eframe::icon_data::from_png_bytes(bytes).ok()?;
    let image = egui::ColorImage::from_rgba_unmultiplied(
        [icon.width as usize, icon.height as usize],
        &icon.rgba,
    );
    Some(ctx.load_texture(name, image, egui::TextureOptions::LINEAR))
}

/// Draw the iconic G-Earth `#888888` 5px rounded border container.
pub fn group_box<R>(
    ui: &mut egui::Ui,
    theme: AppTheme,
    inner_margin: egui::Margin,
    add_contents: impl FnOnce(&mut egui::Ui) -> R,
) -> egui::InnerResponse<R> {
    let p = theme.palette();
    egui::Frame::none()
        .fill(p.content_bg)
        .stroke(egui::Stroke::new(1.0_f32, p.group_border))
        .rounding(egui::Rounding::same(5.0))
        .inner_margin(inner_margin)
        .show(ui, add_contents)
}

/// Borderless icon action button (e.g., green Play triangle / red Exit door from beta-29).
pub fn icon_action(
    ui: &mut egui::Ui,
    tex: Option<&egui::TextureHandle>,
    fallback: &str,
    size: f32,
) -> egui::Response {
    if let Some(tex) = tex {
        let (rect, response) =
            ui.allocate_exact_size(egui::vec2(size + 4.0, size + 4.0), egui::Sense::click());
        if ui.is_rect_visible(rect) {
            if response.hovered() {
                ui.painter().rect_filled(
                    rect,
                    egui::Rounding::same(3.0),
                    egui::Color32::from_white_alpha(28),
                );
            }
            let img_rect = egui::Rect::from_center_size(rect.center(), egui::vec2(size, size));
            ui.painter().image(
                tex.id(),
                img_rect,
                egui::Rect::from_min_max(egui::pos2(0.0, 0.0), egui::pos2(1.0, 1.0)),
                egui::Color32::WHITE,
            );
        }
        response
    } else {
        ui.small_button(fallback)
    }
}

/// Exact beta-29 titlebar pill switch to toggle G-Earth Light / G-Earth Dark (right-click for Tanji).
pub fn dark_mode_pill_switch(ui: &mut egui::Ui, theme: &mut AppTheme) -> egui::Response {
    let desired = egui::vec2(38.0, 20.0);
    let (rect, response) = ui.allocate_exact_size(desired, egui::Sense::click());
    if response.clicked() {
        *theme = if theme.is_dark() {
            AppTheme::GEarth
        } else {
            AppTheme::GEarthDark
        };
    } else if response.secondary_clicked() {
        *theme = AppTheme::Tanji;
    }
    if ui.is_rect_visible(rect) {
        let radius = rect.height() * 0.5;
        let is_dark = theme.is_dark();
        let bg = if is_dark {
            egui::Color32::from_rgb(0x4a, 0x4a, 0x4a)
        } else if *theme == AppTheme::Tanji {
            egui::Color32::from_rgb(0xe9, 0xb3, 0x65)
        } else {
            egui::Color32::from_rgb(0xd4, 0xd4, 0xd4)
        };
        let border = if is_dark {
            egui::Color32::from_rgb(0x88, 0x88, 0x88)
        } else {
            egui::Color32::from_rgb(0x99, 0x99, 0x99)
        };
        ui.painter()
            .rect(rect, radius, bg, egui::Stroke::new(1.0_f32, border));
        let knob_x = if is_dark {
            rect.right() - radius
        } else {
            rect.left() + radius
        };
        ui.painter().circle_filled(
            egui::pos2(knob_x, rect.center().y),
            radius - 4.0,
            egui::Color32::WHITE,
        );
    }
    response
}

/// Draw an original Bootstrap-styled G-Earth top tab.
pub fn tab_button(
    ui: &mut egui::Ui,
    selected: bool,
    label: &str,
    theme: AppTheme,
) -> egui::Response {
    let p = theme.palette();
    let font = egui::FontId::proportional(13.0);
    let galley = ui.painter().layout_no_wrap(
        label.to_owned(),
        font,
        if selected {
            p.tab_active_text
        } else {
            p.tab_inactive_text
        },
    );
    let desired = egui::vec2(galley.size().x + 20.0, 26.0);
    let (rect, response) = ui.allocate_exact_size(desired, egui::Sense::click());
    if ui.is_rect_visible(rect) {
        let rounding = egui::Rounding {
            nw: 4.0,
            ne: 4.0,
            sw: 0.0,
            se: 0.0,
        };
        let fill = if selected {
            p.tab_active_bg
        } else if response.hovered() {
            p.tab_hover_bg
        } else {
            egui::Color32::TRANSPARENT
        };
        if fill != egui::Color32::TRANSPARENT {
            ui.painter().rect_filled(rect, rounding, fill);
        }
        if selected {
            let stroke = egui::Stroke::new(1.0_f32, p.tab_active_border);
            ui.painter()
                .line_segment([rect.left_bottom(), rect.left_top()], stroke);
            ui.painter()
                .line_segment([rect.left_top(), rect.right_top()], stroke);
            ui.painter()
                .line_segment([rect.right_top(), rect.right_bottom()], stroke);
        }
        let text_pos = egui::pos2(
            rect.center().x - galley.size().x * 0.5,
            rect.center().y - galley.size().y * 0.5,
        );
        ui.painter().galley(text_pos, galley, p.tab_active_text);
    }
    response
}

/// Crisp DPI-independent vector icons drawn directly via `egui::Painter`
/// (never relies on missing Unicode/emoji font glyphs).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VectorIcon {
    Check,
    UpdateArrow,
    Refresh,
    Search,
    Star,
    Warning,
    Gear,
    Close,
    Trash,
    Play,
    Pause,
    Block,
    Sparkle,
    ArrowRight,
    ArrowLeft,
}

pub fn draw_vector_icon(
    painter: &egui::Painter,
    rect: egui::Rect,
    icon: VectorIcon,
    color: egui::Color32,
) {
    let c = rect.center();
    let s = rect.width().min(rect.height());
    let r = s * 0.44;
    let sw = (s * 0.125).clamp(1.2_f32, 2.4_f32);
    let stroke = egui::Stroke::new(sw, color);

    match icon {
        VectorIcon::Check => {
            let p1 = egui::pos2(c.x - r * 0.85, c.y + r * 0.05);
            let p2 = egui::pos2(c.x - r * 0.22, c.y + r * 0.68);
            let p3 = egui::pos2(c.x + r * 0.90, c.y - r * 0.62);
            painter.line_segment([p1, p2], stroke);
            painter.line_segment([p2, p3], stroke);
        }
        VectorIcon::UpdateArrow => {
            let top = egui::pos2(c.x, c.y - r * 0.85);
            let bot = egui::pos2(c.x, c.y + r * 0.85);
            let left = egui::pos2(c.x - r * 0.68, c.y - r * 0.12);
            let right = egui::pos2(c.x + r * 0.68, c.y - r * 0.12);
            painter.line_segment([bot, top], stroke);
            painter.line_segment([left, top], stroke);
            painter.line_segment([right, top], stroke);
        }
        VectorIcon::Refresh => {
            // 270-degree circular arc + crisp arrowhead
            let arc_r = r * 0.78;
            let segments = 14usize;
            let start_deg = -45.0_f32;
            let sweep_deg = 275.0_f32;
            let pts: Vec<egui::Pos2> = (0..=segments)
                .map(|i| {
                    let deg = start_deg + sweep_deg * (i as f32 / segments as f32);
                    let rad = deg.to_radians();
                    egui::pos2(c.x + arc_r * rad.cos(), c.y + arc_r * rad.sin())
                })
                .collect();
            painter.add(egui::Shape::line(pts, stroke));
            let tip_rad = start_deg.to_radians();
            let tip = egui::pos2(c.x + arc_r * tip_rad.cos(), c.y + arc_r * tip_rad.sin());
            let head = r * 0.42;
            painter.line_segment([tip, egui::pos2(tip.x - head, tip.y - head * 0.15)], stroke);
            painter.line_segment([tip, egui::pos2(tip.x + head * 0.1, tip.y - head)], stroke);
        }
        VectorIcon::Search => {
            let lens_c = egui::pos2(c.x - r * 0.18, c.y - r * 0.18);
            let lens_r = r * 0.58;
            painter.circle_stroke(lens_c, lens_r, stroke);
            let h_start = egui::pos2(lens_c.x + lens_r * 0.70, lens_c.y + lens_r * 0.70);
            let h_end = egui::pos2(c.x + r * 0.88, c.y + r * 0.88);
            painter.line_segment([h_start, h_end], egui::Stroke::new(sw * 1.15, color));
        }
        VectorIcon::Star => {
            let inner_r = r * 0.42;
            let pts: Vec<egui::Pos2> = (0..10)
                .map(|i| {
                    let rad = (-90.0_f32 + i as f32 * 36.0_f32).to_radians();
                    let rad_len = if i % 2 == 0 { r * 0.95 } else { inner_r };
                    egui::pos2(c.x + rad_len * rad.cos(), c.y + rad_len * rad.sin())
                })
                .collect();
            for i in 0..10 {
                let next = (i + 1) % 10;
                painter.add(egui::Shape::convex_polygon(
                    vec![c, pts[i], pts[next]],
                    color,
                    egui::Stroke::NONE,
                ));
            }
        }
        VectorIcon::Warning => {
            let top = egui::pos2(c.x, c.y - r * 0.88);
            let bl = egui::pos2(c.x - r * 0.92, c.y + r * 0.76);
            let br = egui::pos2(c.x + r * 0.92, c.y + r * 0.76);
            painter.line_segment([top, br], stroke);
            painter.line_segment([br, bl], stroke);
            painter.line_segment([bl, top], stroke);
            painter.line_segment(
                [
                    egui::pos2(c.x, c.y - r * 0.30),
                    egui::pos2(c.x, c.y + r * 0.22),
                ],
                stroke,
            );
            painter.circle_filled(egui::pos2(c.x, c.y + r * 0.48), (sw * 0.55).max(1.0), color);
        }
        VectorIcon::Gear => {
            let ring_r = r * 0.54;
            painter.circle_stroke(c, ring_r, egui::Stroke::new(sw * 1.15, color));
            for i in 0..8 {
                let rad = (i as f32 * 45.0_f32).to_radians();
                let p0 = egui::pos2(
                    c.x + (ring_r * 1.05) * rad.cos(),
                    c.y + (ring_r * 1.05) * rad.sin(),
                );
                let p1 = egui::pos2(c.x + (r * 0.95) * rad.cos(), c.y + (r * 0.95) * rad.sin());
                painter.line_segment([p0, p1], egui::Stroke::new(sw * 1.1, color));
            }
        }
        VectorIcon::Close => {
            let d = r * 0.66;
            painter.line_segment(
                [egui::pos2(c.x - d, c.y - d), egui::pos2(c.x + d, c.y + d)],
                stroke,
            );
            painter.line_segment(
                [egui::pos2(c.x + d, c.y - d), egui::pos2(c.x - d, c.y + d)],
                stroke,
            );
        }
        VectorIcon::Trash => {
            // Lid + handle
            painter.line_segment(
                [
                    egui::pos2(c.x - r * 0.78, c.y - r * 0.45),
                    egui::pos2(c.x + r * 0.78, c.y - r * 0.45),
                ],
                stroke,
            );
            painter.line_segment(
                [
                    egui::pos2(c.x - r * 0.30, c.y - r * 0.75),
                    egui::pos2(c.x + r * 0.30, c.y - r * 0.75),
                ],
                stroke,
            );
            // Bin body
            let body = egui::Rect::from_min_max(
                egui::pos2(c.x - r * 0.58, c.y - r * 0.42),
                egui::pos2(c.x + r * 0.58, c.y + r * 0.80),
            );
            painter.rect_stroke(body, egui::Rounding::same(1.5), stroke);
            let slat_s = egui::Stroke::new((sw * 0.85).max(1.0), color);
            painter.line_segment(
                [
                    egui::pos2(c.x - r * 0.18, c.y - r * 0.18),
                    egui::pos2(c.x - r * 0.18, c.y + r * 0.55),
                ],
                slat_s,
            );
            painter.line_segment(
                [
                    egui::pos2(c.x + r * 0.18, c.y - r * 0.18),
                    egui::pos2(c.x + r * 0.18, c.y + r * 0.55),
                ],
                slat_s,
            );
        }
        VectorIcon::Play => {
            let pts = vec![
                egui::pos2(c.x - r * 0.55, c.y - r * 0.78),
                egui::pos2(c.x + r * 0.82, c.y),
                egui::pos2(c.x - r * 0.55, c.y + r * 0.78),
            ];
            painter.add(egui::Shape::convex_polygon(pts, color, egui::Stroke::NONE));
        }
        VectorIcon::Pause => {
            let bw = r * 0.42;
            let bh = r * 0.78;
            painter.rect_filled(
                egui::Rect::from_min_max(
                    egui::pos2(c.x - r * 0.62, c.y - bh),
                    egui::pos2(c.x - r * 0.62 + bw, c.y + bh),
                ),
                egui::Rounding::same(1.0),
                color,
            );
            painter.rect_filled(
                egui::Rect::from_min_max(
                    egui::pos2(c.x + r * 0.62 - bw, c.y - bh),
                    egui::pos2(c.x + r * 0.62, c.y + bh),
                ),
                egui::Rounding::same(1.0),
                color,
            );
        }
        VectorIcon::Block => {
            let cr = r * 0.78;
            painter.circle_stroke(c, cr, stroke);
            let d = cr * 0.68;
            painter.line_segment(
                [egui::pos2(c.x - d, c.y - d), egui::pos2(c.x + d, c.y + d)],
                stroke,
            );
        }
        VectorIcon::Sparkle => {
            let pts = [
                egui::pos2(c.x, c.y - r * 0.92),
                egui::pos2(c.x + r * 0.28, c.y - r * 0.28),
                egui::pos2(c.x + r * 0.92, c.y),
                egui::pos2(c.x + r * 0.28, c.y + r * 0.28),
                egui::pos2(c.x, c.y + r * 0.92),
                egui::pos2(c.x - r * 0.28, c.y + r * 0.28),
                egui::pos2(c.x - r * 0.92, c.y),
                egui::pos2(c.x - r * 0.28, c.y - r * 0.28),
            ];
            for i in 0..8 {
                let next = (i + 1) % 8;
                painter.add(egui::Shape::convex_polygon(
                    vec![c, pts[i], pts[next]],
                    color,
                    egui::Stroke::NONE,
                ));
            }
        }
        VectorIcon::ArrowRight => {
            let left = egui::pos2(c.x - r * 0.78, c.y);
            let right = egui::pos2(c.x + r * 0.78, c.y);
            painter.line_segment([left, right], stroke);
            painter.line_segment([egui::pos2(c.x + r * 0.14, c.y - r * 0.62), right], stroke);
            painter.line_segment([egui::pos2(c.x + r * 0.14, c.y + r * 0.62), right], stroke);
        }
        VectorIcon::ArrowLeft => {
            let left = egui::pos2(c.x - r * 0.78, c.y);
            let right = egui::pos2(c.x + r * 0.78, c.y);
            painter.line_segment([left, right], stroke);
            painter.line_segment([egui::pos2(c.x - r * 0.14, c.y - r * 0.62), left], stroke);
            painter.line_segment([egui::pos2(c.x - r * 0.14, c.y + r * 0.62), left], stroke);
        }
    }
}

/// Inline vector icon with no border.
pub fn vector_icon(
    ui: &mut egui::Ui,
    icon: VectorIcon,
    size: f32,
    color: egui::Color32,
) -> egui::Response {
    let (rect, resp) = ui.allocate_exact_size(egui::vec2(size, size), egui::Sense::hover());
    if ui.is_rect_visible(rect) {
        draw_vector_icon(ui.painter(), rect, icon, color);
    }
    resp
}

/// Compact clickable button containing only a crisp vector icon.
pub fn vector_icon_button(
    ui: &mut egui::Ui,
    icon: VectorIcon,
    button_size: egui::Vec2,
    icon_size: f32,
    fill: Option<egui::Color32>,
    color: egui::Color32,
) -> egui::Response {
    let (rect, resp) = ui.allocate_exact_size(button_size, egui::Sense::click());
    if ui.is_rect_visible(rect) {
        let visuals = ui.style().interact(&resp);
        let bg = match fill {
            Some(base) if resp.hovered() => base.linear_multiply(1.12),
            Some(base) => base,
            None => visuals.bg_fill,
        };
        let stroke = if fill.is_some() {
            egui::Stroke::NONE
        } else {
            visuals.bg_stroke
        };
        ui.painter().rect(rect, visuals.rounding, bg, stroke);
        let icon_rect =
            egui::Rect::from_center_size(rect.center(), egui::vec2(icon_size, icon_size));
        draw_vector_icon(ui.painter(), icon_rect, icon, color);
    }
    resp
}

/// Clickable button with a crisp vector icon on the left and a text label on the right.
pub fn vector_text_button(
    ui: &mut egui::Ui,
    icon: VectorIcon,
    icon_color: egui::Color32,
    label: &str,
    text_color: Option<egui::Color32>,
    fill: Option<egui::Color32>,
    small: bool,
) -> egui::Response {
    let font = if small {
        egui::FontId::proportional(11.5)
    } else {
        egui::FontId::proportional(12.5)
    };
    let fg = text_color.unwrap_or_else(|| ui.visuals().text_color());
    let galley = ui.painter().layout_no_wrap(label.to_owned(), font, fg);
    let icon_sz = if small { 11.5_f32 } else { 13.0_f32 };
    let pad_x = if small { 6.0_f32 } else { 8.0_f32 };
    let pad_y = if small { 3.0_f32 } else { 4.5_f32 };
    let gap = 4.5_f32;
    let desired = egui::vec2(
        pad_x * 2.0 + icon_sz + gap + galley.size().x,
        (galley.size().y.max(icon_sz) + pad_y * 2.0).max(if small { 20.0 } else { 24.0 }),
    );
    let (rect, resp) = ui.allocate_exact_size(desired, egui::Sense::click());
    if ui.is_rect_visible(rect) {
        let visuals = ui.style().interact(&resp);
        let bg = match fill {
            Some(base) if resp.hovered() => base.linear_multiply(1.08),
            Some(base) => base,
            None => visuals.bg_fill,
        };
        let stroke = if fill == Some(egui::Color32::TRANSPARENT) {
            egui::Stroke::new(1.0_f32, visuals.bg_stroke.color)
        } else if fill.is_some() {
            egui::Stroke::NONE
        } else {
            visuals.bg_stroke
        };
        ui.painter().rect(rect, visuals.rounding, bg, stroke);
        let icon_center = egui::pos2(rect.left() + pad_x + icon_sz * 0.5, rect.center().y);
        draw_vector_icon(
            ui.painter(),
            egui::Rect::from_center_size(icon_center, egui::vec2(icon_sz, icon_sz)),
            icon,
            icon_color,
        );
        let text_pos = egui::pos2(
            rect.left() + pad_x + icon_sz + gap,
            rect.center().y - galley.size().y * 0.5,
        );
        ui.painter().galley(text_pos, galley, fg);
    }
    resp
}

/// Parse beta-29 `500+0` or `500` scheduler interval strings.
pub fn parse_interval_spec(input: &str) -> Result<(u64, Option<u64>), String> {
    let trimmed = input.trim();
    if let Some((delay_str, offset_str)) = trimmed.split_once('+') {
        let delay = delay_str
            .trim()
            .parse::<u64>()
            .map_err(|_| "Invalid interval".to_owned())?;
        let offset = offset_str
            .trim()
            .parse::<u64>()
            .map_err(|_| "Invalid offset".to_owned())?;
        if delay == 0 || delay > gearth_rust::scheduler::MAX_INTERVAL_MS {
            return Err("Interval out of range".into());
        }
        if offset > delay {
            return Err("Offset must not exceed the interval".into());
        }
        Ok((delay, Some(offset)))
    } else {
        let delay = trimmed
            .parse::<u64>()
            .map_err(|_| "Invalid interval".to_owned())?;
        if delay == 0 || delay > gearth_rust::scheduler::MAX_INTERVAL_MS {
            return Err("Interval out of range".into());
        }
        Ok((delay, None))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_theme_logos_decode_cleanly() {
        for (name, bytes) in [
            (
                "gearth_logo",
                include_bytes!("../resources/themes/gearth_logo.png").as_slice(),
            ),
            (
                "gearth_small",
                include_bytes!("../resources/themes/gearth_small.png").as_slice(),
            ),
            (
                "tanji_logo",
                include_bytes!("../resources/themes/tanji_logo.png").as_slice(),
            ),
            (
                "tanji_small",
                include_bytes!("../resources/themes/tanji_small.png").as_slice(),
            ),
            (
                "btn_fire",
                include_bytes!("../resources/ui/ButtonFire.png").as_slice(),
            ),
            (
                "btn_exit",
                include_bytes!("../resources/ui/ButtonExit.png").as_slice(),
            ),
            (
                "btn_edit",
                include_bytes!("../resources/ui/ButtonEdit.png").as_slice(),
            ),
            (
                "btn_pause",
                include_bytes!("../resources/ui/ButtonPause.png").as_slice(),
            ),
            (
                "btn_resume",
                include_bytes!("../resources/ui/ButtonResume.png").as_slice(),
            ),
            (
                "btn_delete",
                include_bytes!("../resources/ui/ButtonDelete.png").as_slice(),
            ),
            (
                "flag_fr",
                include_bytes!("../resources/ui/flags/FR.png").as_slice(),
            ),
            (
                "flag_en",
                include_bytes!("../resources/ui/flags/EN.png").as_slice(),
            ),
        ] {
            let icon = eframe::icon_data::from_png_bytes(bytes)
                .unwrap_or_else(|e| panic!("failed to decode {name}: {e}"));
            assert!(icon.width > 0 && icon.height > 0, "{name} empty");
        }
    }

    #[test]
    fn interval_spec_parses_beta29_delay_and_offset() {
        assert_eq!(parse_interval_spec("500+0").unwrap(), (500, Some(0)));
        assert_eq!(parse_interval_spec("1000+250").unwrap(), (1000, Some(250)));
        assert_eq!(parse_interval_spec("250").unwrap(), (250, None));
        assert!(parse_interval_spec("0+0").is_err());
        assert!(parse_interval_spec("500+501").is_err());
        assert!(parse_interval_spec("abc").is_err());
    }
}
