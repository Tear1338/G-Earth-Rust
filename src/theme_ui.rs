//! Original G-Earth 1.5.4-beta-29 Bootstrap/JavaFX theme visuals, logos, and layout primitives.
use eframe::egui;

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

    pub fn next(self) -> Self {
        match self {
            Self::GEarth => Self::GEarthDark,
            Self::GEarthDark => Self::Tanji,
            Self::Tanji => Self::GEarth,
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
                table_header_text: egui::Color32::from_rgb(0x66, 0x66, 0x66),
                table_row_alt_bg: egui::Color32::from_rgb(0xfa, 0xfa, 0xfa),
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
                table_header_text: egui::Color32::from_rgb(0xcc, 0xcc, 0xcc),
                table_row_alt_bg: egui::Color32::from_rgb(0x38, 0x38, 0x38),
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
                table_header_text: egui::Color32::from_rgb(0x66, 0x66, 0x66),
                table_row_alt_bg: egui::Color32::from_rgb(0xfc, 0xf9, 0xf4),
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
}

impl ThemeLogos {
    pub fn load(ctx: &egui::Context) -> Self {
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
