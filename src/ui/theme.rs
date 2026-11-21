use crate::models::{ForensicConfidence, MitreTactic};
use ratatui::style::{Color, Modifier, Style};

pub struct DfirTheme;

impl DfirTheme {
    // High-contrast Obsidian DFIR Palette
    pub const OBSIDIAN_BG: Color = Color::Rgb(11, 14, 20);
    pub const PANEL_BG: Color = Color::Rgb(17, 21, 30);
    pub const BORDER_NORMAL: Color = Color::Rgb(60, 72, 92);
    pub const BORDER_FOCUSED: Color = Color::Rgb(0, 240, 255); // Electric Cyan
    pub const TEXT_PRIMARY: Color = Color::Rgb(226, 232, 240);
    pub const TEXT_DIM: Color = Color::Rgb(125, 137, 156);

    // Accent Alert Colors
    pub const CYAN_TIMESTAMP: Color = Color::Rgb(0, 240, 255);
    pub const AMBER_BURST: Color = Color::Rgb(255, 184, 0);
    pub const CRIMSON_ALERT: Color = Color::Rgb(255, 46, 85);
    pub const EMERALD_CLEAN: Color = Color::Rgb(0, 230, 118);
    pub const PURPLE_PERSIST: Color = Color::Rgb(189, 147, 249);
    pub const MAGENTA_EVASION: Color = Color::Rgb(255, 85, 187);

    // Entropy Analysis Colors
    pub const ENTROPY_PACKED: Color = Color::Rgb(255, 46, 85);    // Blood red  — > 7.2
    pub const ENTROPY_HIGH: Color = Color::Rgb(255, 184, 0);       // Amber      — 6.0–7.2
    pub const ENTROPY_NORMAL: Color = Color::Rgb(0, 230, 118);     // Emerald    — < 6.0
    pub const ENTROPY_BAR_DIM: Color = Color::Rgb(45, 55, 72);    // Dim track fill

    pub fn base_style() -> Style {
        Style::default().bg(Self::OBSIDIAN_BG).fg(Self::TEXT_PRIMARY)
    }

    pub fn panel_block(title: &str, is_focused: bool) -> ratatui::widgets::Block<'static> {
        let border_color = if is_focused {
            Self::BORDER_FOCUSED
        } else {
            Self::BORDER_NORMAL
        };

        ratatui::widgets::Block::default()
            .borders(ratatui::widgets::Borders::ALL)
            .border_style(Style::default().fg(border_color))
            .title(format!(" {} ", title))
            .title_style(
                Style::default()
                    .fg(if is_focused {
                        Self::CYAN_TIMESTAMP
                    } else {
                        Self::TEXT_DIM
                    })
                    .add_modifier(Modifier::BOLD),
            )
            .style(Style::default().bg(Self::PANEL_BG))
    }

    pub fn confidence_style(conf: ForensicConfidence) -> Style {
        match conf {
            ForensicConfidence::Info => Style::default().fg(Self::TEXT_DIM),
            ForensicConfidence::Low => Style::default().fg(Color::Rgb(100, 200, 255)),
            ForensicConfidence::Medium => Style::default().fg(Self::AMBER_BURST),
            ForensicConfidence::High => Style::default().fg(Color::Rgb(255, 110, 50)),
            ForensicConfidence::Critical => Style::default()
                .fg(Self::CRIMSON_ALERT)
                .add_modifier(Modifier::BOLD),
        }
    }

    pub fn tactic_color(tactic: Option<MitreTactic>) -> Color {
        match tactic {
            Some(MitreTactic::InitialAccess) => Color::Rgb(255, 130, 0),
            Some(MitreTactic::Execution) => Self::CRIMSON_ALERT,
            Some(MitreTactic::Persistence) => Self::PURPLE_PERSIST,
            Some(MitreTactic::PrivilegeEscalation) => Color::Rgb(255, 60, 60),
            Some(MitreTactic::DefenseEvasion) => Self::MAGENTA_EVASION,
            Some(MitreTactic::CredentialAccess) => Color::Rgb(255, 215, 0),
            Some(MitreTactic::Discovery) => Color::Rgb(0, 200, 255),
            Some(MitreTactic::LateralMovement) => Color::Rgb(160, 100, 240),
            Some(MitreTactic::Collection) => Color::Rgb(80, 220, 180),
            Some(MitreTactic::CommandAndControl) => Color::Rgb(255, 70, 120),
            Some(MitreTactic::Exfiltration) => Color::Rgb(255, 90, 40),
            Some(MitreTactic::Impact) => Color::Rgb(220, 20, 60),
            Some(MitreTactic::Unknown) | None => Self::TEXT_DIM,
        }
    }
}
