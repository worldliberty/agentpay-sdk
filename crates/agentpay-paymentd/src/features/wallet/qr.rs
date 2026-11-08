//! QR codes for funding URIs: an SVG document and terminal text, both drawn
//! from the module grid of the `qrcode` crate (error correction level M,
//! 4-module quiet zone).

use std::fmt::Write as _;

use agentpay_api::payments::FundingQr;
use qrcode::{Color, EcLevel, QrCode};

use crate::error::PaymentsError;

/// Light modules around the code.
const QUIET_ZONE: usize = 4;
/// SVG pixels per module.
const SVG_SCALE: usize = 8;

/// Renders `text` as a QR code.
pub(super) fn render(text: &str) -> Result<FundingQr, PaymentsError> {
    let code = QrCode::with_error_correction_level(text.as_bytes(), EcLevel::M)
        .map_err(|err| PaymentsError::InvalidRequest(format!("cannot encode a QR code: {err}")))?;
    let grid = Grid::new(code.width(), &code.to_colors());
    Ok(FundingQr {
        modules: u32::try_from(code.width()).unwrap_or(u32::MAX),
        svg: grid.svg(),
        terminal: grid.terminal(),
    })
}

/// The modules with the quiet zone; `true` is dark.
struct Grid {
    size: usize,
    dark: Vec<bool>,
}

impl Grid {
    fn new(width: usize, colors: &[Color]) -> Self {
        let size = width + 2 * QUIET_ZONE;
        let mut dark = vec![false; size * size];
        for (index, color) in colors.iter().enumerate() {
            let (x, y) = (index % width, index / width);
            dark[(y + QUIET_ZONE) * size + x + QUIET_ZONE] = *color == Color::Dark;
        }
        Self { size, dark }
    }

    fn is_dark(&self, x: usize, y: usize) -> bool {
        y < self.size && x < self.size && self.dark[y * self.size + x]
    }

    /// Black modules on white, one path of horizontal runs.
    fn svg(&self) -> String {
        let pixels = self.size * SVG_SCALE;
        let mut path = String::new();
        for y in 0..self.size {
            let mut x = 0;
            while x < self.size {
                if !self.is_dark(x, y) {
                    x += 1;
                    continue;
                }
                let start = x;
                while x < self.size && self.is_dark(x, y) {
                    x += 1;
                }
                let run = x - start;
                let _ = write!(path, "M{start} {y}h{run}v1h-{run}z");
            }
        }
        format!(
            "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 {size} {size}\" \
             width=\"{pixels}\" height=\"{pixels}\" shape-rendering=\"crispEdges\" role=\"img\" \
             aria-label=\"Funding QR code\"><rect width=\"{size}\" height=\"{size}\" fill=\"#fff\"/>\
             <path d=\"{path}\" fill=\"#000\"/></svg>",
            size = self.size,
        )
    }

    /// Two module rows per line; light modules are drawn (dark backgrounds).
    fn terminal(&self) -> String {
        let mut lines = Vec::with_capacity(self.size.div_ceil(2));
        for y in (0..self.size).step_by(2) {
            let line: String = (0..self.size)
                .map(|x| {
                    let top = !self.is_dark(x, y);
                    // Below the last row is outside the code: leave it blank.
                    let bottom = y + 1 < self.size && !self.is_dark(x, y + 1);
                    match (top, bottom) {
                        (true, true) => '█',
                        (true, false) => '▀',
                        (false, true) => '▄',
                        (false, false) => ' ',
                    }
                })
                .collect();
            lines.push(line);
        }
        lines.join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn svg_and_terminal_draw_the_same_modules() {
        let uri = "ethereum:0x8d0d000ee44948fc98c9b98a4fa4921476f08b0d@56/transfer?address=0x2c7536e3605d9c16a7a3d7b1898e529396a65c23";
        let qr = render(uri).expect("qr");
        let code = QrCode::with_error_correction_level(uri.as_bytes(), EcLevel::M).expect("code");
        assert_eq!(qr.modules as usize, code.width());
        let size = code.width() + 2 * QUIET_ZONE;

        assert!(qr
            .svg
            .starts_with("<svg xmlns=\"http://www.w3.org/2000/svg\""));
        assert!(qr.svg.contains(&format!("viewBox=\"0 0 {size} {size}\"")));
        assert!(qr.svg.ends_with("</svg>"));
        // The top-left finder pattern starts at the quiet zone with a 7-module run.
        assert!(qr
            .svg
            .contains(&format!("M{QUIET_ZONE} {QUIET_ZONE}h7v1h-7z")));

        let lines: Vec<&str> = qr.terminal.lines().collect();
        assert_eq!(lines.len(), size.div_ceil(2));
        assert!(lines.iter().all(|line| line.chars().count() == size));
        // The quiet zone is light, so the first two rows are solid blocks.
        assert!(lines[0].chars().all(|c| c == '█'));
        // Decoding the text back gives the module grid.
        let colors = code.to_colors();
        for y in 0..code.width() {
            for x in 0..code.width() {
                let row = y + QUIET_ZONE;
                let cell = lines[row / 2].chars().nth(x + QUIET_ZONE).expect("cell");
                let light = if row.is_multiple_of(2) {
                    matches!(cell, '█' | '▀')
                } else {
                    matches!(cell, '█' | '▄')
                };
                assert_eq!(
                    light,
                    colors[y * code.width() + x] == Color::Light,
                    "({x}, {y})"
                );
            }
        }
    }

    #[test]
    fn rendering_is_deterministic() {
        assert_eq!(
            render("solana:abc").expect("a"),
            render("solana:abc").expect("b")
        );
    }
}
