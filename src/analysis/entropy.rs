/// Shannon Entropy analysis and obfuscation detection
/// Pure Rust — no external dependencies required

/// Compute Shannon entropy H(X) for a byte slice.
/// Returns a value in [0.0, 8.0] where 8.0 is maximum (fully random / encrypted).
pub fn shannon_entropy(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u64; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let len = data.len() as f32;
    freq.iter()
        .filter(|&&c| c > 0)
        .fold(0.0f32, |acc, &c| {
            let p = c as f32 / len;
            acc - p * p.log2()
        })
}

/// Extract printable ASCII strings (runs of >= 4 printable bytes), up to `max_strings`.
/// Equivalent to running `strings` on the binary.
pub fn extract_strings(data: &[u8], max_strings: usize) -> Vec<String> {
    let mut result = Vec::new();
    let mut current = Vec::new();

    for &b in data {
        if b >= 0x20 && b < 0x7f {
            current.push(b);
        } else {
            if current.len() >= 4 {
                if let Ok(s) = std::str::from_utf8(&current) {
                    result.push(s.to_string());
                    if result.len() >= max_strings {
                        break;
                    }
                }
            }
            current.clear();
        }
    }

    // Flush trailing run
    if current.len() >= 4 && result.len() < max_strings {
        if let Ok(s) = std::str::from_utf8(&current) {
            result.push(s.to_string());
        }
    }

    result
}

/// Entropy classification tier
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EntropyClass {
    Normal,           // < 6.0 — typical source/text
    HighEntropy,      // 6.0–7.2 — compressed, possibly suspicious
    PackedOrEncrypted, // > 7.2 — UPX / XOR / AES payload
}

pub fn classify_entropy(e: f32) -> EntropyClass {
    if e > 7.2 {
        EntropyClass::PackedOrEncrypted
    } else if e > 6.0 {
        EntropyClass::HighEntropy
    } else {
        EntropyClass::Normal
    }
}

/// Render an 8-segment Unicode block spark-bar for entropy [0.0, 8.0].
/// Returns a String of 8 Unicode block chars (▁▂▃▄▅▆▇█).
#[allow(dead_code)]
pub fn entropy_spark_bar(entropy: f32) -> String {
    let (active, dim) = entropy_spark_bar_parts(entropy);
    format!("{}{}", active, dim)
}

/// Returns (active_bar_spans, dim_track_spans) for two-tone spark-bar rendering.
pub fn entropy_spark_bar_parts(entropy: f32) -> (String, String) {
    const BLOCKS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
    let clamped = entropy.clamp(0.0, 8.0);
    // Each of 8 segments represents 1.0 of entropy
    let full_segments = (clamped.floor() as usize).min(8);
    let remainder = clamped - clamped.floor();
    // Fractional block index (0–7)
    let frac_block = if full_segments < 8 && remainder > 0.0 {
        let idx = ((remainder * 8.0) as usize).min(7);
        Some(BLOCKS[idx])
    } else {
        None
    };

    let mut active = String::with_capacity(8);
    for _ in 0..full_segments {
        active.push('█');
    }
    if let Some(fb) = frac_block {
        active.push(fb);
    }
    let filled_count = active.chars().count();
    let dim: String = (0..8usize.saturating_sub(filled_count)).map(|_| '░').collect();
    (active, dim)
}
