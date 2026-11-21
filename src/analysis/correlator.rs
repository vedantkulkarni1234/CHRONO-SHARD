use crate::models::{EventSource, ForensicEvent, MitreTactic, TemporalBurst};
use chrono::Duration;
use std::collections::{HashMap, HashSet};

pub struct Correlator {
    window_duration: Duration,
    burst_threshold_events: usize,
}

impl Correlator {
    pub fn new(window_seconds: i64, burst_threshold_events: usize) -> Self {
        Self {
            window_duration: Duration::seconds(window_seconds),
            burst_threshold_events,
        }
    }

    /// Primary correlation pipeline:
    /// 1. Chronological sort (strictly by UTC)
    /// 2. Deduplication (hash fingerprint)
    /// 3. Sliding-window temporal burst detection
    pub fn process(&self, mut events: Vec<ForensicEvent>) -> (Vec<ForensicEvent>, Vec<TemporalBurst>) {
        if events.is_empty() {
            return (Vec::new(), Vec::new());
        }

        // 1. Chronological sort
        events.sort_by_key(|e| e.timestamp);

        // 2. Deduplication based on timestamp + source + summary
        let mut seen = HashSet::new();
        events.retain(|e| {
            let key = (
                e.timestamp.timestamp(),
                e.source,
                e.summary.clone(),
                e.path_or_target.clone(),
            );
            seen.insert(key)
        });

        // 3. Sliding-window burst detection
        let bursts = self.detect_bursts(&mut events);

        (events, bursts)
    }

    fn detect_bursts(&self, events: &mut [ForensicEvent]) -> Vec<TemporalBurst> {
        let mut bursts = Vec::new();
        let len = events.len();
        if len == 0 {
            return bursts;
        }

        let mut right = 0;
        let mut burst_counter = 0;
        let mut in_burst_indices = HashSet::new();

        for left in 0..len {
            let left_time = events[left].timestamp;
            let window_end = left_time + self.window_duration;

            while right < len && events[right].timestamp <= window_end {
                right += 1;
            }

            let count = right - left;
            if count >= self.burst_threshold_events {
                // Check if any of these indices are already part of an overlapping burst
                let cluster_indices: Vec<usize> = (left..right)
                    .filter(|idx| !in_burst_indices.contains(idx))
                    .collect();

                if cluster_indices.len() >= (self.burst_threshold_events / 2).max(3) {
                    burst_counter += 1;
                    let burst_id = burst_counter;

                    let mut source_counts: HashMap<EventSource, usize> = HashMap::new();
                    let mut tactics_set: HashSet<MitreTactic> = HashSet::new();
                    let mut max_anomaly: f32 = 0.0;

                    let b_start = events[cluster_indices[0]].timestamp;
                    let b_end = events[*cluster_indices.last().unwrap()].timestamp;

                    for &idx in &cluster_indices {
                        in_burst_indices.insert(idx);
                        events[idx].burst_id = Some(burst_id);
                        *source_counts.entry(events[idx].source).or_insert(0) += 1;

                        if let Some(tactic) = events[idx].tactic {
                            tactics_set.insert(tactic);
                        }
                        if events[idx].anomaly_score > max_anomaly {
                            max_anomaly = events[idx].anomaly_score;
                        }
                    }

                    let dominant_source = source_counts
                        .into_iter()
                        .max_by_key(|(_, count)| *count)
                        .map(|(s, _)| s)
                        .unwrap_or(EventSource::Filesystem);

                    let tactics_vec: Vec<MitreTactic> = tactics_set.into_iter().collect();
                    let tactic_names: Vec<&str> = tactics_vec.iter().map(|t| t.name()).collect();

                    let summary = format!(
                        "Burst #{}: {} events in {}s [{}] {}",
                        burst_id,
                        cluster_indices.len(),
                        (b_end - b_start).num_seconds().max(1),
                        dominant_source.as_str(),
                        if !tactic_names.is_empty() {
                            format!("- Tactics: {}", tactic_names.join(", "))
                        } else {
                            String::new()
                        }
                    );

                    // Burst anomaly score incorporates density and tactic severity
                    let density_bonus = ((cluster_indices.len() as f32) / 20.0).min(0.3);
                    let final_anomaly = (max_anomaly + density_bonus).min(1.0);

                    bursts.push(TemporalBurst {
                        id: burst_id,
                        start_time: b_start,
                        end_time: b_end,
                        event_count: cluster_indices.len(),
                        anomaly_score: final_anomaly,
                        dominant_source,
                        summary,
                        mitre_tactics: tactics_vec,
                    });
                }
            }
        }

        bursts
    }

    /// Generates bucketed sparkline/histogram data for the TUI header
    pub fn generate_sparkline_buckets(events: &[ForensicEvent], num_buckets: usize) -> Vec<u64> {
        if events.is_empty() || num_buckets == 0 {
            return vec![0; num_buckets];
        }

        let first = events.first().unwrap().timestamp;
        let last = events.last().unwrap().timestamp;
        let total_seconds = (last - first).num_seconds().max(1) as f64;
        let bucket_span = total_seconds / (num_buckets as f64);

        let mut buckets = vec![0u64; num_buckets];

        for ev in events {
            let offset = (ev.timestamp - first).num_seconds().max(0) as f64;
            let mut idx = (offset / bucket_span) as usize;
            if idx >= num_buckets {
                idx = num_buckets - 1;
            }
            buckets[idx] += 1;
        }

        buckets
    }
}
