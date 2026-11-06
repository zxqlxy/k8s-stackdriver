//! Deterministic horizontal sharding (KEP-5866 server-side and Jump Consistent Hash client-side).

/// Sharding strategy across StatefulSet replicas.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShardMode {
    None,
    Client,
    Server,
}

impl ShardMode {
    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "none" | "" => Ok(Self::None),
            "client" => Ok(Self::Client),
            "server" => Ok(Self::Server),
            other => Err(format!(
                "unsupported --shard-mode='{other}' (expected none, client, or server)"
            )),
        }
    }
}

/// Active shard assignment for this replica.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShardSpec {
    pub mode: ShardMode,
    pub shard_count: u32,
    pub shard_index: u32,
}

impl Default for ShardSpec {
    fn default() -> Self {
        Self {
            mode: ShardMode::None,
            shard_count: 1,
            shard_index: 0,
        }
    }
}

impl ShardSpec {
    /// Resolves shard configuration from CLI flags and `POD_NAME` StatefulSet ordinal.
    pub fn resolve(
        mode: ShardMode,
        shard_count: u32,
        explicit_index: Option<u32>,
        pod_name_env: Option<&str>,
    ) -> Result<Self, String> {
        if shard_count == 0 {
            return Err("shard_count must be >= 1".to_string());
        }
        if mode == ShardMode::None || shard_count == 1 {
            return Ok(Self {
                mode: ShardMode::None,
                shard_count: 1,
                shard_index: 0,
            });
        }

        let shard_index = match explicit_index {
            Some(idx) => idx,
            None => {
                let pod_name = pod_name_env.ok_or_else(|| {
                    "sharding enabled (--shard-count > 1) requires --shard-index or POD_NAME"
                        .to_string()
                })?;
                parse_statefulset_ordinal(pod_name)?
            }
        };

        if shard_index >= shard_count {
            return Err(format!(
                "shard_index ({shard_index}) must be < shard_count ({shard_count})"
            ));
        }
        Ok(Self {
            mode,
            shard_count,
            shard_index,
        })
    }

    /// Only shard 0 emits the startup loss-marker entry so N replicas do not emit N duplicates.
    pub fn is_leader(&self) -> bool {
        self.shard_index == 0
    }

    /// Returns KEP-5866 query parameters when server-side sharding is active.
    pub fn server_query_params(&self) -> Option<String> {
        if self.mode == ShardMode::Server && self.shard_count > 1 {
            Some(format!(
                "shardCount={}&shardIndex={}",
                self.shard_count, self.shard_index
            ))
        } else {
            None
        }
    }

    /// Returns a client-side fallback spec when an API server (< 1.37) rejects KEP-5866 params.
    pub fn fallback_to_client(&self) -> Self {
        if self.shard_count <= 1 {
            *self
        } else {
            Self {
                mode: ShardMode::Client,
                shard_count: self.shard_count,
                shard_index: self.shard_index,
            }
        }
    }

    /// Co-partitions Pods with Pod-involved Events by `(namespace, pod_name)` so every shard caches
    /// only `1/N` of cluster Pods while achieving 100% local Pod-owner cache lookup accuracy.
    pub fn owns_pod(&self, namespace: &str, pod_name: &str, server_filtered: bool) -> bool {
        if self.shard_count <= 1 || (self.mode == ShardMode::Server && server_filtered) {
            return true;
        }
        let hash = fnv1a_parts(&[namespace.as_bytes(), b"/", pod_name.as_bytes()]);
        jump_consistent_hash(hash, self.shard_count) == self.shard_index
    }

    /// Determines whether this shard owns a Kubernetes Event.
    pub fn owns_event(
        &self,
        event_namespace: &str,
        involved_kind: &str,
        involved_namespace: &str,
        involved_name: &str,
        event_uid: &str,
        server_filtered: bool,
    ) -> bool {
        if self.shard_count <= 1 || (self.mode == ShardMode::Server && server_filtered) {
            return true;
        }
        let hash = if involved_kind == "Pod"
            && !event_namespace.is_empty()
            && event_namespace == involved_namespace
            && !involved_name.is_empty()
        {
            fnv1a_parts(&[
                involved_namespace.as_bytes(),
                b"/",
                involved_name.as_bytes(),
            ])
        } else {
            fnv1a_parts(&[
                event_namespace.as_bytes(),
                b"/",
                involved_kind.as_bytes(),
                b"/",
                involved_name.as_bytes(),
                b"/",
                event_uid.as_bytes(),
            ])
        };
        jump_consistent_hash(hash, self.shard_count) == self.shard_index
    }
}

/// Parses the trailing numeric ordinal from a StatefulSet pod name (e.g. `event-exporter-gke-2` ->
/// `2`).
pub fn parse_statefulset_ordinal(pod_name: &str) -> Result<u32, String> {
    let (_, suffix) = pod_name
        .trim()
        .rsplit_once('-')
        .ok_or_else(|| format!("POD_NAME '{pod_name}' has no StatefulSet '-<ordinal>' suffix"))?;
    suffix
        .parse::<u32>()
        .map_err(|e| format!("POD_NAME '{pod_name}' has non-numeric ordinal '{suffix}': {e}"))
}

fn fnv1a_parts(parts: &[&[u8]]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for part in parts {
        for &byte in *part {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x100000001b3);
        }
    }
    hash
}

/// Lamping & Veach (2014) Jump Consistent Hash mapping a 64-bit key into `0..num_buckets`.
pub fn jump_consistent_hash(mut key: u64, num_buckets: u32) -> u32 {
    let buckets = i64::from(num_buckets.max(1));
    let mut b: i64 = -1;
    let mut j: i64 = 0;
    while j < buckets {
        b = j;
        key = key.wrapping_mul(2862933555777941757).wrapping_add(1);
        let denom = ((key >> 33).wrapping_add(1)) as f64;
        j = (((b.wrapping_add(1)) as f64) * ((1u64 << 31) as f64 / denom)) as i64;
    }
    b as u32
}
