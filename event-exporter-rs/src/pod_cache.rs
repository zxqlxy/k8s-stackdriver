//! Bounded-memory `PodOwnerTable` (~28–32 B/pod, zero per-Pod heap allocations) and streaming
//! `PartialObjectMetadata` Pod JSON deserializer.

use crate::metrics::MetricsRegistry;
use serde::Deserialize;
use serde::de::{Deserializer, IgnoredAny, MapAccess, Visitor};
use std::collections::hash_map::RandomState;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::hash::{BuildHasher, Hash, Hasher};
use std::sync::RwLock;

/// Top-level Kubernetes workload controller types recognized by GKE Cloud Logging & Monarch.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControllerKind {
    Deployment = 1,
    DaemonSet = 2,
    StatefulSet = 3,
    CronJob = 4,
    JobSet = 5,
    Job = 6,
}

impl ControllerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Deployment => "Deployment",
            Self::DaemonSet => "DaemonSet",
            Self::StatefulSet => "StatefulSet",
            Self::CronJob => "CronJob",
            Self::JobSet => "JobSet",
            Self::Job => "Job",
        }
    }
}

/// Resolved workload owner and optional JobSet metadata attached to `k8s_pod` Event LogEntries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedPodOwner {
    pub kind: ControllerKind,
    pub name: String,
    pub jobset_restart_attempt: Option<String>,
    pub jobset_uid: Option<String>,
}

/// 128-bit double-SipHash key with 8-byte alignment so `(PodKey, CompactOwner)` packs into 24 bytes
/// without `u128`'s 16-byte alignment padding.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PodKey([u64; 2]);

impl Hash for PodKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_u64(self.0[0]);
    }
}

#[derive(Default)]
struct IdentityBuildHasher;

#[derive(Default)]
struct IdentityHasher(u64);

impl BuildHasher for IdentityBuildHasher {
    type Hasher = IdentityHasher;

    fn build_hasher(&self) -> Self::Hasher {
        IdentityHasher(0)
    }
}

impl Hasher for IdentityHasher {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.0 = self.0.rotate_left(8) ^ u64::from(b);
        }
    }

    fn write_u64(&mut self, val: u64) {
        self.0 = val;
    }
}

const JOBSET_OVERFLOW_SENTINEL: u16 = u16::MAX;

/// 8-byte value stored inline per Pod in `PodOwnerTable`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompactOwner {
    kind: ControllerKind,
    _pad: u8,
    jobset_extra_id: u16,
    controller_name_id: u32,
}

const _: () = assert!(std::mem::size_of::<(PodKey, CompactOwner)>() == 24);

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct JobSetExtraIds {
    restart_attempt_id: u32,
    jobset_uid_id: u32,
}

#[derive(Default)]
struct StringInterner {
    by_str: HashMap<Box<str>, u32>,
    values: Vec<Box<str>>,
}

impl StringInterner {
    fn new() -> Self {
        let mut values = Vec::with_capacity(64);
        values.push(Box::<str>::from(""));
        Self {
            by_str: HashMap::with_capacity(64),
            values,
        }
    }

    fn intern(&mut self, value: &str) -> u32 {
        if value.is_empty() {
            return 0;
        }
        if let Some(&existing) = self.by_str.get(value) {
            return existing;
        }
        // shortcut: 2^32 unique controller names per process lifetime, upgrade to refcounted pool
        // if exceeded.
        let id = u32::try_from(self.values.len()).unwrap_or(0);
        if id == 0 {
            return 0;
        }
        let boxed: Box<str> = value.into();
        self.values.push(boxed.clone());
        self.by_str.insert(boxed, id);
        id
    }

    fn resolve(&self, id: u32) -> &str {
        self.values
            .get(id as usize)
            .map(AsRef::as_ref)
            .unwrap_or("")
    }
}

struct PodTableInner {
    entries: HashMap<PodKey, CompactOwner, IdentityBuildHasher>,
    interner: StringInterner,
    jobset_extras: Vec<JobSetExtraIds>,
    jobset_extra_dedup: HashMap<JobSetExtraIds, u16>,
    jobset_overflow: HashMap<PodKey, JobSetExtraIds, IdentityBuildHasher>,
    max_inline_jobsets: usize,
}

impl PodTableInner {
    fn new(max_inline_jobsets: usize) -> Self {
        let mut jobset_extras = Vec::with_capacity(8);
        jobset_extras.push(JobSetExtraIds {
            restart_attempt_id: 0,
            jobset_uid_id: 0,
        });
        Self {
            entries: HashMap::with_hasher(IdentityBuildHasher),
            interner: StringInterner::new(),
            jobset_extras,
            jobset_extra_dedup: HashMap::new(),
            jobset_overflow: HashMap::with_hasher(IdentityBuildHasher),
            max_inline_jobsets: max_inline_jobsets.min((JOBSET_OVERFLOW_SENTINEL as usize) - 1),
        }
    }
}

/// Thread-safe, zero-per-Pod-allocation workload owner lookup table.
pub struct PodOwnerTable {
    hasher_hi: RandomState,
    hasher_lo: RandomState,
    system_namespaces: HashSet<String>,
    inner: RwLock<PodTableInner>,
}

impl PodOwnerTable {
    pub fn new(system_namespaces: HashSet<String>) -> Self {
        Self::with_max_inline_jobsets(system_namespaces, (JOBSET_OVERFLOW_SENTINEL as usize) - 1)
    }

    pub fn with_max_inline_jobsets(
        system_namespaces: HashSet<String>,
        max_inline_jobsets: usize,
    ) -> Self {
        Self {
            hasher_hi: RandomState::new(),
            hasher_lo: RandomState::new(),
            system_namespaces,
            inner: RwLock::new(PodTableInner::new(max_inline_jobsets)),
        }
    }

    pub fn compute_key(&self, namespace: &str, pod_name: &str) -> PodKey {
        let hi = hash_pair(&self.hasher_hi, namespace, pod_name);
        let lo = hash_pair(&self.hasher_lo, namespace, pod_name);
        PodKey([hi, lo])
    }

    /// Upserts or removes a Pod's top-level workload owner from parsed `PartialObjectMetadata`.
    pub fn upsert_pod_metadata(&self, pod: &PodMetadataExtract, metrics: Option<&MetricsRegistry>) {
        if pod.namespace.is_empty()
            || pod.name.is_empty()
            || self.system_namespaces.contains(&pod.namespace)
        {
            return;
        }
        let key = self.compute_key(&pod.namespace, &pod.name);
        let Some(owner) = infer_top_level_owner(pod) else {
            self.remove_by_key(key, metrics);
            return;
        };

        let mut guard = self.inner.write().unwrap_or_else(|e| e.into_inner());
        let compact = encode_owner(&mut guard, &owner, key);
        let is_new = guard.entries.insert(key, compact).is_none();
        drop(guard);
        if is_new && let Some(m) = metrics {
            m.inc_pod_cache_op("add");
        }
    }

    /// Removes a deleted Pod from the lookup table.
    pub fn remove_pod(&self, namespace: &str, pod_name: &str, metrics: Option<&MetricsRegistry>) {
        if namespace.is_empty() || pod_name.is_empty() {
            return;
        }
        let key = self.compute_key(namespace, pod_name);
        self.remove_by_key(key, metrics);
    }

    fn remove_by_key(&self, key: PodKey, metrics: Option<&MetricsRegistry>) {
        let mut guard = self.inner.write().unwrap_or_else(|e| e.into_inner());
        let removed = guard.entries.remove(&key);
        if let Some(prev) = removed
            && prev.jobset_extra_id == JOBSET_OVERFLOW_SENTINEL
        {
            guard.jobset_overflow.remove(&key);
        }
        drop(guard);
        if removed.is_some()
            && let Some(m) = metrics
        {
            m.inc_pod_cache_op("evict");
        }
    }

    /// Evicts any cached Pods whose keys are not in `live_keys` after a full re-list recovery.
    pub fn retain_only(&self, live_keys: &HashSet<PodKey>, metrics: Option<&MetricsRegistry>) {
        let mut evicted = 0u64;
        let mut guard = self.inner.write().unwrap_or_else(|e| e.into_inner());
        let PodTableInner {
            entries,
            jobset_overflow,
            ..
        } = &mut *guard;
        entries.retain(|k, v| {
            let keep = live_keys.contains(k);
            if !keep {
                evicted += 1;
                if v.jobset_extra_id == JOBSET_OVERFLOW_SENTINEL {
                    jobset_overflow.remove(k);
                }
            }
            keep
        });
        drop(guard);
        if evicted > 0
            && let Some(m) = metrics
        {
            m.add_pod_cache_op("evict", evicted);
        }
    }

    /// Looks up a Pod's top-level workload controller in O(1) time under a shared read lock.
    pub fn lookup(
        &self,
        namespace: &str,
        pod_name: &str,
        metrics: Option<&MetricsRegistry>,
    ) -> Option<ResolvedPodOwner> {
        if namespace.is_empty() || pod_name.is_empty() || self.system_namespaces.contains(namespace)
        {
            return None;
        }
        let key = self.compute_key(namespace, pod_name);
        let guard = self.inner.read().unwrap_or_else(|e| e.into_inner());
        let Some(&compact) = guard.entries.get(&key) else {
            drop(guard);
            if let Some(m) = metrics {
                m.inc_pod_cache_op("querymiss");
            }
            return None;
        };

        let controller_name = guard
            .interner
            .resolve(compact.controller_name_id)
            .to_string();
        let (restart_attempt, jobset_uid) = if compact.jobset_extra_id == 0 {
            (None, None)
        } else {
            let extra = if compact.jobset_extra_id == JOBSET_OVERFLOW_SENTINEL {
                guard.jobset_overflow.get(&key).cloned()
            } else {
                guard
                    .jobset_extras
                    .get(compact.jobset_extra_id as usize)
                    .cloned()
            };
            match extra {
                Some(ids) => {
                    let ra = non_empty_string(guard.interner.resolve(ids.restart_attempt_id));
                    let uid = non_empty_string(guard.interner.resolve(ids.jobset_uid_id));
                    (ra, uid)
                }
                None => (None, None),
            }
        };
        drop(guard);

        if let Some(m) = metrics {
            m.inc_pod_cache_op("queryhit");
        }
        Some(ResolvedPodOwner {
            kind: compact.kind,
            name: controller_name,
            jobset_restart_attempt: restart_attempt,
            jobset_uid,
        })
    }

    /// Returns the number of cached Pods currently in the table.
    pub fn len(&self) -> usize {
        self.inner
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .entries
            .len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

fn non_empty_string(s: &str) -> Option<String> {
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

fn encode_owner(inner: &mut PodTableInner, owner: &ResolvedPodOwner, key: PodKey) -> CompactOwner {
    let controller_name_id = inner.interner.intern(&owner.name);
    let restart_attempt_id = owner
        .jobset_restart_attempt
        .as_deref()
        .map(|s| inner.interner.intern(s))
        .unwrap_or(0);
    let jobset_uid_id = owner
        .jobset_uid
        .as_deref()
        .map(|s| inner.interner.intern(s))
        .unwrap_or(0);

    let jobset_extra_id = if restart_attempt_id == 0 && jobset_uid_id == 0 {
        inner.jobset_overflow.remove(&key);
        0
    } else {
        let pair = JobSetExtraIds {
            restart_attempt_id,
            jobset_uid_id,
        };
        if let Some(&existing_id) = inner.jobset_extra_dedup.get(&pair) {
            inner.jobset_overflow.remove(&key);
            existing_id
        } else if inner.jobset_extras.len() <= inner.max_inline_jobsets {
            let new_id = inner.jobset_extras.len() as u16;
            inner.jobset_extras.push(pair.clone());
            inner.jobset_extra_dedup.insert(pair, new_id);
            inner.jobset_overflow.remove(&key);
            new_id
        } else {
            inner.jobset_overflow.insert(key, pair);
            JOBSET_OVERFLOW_SENTINEL
        }
    };

    CompactOwner {
        kind: owner.kind,
        _pad: 0,
        jobset_extra_id,
        controller_name_id,
    }
}

fn hash_pair(state: &RandomState, namespace: &str, pod_name: &str) -> u64 {
    let mut hasher = state.build_hasher();
    hasher.write_usize(namespace.len());
    hasher.write(namespace.as_bytes());
    hasher.write_u8(0xff);
    hasher.write_usize(pod_name.len());
    hasher.write(pod_name.as_bytes());
    hasher.finish()
}

/// Infers top-level GKE workload controller matching `parser.lua` and `pod_label_collector.go`.
pub fn infer_top_level_owner(pod: &PodMetadataExtract) -> Option<ResolvedPodOwner> {
    let mut result: Option<ResolvedPodOwner> = None;
    for owner in &pod.owner_references {
        if owner.name.is_empty() {
            continue;
        }
        let candidate = match owner.kind.as_str() {
            "DaemonSet" => Some(ResolvedPodOwner {
                kind: ControllerKind::DaemonSet,
                name: owner.name.clone(),
                jobset_restart_attempt: None,
                jobset_uid: None,
            }),
            "StatefulSet" => Some(ResolvedPodOwner {
                kind: ControllerKind::StatefulSet,
                name: owner.name.clone(),
                jobset_restart_attempt: None,
                jobset_uid: None,
            }),
            "ReplicaSet" => {
                if let Some(hash) = pod.labels.pod_template_hash.as_deref() {
                    if !hash.is_empty() {
                        let suffix = format!("-{hash}");
                        if let Some(prefix) = owner.name.strip_suffix(&suffix) {
                            if !prefix.is_empty() {
                                Some(ResolvedPodOwner {
                                    kind: ControllerKind::Deployment,
                                    name: prefix.to_string(),
                                    jobset_restart_attempt: None,
                                    jobset_uid: None,
                                })
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
            "Job" => {
                if let Some(cronjob_name) = strip_cronjob_timestamp_suffix(&owner.name) {
                    Some(ResolvedPodOwner {
                        kind: ControllerKind::CronJob,
                        name: cronjob_name.to_string(),
                        jobset_restart_attempt: None,
                        jobset_uid: None,
                    })
                } else if let Some(jobset_name) =
                    pod.labels.jobset_name.as_deref().filter(|s| !s.is_empty())
                {
                    Some(ResolvedPodOwner {
                        kind: ControllerKind::JobSet,
                        name: jobset_name.to_string(),
                        jobset_restart_attempt: pod
                            .labels
                            .jobset_restart_attempt
                            .clone()
                            .filter(|s| !s.is_empty()),
                        jobset_uid: pod.labels.jobset_uid.clone().filter(|s| !s.is_empty()),
                    })
                } else {
                    Some(ResolvedPodOwner {
                        kind: ControllerKind::Job,
                        name: owner.name.clone(),
                        jobset_restart_attempt: None,
                        jobset_uid: None,
                    })
                }
            }
            _ => None,
        };
        if candidate.is_some() {
            result = candidate;
        }
    }
    result
}

/// Matches Kubernetes CronJob's 8-digit Unix minute suffix (`-[2-5][0-9]{7}`, valid 2008..2084).
fn strip_cronjob_timestamp_suffix(job_name: &str) -> Option<&str> {
    let (prefix, suffix) = job_name.rsplit_once('-')?;
    if prefix.is_empty() || suffix.len() != 8 {
        return None;
    }
    let bytes = suffix.as_bytes();
    if !(b'2'..=b'5').contains(&bytes[0]) {
        return None;
    }
    if !bytes[1..].iter().all(u8::is_ascii_digit) {
        return None;
    }
    Some(prefix)
}

/// Minimal `OwnerReference` fields extracted during streaming deserialization.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct OwnerRefExtract {
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub name: String,
}

/// Selective Pod labels deserialized without allocating a `HashMap` or retaining arbitrary user
/// labels.
#[derive(Clone, Debug, Default)]
pub struct RelevantPodLabels {
    pub pod_template_hash: Option<String>,
    pub jobset_name: Option<String>,
    pub jobset_restart_attempt: Option<String>,
    pub jobset_uid: Option<String>,
}

impl<'de> Deserialize<'de> for RelevantPodLabels {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct LabelsVisitor;

        impl<'de> Visitor<'de> for LabelsVisitor {
            type Value = RelevantPodLabels;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a Kubernetes metadata.labels map or null")
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E> {
                Ok(RelevantPodLabels::default())
            }

            fn visit_none<E>(self) -> Result<Self::Value, E> {
                Ok(RelevantPodLabels::default())
            }

            fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
            where
                D: Deserializer<'de>,
            {
                deserializer.deserialize_any(self)
            }

            fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut out = RelevantPodLabels::default();
                while let Some(key) = map.next_key::<std::borrow::Cow<'de, str>>()? {
                    match key.as_ref() {
                        "pod-template-hash" => {
                            out.pod_template_hash = map.next_value::<Option<String>>()?;
                        }
                        "jobset.sigs.k8s.io/jobset-name" | "jobset.x-k8s.io/jobset-name" => {
                            let val = map.next_value::<Option<String>>()?;
                            if out.jobset_name.is_none() || key == "jobset.sigs.k8s.io/jobset-name"
                            {
                                out.jobset_name = val;
                            }
                        }
                        "jobset.sigs.k8s.io/restart-attempt"
                        | "jobset.x-k8s.io/restart-attempt" => {
                            let val = map.next_value::<Option<String>>()?;
                            if out.jobset_restart_attempt.is_none()
                                || key == "jobset.sigs.k8s.io/restart-attempt"
                            {
                                out.jobset_restart_attempt = val;
                            }
                        }
                        "jobset.sigs.k8s.io/jobset-uid" | "jobset.x-k8s.io/jobset-uid" => {
                            let val = map.next_value::<Option<String>>()?;
                            if out.jobset_uid.is_none() || key == "jobset.sigs.k8s.io/jobset-uid" {
                                out.jobset_uid = val;
                            }
                        }
                        _ => {
                            let _ = map.next_value::<IgnoredAny>()?;
                        }
                    }
                }
                Ok(out)
            }
        }

        deserializer.deserialize_option(LabelsVisitor)
    }
}

/// Extracted `PartialObjectMetadata` fields for a single Pod; skips `annotations`, `managedFields`,
/// `spec`, and `status` in-flight via serde field ignoring.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct PodMetadataExtract {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub namespace: String,
    #[serde(default, rename = "resourceVersion")]
    pub resource_version: String,
    #[serde(default)]
    pub labels: RelevantPodLabels,
    #[serde(default, rename = "ownerReferences")]
    pub owner_references: Vec<OwnerRefExtract>,
}

/// Envelope of a `PartialObjectMetadata` item inside Watch or paginated List responses.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct PartialPodObject {
    #[serde(default)]
    pub metadata: PodMetadataExtract,
    #[serde(default)]
    pub annotations: Option<HashMap<String, String>>,
}

/// Streaming Kubernetes Watch frame for `PartialObjectMetadata` Pods.
#[derive(Clone, Debug, Deserialize)]
pub struct PodWatchFrame {
    #[serde(rename = "type")]
    pub event_type: String,
    pub object: serde_json::Value,
}

/// Parses a `PartialObjectMetadata` JSON object directly into [`PodMetadataExtract`].
pub fn parse_partial_pod_object(bytes: &[u8]) -> Result<PodMetadataExtract, serde_json::Error> {
    #[derive(Deserialize)]
    struct Wrapper {
        #[serde(default)]
        metadata: PodMetadataExtract,
    }
    let parsed: Wrapper = serde_json::from_slice(bytes)?;
    Ok(parsed.metadata)
}
