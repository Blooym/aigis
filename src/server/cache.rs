use crate::server::routes::{MetadataResponseWrapper, ProxyResponseWrapper};
use moka::{Expiry, future::Cache as MokaCache};
use std::time::{Duration, Instant};

#[derive(Clone)]
pub enum CachedResponse {
    Metadata(MetadataResponseWrapper),
    Proxy(ProxyResponseWrapper),
}

pub trait CacheSize {
    fn cache_size_shallow(&self) -> usize;
}

type CacheKey = u64;
type CacheValue = (CachedResponse, Duration);
pub type Cache = MokaCache<CacheKey, CacheValue>;

struct CacheExpiry;

impl Expiry<CacheKey, CacheValue> for CacheExpiry {
    fn expire_after_create(
        &self,
        _key: &CacheKey,
        value: &CacheValue,
        _current_time: Instant,
    ) -> Option<Duration> {
        Some(value.1)
    }
}

pub fn build_response_cache(max_capacity: u64) -> Cache {
    const REMOVE_IF_IDLE_FOR_SECONDS: u64 = 3600;
    Cache::builder()
        .weigher(|_key, value| -> u32 {
            match &value.0 {
                CachedResponse::Proxy(res) => {
                    res.cache_size_shallow().try_into().unwrap_or(u32::MAX)
                }
                CachedResponse::Metadata(res) => {
                    res.cache_size_shallow().try_into().unwrap_or(u32::MAX)
                }
            }
        })
        .expire_after(CacheExpiry)
        .time_to_idle(Duration::from_secs(REMOVE_IF_IDLE_FOR_SECONDS))
        .max_capacity(max_capacity)
        .build()
}
