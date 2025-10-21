use crate::server::routes::{MetadataResponseWrapper, ProxyResponseWrapper};
use moka::{Expiry, future::Cache as MokaCache};
use std::time::{Duration, Instant};

type CacheKey = u64;
type CacheValue = (CachedResponse, Duration);
pub type Cache = MokaCache<CacheKey, CacheValue>;

pub trait CacheSize {
    fn cache_size_shallow(&self) -> usize;
}

#[derive(Clone)]
pub enum CachedResponse {
    Metadata(MetadataResponseWrapper),
    Proxy(ProxyResponseWrapper),
}

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
        .max_capacity(max_capacity)
        .build()
}
