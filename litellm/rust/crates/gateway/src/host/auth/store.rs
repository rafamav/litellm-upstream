//! A virtual key read through the auth cache, as the proxy's `get_key_object` reads it: the
//! cache, then the database on a miss, which caches the key as `cache_key_object` does, for every
//! pod when the cache has the shared Redis attached. Nothing guards that write against an eviction
//! that lands during the database read, as nothing guards Python's.

use std::{sync::Arc, time::Duration};

use litellm_auth_store::{Error, KeyDatabase};
use litellm_gateway_auth_core::{KeyHash, authn::jwt::MappedClaim};
use litellm_python_compat::Value as PyValue;
use litellm_redis_store::{
    FromValue, IntoValue,
    auth_cache::{AuthCache, AuthObject, KeyEntry, Settings},
};
use litellm_repositories::{JwtKeyMappingRepository, Side};
use serde_json::Value;

pub struct AuthStore {
    cache: Arc<AuthCache>,
    keys: KeyDatabase,
    mappings: JwtKeyMappingRepository,
}

impl AuthStore {
    pub fn new(
        cache: Arc<AuthCache>,
        keys: KeyDatabase,
        mappings: JwtKeyMappingRepository,
    ) -> Self {
        Self {
            cache,
            keys,
            mappings,
        }
    }

    /// The key the cache holds for `hash`. A cache that fails and an entry that does not decode
    /// are both a miss, as they are to `UserApiKeyCache`.
    pub async fn cached(&self, hash: &KeyHash) -> Option<KeyEntry> {
        let value = self
            .cache
            .get(None, &object(hash))
            .await
            .inspect_err(|error| {
                tracing::warn!(
                    error = %litellm_error::Report::new(error),
                    "a key was not read from the auth cache"
                );
            })
            .ok()
            .flatten()?;
        KeyEntry::from_value(&value)
            .inspect_err(|error| {
                tracing::warn!(
                    error = %litellm_error::Report::new(error),
                    "a cached key does not decode and is read as a miss"
                );
            })
            .ok()
    }

    /// The key the database holds for `hash`, cached for the cache's own TTL, as
    /// `get_management_object_ttl` names `default_in_memory_ttl`. A key the cache did not take is
    /// returned all the same.
    pub async fn loaded(&self, hash: &KeyHash) -> Result<Option<KeyEntry>, Error> {
        let Some(key) = Box::pin(self.keys.read(hash, Side::Read)).await? else {
            return Ok(None);
        };
        let value = key.clone().into_value();
        if let Err(error) = self.cache.set(None, &object(hash), value, None).await {
            tracing::warn!(
                error = %litellm_error::Report::new(&error),
                "a key was not cached"
            );
        }
        Ok(Some(key))
    }

    /// `_resize_the_auth_cache` on a reload: `entries` in each partition from the next write on,
    /// with the TTL startup set kept.
    pub(crate) fn resize(&self, entries: usize) {
        self.cache.reconfigure(Settings {
            memory_entries: entries,
            ..self.cache.settings()
        });
    }

    pub async fn cached_key_mapping(&self, claim: MappedClaim<'_>) -> Option<Value> {
        let value = self
            .cache
            .get(None, &mapping_object(claim))
            .await
            .inspect_err(|error| {
                tracing::warn!(
                    error = %litellm_error::Report::new(error),
                    "a JWT key mapping was not read from the auth cache"
                );
            })
            .ok()
            .flatten()?;
        match value {
            PyValue::Str(text) => Some(Value::String(text)),
            _ => None,
        }
    }

    pub async fn cache_key_mapping(&self, claim: MappedClaim<'_>, value: &Value, ttl: Duration) {
        let Some(text) = value.as_str() else {
            return;
        };
        if let Err(error) = self
            .cache
            .set(
                None,
                &mapping_object(claim),
                PyValue::Str(text.to_owned()),
                Some(ttl),
            )
            .await
        {
            tracing::warn!(
                error = %litellm_error::Report::new(&error),
                "a JWT key mapping was not cached"
            );
        }
    }

    pub async fn key_mapping_hash(
        &self,
        claim_field: &str,
        claim_value: &str,
        issuer: Option<&str>,
    ) -> Result<Option<KeyHash>, litellm_db::Error> {
        self.mappings
            .mapped_token(claim_field, claim_value, issuer)
            .await
            .map(|token| token.map(KeyHash::new))
    }
}

fn object(hash: &KeyHash) -> AuthObject {
    AuthObject::Key(hash.as_str().to_owned())
}

fn mapping_object(claim: MappedClaim<'_>) -> AuthObject {
    AuthObject::JwtKeyMapping {
        issuer: claim.issuer.map(str::to_owned),
        claim_name: claim.field.to_owned(),
        claim_value: claim.value.to_owned(),
    }
}
