//! A virtual key, and a JWT's team, membership and user, read through the auth cache, as the
//! proxy's `get_key_object` and its siblings read them: the cache, then the database on a miss,
//! which caches the row as Python does, for every pod when the cache has the shared Redis
//! attached. Nothing guards that write against an eviction that lands during the database read,
//! as nothing guards Python's.

use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};

use litellm_auth_store::{
    AliasMatch, Error, KeyDatabase, TeamDatabase, TeamMembershipDatabase, UserDatabase,
};
use litellm_gateway_auth_core::{KeyHash, authn::jwt::MappedClaim};
use litellm_python_compat::Value as PyValue;
use litellm_redis_store::{
    FromValue, IntoValue,
    auth_cache::{
        AuthCache, AuthObject, KeyEntry, Settings, TeamEntry, TeamMembershipEntry, UserEntry,
    },
};
use litellm_repositories::{
    Database, JwtKeyMappingRepository, ObjectPermissionRepository, Side, TeamMembershipRepository,
    TeamRepository, UserRepository,
};
use serde_json::Value;

/// What `_fetch_team_membership_from_db` caches for a user who is not a member of the team.
const NO_TEAM_MEMBERSHIP: &str = "__no_team_membership__";

pub struct AuthStore {
    cache: Arc<AuthCache>,
    keys: KeyDatabase,
    mappings: JwtKeyMappingRepository,
    affiliations: Option<Affiliations>,
}

/// The rows a JWT's caller belongs to: its team, its membership of that team and its user.
pub struct Affiliations {
    teams: TeamDatabase,
    memberships: TeamMembershipDatabase,
    users: UserDatabase,
}

impl Affiliations {
    pub fn new(database: Database) -> Self {
        Self {
            teams: TeamDatabase::new(
                Arc::new(TeamRepository::new(database.clone())),
                Arc::new(ObjectPermissionRepository::new(database.clone())),
            ),
            memberships: TeamMembershipDatabase::new(Arc::new(TeamMembershipRepository::new(
                database.clone(),
            ))),
            users: UserDatabase::new(Arc::new(UserRepository::new(database))),
        }
    }
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
            affiliations: None,
        }
    }

    pub fn with_affiliations(mut self, affiliations: Affiliations) -> Self {
        self.affiliations = Some(affiliations);
        self
    }

    /// The key the cache holds for `hash`. A cache that fails and an entry that does not decode
    /// are both a miss, as they are to `UserApiKeyCache`.
    pub async fn cached(&self, hash: &KeyHash) -> Option<KeyEntry> {
        decoded(&self.read(&object(hash)).await?)
    }

    async fn read(&self, object: &AuthObject) -> Option<PyValue> {
        self.cache
            .get(None, object)
            .await
            .inspect_err(|error| {
                tracing::warn!(
                    error = %litellm_error::Report::new(error),
                    key = object.key(),
                    "an object was not read from the auth cache"
                );
            })
            .ok()
            .flatten()
    }

    /// Cached for the cache's own TTL, as `get_management_object_ttl` names `default_in_memory_ttl`.
    async fn write(&self, object: &AuthObject, value: PyValue) {
        if let Err(error) = self.cache.set(None, object, value, None).await {
            tracing::warn!(
                error = %litellm_error::Report::new(&error),
                key = object.key(),
                "an object was not cached"
            );
        }
    }

    /// The key the database holds for `hash`, cached for the cache's own TTL, as
    /// `get_management_object_ttl` names `default_in_memory_ttl`. A key the cache did not take is
    /// returned all the same.
    pub async fn loaded(&self, hash: &KeyHash) -> Result<Option<KeyEntry>, Error> {
        let Some(key) = Box::pin(self.keys.read(hash, Side::Read)).await? else {
            return Ok(None);
        };
        self.write(&object(hash), key.clone().into_value()).await;
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
        match self.read(&mapping_object(claim)).await? {
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

    /// `get_team_object`: the cached team, else the database's, cached with the time it was read
    /// as `cache_team_object` stamps it. `None` without the affiliation reads.
    pub async fn team(&self, team_id: &str) -> Option<Result<Option<TeamEntry>, Error>> {
        let affiliations = self.affiliations.as_ref()?;
        let object = AuthObject::Team(team_id.to_owned());
        if let Some(team) = self.read(&object).await.as_ref().and_then(decoded) {
            return Some(Ok(Some(team)));
        }
        Some(match affiliations.teams.team(team_id, Side::Read).await {
            Ok(Some(team)) => {
                let team = TeamEntry {
                    last_refreshed_at: Some(now()),
                    ..team
                };
                self.write(&object, team.clone().into_value()).await;
                Ok(Some(team))
            }
            read => read,
        })
    }

    /// `get_team_object_by_alias`: the team cached under the alias, else the one row the database
    /// holds with it, cached under the alias and the team's id.
    pub async fn team_by_alias(&self, alias: &str) -> Option<Result<AliasMatch<TeamEntry>, Error>> {
        let affiliations = self.affiliations.as_ref()?;
        let object = AuthObject::TeamAlias(alias.to_owned());
        if let Some(team) = self.read(&object).await.as_ref().and_then(decoded) {
            return Some(Ok(AliasMatch::Found(team)));
        }
        Some(match affiliations.teams.team_by_alias(alias).await {
            Ok(AliasMatch::Found(team)) => {
                let value = team.clone().into_value();
                self.write(&object, value.clone()).await;
                self.write(&AuthObject::Team(team.team_id.clone()), value)
                    .await;
                Ok(AliasMatch::Found(team))
            }
            read => read,
        })
    }

    /// `get_team_membership`: the cached membership, or the cached word that there is none, else
    /// the database's answer, cached either way.
    pub async fn team_membership(
        &self,
        user_id: &str,
        team_id: &str,
    ) -> Option<Result<Option<TeamMembershipEntry>, Error>> {
        let affiliations = self.affiliations.as_ref()?;
        let object = AuthObject::TeamMembershipReservation {
            user_id: user_id.to_owned(),
            team_id: team_id.to_owned(),
        };
        match self.read(&object).await {
            Some(PyValue::Str(text)) if text == NO_TEAM_MEMBERSHIP => return Some(Ok(None)),
            Some(value) => {
                if let Some(membership) = decoded(&value) {
                    return Some(Ok(Some(membership)));
                }
            }
            None => {}
        }
        Some(
            match affiliations
                .memberships
                .team_membership(user_id, team_id, Side::Read)
                .await
            {
                Ok(membership) => {
                    let value = membership.clone().map_or_else(
                        || PyValue::Str(NO_TEAM_MEMBERSHIP.to_owned()),
                        IntoValue::into_value,
                    );
                    self.write(&object, value).await;
                    Ok(membership)
                }
                Err(error) => Err(error),
            },
        )
    }

    /// `get_user_object` for a user read by its id: the cached user, else the database's, cached
    /// only when `settled`. Python links a sign-in or backfills an email only on its own database
    /// read, so a row it still owes a write must not become its cache hit.
    pub async fn user(
        &self,
        user_id: &str,
        settled: impl FnOnce(&UserEntry) -> bool,
    ) -> Option<Result<Option<UserEntry>, Error>> {
        let affiliations = self.affiliations.as_ref()?;
        let object = AuthObject::User(user_id.to_owned());
        if let Some(user) = self.read(&object).await.as_ref().and_then(decoded) {
            return Some(Ok(Some(user)));
        }
        Some(match affiliations.users.user(user_id, Side::Read).await {
            Ok(Some(user)) => {
                if settled(&user) {
                    self.write(&object, user.clone().into_value()).await;
                }
                Ok(Some(user))
            }
            read => read,
        })
    }
}

/// An entry that does not decode is a miss, as it is to `UserApiKeyCache`.
fn decoded<T: FromValue>(value: &PyValue) -> Option<T> {
    T::from_value(value)
        .inspect_err(|error| {
            tracing::warn!(
                error = %litellm_error::Report::new(error),
                "a cached object does not decode and is read as a miss"
            );
        })
        .ok()
}

/// `time.time()`, which `cache_team_object` stamps a team with.
fn now() -> f64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
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
