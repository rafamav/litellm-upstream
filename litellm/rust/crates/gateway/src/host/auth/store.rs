//! A virtual key, and the team, membership and user a caller belongs to, read through the auth
//! cache, as the proxy's `get_key_object` and its siblings read them: the cache, then the
//! database on a miss, which caches the row as Python does, for every pod when the cache has the
//! shared Redis attached. Nothing guards that write against an eviction that lands during the
//! database read, as nothing guards Python's.

use std::{sync::Arc, time::SystemTime};

use litellm_auth_store::{
    AliasMatch, Error, KeyDatabase, TeamDatabase, TeamMembershipDatabase, UserDatabase,
};
use litellm_gateway_auth_core::KeyHash;
use litellm_python_compat::Value as PyValue;
use litellm_redis_store::{
    FromValue, IntoValue,
    auth_cache::{
        AuthCache, AuthObject, KeyEntry, Settings, TeamEntry, TeamMembershipEntry, UserEntry,
    },
};
use litellm_repositories::{
    Database, KeyRepository, ObjectPermissionRepository, Side, TeamMembershipRepository,
    TeamRepository, UserRepository,
};

/// What `_fetch_team_membership_from_db` caches for a user who is not a member of the team.
const NO_TEAM_MEMBERSHIP: &str = "__no_team_membership__";

pub struct AuthStore {
    cache: Arc<AuthCache>,
    keys: KeyDatabase,
    teams: TeamDatabase,
    memberships: TeamMembershipDatabase,
    users: UserDatabase,
}

impl AuthStore {
    /// The store over `database`, read as the Python proxy reads it.
    pub fn new(cache: Arc<AuthCache>, database: Database) -> Self {
        let object_permissions = Arc::new(ObjectPermissionRepository::new(database.clone()));
        Self {
            cache,
            keys: KeyDatabase::new(
                Arc::new(KeyRepository::new(database.clone())),
                object_permissions.clone(),
            ),
            teams: TeamDatabase::new(
                Arc::new(TeamRepository::new(database.clone())),
                object_permissions,
            ),
            memberships: TeamMembershipDatabase::new(Arc::new(TeamMembershipRepository::new(
                database.clone(),
            ))),
            users: UserDatabase::new(Arc::new(UserRepository::new(database))),
        }
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

    /// `get_team_object`: the cached team, else the database's, cached with the time it was read
    /// as `cache_team_object` stamps it.
    pub async fn team(&self, team_id: &str) -> Result<Option<TeamEntry>, Error> {
        let object = AuthObject::Team(team_id.to_owned());
        if let Some(team) = self.read(&object).await.as_ref().and_then(decoded) {
            return Ok(Some(team));
        }
        let Some(team) = self.teams.team(team_id, Side::Read).await? else {
            return Ok(None);
        };
        let team = TeamEntry {
            last_refreshed_at: Some(now()),
            ..team
        };
        self.write(&object, team.clone().into_value()).await;
        Ok(Some(team))
    }

    /// `get_team_object_by_alias`: the team cached under the alias, else the one row the database
    /// holds with it, cached under the alias and the team's id.
    pub async fn team_by_alias(&self, alias: &str) -> Result<AliasMatch<TeamEntry>, Error> {
        let object = AuthObject::TeamAlias(alias.to_owned());
        if let Some(team) = self.read(&object).await.as_ref().and_then(decoded) {
            return Ok(AliasMatch::Found(team));
        }
        let found = self.teams.team_by_alias(alias).await?;
        let AliasMatch::Found(team) = &found else {
            return Ok(found);
        };
        let value = team.clone().into_value();
        self.write(&object, value.clone()).await;
        self.write(&AuthObject::Team(team.team_id.clone()), value)
            .await;
        Ok(found)
    }

    /// `get_team_membership`: the cached membership, or the cached word that there is none, else
    /// the database's answer, cached either way.
    pub async fn team_membership(
        &self,
        user_id: &str,
        team_id: &str,
    ) -> Result<Option<TeamMembershipEntry>, Error> {
        let object = AuthObject::TeamMembershipReservation {
            user_id: user_id.to_owned(),
            team_id: team_id.to_owned(),
        };
        match self.read(&object).await {
            Some(PyValue::Str(text)) if text == NO_TEAM_MEMBERSHIP => return Ok(None),
            Some(value) => {
                if let Some(membership) = decoded(&value) {
                    return Ok(Some(membership));
                }
            }
            None => {}
        }
        let membership = self
            .memberships
            .team_membership(user_id, team_id, Side::Read)
            .await?;
        let value = membership.clone().map_or_else(
            || PyValue::Str(NO_TEAM_MEMBERSHIP.to_owned()),
            IntoValue::into_value,
        );
        self.write(&object, value).await;
        Ok(membership)
    }

    /// `get_user_object` for a user read by its id: the cached user, else the database's, cached.
    pub async fn user(&self, user_id: &str) -> Result<Option<UserEntry>, Error> {
        let object = AuthObject::User(user_id.to_owned());
        if let Some(user) = self.read(&object).await.as_ref().and_then(decoded) {
            return Ok(Some(user));
        }
        let Some(user) = self.users.user(user_id, Side::Read).await? else {
            return Ok(None);
        };
        self.write(&object, user.clone().into_value()).await;
        Ok(Some(user))
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

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use serde_json::json;

    use super::*;
    use crate::host::auth::keys::{self, Held};

    fn store(held: &Held) -> AuthStore {
        AuthStore::new(keys::memory_cache(), held.database())
    }

    #[rstest]
    #[tokio::test(flavor = "multi_thread")]
    async fn a_team_found_by_its_alias_is_cached_under_the_alias_and_its_id() {
        let held = Held::start().await;
        held.insert_named(
            "LiteLLM_TeamTable",
            &json!({"team_id": "team-1", "team_alias": "alpha"}),
        )
        .await;
        let store = store(&held);
        let id_of = |read: Result<AliasMatch<TeamEntry>, Error>| match read {
            Ok(AliasMatch::Found(team)) => Some(team.team_id),
            _ => None,
        };

        let from_database = id_of(store.team_by_alias("alpha").await);
        held.execute(r#"DELETE FROM "LiteLLM_TeamTable""#).await;
        let by_alias = id_of(store.team_by_alias("alpha").await);
        let by_id = store.team("team-1").await.unwrap();

        assert_eq!(
            (from_database, by_alias, by_id.map(|team| team.team_alias)),
            (
                Some("team-1".to_owned()),
                Some("team-1".to_owned()),
                Some(Some("alpha".to_owned()))
            )
        );
    }

    const JOINED: &str =
        r#"INSERT INTO "LiteLLM_TeamMembership" (user_id, team_id) VALUES ('user-1', 'team-1')"#;
    const LEFT: &str = r#"DELETE FROM "LiteLLM_TeamMembership""#;

    #[rstest]
    #[case::a_member(JOINED, LEFT, true)]
    #[case::no_member(LEFT, JOINED, false)]
    #[tokio::test(flavor = "multi_thread")]
    async fn a_membership_is_cached_whether_or_not_the_user_is_a_member(
        #[case] before: &'static str,
        #[case] after: &'static str,
        #[case] member: bool,
    ) {
        let held = Held::start().await;
        held.execute(before).await;
        let store = store(&held);
        let read = async || {
            let membership = store.team_membership("user-1", "team-1").await;
            membership.unwrap().is_some()
        };

        let from_database = read().await;
        held.execute(after).await;
        let cached = read().await;

        assert_eq!((from_database, cached), (member, member));
    }

    #[rstest]
    #[tokio::test(flavor = "multi_thread")]
    async fn a_user_read_from_the_database_is_cached() {
        let held = Held::start().await;
        held.insert_named("LiteLLM_UserTable", &json!({"user_id": "user-1"}))
            .await;
        let store = store(&held);
        let read = async || {
            let user = store.user("user-1").await.unwrap();
            user.map(|user| user.user_id)
        };

        let from_database = read().await;
        held.execute(r#"DELETE FROM "LiteLLM_UserTable""#).await;
        let cached = read().await;

        assert_eq!(
            (from_database, cached),
            (Some("user-1".to_owned()), Some("user-1".to_owned()))
        );
    }
}
