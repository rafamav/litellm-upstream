//! `LiteLLM_TeamTable` reads for auth, by id or by alias, with each team's `LiteLLM_ModelTable` aliases nested in by the SQL,
//! and the statements of a team insert.

use chrono::NaiveDateTime;
use serde::Serialize;
use sqlx::PgExecutor;

use litellm_db::Error;

use super::repository::NewTeam;
use crate::RawJson;
use crate::utc_timestamp::naive_utc;

/// One `LiteLLM_TeamTable` row as auth reads it, with its JSON columns kept opaque for the host's codec.
#[macro_rules_attribute::apply(crate::db_row)]
#[derive(Serialize)]
pub struct Team {
    pub team_id: String,
    pub team_alias: Option<String>,
    pub organization_id: Option<String>,
    pub admins: Vec<String>,
    pub members: Vec<String>,
    pub members_with_roles: RawJson,
    pub metadata: RawJson,
    pub max_budget: Option<f64>,
    pub soft_budget: Option<f64>,
    pub spend: f64,
    pub models: Vec<String>,
    pub max_parallel_requests: Option<i32>,
    pub tpm_limit: Option<i64>,
    pub rpm_limit: Option<i64>,
    pub tpd_limit: Option<i64>,
    pub budget_duration: Option<String>,
    #[serde(with = "crate::utc_timestamp::option")]
    pub budget_reset_at: Option<NaiveDateTime>,
    pub blocked: bool,
    #[serde(with = "crate::utc_timestamp")]
    pub created_at: NaiveDateTime,
    #[serde(with = "crate::utc_timestamp")]
    pub updated_at: NaiveDateTime,
    pub model_spend: RawJson,
    pub model_max_budget: RawJson,
    pub router_settings: Option<RawJson>,
    pub team_member_permissions: Vec<String>,
    pub access_group_ids: Vec<String>,
    pub policies: Vec<String>,
    pub default_team_member_models: Vec<String>,
    pub budget_limits: Option<RawJson>,
    pub model_id: Option<i32>,
    pub allow_team_guardrail_config: bool,
    pub object_permission_id: Option<String>,
    pub litellm_model_table: Option<RawJson>,
}

/// The team `team_id`, or `None` when no row has that id.
pub(super) async fn find_team(
    executor: impl PgExecutor<'_>,
    team_id: &str,
) -> Result<Option<Team>, Error> {
    Ok(
        sqlx::query_file_as!(Team, "src/team/queries/find_team.sql", team_id)
            .fetch_optional(executor)
            .await?,
    )
}

/// Up to two teams whose alias is `team_alias`, so a caller can tell a unique alias from a shared one.
pub(super) async fn find_teams_by_alias(
    executor: impl PgExecutor<'_>,
    team_alias: &str,
) -> Result<Vec<Team>, Error> {
    Ok(
        sqlx::query_file_as!(Team, "src/team/queries/find_teams_by_alias.sql", team_alias)
            .fetch_all(executor)
            .await?,
    )
}

/// Inserts `team`, or nothing when its id is already taken; the id when this call stored it.
pub(super) async fn insert_team(
    executor: impl PgExecutor<'_>,
    team: &NewTeam,
) -> Result<Option<String>, Error> {
    Ok(sqlx::query_file_scalar!(
        "src/team/queries/insert_team.sql",
        team.team_id,
        team.organization_id.as_deref(),
        team.max_budget,
        team.budget_duration.as_deref(),
        team.budget_reset_at.and_then(naive_utc),
        team.tpm_limit,
        team.rpm_limit,
        team.team_member_permissions.as_deref(),
        team.access_group_ids.as_deref()
    )
    .fetch_optional(executor)
    .await?)
}

/// Takes the advisory lock the management endpoints hold while they write `team_id`, until the transaction ends.
pub(super) async fn lock_team(executor: impl PgExecutor<'_>, team_id: &str) -> Result<(), Error> {
    sqlx::query_file_scalar!("src/team/queries/lock_team.sql", team_id)
        .fetch_one(executor)
        .await?;
    Ok(())
}

/// The access groups `team_id` names, with its row locked, or `None` when the team is gone.
pub(super) async fn lock_team_access_group_ids(
    executor: impl PgExecutor<'_>,
    team_id: &str,
) -> Result<Option<Vec<String>>, Error> {
    Ok(
        sqlx::query_file_scalar!("src/team/queries/lock_team_access_group_ids.sql", team_id)
            .fetch_optional(executor)
            .await?,
    )
}

/// An access group on either side of a reconcile, and whether it lists the team now.
#[macro_rules_attribute::apply(crate::db_row)]
pub(super) struct TeamAccessGroup {
    pub access_group_id: String,
    pub attached: bool,
}

/// The access groups `access_group_ids` names or that list `team_id`.
pub(super) async fn access_groups_of_team(
    executor: impl PgExecutor<'_>,
    team_id: &str,
    access_group_ids: &[String],
) -> Result<Vec<TeamAccessGroup>, Error> {
    Ok(sqlx::query_file_as!(
        TeamAccessGroup,
        "src/team/queries/access_groups_of_team.sql",
        team_id,
        access_group_ids
    )
    .fetch_all(executor)
    .await?)
}

/// Locks the rows of `access_group_ids` in id order.
pub(super) async fn lock_access_groups(
    executor: impl PgExecutor<'_>,
    access_group_ids: &[String],
) -> Result<(), Error> {
    sqlx::query_file_scalar!("src/team/queries/lock_access_groups.sql", access_group_ids)
        .fetch_all(executor)
        .await?;
    Ok(())
}

/// Adds `team_id` to the teams of each access group in `access_group_ids` that does not list it.
pub(super) async fn attach_team_to_access_groups(
    executor: impl PgExecutor<'_>,
    team_id: &str,
    access_group_ids: &[String],
) -> Result<(), Error> {
    sqlx::query_file!(
        "src/team/queries/attach_team_to_access_groups.sql",
        team_id,
        access_group_ids
    )
    .execute(executor)
    .await?;
    Ok(())
}

/// Takes `team_id` off the teams of each access group in `access_group_ids`.
pub(super) async fn detach_team_from_access_groups(
    executor: impl PgExecutor<'_>,
    team_id: &str,
    access_group_ids: &[String],
) -> Result<(), Error> {
    sqlx::query_file!(
        "src/team/queries/detach_team_from_access_groups.sql",
        team_id,
        access_group_ids
    )
    .execute(executor)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::error::Error as StdError;

    use super::{find_team, find_teams_by_alias};
    use crate::test_support::database_pool;
    use rstest::rstest;
    use sqlx::PgPool;

    #[rstest]
    #[case::with_model_aliases(Some(r#"{"gpt": "gpt-4o"}"#))]
    #[case::without_model_aliases(None)]
    #[tokio::test]
    #[ignore = "requires DATABASE_URL pointing to a Prisma-migrated PostgreSQL database"]
    async fn reads_team_with_its_model_aliases(
        #[case] aliases: Option<&str>,
        #[future(awt)] database_pool: Result<PgPool, Box<dyn StdError>>,
    ) -> Result<(), Box<dyn StdError>> {
        let pool = database_pool?;
        let mut tx = pool.begin().await?;
        #[expect(
            clippy::disallowed_methods,
            reason = "Fixture writes are outside the compile-checked query set"
        )]
        let model_id: Option<i32> = sqlx::query_scalar(
            r#"INSERT INTO "LiteLLM_ModelTable" (aliases, created_by, updated_by)
               SELECT $1::jsonb, 'a', 'b' WHERE $1 IS NOT NULL RETURNING id"#,
        )
        .bind(aliases)
        .fetch_optional(&mut *tx)
        .await?;
        #[expect(
            clippy::disallowed_methods,
            reason = "Fixture writes are outside the compile-checked query set"
        )]
        let _inserted = sqlx::query(
            r#"INSERT INTO "LiteLLM_TeamTable"
                   (team_id, team_alias, models, members_with_roles, metadata, tpm_limit,
                    budget_reset_at, created_at, updated_at, model_id, admins)
               VALUES ('find-team', 'alias', '{gpt-4o}', '[{"role": "admin", "user_id": "u"}]',
                       '{"k": 1}', 9007199254740993, '2026-01-02 03:04:05.678',
                       '2026-01-01', '2026-01-01', $1, NULL)"#,
        )
        .bind(model_id)
        .execute(&mut *tx)
        .await?;

        let team = find_team(&mut *tx, "find-team")
            .await?
            .ok_or("team missing")?;

        assert_eq!(team.team_alias.as_deref(), Some("alias"));
        assert_eq!(team.models, ["gpt-4o"]);
        assert!(team.admins.is_empty());
        assert_eq!(team.tpm_limit, Some(9_007_199_254_740_993));
        assert_eq!(
            team.members_with_roles.get(),
            r#"[{"role": "admin", "user_id": "u"}]"#
        );
        assert_eq!(team.model_id, model_id);
        let encoded = serde_json::to_value(&team)?;
        assert_eq!(encoded["budget_reset_at"], "2026-01-02T03:04:05.678+00:00");
        assert_eq!(encoded["created_at"], "2026-01-01T00:00:00+00:00");
        assert_eq!(
            encoded["litellm_model_table"],
            model_id.map_or(serde_json::Value::Null, |id| serde_json::json!({
                "id": id, "model_aliases": {"gpt": "gpt-4o"}, "created_by": "a", "updated_by": "b"
            }))
        );
        Ok(())
    }

    #[rstest]
    #[tokio::test]
    #[ignore = "requires DATABASE_URL pointing to a Prisma-migrated PostgreSQL database"]
    async fn missing_team_is_none(
        #[future(awt)] database_pool: Result<PgPool, Box<dyn StdError>>,
    ) -> Result<(), Box<dyn StdError>> {
        let pool = database_pool?;
        assert!(find_team(&pool, "no-such-team").await?.is_none());
        Ok(())
    }

    #[rstest]
    #[case::unique("unique-alias", &["by-alias-a"])]
    #[case::shared("shared-alias", &["by-alias-b", "by-alias-c"])]
    #[case::missing("no-such-alias", &[])]
    #[tokio::test]
    #[ignore = "requires DATABASE_URL pointing to a Prisma-migrated PostgreSQL database"]
    async fn reads_teams_by_alias(
        #[case] alias: &str,
        #[case] expected: &[&str],
        #[future(awt)] database_pool: Result<PgPool, Box<dyn StdError>>,
    ) -> Result<(), Box<dyn StdError>> {
        let pool = database_pool?;
        let mut tx = pool.begin().await?;
        #[expect(
            clippy::disallowed_methods,
            reason = "Fixture writes are outside the compile-checked query set"
        )]
        let _inserted = sqlx::query(
            r#"INSERT INTO "LiteLLM_TeamTable" (team_id, team_alias, created_at, updated_at)
               VALUES ('by-alias-a', 'unique-alias', '2026-01-01', '2026-01-01'),
                      ('by-alias-b', 'shared-alias', '2026-01-01', '2026-01-01'),
                      ('by-alias-c', 'shared-alias', '2026-01-01', '2026-01-01'),
                      ('by-alias-d', 'shared-alias', '2026-01-01', '2026-01-01')"#,
        )
        .execute(&mut *tx)
        .await?;

        let teams = find_teams_by_alias(&mut *tx, alias).await?;

        assert_eq!(
            teams
                .iter()
                .map(|team| team.team_id.as_str())
                .collect::<Vec<_>>(),
            expected
        );
        Ok(())
    }
}
