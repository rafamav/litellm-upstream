//! A team membership's database read against a Prisma-migrated Postgres. Each row literal is what
//! the repository hands the Python proxy, and each entry literal is what Python caches for that
//! row. `tests/unit/redis/stores/test_auth_cache_team_membership.py` checks both against Python's
//! own model and membership readers, and `redis-store/tests/auth_cache_team_membership.rs`
//! round-trips the entries through Redis. Change all three together.

mod support;

use std::sync::Arc;

use litellm_auth_store::{Error, MemberAdded, MemberRemoved, TeamMembershipDatabase};
use litellm_db_testing::MigratedPostgres;
use litellm_repositories::{
    JoinBudget, MappedClaim, MemberBudget, NewCappedMemberBudget, RosterRole, Side,
    TeamMembershipRepository,
};
use rstest::{fixture, rstest};
use sqlx::PgPool;

use support::{database, dumped, execute, insert_budgets};

const CREATED_ROW: &str = concat!(
    r#"{"user_id":"member","team_id":"created","budget_id":null,"spend":0.0,"total_spend":0.0,"#,
    r#""litellm_budget_table":null}"#,
);
const CREATED_ENTRY: &str = concat!(
    r#"{"user_id": "member", "team_id": "created", "budget_id": null, "spend": 0.0,"#,
    r#" "total_spend": 0.0, "litellm_budget_table": null}"#,
);
const BARE_BUDGET_ROW: &str = concat!(
    r#"{"user_id":"member","team_id":"bare_budget","budget_id":"bare","spend":0.0,"#,
    r#""total_spend":0.0,"litellm_budget_table":{"budget_id":"bare","name":null,"#,
    r#""max_budget":null,"soft_budget":null,"max_parallel_requests":null,"tpm_limit":null,"#,
    r#""rpm_limit":null,"tpd_limit":null,"model_max_budget":null,"model_tpm_limit":null,"#,
    r#""model_rpm_limit":null,"budget_duration":null,"budget_limits":null,"cap_policy":null,"#,
    r#""budget_reset_at":null,"budget_reset_count":0,"allowed_models":[],"#,
    r#""temp_budget_increase":null,"temp_budget_expiry":null,"#,
    r#""created_at":"2026-11-01T00:00:00+00:00","created_by":"test","#,
    r#""updated_at":"2026-11-01T00:00:00+00:00","updated_by":"test"}}"#,
);
const BARE_BUDGET_ENTRY: &str = concat!(
    r#"{"user_id": "member", "team_id": "bare_budget", "budget_id": "bare", "spend": 0.0,"#,
    r#" "total_spend": 0.0, "litellm_budget_table": {"budget_id": "bare", "soft_budget": null,"#,
    r#" "max_budget": null, "max_parallel_requests": null, "tpm_limit": null,"#,
    r#" "rpm_limit": null, "tpd_limit": null, "model_max_budget": null,"#,
    r#" "model_tpm_limit": null, "model_rpm_limit": null, "budget_duration": null,"#,
    r#" "allowed_models": [], "temp_budget_increase": null, "temp_budget_expiry": null,"#,
    r#" "budget_reset_at": null, "created_at": "2026-11-01T00:00:00Z"}}"#,
);
const FULL_ROW: &str = concat!(
    r#"{"user_id":"member","team_id":"full","budget_id":"budget","spend":1.5,"#,
    r#""rollover_credit":2.5,"total_spend":3.0,"litellm_budget_table":{"budget_id":"budget","#,
    r#""name":"Budget","max_budget":10.5,"rollover_max_budget":20.0,"soft_budget":8.0,"#,
    r#""max_parallel_requests":3,"tpm_limit":1000,"rpm_limit":10,"tpd_limit":100000,"#,
    r#""model_max_budget":{"claude": {"max_budget": 1}},"model_tpm_limit":{"gpt": "7","#,
    r#" "claude": 100.0},"model_rpm_limit":{"claude": "5"},"budget_duration":"30d","#,
    r#""budget_limits":[],"cap_policy":"hard","budget_reset_at":"2026-12-01T00:00:00+00:00","#,
    r#""budget_reset_count":2,"allowed_models":["claude"],"temp_budget_increase":1.5,"#,
    r#""temp_budget_expiry":"2026-11-20T12:30:00.250+00:00","#,
    r#""created_at":"2026-11-01T00:00:00+00:00","created_by":"test","#,
    r#""updated_at":"2026-11-02T00:00:00+00:00","updated_by":"test"}}"#,
);
const FULL_ENTRY: &str = concat!(
    r#"{"user_id": "member", "team_id": "full", "budget_id": "budget", "spend": 1.5,"#,
    r#" "total_spend": 3.0, "rollover_credit": 2.5,"#,
    r#" "litellm_budget_table": {"budget_id": "budget", "soft_budget": 8.0, "max_budget": 10.5,"#,
    r#" "rollover_max_budget": 20.0, "max_parallel_requests": 3, "tpm_limit": 1000,"#,
    r#" "rpm_limit": 10, "tpd_limit": 100000,"#,
    r#" "model_max_budget": {"claude": {"max_budget": 1}}, "model_tpm_limit": {"gpt": 7,"#,
    r#" "claude": 100}, "model_rpm_limit": {"claude": 5}, "budget_duration": "30d","#,
    r#" "allowed_models": ["claude"], "temp_budget_increase": 1.5,"#,
    r#" "temp_budget_expiry": "2026-11-20T12:30:00.250000Z","#,
    r#" "budget_reset_at": "2026-12-01T00:00:00Z", "created_at": "2026-11-01T00:00:00Z"}}"#,
);

struct Memberships {
    postgres: MigratedPostgres,
    rows: Arc<TeamMembershipRepository>,
    database: TeamMembershipDatabase,
}

/// A migrated Postgres holding a membership as a member add stores it without a budget, one with
/// every column set, its budget's too, and one whose budget has only its defaults.
#[fixture]
async fn memberships() -> Memberships {
    let postgres = MigratedPostgres::start().await.unwrap();
    insert_budgets(postgres.pool()).await;
    insert_memberships(postgres.pool()).await;
    let rows = Arc::new(TeamMembershipRepository::new(database(&postgres)));
    Memberships {
        database: TeamMembershipDatabase::new(rows.clone()),
        rows,
        postgres,
    }
}

async fn insert_memberships(pool: &PgPool) {
    execute(
        pool,
        r#"INSERT INTO "LiteLLM_TeamMembership" (user_id, team_id) VALUES ('member', 'created')"#,
    )
    .await;
    execute(
        pool,
        r#"INSERT INTO "LiteLLM_TeamMembership" (user_id, team_id, budget_id)
           VALUES ('member', 'bare_budget', 'bare')"#,
    )
    .await;
    execute(
        pool,
        r#"INSERT INTO "LiteLLM_TeamMembership" (user_id, team_id, budget_id, spend, rollover_credit, total_spend)
           VALUES ('member', 'full', 'budget', 1.5, 2.5, 3.0)"#,
    )
    .await;
}

#[rstest]
#[case::as_created("created", CREATED_ROW, CREATED_ENTRY)]
#[case::every_column_set("full", FULL_ROW, FULL_ENTRY)]
#[case::a_budget_with_its_defaults("bare_budget", BARE_BUDGET_ROW, BARE_BUDGET_ENTRY)]
#[tokio::test(flavor = "multi_thread")]
async fn a_team_membership_read_from_the_database_is_the_entry_python_caches(
    #[future(awt)] memberships: Memberships,
    #[case] team_id: &str,
    #[case] row: &str,
    #[case] cached: &str,
) {
    let found = memberships
        .rows
        .find_with_budget("member", team_id, Side::Read)
        .await
        .unwrap()
        .unwrap();
    let read = memberships
        .database
        .team_membership("member", team_id, Side::Read)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        (
            serde_json::to_string(&found).unwrap().as_str(),
            dumped(read).as_str()
        ),
        (row, cached)
    );
}

#[rstest]
#[tokio::test(flavor = "multi_thread")]
async fn a_user_who_is_not_a_member_is_not_found(#[future(awt)] memberships: Memberships) {
    let read = memberships
        .database
        .team_membership("member", "gone", Side::Read)
        .await
        .unwrap();

    assert_eq!(read, None);
}

#[rstest]
#[tokio::test(flavor = "multi_thread")]
async fn a_budget_the_model_refuses_fails_the_read_under_the_field_it_sits_in(
    #[future(awt)] memberships: Memberships,
) {
    execute(
        memberships.postgres.pool(),
        r#"UPDATE "LiteLLM_BudgetTable" SET budget_limits = '[{"budget_duration": "1d", "max_budget": 1}]'"#,
    )
    .await;

    let read = memberships
        .database
        .team_membership("member", "full", Side::Read)
        .await;

    assert!(
        matches!(
            &read,
            Err(Error::Row {
                column: "budget_limits",
                within: Some("litellm_budget_table")
            })
        ),
        "{:?}",
        read.err()
    );
}

/// Python's own rows for the same fixture, captured on 2026-11-27 by running
/// `scim_v2._remove_user_from_team("leaver", "roster")` (which calls `team_member_delete`) and
/// `get_user_object(..., user_id_upsert=True)` with `default_internal_user_params.teams` set to
/// `[{"team_id": "dt-capped", "max_budget_in_team": 3.0, "user_role": "admin"}, {"team_id":
/// "dt-plain"}]` against a migrated Postgres, then `row_to_json` of each row, less its generated id
/// and times. Prisma reads the key's NULL array columns as `[]`, which is what Python archives.
const PYTHON_ARCHIVED_KEY: &str = concat!(
    r#"{"access_group_ids":[],"agent_id":null,"aliases":{},"allowed_cache_controls":[],"#,
    r#""allowed_routes":[],"auto_rotate":false,"blocked":null,"budget_duration":null,"#,
    r#""budget_fallbacks":{},"budget_id":null,"budget_reset_at":null,"config":{},"created_by":null,"#,
    r#""deleted_by":null,"deleted_by_api_key":null,"expires":null,"key_alias":"kept alias","#,
    r#""key_id":null,"key_name":null,"key_rotation_at":null,"key_type":null,"last_active":null,"#,
    r#""last_rotation_at":null,"litellm_changed_by":null,"max_budget":null,"#,
    r#""max_parallel_requests":null,"metadata":{},"model_max_budget":{},"model_spend":{},"#,
    r#""models":[],"object_permission_id":null,"organization_id":null,"permissions":{},"#,
    r#""policies":[],"project_id":null,"rotation_count":0,"rotation_interval":null,"#,
    r#""router_settings":{},"rpm_limit":null,"settings_updated_at":null,"#,
    r#""soft_budget_cooldown":false,"spend":1.5,"team_id":"roster","token":"leaver-roster-key","#,
    r#""total_spend":0,"tpd_limit":null,"tpm_limit":null,"updated_by":null,"user_id":"leaver"}"#,
);
const PYTHON_CAPPED_MEMBER_BUDGET: &str = concat!(
    r#"{"allowed_models":["claude"],"budget_duration":null,"budget_limits":null,"#,
    r#""budget_reset_at":null,"budget_reset_count":0,"cap_policy":null,"#,
    r#""created_by":"default_user_id","max_budget":3,"max_parallel_requests":null,"#,
    r#""model_max_budget":null,"model_rpm_limit":null,"model_tpm_limit":null,"name":null,"#,
    r#""rollover_max_budget":null,"rpm_limit":null,"soft_budget":null,"temp_budget_expiry":null,"#,
    r#""temp_budget_increase":null,"tpd_limit":null,"tpm_limit":null,"updated_by":"default_user_id"}"#,
);
const PYTHON_CAPPED_ROSTER: &str =
    r#"[{"role": "admin", "user_id": "joiner", "user_email": "joiner@example.com"}]"#;
const PYTHON_PLAIN_ROSTER: &str =
    r#"[{"role": "user", "user_id": "joiner", "user_email": "joiner@example.com"}]"#;

/// The JSON of the one row `sql` reads, less the columns generated per write.
async fn row_without(pool: &PgPool, sql: &'static str, generated: &[&str]) -> serde_json::Value {
    let mut row: serde_json::Value = serde_json::from_str(&scalar(pool, sql).await).unwrap();
    let fields = row.as_object_mut().unwrap();
    generated.iter().for_each(|column| {
        fields.remove(*column);
    });
    row
}

/// `roster` lists `other` and then `leaver`, whose row lists `roster` and `elsewhere` among its
/// teams and who holds a key in each, the one in `roster` mapped to a JWT claim. `stale` lists
/// `roster` among its teams with no roster entry, and `joiner` is in no team.
async fn insert_roster(pool: &PgPool) {
    execute(
        pool,
        r#"INSERT INTO "LiteLLM_TeamTable" (team_id, members_with_roles, created_at, updated_at)
           VALUES ('roster', '[{"user_id": "other", "user_email": null, "role": "admin"},
                               {"user_id": "leaver", "user_email": "leaver@example.com", "role": "user"}]',
                   '2026-11-01 00:00:00', '2026-11-01 00:00:00'),
                  ('elsewhere', '[]', '2026-11-01 00:00:00', '2026-11-01 00:00:00')"#,
    )
    .await;
    execute(
        pool,
        r#"INSERT INTO "LiteLLM_TeamTable" (team_id, members_with_roles, default_team_member_models, created_at, updated_at)
           VALUES ('dt-capped', '[]', ARRAY['claude'], '2026-11-01 00:00:00', '2026-11-01 00:00:00'),
                  ('dt-plain', '[]', ARRAY[]::text[], '2026-11-01 00:00:00', '2026-11-01 00:00:00')"#,
    )
    .await;
    execute(
        pool,
        r#"INSERT INTO "LiteLLM_UserTable" (user_id, user_email, teams, created_at, updated_at)
           VALUES ('leaver', 'leaver@example.com', ARRAY['roster', 'elsewhere'], '2026-11-01 00:00:00', '2026-11-01 00:00:00'),
                  ('stale', NULL, ARRAY['roster'], '2026-11-01 00:00:00', '2026-11-01 00:00:00'),
                  ('joiner', 'joiner@example.com', ARRAY[]::text[], '2026-11-01 00:00:00', '2026-11-01 00:00:00')"#,
    )
    .await;
    execute(
        pool,
        r#"INSERT INTO "LiteLLM_TeamMembership" (user_id, team_id) VALUES ('leaver', 'roster'), ('leaver', 'elsewhere')"#,
    )
    .await;
    execute(
        pool,
        r#"INSERT INTO "LiteLLM_VerificationToken"
               (token, user_id, team_id, key_alias, spend, allowed_cache_controls, allowed_routes, policies, access_group_ids)
           VALUES ('leaver-roster-key', 'leaver', 'roster', 'kept alias', 1.5, NULL, NULL, NULL, NULL),
                  ('leaver-elsewhere-key', 'leaver', 'elsewhere', NULL, 0, '{}', '{}', '{}', '{}')"#,
    )
    .await;
    execute(
        pool,
        r#"INSERT INTO "LiteLLM_JWTKeyMapping" (id, jwt_claim_name, jwt_claim_value, token, jwt_issuer)
           VALUES ('mapping', 'sub', 'leaver-sub', 'leaver-roster-key', 'https://issuer.example.com')"#,
    )
    .await;
}

#[fixture]
async fn rosters(#[future(awt)] memberships: Memberships) -> Memberships {
    insert_roster(memberships.postgres.pool()).await;
    memberships
}

async fn scalar(pool: &PgPool, sql: &'static str) -> String {
    #[expect(
        clippy::disallowed_methods,
        reason = "Assertion reads are outside the compile-checked query set"
    )]
    let read = sqlx::query_scalar(sql);
    read.fetch_one(pool).await.unwrap()
}

fn user_ids(roster: &[litellm_redis_store::auth_cache::MemberEntry]) -> Vec<Option<&str>> {
    roster
        .iter()
        .map(|member| member.user_id.as_deref())
        .collect()
}

#[rstest]
#[tokio::test(flavor = "multi_thread")]
async fn a_member_add_returns_the_roster_as_stored_with_the_new_member_last(
    #[future(awt)] rosters: Memberships,
) {
    let added = rosters
        .database
        .add_member("joiner", "roster", MemberBudget::None)
        .await
        .unwrap();
    let membership = rosters
        .database
        .team_membership("joiner", "roster", Side::Writer)
        .await
        .unwrap();

    let MemberAdded::Added { roster } = added else {
        panic!("the user was added: {added:?}");
    };
    assert_eq!(
        (
            dumped(roster.last().cloned().unwrap()).as_str(),
            user_ids(&roster),
            membership.map(|membership| membership.team_id)
        ),
        (
            r#"{"user_id": "joiner", "user_email": "joiner@example.com", "role": "user"}"#,
            vec![Some("other"), Some("leaver"), Some("joiner")],
            Some("roster".to_owned())
        )
    );
}

#[rstest]
#[case::already_on_the_roster("leaver", "roster", MemberAdded::AlreadyMember)]
#[case::a_team_no_row_has("joiner", "gone", MemberAdded::TeamMissing)]
#[case::a_user_no_row_has("gone", "roster", MemberAdded::UserMissing)]
#[tokio::test(flavor = "multi_thread")]
async fn a_member_add_that_writes_nothing_says_why(
    #[future(awt)] rosters: Memberships,
    #[case] user_id: &str,
    #[case] team_id: &str,
    #[case] expected: MemberAdded,
) {
    let added = rosters
        .database
        .add_member(user_id, team_id, MemberBudget::None)
        .await
        .unwrap();

    assert_eq!(added, expected);
}

/// The sync removes a member the way `team_member_delete` does: off the roster, the team off the
/// user's teams, the membership row and the user's keys in the team, archived first.
#[rstest]
#[tokio::test(flavor = "multi_thread")]
async fn a_member_removal_takes_the_user_off_the_team_with_its_keys_in_the_team(
    #[future(awt)] rosters: Memberships,
) {
    let removed = rosters
        .database
        .remove_member("leaver", "roster")
        .await
        .unwrap();
    let pool = rosters.postgres.pool();

    let MemberRemoved::Removed {
        roster_before,
        roster_after,
        deleted_tokens,
        mapped_claims,
    } = removed
    else {
        panic!("the user was removed: {removed:?}");
    };
    assert_eq!(
        (
            user_ids(&roster_before),
            user_ids(&roster_after),
            deleted_tokens,
            mapped_claims,
        ),
        (
            vec![Some("other"), Some("leaver")],
            vec![Some("other")],
            vec!["leaver-roster-key".to_owned()],
            vec![MappedClaim {
                jwt_issuer: "https://issuer.example.com".to_owned(),
                jwt_claim_name: "sub".to_owned(),
                jwt_claim_value: "leaver-sub".to_owned(),
            }],
        )
    );
    assert_eq!(
        (
            scalar(pool, r#"SELECT members_with_roles::text FROM "LiteLLM_TeamTable" WHERE team_id = 'roster'"#).await,
            scalar(pool, r#"SELECT array_to_string(teams, ',') FROM "LiteLLM_UserTable" WHERE user_id = 'leaver'"#).await,
            scalar(pool, r#"SELECT string_agg(team_id, ',' ORDER BY team_id) FROM "LiteLLM_TeamMembership" WHERE user_id = 'leaver'"#).await,
            scalar(pool, r#"SELECT string_agg(token, ',' ORDER BY token) FROM "LiteLLM_VerificationToken""#).await,
            scalar(pool, r#"SELECT count(*)::text FROM "LiteLLM_JWTKeyMapping""#).await,
            scalar(
                pool,
                r#"SELECT token || ',' || key_alias || ',' || spend::text || ',' || user_id || ',' || team_id || ','
                          || (abs(extract(epoch FROM deleted_at - (now() AT TIME ZONE 'UTC'))) < 5)::text
                   FROM "LiteLLM_DeletedVerificationToken""#,
            )
            .await,
        ),
        (
            r#"[{"role": "admin", "user_id": "other", "user_email": null}]"#.to_owned(),
            "elsewhere".to_owned(),
            "elsewhere".to_owned(),
            "leaver-elsewhere-key".to_owned(),
            "0".to_owned(),
            "leaver-roster-key,kept alias,1.5,leaver,roster,true".to_owned(),
        )
    );
}

#[rstest]
#[tokio::test(flavor = "multi_thread")]
async fn a_member_removal_clears_a_team_the_users_row_still_lists_without_a_roster_entry(
    #[future(awt)] rosters: Memberships,
) {
    let removed = rosters
        .database
        .remove_member("stale", "roster")
        .await
        .unwrap();
    let teams = scalar(
        rosters.postgres.pool(),
        r#"SELECT array_to_string(teams, ',') FROM "LiteLLM_UserTable" WHERE user_id = 'stale'"#,
    )
    .await;

    let MemberRemoved::Removed {
        roster_before,
        roster_after,
        ..
    } = removed
    else {
        panic!("the stale team was cleared: {removed:?}");
    };
    assert_eq!(
        (
            user_ids(&roster_after),
            roster_before == roster_after,
            teams
        ),
        (vec![Some("other"), Some("leaver")], true, String::new())
    );
}

#[rstest]
#[case::a_user_the_team_does_not_list("joiner", "roster", MemberRemoved::NotMember)]
#[case::a_team_no_row_has("leaver", "gone", MemberRemoved::TeamMissing)]
#[tokio::test(flavor = "multi_thread")]
async fn a_member_removal_that_writes_nothing_says_why(
    #[future(awt)] rosters: Memberships,
    #[case] user_id: &str,
    #[case] team_id: &str,
    #[case] expected: MemberRemoved,
) {
    let removed = rosters
        .database
        .remove_member(user_id, team_id)
        .await
        .unwrap();

    assert_eq!(removed, expected);
}

#[rstest]
#[tokio::test(flavor = "multi_thread")]
async fn a_removed_members_key_is_archived_as_python_archives_it(
    #[future(awt)] rosters: Memberships,
) {
    rosters
        .database
        .remove_member("leaver", "roster")
        .await
        .unwrap();

    let archived = row_without(
        rosters.postgres.pool(),
        r#"SELECT row_to_json(d)::text FROM "LiteLLM_DeletedVerificationToken" AS d"#,
        &["id", "created_at", "updated_at", "deleted_at"],
    )
    .await;
    assert_eq!(
        archived,
        serde_json::from_str::<serde_json::Value>(PYTHON_ARCHIVED_KEY).unwrap()
    );
}

/// The host joins a user `user_id_upsert` created to each default team as Python does: an admin
/// with a capped budget of their own taking the team's default member models, and a plain member
/// with no budget. The rows match the ones Python's `add_new_user_to_default_team` stored.
#[rstest]
#[tokio::test(flavor = "multi_thread")]
async fn a_default_team_join_stores_the_rows_python_stores(#[future(awt)] rosters: Memberships) {
    let capped = NewCappedMemberBudget {
        budget_id: "joiner-capped".to_owned(),
        max_budget: 3.0,
        allowed_models: Some(vec!["claude".to_owned()]),
        created_by: "default_user_id".to_owned(),
        updated_by: "default_user_id".to_owned(),
    };
    let as_admin = rosters
        .database
        .add_member_as(
            "joiner",
            "dt-capped",
            RosterRole::Admin,
            JoinBudget::Capped(&capped),
        )
        .await
        .unwrap();
    let as_user = rosters
        .database
        .add_member_as(
            "joiner",
            "dt-plain",
            RosterRole::User,
            JoinBudget::Member(MemberBudget::None),
        )
        .await
        .unwrap();
    let pool = rosters.postgres.pool();

    assert!(
        matches!(
            (&as_admin, &as_user),
            (MemberAdded::Added { .. }, MemberAdded::Added { .. })
        ),
        "{as_admin:?} {as_user:?}"
    );
    assert_eq!(
        (
            scalar(pool, r#"SELECT members_with_roles::text FROM "LiteLLM_TeamTable" WHERE team_id = 'dt-capped'"#).await,
            scalar(pool, r#"SELECT members_with_roles::text FROM "LiteLLM_TeamTable" WHERE team_id = 'dt-plain'"#).await,
            scalar(pool, r#"SELECT array_to_string(teams, ',') FROM "LiteLLM_UserTable" WHERE user_id = 'joiner'"#).await,
            scalar(
                pool,
                r#"SELECT team_id || '=' || COALESCE(budget_id, 'none') FROM "LiteLLM_TeamMembership"
                   WHERE user_id = 'joiner' AND team_id = 'dt-plain'"#,
            )
            .await,
            row_without(
                pool,
                r#"SELECT row_to_json(b)::text FROM "LiteLLM_BudgetTable" AS b
                   JOIN "LiteLLM_TeamMembership" AS m ON m.budget_id = b.budget_id
                   WHERE m.user_id = 'joiner' AND m.team_id = 'dt-capped'"#,
                &["budget_id", "created_at", "updated_at"],
            )
            .await,
        ),
        (
            PYTHON_CAPPED_ROSTER.to_owned(),
            PYTHON_PLAIN_ROSTER.to_owned(),
            "dt-capped,dt-plain".to_owned(),
            "dt-plain=none".to_owned(),
            serde_json::from_str::<serde_json::Value>(PYTHON_CAPPED_MEMBER_BUDGET).unwrap(),
        )
    );
}
