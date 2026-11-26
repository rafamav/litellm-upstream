//! A JWT caller's team, membership and user as the auth cache holds them, as far as the native
//! host reads them. Each entry is taken apart by name, so a field added to it does not compile
//! here until it is honored or named as one the native app has no counterpart for. Nothing here
//! charges or limits a team, a member or a user, so a row that holds a limit, a budget, a model
//! list or anything Python applies after auth is declined, naming the field.

use litellm_gateway_auth_core::{
    authz::ModelList,
    identity::jwt::{Team, User},
    record::{MembershipRecord, TeamRecord, UserRecord},
    routes::passthrough::PassthroughGrants,
};
use litellm_python_compat::Value;
use litellm_redis_store::auth_cache::{Bag, TeamEntry, TeamMembershipEntry, UserEntry};

use super::key::Carried;

/// The `metadata` key SCIM sets to `False` on a user it deactivated.
const SCIM_ACTIVE: &str = "scim_active";

/// The fields that describe a team rather than govern its calls, its roster and spend included,
/// are read for nothing. `models` is the team's layer of the model rule, and a list with an entry
/// that rule does not read declines. Every other field that holds something is a limit, a budget,
/// a grant or a setting Python applies after auth.
pub(super) fn team(team: &TeamEntry) -> Result<Team<TeamRecord>, &'static str> {
    let TeamEntry {
        team_alias,
        team_id,
        organization_id,
        admins: _,
        members: _,
        members_with_roles,
        team_member_permissions: _,
        metadata,
        tpm_limit,
        rpm_limit,
        tpd_limit,
        max_budget,
        soft_budget,
        budget_duration,
        budget_limits,
        models,
        blocked,
        router_settings,
        access_group_ids,
        default_team_member_models,
        spend: _,
        max_parallel_requests,
        budget_reset_at,
        model_id,
        model_spend: _,
        model_max_budget,
        policies,
        allow_team_guardrail_config,
        litellm_model_table,
        object_permission,
        object_permission_id,
        updated_at: _,
        created_at: _,
        last_refreshed_at: _,
        unread,
    } = team;
    let unread = &newer(unread);
    let unread_models = matches!(ModelList::read(models), ModelList::Unread);
    let held = unread_models.then_some("models").or(carried![
        organization_id,
        metadata,
        tpm_limit,
        rpm_limit,
        tpd_limit,
        max_budget,
        soft_budget,
        budget_duration,
        budget_limits,
        blocked,
        router_settings,
        access_group_ids,
        default_team_member_models,
        max_parallel_requests,
        budget_reset_at,
        model_id,
        model_max_budget,
        policies,
        allow_team_guardrail_config,
        litellm_model_table,
        object_permission,
        object_permission_id,
        unread,
    ]);
    if let Some(field) = held {
        return Err(field);
    }
    Ok(Team {
        team_id: team_id.clone(),
        models: Some(models.clone()),
        passthrough: PassthroughGrants::default(),
        members: members_with_roles
            .iter()
            .filter_map(|member| member.user_id.clone())
            .collect(),
        row: TeamRecord {
            team_id: team_id.clone(),
            team_alias: team_alias.clone(),
            models: models.clone(),
        },
    })
}

/// A membership with a budget of its own is one the team member budget check reads.
pub(super) fn membership(
    membership: &TeamMembershipEntry,
) -> Result<MembershipRecord, &'static str> {
    let TeamMembershipEntry {
        user_id,
        team_id,
        budget_id,
        spend: _,
        total_spend: _,
        rollover_credit,
        litellm_budget_table,
        unread,
    } = membership;
    let unread = &newer(unread);
    if let Some(field) = carried![budget_id, rollover_credit, litellm_budget_table, unread] {
        return Err(field);
    }
    Ok(MembershipRecord {
        user_id: user_id.clone(),
        team_id: team_id.clone(),
    })
}

/// The user's id, alias, email, role, teams and SCIM state are what the core reads. The fields
/// that describe the row or its sign-in are read for nothing, and every other field that holds
/// something is a limit, a budget, a grant or an owner Python reads after auth.
pub(super) fn user(user: &UserEntry) -> Result<User<UserRecord>, &'static str> {
    let UserEntry {
        user_id,
        user_alias,
        team_id,
        sso_user_id: _,
        organization_id,
        object_permission_id,
        password_reset_required: _,
        last_breach_check_at: _,
        teams,
        user_role,
        max_budget,
        rollover_max_budget,
        rollover_credit,
        budget_limits,
        spend: _,
        user_email,
        models,
        metadata,
        max_parallel_requests,
        tpm_limit,
        rpm_limit,
        budget_duration,
        budget_reset_at,
        allowed_cache_controls,
        policies,
        model_spend: _,
        model_max_budget,
        created_at: _,
        updated_at: _,
        organization_memberships,
        object_permission,
        unread,
    } = user;
    let unread = &newer(unread);
    let deactivated = scim_deactivated(metadata.as_ref()).ok_or("metadata")?;
    let held = carried![
        team_id,
        organization_id,
        object_permission_id,
        max_budget,
        rollover_max_budget,
        rollover_credit,
        budget_limits,
        models,
        max_parallel_requests,
        tpm_limit,
        rpm_limit,
        budget_duration,
        budget_reset_at,
        allowed_cache_controls,
        policies,
        model_max_budget,
        organization_memberships,
        object_permission,
        unread,
    ];
    if let Some(field) = held {
        return Err(field);
    }
    Ok(User {
        user_id: user_id.clone(),
        user_email: user_email.clone(),
        user_role: user_role.clone(),
        teams: teams.clone(),
        deactivated,
        row: UserRecord {
            user_id: user_id.clone(),
            user_alias: user_alias.clone(),
        },
    })
}

/// Whether a field this build does not name, which a newer pod wrote, holds something.
fn newer(unread: &[(String, Value)]) -> bool {
    unread.iter().any(|(_, value)| value.is_carried())
}

/// Whether SCIM deactivated the user, as `metadata.get("scim_active") is False` reads it. `None`
/// when the metadata holds anything else.
fn scim_deactivated(metadata: Option<&Bag>) -> Option<bool> {
    let entries = metadata.map(Bag::entries).unwrap_or_default();
    match entries {
        [] => Some(false),
        [(Value::Str(key), active)] if key == SCIM_ACTIVE => {
            Some(matches!(active, Value::Bool(false)))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use litellm_redis_store::FromValue;
    use rstest::rstest;
    use serde_json::{Value as Json, json};

    use super::*;

    /// The cache entry holding `named` with `held` set on it.
    fn entry<T: FromValue>(named: Json, held: &Json) -> T {
        let fields: serde_json::Map<_, _> = [&named, held]
            .into_iter()
            .flat_map(|fields| fields.as_object().unwrap().clone())
            .collect();
        let dumped = litellm_python_compat::json::loads(&Json::Object(fields).to_string());
        T::from_value(&dumped.unwrap()).unwrap()
    }

    fn owned(texts: &[&str]) -> Vec<String> {
        texts.iter().map(|text| (*text).to_owned()).collect()
    }

    #[rstest]
    #[case::a_model_entry_the_rule_does_not_read(json!({"models": ["claude", "anthropic/*"]}), "models")]
    #[case::organization_id(json!({"organization_id": "org"}), "organization_id")]
    #[case::metadata(json!({"metadata": {"guardrails": ["pii"]}}), "metadata")]
    #[case::tpm_limit(json!({"tpm_limit": 100}), "tpm_limit")]
    #[case::rpm_limit(json!({"rpm_limit": 2}), "rpm_limit")]
    #[case::tpd_limit(json!({"tpd_limit": 1000}), "tpd_limit")]
    #[case::max_budget(json!({"max_budget": 5.0}), "max_budget")]
    #[case::soft_budget(json!({"soft_budget": 4.0}), "soft_budget")]
    #[case::budget_duration(json!({"budget_duration": "30d"}), "budget_duration")]
    #[case::budget_limits(
        json!({"budget_limits": [{"budget_duration": "30d", "max_budget": 5.0}]}),
        "budget_limits"
    )]
    #[case::blocked(json!({"blocked": true}), "blocked")]
    #[case::router_settings(json!({"router_settings": {"num_retries": 2}}), "router_settings")]
    #[case::access_group_ids(json!({"access_group_ids": ["group"]}), "access_group_ids")]
    #[case::default_team_member_models(
        json!({"default_team_member_models": ["claude"]}),
        "default_team_member_models"
    )]
    #[case::max_parallel_requests(json!({"max_parallel_requests": 1}), "max_parallel_requests")]
    #[case::budget_reset_at(json!({"budget_reset_at": "2100-01-01T00:00:00"}), "budget_reset_at")]
    #[case::model_id(json!({"model_id": 7}), "model_id")]
    #[case::model_max_budget(json!({"model_max_budget": {"claude": 1.0}}), "model_max_budget")]
    #[case::policies(json!({"policies": ["policy"]}), "policies")]
    #[case::allow_team_guardrail_config(
        json!({"allow_team_guardrail_config": true}),
        "allow_team_guardrail_config"
    )]
    #[case::litellm_model_table(
        json!({"litellm_model_table": {"created_by": "admin", "updated_by": "admin"}}),
        "litellm_model_table"
    )]
    #[case::object_permission(
        json!({"object_permission": {"object_permission_id": "permission"}}),
        "object_permission"
    )]
    #[case::object_permission_id(
        json!({"object_permission_id": "permission"}),
        "object_permission_id"
    )]
    #[case::a_field_a_newer_pod_wrote(json!({"token_budget": 5}), "unread")]
    fn a_team_holding_what_python_applies_after_auth_is_declined_over_that_field(
        #[case] held: Json,
        #[case] field: &str,
    ) {
        let team: TeamEntry = entry(json!({"team_id": "team"}), &held);

        assert_eq!(super::team(&team), Err(field));
    }

    #[test]
    fn a_team_is_read_as_its_id_its_alias_its_models_and_the_users_on_its_roster() {
        let described = json!({
            "team_alias": "alpha",
            "models": ["claude"],
            "members_with_roles": [
                {"user_id": "user-1", "role": "admin"},
                {"user_email": "invited@example.com", "role": "user"},
            ],
            "admins": ["user-1"],
            "members": ["user-2"],
            "team_member_permissions": ["/key/generate"],
            "spend": 3.5,
            "model_spend": {"claude": 3.5},
            "created_at": "2026-01-01T00:00:00",
            "updated_at": "2026-01-02T00:00:00",
            "last_refreshed_at": 1.0,
            "token_budget": null,
        });
        let team: TeamEntry = entry(json!({"team_id": "team"}), &described);

        assert_eq!(
            super::team(&team),
            Ok(Team {
                team_id: "team".to_owned(),
                models: Some(owned(&["claude"])),
                passthrough: PassthroughGrants::default(),
                members: owned(&["user-1"]),
                row: TeamRecord {
                    team_id: "team".to_owned(),
                    team_alias: Some("alpha".to_owned()),
                    models: owned(&["claude"]),
                },
            })
        );
    }

    #[rstest]
    #[case::budget_id(json!({"budget_id": "budget"}), "budget_id")]
    #[case::rollover_credit(json!({"rollover_credit": 1.5}), "rollover_credit")]
    #[case::litellm_budget_table(
        json!({"litellm_budget_table": {"max_budget": 5.0, "created_at": "2026-01-01T00:00:00"}}),
        "litellm_budget_table"
    )]
    #[case::a_field_a_newer_pod_wrote(json!({"token_budget": 5}), "unread")]
    fn a_membership_holding_a_budget_of_its_own_is_declined_over_that_field(
        #[case] held: Json,
        #[case] field: &str,
    ) {
        let membership: TeamMembershipEntry =
            entry(json!({"user_id": "user-1", "team_id": "team"}), &held);

        assert_eq!(super::membership(&membership), Err(field));
    }

    #[test]
    fn a_membership_is_read_as_the_user_and_the_team_it_joins() {
        let spent = json!({"spend": 2.0, "total_spend": 5.0});
        let membership: TeamMembershipEntry =
            entry(json!({"user_id": "user-1", "team_id": "team"}), &spent);

        assert_eq!(
            super::membership(&membership),
            Ok(MembershipRecord {
                user_id: "user-1".to_owned(),
                team_id: "team".to_owned(),
            })
        );
    }

    #[rstest]
    #[case::team_id(json!({"team_id": "team"}), "team_id")]
    #[case::organization_id(json!({"organization_id": "org"}), "organization_id")]
    #[case::object_permission_id(
        json!({"object_permission_id": "permission"}),
        "object_permission_id"
    )]
    #[case::max_budget(json!({"max_budget": 5.0}), "max_budget")]
    #[case::rollover_max_budget(json!({"rollover_max_budget": 5.0}), "rollover_max_budget")]
    #[case::rollover_credit(json!({"rollover_credit": 1.5}), "rollover_credit")]
    #[case::budget_limits(
        json!({"budget_limits": [{"budget_duration": "30d", "max_budget": 5.0}]}),
        "budget_limits"
    )]
    #[case::models(json!({"models": ["claude"]}), "models")]
    #[case::max_parallel_requests(json!({"max_parallel_requests": 1}), "max_parallel_requests")]
    #[case::tpm_limit(json!({"tpm_limit": 100}), "tpm_limit")]
    #[case::rpm_limit(json!({"rpm_limit": 2}), "rpm_limit")]
    #[case::budget_duration(json!({"budget_duration": "30d"}), "budget_duration")]
    #[case::budget_reset_at(json!({"budget_reset_at": "2100-01-01T00:00:00"}), "budget_reset_at")]
    #[case::allowed_cache_controls(
        json!({"allowed_cache_controls": ["no-cache"]}),
        "allowed_cache_controls"
    )]
    #[case::policies(json!({"policies": ["policy"]}), "policies")]
    #[case::model_max_budget(json!({"model_max_budget": {"claude": 1.0}}), "model_max_budget")]
    #[case::organization_memberships(
        json!({"organization_memberships": [{
            "user_id": "user-1",
            "organization_id": "org",
            "created_at": "2026-01-01T00:00:00",
            "updated_at": "2026-01-01T00:00:00",
        }]}),
        "organization_memberships"
    )]
    #[case::object_permission(
        json!({"object_permission": {"object_permission_id": "permission"}}),
        "object_permission"
    )]
    #[case::a_field_a_newer_pod_wrote(json!({"token_budget": 5}), "unread")]
    fn a_user_holding_what_python_applies_after_auth_is_declined_over_that_field(
        #[case] held: Json,
        #[case] field: &str,
    ) {
        let user: UserEntry = entry(json!({"user_id": "user-1"}), &held);

        assert_eq!(super::user(&user), Err(field));
    }

    #[test]
    fn a_user_is_read_as_its_id_alias_email_role_and_teams() {
        let described = json!({
            "user_alias": "Ada",
            "user_email": "ada@example.com",
            "user_role": "internal_user",
            "teams": ["team"],
            "sso_user_id": "sso-1",
            "password_reset_required": true,
            "last_breach_check_at": "2026-01-01T00:00:00",
            "spend": 3.5,
            "model_spend": {"claude": 3.5},
            "created_at": "2026-01-01T00:00:00",
            "updated_at": "2026-01-02T00:00:00",
            "token_budget": null,
        });
        let user: UserEntry = entry(json!({"user_id": "user-1"}), &described);

        assert_eq!(
            super::user(&user),
            Ok(User {
                user_id: "user-1".to_owned(),
                user_email: Some("ada@example.com".to_owned()),
                user_role: Some("internal_user".to_owned()),
                teams: owned(&["team"]),
                deactivated: false,
                row: UserRecord {
                    user_id: "user-1".to_owned(),
                    user_alias: Some("Ada".to_owned()),
                },
            })
        );
    }

    #[rstest]
    #[case::deactivated(json!({"scim_active": false}), Ok(true))]
    #[case::active(json!({"scim_active": true}), Ok(false))]
    #[case::active_beside_other_metadata(
        json!({"scim_active": true, "department": "eng"}),
        Err("metadata")
    )]
    #[case::another_flag_that_is_off(json!({"suspended": false}), Err("metadata"))]
    fn a_user_is_deactivated_only_by_scim_and_declined_over_any_other_metadata(
        #[case] metadata: Json,
        #[case] deactivated: Result<bool, &str>,
    ) {
        let user: UserEntry = entry(json!({"user_id": "user-1"}), &json!({"metadata": metadata}));

        assert_eq!(super::user(&user).map(|user| user.deactivated), deactivated);
    }
}
