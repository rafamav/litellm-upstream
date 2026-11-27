//! The end user a request names, read as the proxy's `get_end_user_object` reads it and turned
//! into the core's record. The native app charges and limits no end user, so a row that holds
//! anything Python applies to the request is declined, naming the field.

use litellm_gateway_auth_core::{Error, record::EndUserRecord};
use litellm_redis_store::auth_cache::EndUserEntry;

use super::{AuthStore, key::Carried, store::EndUserRead};

/// The end user `end_user_id` as the native app serves it: one with no row, or a row that only
/// describes it. With no database Python reads no row either and serves the request under the id
/// alone. A row the database could not give is left to Python, which serves the request without
/// it.
pub(crate) async fn end_user(
    store: Option<&AuthStore>,
    end_user_id: &str,
) -> Result<EndUserRecord, Error> {
    let unrestricted = || EndUserRecord {
        end_user_id: Some(end_user_id.to_owned()),
        found: false,
    };
    let Some(store) = store else {
        return Ok(unrestricted());
    };
    match store.end_user(end_user_id).await {
        None => super::declined("end_user"),
        Some(EndUserRead::NoRow) => Ok(unrestricted()),
        Some(EndUserRead::Row(end_user)) => record(&end_user).map_err(|field| {
            tracing::debug!(
                field,
                "the end user's row holds what only the proxy applies"
            );
            Error::HostDeclined
        }),
        Some(EndUserRead::Unread) => Err(Error::HostFailed),
    }
}

/// The entry is taken apart by name, so a field added to it does not compile here until it is
/// read for nothing or declined. The alias and the spend describe the end user. Every other field
/// that holds something is a budget, a model list, a region, a block or a grant Python applies.
fn record(end_user: &EndUserEntry) -> Result<EndUserRecord, &'static str> {
    let EndUserEntry {
        user_id,
        blocked,
        alias: _,
        spend: _,
        allowed_model_region,
        default_model,
        models,
        budget_id,
        litellm_budget_table,
        object_permission_id,
        object_permission,
        unread,
    } = end_user;
    let unread = &unread.iter().any(|(_, value)| value.is_carried());
    let held = carried![
        blocked,
        allowed_model_region,
        default_model,
        models,
        budget_id,
        litellm_budget_table,
        object_permission_id,
        object_permission,
        unread,
    ];
    match held {
        Some(field) => Err(field),
        None => Ok(EndUserRecord {
            end_user_id: Some(user_id.clone()),
            found: true,
        }),
    }
}

#[cfg(test)]
mod tests {
    use litellm_redis_store::FromValue;
    use rstest::rstest;
    use serde_json::{Value, json};

    use super::*;
    use crate::host::auth::{EndUsers, LOOKUP_DEADLINE, keys};

    #[rstest]
    #[tokio::test(flavor = "multi_thread")]
    async fn an_end_user_the_database_cannot_give_is_left_to_python() {
        let store = AuthStore::new(keys::memory_cache(), keys::unreachable()).with_end_users(
            EndUsers::new(keys::unreachable_repositories(), LOOKUP_DEADLINE),
        );

        assert_eq!(end_user(Some(&store), "eu-1").await, Err(Error::HostFailed));
    }

    fn stored(columns: Value) -> EndUserEntry {
        let mut row = json!({"user_id": "eu-1", "blocked": false, "spend": 0.0, "models": []});
        row.as_object_mut()
            .unwrap()
            .extend(columns.as_object().unwrap().clone());
        EndUserEntry::from_value(&litellm_python_compat::json::from_json(row)).unwrap()
    }

    #[rstest]
    #[case::nothing_else(json!({}))]
    #[case::what_it_spent_and_is_called(json!({"spend": 12.5, "alias": "acme"}))]
    fn a_row_that_only_describes_the_end_user_is_served(#[case] columns: Value) {
        assert_eq!(
            record(&stored(columns)),
            Ok(EndUserRecord {
                end_user_id: Some("eu-1".to_owned()),
                found: true
            })
        );
    }

    #[rstest]
    #[case::a_block(json!({"blocked": true}), "blocked")]
    #[case::a_region(json!({"allowed_model_region": "eu"}), "allowed_model_region")]
    #[case::a_default_model(json!({"default_model": "claude"}), "default_model")]
    #[case::a_model_list(json!({"models": ["claude"]}), "models")]
    #[case::a_budget_it_names(json!({"budget_id": "b-1"}), "budget_id")]
    #[case::a_budget_it_holds(
        json!({"litellm_budget_table": {"max_budget": 1.0}}),
        "litellm_budget_table"
    )]
    #[case::an_object_permission_it_names(
        json!({"object_permission_id": "p-1"}),
        "object_permission_id"
    )]
    #[case::an_object_permission_it_holds(
        json!({"object_permission": {"object_permission_id": "p-1"}}),
        "object_permission"
    )]
    #[case::a_field_this_build_does_not_name(json!({"future_limit": 1}), "unread")]
    fn a_row_that_holds_what_python_applies_is_declined_by_its_field(
        #[case] columns: Value,
        #[case] field: &str,
    ) {
        assert_eq!(record(&stored(columns)), Err(field));
    }
}
