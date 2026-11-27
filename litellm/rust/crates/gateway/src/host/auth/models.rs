//! The model lists the native host read for a caller, as the auth core's model rule and the
//! router read them.

use litellm_gateway_auth::Authenticated;
use litellm_gateway_auth_core::{
    Credential, Team,
    authz::{Layer, ModelList},
};

use super::NativeRows;

/// The model lists the native host read for `identity`: a key's own and its team's, and none for
/// the master key. A key that names an owner or anything else that carries a list was declined
/// when it was authenticated. A team the caller names with no row behind it has no list, as
/// Python checks no team it holds no object for.
pub(crate) fn layers(identity: &Authenticated<NativeRows>) -> impl Iterator<Item = Layer<'_>> {
    let key = match &identity.credential {
        Credential::MasterKey => None,
        Credential::Key { key } => Some(Layer::Key(ModelList::read(key.models()))),
    };
    let team = identity
        .affiliation
        .holder
        .team()
        .and_then(team_list)
        .map(Layer::Team);
    key.into_iter().chain(team)
}

/// The team's list as its row holds it. A key's copy of its team is never served natively, so it
/// reaches nothing.
fn team_list(team: &Team<NativeRows>) -> Option<ModelList<'_>> {
    match team {
        Team::Row(record) => Some(ModelList::read(&record.models)),
        Team::KeyCopy(_) => Some(ModelList::Unread),
        Team::Unstored(_) => None,
    }
}

/// Every entry of the model lists the native host read for `identity`, as their rows hold them:
/// the key's and then its team's. The router narrows a caller that reaches a model only through
/// an access group by these, as Python's does by a key's `models` plus its `team_models`, special
/// values included.
pub(crate) fn allowed_models(identity: &Authenticated<NativeRows>) -> Vec<String> {
    let key = match &identity.credential {
        Credential::MasterKey => &[][..],
        Credential::Key { key } => key.models(),
    };
    let team = match identity.affiliation.holder.team() {
        Some(Team::Row(record)) => &record.models[..],
        Some(Team::KeyCopy(_) | Team::Unstored(_)) | None => &[],
    };
    [key, team].concat()
}

#[cfg(test)]
mod tests {
    use litellm_gateway_auth_core::{TeamCopy, record::TeamRecord};
    use rstest::rstest;

    use super::*;

    fn row(models: &[&str]) -> Team<NativeRows> {
        Team::Row(TeamRecord {
            team_id: "team-1".to_owned(),
            team_alias: None,
            models: models.iter().map(|model| (*model).to_owned()).collect(),
        })
    }

    fn key_copy() -> Team<NativeRows> {
        Team::KeyCopy(TeamCopy {
            team_id: "team-1".to_owned(),
            object_permission: None,
        })
    }

    #[rstest]
    #[case::a_team_with_no_list(row(&[]), Some(true))]
    #[case::a_team_that_names_its_models(row(&["claude"]), Some(false))]
    #[case::a_keys_copy_of_a_team(key_copy(), Some(false))]
    #[case::a_team_no_row_stands_behind(Team::Unstored("team-1".to_owned()), None)]
    fn only_a_teams_own_row_reaches_a_model(
        #[case] team: Team<NativeRows>,
        #[case] reaches_every_model: Option<bool>,
    ) {
        assert_eq!(
            team_list(&team).map(|list| list == ModelList::Every),
            reaches_every_model
        );
    }
}
