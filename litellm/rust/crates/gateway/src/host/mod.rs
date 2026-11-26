//! The gateway's answers to router-core's hostcalls, so it routes with no Python behind it, the
//! native counterpart of python-bridge's `PythonRouterHost`. [`NativeBootHost`] answers the
//! deployment build at boot, and [`NativeHost`] one inference call: router-core's hostcalls
//! through [`NativeRouterHost`], and the callback hooks through the [`Callbacks`] it holds.

pub mod auth;
mod boot;
mod capacity;
mod model_info;
mod precall;
mod prompt_estimate;
mod router;
mod spend_log;

pub use auth::NativeRows;
pub use boot::NativeBootHost;
pub use capacity::NativeCapacityHost;
pub use precall::ContextWindows;
pub use router::NativeRouterHost;
pub use spend_log::RustSpendLogHost;

use std::{collections::BTreeSet, sync::Arc};

use litellm_gateway_auth::Authenticated;
use litellm_gateway_auth_core::{
    Credential, Team,
    authz::{Layer, ModelList},
    body::{self, Credentials},
};
use litellm_gateway_inference::routing::{Host, RouteAttempt};
use tokio::sync::OnceCell;

use crate::{Gateway, callbacks, callbacks::Callbacks};

/// The model lists the native host read for `identity`: a key's own, a JWT's team's, and none for
/// the master key. A key that names a team, an owner or anything else that carries a list was
/// declined when it was authenticated.
pub(crate) fn layers(identity: &Authenticated<NativeRows>) -> impl Iterator<Item = Layer<'_>> {
    let key = match &identity.credential {
        Credential::MasterKey | Credential::Jwt { .. } => None,
        Credential::Key { key, .. } => Some(Layer::Key(ModelList::read(key.models()))),
    };
    let team = team_models(identity).map(|models| Layer::Team(ModelList::read(models)));
    key.into_iter().chain(team)
}

/// The list of the team `identity` acts in, as its row holds it. A team the token names with no
/// row behind it has none, as Python checks no team it holds no object for. Only a key holds a
/// copy of its team, and the host declines every key in a team, so no caller holds one.
fn team_models(identity: &Authenticated<NativeRows>) -> Option<&[String]> {
    match identity.affiliation.holder.team()? {
        Team::Row(record) => Some(&record.models),
        Team::KeyCopy(_) | Team::Unstored(_) => None,
    }
}

/// Every entry of the model lists the native host read for `identity`, as their rows hold them:
/// the key's and then its team's. The router narrows a caller that reaches a model only through
/// an access group by these, as Python's does by a key's `models` plus its `team_models`, special
/// values included.
pub(crate) fn allowed_models(identity: &Authenticated<NativeRows>) -> Vec<String> {
    let key = match &identity.credential {
        Credential::MasterKey | Credential::Jwt { .. } => &[][..],
        Credential::Key { key, .. } => key.models(),
    };
    [key, team_models(identity).unwrap_or_default()].concat()
}

/// The host the gateway's routes are served through, over each deployment's context window as
/// read at boot.
#[derive(Clone, Default)]
pub struct NativeHost {
    callbacks: Arc<Callbacks>,
    windows: Arc<ContextWindows>,
}

impl NativeHost {
    pub fn new(callbacks: Arc<Callbacks>, windows: Arc<ContextWindows>) -> Self {
        Self { callbacks, windows }
    }
}

impl Host for NativeHost {
    type RouterHost<'a, A: RouteAttempt + 'a> = NativeRouterHost<'a, A>;
    type Hooks = callbacks::Call;
    type Rows = NativeRows;

    fn layers<'a>(
        &self,
        identity: &'a Authenticated<NativeRows>,
    ) -> impl Iterator<Item = Layer<'a>> {
        layers(identity)
    }

    fn allowed_models(&self, identity: &Authenticated<NativeRows>) -> Vec<String> {
        allowed_models(identity)
    }

    async fn credentials(
        &self,
        names: &BTreeSet<String>,
    ) -> Result<Credentials, litellm_gateway_auth_core::Error> {
        body::credentials(&auth::NativeAuthHost::credential_store(), names).await
    }

    fn hooks(&self, identity: &Authenticated<NativeRows>) -> callbacks::Call {
        self.callbacks.begin(identity)
    }

    fn router_host<'a, A: RouteAttempt>(
        &'a self,
        gateway: &'a Gateway,
        identity: &'a Authenticated<NativeRows>,
        route: &'a A,
    ) -> NativeRouterHost<'a, A> {
        NativeRouterHost {
            gateway,
            identity,
            route,
            prompt: route.prompt(),
            windows: &self.windows,
            prompt_tokens: OnceCell::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use litellm_config::LitellmRole;
    use litellm_gateway_auth_core::{
        Affiliation, Caller, Holder, JwtActor, JwtStamp, Via, record::TeamRecord,
    };
    use rstest::rstest;

    use super::{auth::Key, *};

    fn in_team(
        credential: Credential<NativeRows>,
        team: Option<Team<NativeRows>>,
    ) -> Authenticated<NativeRows> {
        Authenticated::from(Caller {
            credential,
            affiliation: Affiliation {
                holder: Holder::new(None, team.map(|team| (team, None))),
                org: None,
                project: None,
            },
            end_user: None,
        })
    }

    fn jwt_in(team: Option<Team<NativeRows>>) -> Authenticated<NativeRows> {
        let credential = Credential::Jwt {
            jwt: JwtStamp {
                claims: serde_json::Map::new(),
                user_email: None,
            },
            actor: JwtActor::User {
                role: LitellmRole::InternalUser,
            },
        };
        in_team(credential, team)
    }

    fn row(models: &[&str]) -> Team<NativeRows> {
        Team::Row(TeamRecord {
            team_id: "team-1".to_owned(),
            team_alias: None,
            models: owned(models),
        })
    }

    fn owned(models: &[&str]) -> Vec<String> {
        models.iter().map(|model| (*model).to_owned()).collect()
    }

    #[rstest]
    #[case::a_team_that_names_its_models(Some(row(&["claude"])), Some(&["claude"][..]))]
    #[case::a_team_with_no_list(Some(row(&[])), Some(&[][..]))]
    #[case::a_team_no_row_stands_behind(Some(Team::Unstored("team-1".to_owned())), None)]
    #[case::no_team(None, None)]
    fn a_jwt_is_checked_against_its_teams_list(
        #[case] team: Option<Team<NativeRows>>,
        #[case] listed: Option<&[&str]>,
    ) {
        let identity = jwt_in(team);
        let listed = listed.map(owned);

        assert_eq!(
            (
                layers(&identity).collect::<Vec<_>>(),
                allowed_models(&identity)
            ),
            (
                listed
                    .iter()
                    .map(|models| Layer::Team(ModelList::read(models)))
                    .collect(),
                listed.clone().unwrap_or_default()
            )
        );
    }

    #[test]
    fn a_keys_list_is_read_before_its_teams() {
        let credential = Credential::Key {
            key: Key::listing(&["claude"]),
            via: Via::OwnToken,
        };
        let identity = in_team(credential, Some(row(&["haiku"])));
        let (key, team) = (owned(&["claude"]), owned(&["haiku"]));

        assert_eq!(
            (
                layers(&identity).collect::<Vec<_>>(),
                allowed_models(&identity)
            ),
            (
                vec![
                    Layer::Key(ModelList::read(&key)),
                    Layer::Team(ModelList::read(&team))
                ],
                owned(&["claude", "haiku"])
            )
        );
    }
}
