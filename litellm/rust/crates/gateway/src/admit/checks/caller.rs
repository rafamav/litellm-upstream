use litellm_gateway_auth_core::{Credential, Via};

use super::{Admit, Authentication, Reason, Refused};

/// Each caller the core hands back is matched by name, with no catch-all, so a caller the native
/// host learns to serve does not compile here until it is named native or not. A credential the
/// core did not authenticate is over the error's name.
pub(super) fn caller(_: &Admit, authentication: &Authentication) -> Option<Reason> {
    match authentication {
        Ok(caller) => match &caller.credential {
            Credential::MasterKey
            | Credential::Key {
                via: Via::OwnToken, ..
            } => None,
            Credential::Key {
                via: Via::MappedJwt(_),
                ..
            }
            | Credential::Jwt { .. } => Some(Reason::new(Refused::Credential, "not_native")),
        },
        Err(error) => Some(Reason::new(
            Refused::Credential,
            <&'static str>::from(error),
        )),
    }
}

#[cfg(test)]
mod tests {
    use litellm_config::{Config, LitellmRole};
    use litellm_gateway_auth::Authenticated;
    use litellm_gateway_auth_core::{Affiliation, Caller, JwtActor, JwtStamp};
    use rstest::rstest;

    use super::*;
    use crate::host::{NativeRows, auth::Key};

    fn stamp() -> JwtStamp {
        JwtStamp {
            claims: serde_json::Map::new(),
            user_email: None,
        }
    }

    fn mapped_key() -> Credential<NativeRows> {
        Credential::Key {
            key: Key::stored("stored"),
            via: Via::MappedJwt(stamp()),
        }
    }

    fn jwt() -> Credential<NativeRows> {
        Credential::Jwt {
            jwt: stamp(),
            actor: JwtActor::User {
                role: LitellmRole::InternalUser,
            },
        }
    }

    #[rstest]
    #[case::a_key_a_jwt_maps_to(mapped_key())]
    #[case::a_jwt(jwt())]
    fn a_caller_no_native_route_serves_yet_goes_to_python(
        #[case] credential: Credential<NativeRows>,
    ) {
        let config = Config::from_yaml("general_settings:\n  master_key: gateway-key\n").unwrap();
        let authentication: Authentication = Ok(Authenticated::from(Caller {
            credential,
            affiliation: Affiliation::nobody(),
            end_user: None,
        }));

        let reason = caller(&Admit::over(&config, vec![]), &authentication);

        assert_eq!(reason, Some(Reason::new(Refused::Credential, "not_native")));
    }
}
