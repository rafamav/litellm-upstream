//! Callers for the inline tests, over rows that hold a key, which the native host's do not yet.

use litellm_config::LitellmRole;
use litellm_gateway_auth_core::{
    Affiliation, Caller, Credential, JwtActor, JwtStamp, KeyHash, Rows, Via, authn::key::KeyRecord,
};
use serde_json::Value;

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Held;

impl Rows for Held {
    type Key = KeyRecord;
    type User = ();
    type Team = ();
    type EndUser = ();
    type ObjectPermission = ();
    type Project = ();
    type Membership = ();
    type Org = ();
    type Agent = ();
}

/// A key whose row is stored under `stored` and says `is_proxy_admin`.
pub(crate) fn key(stored: &str, is_proxy_admin: bool) -> Caller<Held> {
    Caller {
        credential: Credential::Key {
            key: KeyRecord {
                token: Some(KeyHash::new(stored)),
                is_proxy_admin,
                ..KeyRecord::default()
            },
            via: Via::OwnToken,
        },
        affiliation: Affiliation::nobody(),
        end_user: Some(()),
    }
}

/// A JWT acting as itself, verified with `claims`.
pub(crate) fn jwt(claims: Value) -> Caller<Held> {
    let Value::Object(claims) = claims else {
        panic!("JWT claims are an object");
    };
    Caller {
        credential: Credential::Jwt {
            jwt: JwtStamp {
                claims,
                user_email: None,
            },
            actor: JwtActor::User {
                role: LitellmRole::InternalUser,
            },
        },
        affiliation: Affiliation::nobody(),
        end_user: Some(()),
    }
}
