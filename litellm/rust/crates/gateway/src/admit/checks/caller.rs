use axum::http::request::Parts;
use litellm_config::GeneralSettings;
use litellm_gateway_auth_core::{Credential, Via};

use super::{Admit, Authentication, Reason, Refused, head::TEAM_HEADER};

/// Each caller the core hands back is matched by name, with no catch-all, so a caller the native
/// host learns to serve does not compile here until it is named native or not. A credential the
/// core did not authenticate is over the error's name. A JWT is checked against its scope mappings
/// only for the model the request names, which the core is not handed before the body is read.
/// With a customer claim mapped, Python resolves the customer a verified JWT names after auth, and
/// applies that customer's budgets and models, which the native app does not.
/// Only the JWT path reads the team header, and Python code after auth reads it beside a key, so a
/// key that sends one stays with Python, a key a JWT maps to included.
pub(super) fn caller(
    admit: &Admit,
    request: &Parts,
    authentication: &Authentication,
) -> Option<Reason> {
    let team_header = || {
        request
            .headers
            .contains_key(TEAM_HEADER)
            .then(|| Reason::new(Refused::Headers, TEAM_HEADER))
    };
    let scope_mappings = || {
        scope_mappings_enforced(&admit.config.general_settings)
            .then(|| Reason::new(Refused::Settings, "enforce_scope_based_access"))
    };
    match authentication {
        Ok(caller) => match &caller.credential {
            Credential::MasterKey
            | Credential::Key {
                via: Via::OwnToken, ..
            } => team_header(),
            Credential::Key {
                via: Via::MappedJwt(_),
                ..
            } => team_header()
                .or_else(scope_mappings)
                .or_else(|| customer_claims(admit)),
            Credential::Jwt { .. } => scope_mappings().or_else(|| customer_claims(admit)),
        },
        Err(error) => Some(Reason::new(
            Refused::Credential,
            <&'static str>::from(error),
        )),
    }
}

fn scope_mappings_enforced(general: &GeneralSettings) -> bool {
    general.litellm_jwtauth.as_ref().is_some_and(|jwt| {
        jwt.enforce_scope_based_access
            && jwt
                .scope_mappings
                .as_deref()
                .is_some_and(|mappings| !mappings.is_empty())
    })
}

fn customer_claims(admit: &Admit) -> Option<Reason> {
    maps_customer_claims(&admit.config.general_settings)
        .then(|| Reason::new(Refused::Settings, "customer_jwt_fields"))
}

/// `_maps_customer_claims`, over the settings and every issuer.
fn maps_customer_claims(general: &GeneralSettings) -> bool {
    general.litellm_jwtauth.as_ref().is_some_and(|jwt| {
        let by_issuer = jwt
            .issuers
            .as_deref()
            .unwrap_or_default()
            .iter()
            .flat_map(|issuer| {
                [
                    &issuer.customer_org_alias_jwt_field,
                    &issuer.customer_member_id_jwt_field,
                    &issuer.customer_team_id_jwt_field,
                ]
            });
        [
            &jwt.customer_org_alias_jwt_field,
            &jwt.customer_member_id_jwt_field,
            &jwt.customer_team_id_jwt_field,
        ]
        .into_iter()
        .chain(by_issuer)
        .any(Option::is_some)
    })
}

#[cfg(test)]
mod tests {
    use litellm_config::Config;
    use rstest::rstest;

    use super::*;

    fn jwtauth(settings: &str) -> GeneralSettings {
        let yaml = format!("general_settings:\n  litellm_jwtauth:\n{settings}");
        Config::from_yaml(&yaml).unwrap().general_settings
    }

    #[rstest]
    #[case::no_customer_claim("    team_id_jwt_field: team\n", false)]
    #[case::an_org_alias_in_the_settings("    customer_org_alias_jwt_field: customer.org\n", true)]
    #[case::a_member_id_in_the_settings(
        "    customer_member_id_jwt_field: customer.member\n",
        true
    )]
    #[case::a_team_id_in_the_settings("    customer_team_id_jwt_field: customer.team\n", true)]
    #[case::an_org_alias_in_an_issuer(
        "    issuers:\n      - issuer: https://idp.example\n        customer_org_alias_jwt_field: customer.org\n",
        true
    )]
    #[case::a_member_id_in_an_issuer(
        "    issuers:\n      - issuer: https://idp.example\n        customer_member_id_jwt_field: customer.member\n",
        true
    )]
    #[case::a_team_id_in_an_issuer(
        "    issuers:\n      - issuer: https://idp.example\n        customer_team_id_jwt_field: customer.team\n",
        true
    )]
    fn a_config_that_maps_a_customer_claim_is_one_python_resolves(
        #[case] settings: &str,
        #[case] maps: bool,
    ) {
        assert_eq!(maps_customer_claims(&jwtauth(settings)), maps);
    }

    #[rstest]
    #[case::enforced_with_a_mapping(
        "    enforce_scope_based_access: true\n    scope_mappings:\n      - scope: read\n        models: [claude]\n",
        true
    )]
    #[case::a_mapping_that_is_not_enforced(
        "    scope_mappings:\n      - scope: read\n        models: [claude]\n",
        false
    )]
    #[case::enforced_with_no_mappings("    enforce_scope_based_access: true\n", false)]
    #[case::enforced_with_an_empty_list(
        "    enforce_scope_based_access: true\n    scope_mappings: []\n",
        false
    )]
    fn scope_mappings_gate_a_jwt_only_when_enforced_and_listed(
        #[case] settings: &str,
        #[case] enforced: bool,
    ) {
        assert_eq!(scope_mappings_enforced(&jwtauth(settings)), enforced);
    }
}
