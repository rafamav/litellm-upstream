//! Whether a call drops what its provider rejects, decided here and nowhere else.
//!
//! `litellm_settings.drop_params` on keeps dropping on whatever else is written
//! (`litellm.drop_params or drop_params`). Otherwise the request's own `drop_params` decides,
//! then the deployment's, as Python lays a call's kwargs over the deployment's. With neither
//! written, a coding agent's call drops, unless the setting is written as off.
//!
//! The proxy differs in two places, and neither is kept. It writes a coding agent's default into
//! the request, so there the default wins over a deployment's own `drop_params: false`, where
//! the deployment's flag wins here. And it reads the setting for that default from the config
//! alone, where `LITELLM_DROP_PARAMS=false` turns the default off here too, since the config
//! crate reads that variable as the key's value.

use litellm_python_compat::{flags::lax_bool, json::from_json};
use serde_json::Value;

use crate::coding_agent::CodingAgent;

/// Everything that says whether a call drops, each as it was written or `None` when it was not.
pub(crate) struct Sources<'a> {
    /// `litellm_settings.drop_params`, with its variable under it.
    pub global: Option<bool>,
    pub deployment: Option<bool>,
    /// The request body's `drop_params`.
    pub request: Option<&'a Value>,
    pub client: Option<CodingAgent>,
}

pub(crate) fn drops(sources: &Sources<'_>) -> bool {
    sources.global == Some(true)
        || sources
            .request
            .map(is_on)
            .or(sources.deployment)
            .unwrap_or(sources.client.is_some() && sources.global.is_none())
}

/// `lax_bool(value) is True`, the rule Python reads a call's `drop_params` by.
fn is_on(value: &Value) -> bool {
    lax_bool(&from_json(value.clone())) == Some(true)
}

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use serde_json::json;

    use super::*;

    const AGENT: Option<CodingAgent> = Some(CodingAgent::ClaudeCode);

    #[rstest]
    #[case::nothing_written(None, None, None, None, false)]
    #[case::the_setting(Some(true), None, None, None, true)]
    #[case::the_setting_over_a_deployment_turning_it_off(Some(true), Some(false), None, None, true)]
    #[case::the_setting_over_a_request_turning_it_off(
        Some(true),
        None,
        Some(json!(false)),
        None,
        true
    )]
    #[case::the_deployment(None, Some(true), None, None, true)]
    #[case::the_deployment_under_a_setting_that_is_off(Some(false), Some(true), None, None, true)]
    #[case::a_request_turning_it_on(None, None, Some(json!(true)), None, true)]
    #[case::a_request_flag_word(None, None, Some(json!(" yes ")), None, true)]
    #[case::a_request_turning_the_deployments_off(None, Some(true), Some(json!(false)), None, false)]
    #[case::a_request_number_that_is_no_flag(None, Some(true), Some(json!(2)), None, false)]
    #[case::a_request_null(None, Some(true), Some(json!(null)), None, false)]
    #[case::a_coding_agent(None, None, None, AGENT, true)]
    #[case::codex(None, None, None, Some(CodingAgent::Codex), true)]
    #[case::copilot_chat(None, None, None, Some(CodingAgent::CopilotChat), true)]
    #[case::a_coding_agent_under_a_setting_that_is_off(Some(false), None, None, AGENT, false)]
    #[case::a_coding_agent_to_a_deployment_that_turns_it_off(None, Some(false), None, AGENT, false)]
    #[case::a_coding_agent_turning_it_off_for_its_call(None, None, Some(json!(false)), AGENT, false)]
    #[case::a_coding_agent_sending_null(None, None, Some(json!(null)), AGENT, false)]
    fn the_call_drops_by_what_is_written(
        #[case] global: Option<bool>,
        #[case] deployment: Option<bool>,
        #[case] request: Option<Value>,
        #[case] client: Option<CodingAgent>,
        #[case] expected: bool,
    ) {
        let sources = Sources {
            global,
            deployment,
            request: request.as_ref(),
            client,
        };

        assert_eq!(drops(&sources), expected);
    }
}
