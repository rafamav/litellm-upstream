SELECT members_with_roles AS "members_with_roles!: Json<serde_json::Value>"
FROM "LiteLLM_TeamTable"
WHERE team_id = $1
