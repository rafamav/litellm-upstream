DELETE FROM "LiteLLM_VerificationToken"
WHERE user_id = $1
  AND team_id = $2
RETURNING token
