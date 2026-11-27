SELECT m.jwt_issuer,
       m.jwt_claim_name,
       m.jwt_claim_value
FROM "LiteLLM_JWTKeyMapping" AS m
JOIN "LiteLLM_VerificationToken" AS k ON k.token = m.token
WHERE k.user_id = $1
  AND k.team_id = $2
