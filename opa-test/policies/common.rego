package istio.authz.common

import input.attributes.request.http as http_request


issuers := {"https://dev-78931024.okta.com/oauth2/default", "https://login.microsoftonline.com/91dd274a-bb2a-4e3a-9a5f-09c4a2390aef/v2.0"}

bearer_token := t {
	[_, encoded] := split(http_request.headers.authorization, " ")
	t := encoded
}

decoded_jwt := io.jwt.decode(bearer_token)[1]

metadata_discovery(issuer) := http.send({
	"url": concat("", [issuers[issuer], "/.well-known/openid-configuration"]),
	"method": "get",
	"force_cache": true,
	"force_cache_duration_seconds": 86400
}).body

# Cache response for 24 hours
jwks_request(url) := http.send({
	"url": url,
	"method": "get",
	"force_cache": true,
	"force_cache_duration_seconds": 60 # Cache response for an hour
})

metadata := metadata_discovery(decoded_jwt.iss)

jwks := jwks_request(metadata.jwks_uri).raw_body

is_token_valid {
	decoded_jwt

	constraints := {
		"cert": jwks,
		"aud": decoded_jwt.aud,
		"time": time.now_ns(),
	}

	[valid, header, payload] := io.jwt.decode_verify(bearer_token, constraints)

	# Assert `valid` is `true`.
#	print("valid: ", valid)
	valid == true

	# Assert there's an `exp` field in the payload.
	# If true, then `decode_verify` must've checked `exp`'s value is a date
	# in the future. We need this since if `exp` isn't there, `decode_verify`
	# sets `valid` to `true`.
	payload.exp

	#now := time.now_ns() / 1000000000
	#now < token.payload.exp
	#print("payload.scp: ", payload.scp)
	#count(payload.scp) > 0
}
