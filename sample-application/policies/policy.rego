package istio.authz

import data.istio.authz.common
import data.roles
import input.attributes.request.http as http_request
import input.parsed_path

default allow = false

allow {
	parsed_path[0] == "health"
	http_request.method == "GET"
}

allow {
	parsed_path[0] == "ip"
	http_request.method == "GET"
}

allow {

	common.is_token_valid
	
	some i
	role := common.decoded_jwt.roles[i]

	# `permission` assigned a single permission from the permissions list for 'role'...
	permission := data.permissions[role]

	some path
	data.api[path]
	glob.match(path, [], http_request.path)
	# print("path", path)
	required_permission := data.api[path][http_request.method]

	# print("role", role)
	# print("data.roles", data.permissions)
	# print("permission", permission)
	# print("required_permission", required_permission)

	some p
	permission[p] == required_permission
}

