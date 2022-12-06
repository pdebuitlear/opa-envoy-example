package istio.authz
import future.keywords

test_ip_allowed if {
    allow with input as {
    "attributes": {
        "request": {
            "http": {
                "headers": {
                    ":method": "GET",
                    ":path": "/ip"
                },
                "method": "GET",
                "path": "/ip"
            }
        }
    },
    "parsed_path": [
        "ip"
    ]
}
}


test_health_allowed if {
    allow with input as {
    "attributes": {
        "request": {
            "http": {
                "headers": {
                    ":method": "GET",
                    ":path": "/health?plugins"
                },
                "method": "GET",
                "path": "/health?plugins"
            }
        }
    },
    "parsed_path": [
        "health"
    ]
}
}

test_productpage_allowed_for_okta if {
    allow with input as {
    "attributes": {
        "request": {
            "http": {
                "headers": {
                    ":method": "GET",
                    ":path": "/api/v1/customers/12345/policies/6789",
                    "authorization": "Bearer eyJraWQiOiJOOTZuR1F4MWNxSFFCSi1JamtjcF8zSXZoYnpENzBlT0pSM1RLMEY3bmZNIiwiYWxnIjoiUlMyNTYifQ.eyJ2ZXIiOjEsImp0aSI6IkFULl9jTXZ5LXlYNmdGNWwwOGVZMlp4UUcwMVp5djFkVExKNHUzVDNCMGxTVzQiLCJpc3MiOiJodHRwczovL2Rldi03ODkzMTAyNC5va3RhLmNvbS9vYXV0aDIvZGVmYXVsdCIsImF1ZCI6ImFwaTovL2RlZmF1bHQiLCJpYXQiOjE2Njk4OTg4NDMsImV4cCI6MTY2OTkwMjQ0MywiY2lkIjoiMG9hNHVlZTMycWtuaXZhQXg1ZDciLCJ1aWQiOiIwMHU0dWF3eHpwdDd6U1R4eDVkNyIsInNjcCI6WyJvcGVuaWQiXSwiYXV0aF90aW1lIjoxNjY5ODk0NjI1LCJzdWIiOiJsdWlnaS5icm9zQHRlc3QuY29tIiwicm9sZXMiOlsiRXZlcnlvbmUiLCJtZW1iZXIiXX0.D0R3bSv9JvoL-_7umquriYSevAlNupWK7Hf0oE7aIVj_Z8PP3FYKzW3iiJj_Z1OSRH5xvCwgFZ97xq9dEracFg6nV1fu2R3RRr352hKA0_Ds1GFIY6MhFtpWJY21gD5JyfRSYXMqW-m1buG6AdlXnYS4nl3hwxdbROziu_f4TkuVHLaVy5J7yhlf_7JnjnjP5tqUKK-Z74mluklm3L6-3XgeOLFIPrAGkD2yacdp5_LKAWgnAa_fpj90VR3IlDXEHY5Lzc9hALxg5VImdRSLjHR8Lze8FJjq1C3nP8_GTiAhY4n0sXVx3zLvb5n_o7hI1QpRbHPMvsElmHaJ93gXyw"
                },
                "method": "GET",
                "path": "/api/v1/customers/12345/policies/6789"
            }
        }
    },
    "parsed_path": [
        "productpage"
    ]
}
}

test_productpage_allowed_for_azuread if {
    allow with input as {
    "attributes": {
        "request": {
            "http": {
                "headers": {
                    ":method": "PUT",
                    ":path": "/api/v1/customers/12345/policies/6789",
                    "authorization": "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjJaUXBKM1VwYmpBWVhZR2FYRUpsOGxWMFRPSSJ9.eyJhdWQiOiJiMmUyZGVjZS02ZmY3LTQyMzctOGQzZC0zYTU0N2FlZWMxM2QiLCJpc3MiOiJodHRwczovL2xvZ2luLm1pY3Jvc29mdG9ubGluZS5jb20vOTFkZDI3NGEtYmIyYS00ZTNhLTlhNWYtMDljNGEyMzkwYWVmL3YyLjAiLCJpYXQiOjE2Njk4OTg0MzYsIm5iZiI6MTY2OTg5ODQzNiwiZXhwIjoxNjY5OTAyMzM2LCJhaW8iOiJFMlpnWUdoL2RuMGhiNHN4UTBlTDhyS1dYVUppQUE9PSIsImF6cCI6ImIyZTJkZWNlLTZmZjctNDIzNy04ZDNkLTNhNTQ3YWVlYzEzZCIsImF6cGFjciI6IjEiLCJvaWQiOiJlZmFiNzc3MS1mZGJmLTQ3ZTktOGJkNC0yZjY2Y2JhNzU1MjgiLCJyaCI6IjAuQVM4QVNpZmRrU3E3T2s2YVh3bkVvamtLNzg3ZTRyTDNiemRDalQwNlZIcnV3VDB2QUFBLiIsInJvbGVzIjpbIm1hcmtldGluZyJdLCJzdWIiOiJlZmFiNzc3MS1mZGJmLTQ3ZTktOGJkNC0yZjY2Y2JhNzU1MjgiLCJ0aWQiOiI5MWRkMjc0YS1iYjJhLTRlM2EtOWE1Zi0wOWM0YTIzOTBhZWYiLCJ1dGkiOiJUTGkxdFdNREUwNkRVNVM1NkFVbUFBIiwidmVyIjoiMi4wIn0.k3V4JLupdyfx-VxHgvcPKXcW8So-YWTCYFzkf-98bbCGChsAHdJ8ConPowBOaoZjQwfSdKXMZWkf4TRI0v2gUQv0WCV0_q-ZrENS-kS819XioeW75MzyKiVy4lMLDcwzbeIoFux50PNsrRkmC2JyQdwxIgUiJh42T2RB7FszUYIxvFv_E3fbMdwon3WMFpDDHyHXBwyPNNDVKIReiqVm0j0GNLsZD3aNtbeWNpfzookRsXNG_oCn_QiIGDikhUzpH-3h0BHrjgxIN7gprBtMv6_Glb1GGJGt1KRevHu1_sVDrg9nJ39Ff4uAaFOnhhHc3e2t-tglNkuGES1CccKvaw"
                },
                "method": "PUT",
                "path": "/api/v1/customers/12345/policies/6789"
            }
        }
    },
    "parsed_path": [
			"api",
			"v1",
			"products"
		]
}
}