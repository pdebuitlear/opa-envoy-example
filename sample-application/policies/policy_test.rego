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
                    "authorization": "Bearer eyJraWQiOiJOOTZuR1F4MWNxSFFCSi1JamtjcF8zSXZoYnpENzBlT0pSM1RLMEY3bmZNIiwiYWxnIjoiUlMyNTYifQ.eyJ2ZXIiOjEsImp0aSI6IkFULm1MekhYWC1vaktQNWozSXRwSEpLVzZVcWR6ZlJlcFhEM0VlQ0JzY0YyUk0iLCJpc3MiOiJodHRwczovL2Rldi03ODkzMTAyNC5va3RhLmNvbS9vYXV0aDIvZGVmYXVsdCIsImF1ZCI6ImFwaTovL2RlZmF1bHQiLCJpYXQiOjE2NzM1NDIwMzgsImV4cCI6MTY3MzU0NTYzOCwiY2lkIjoiMG9hNHVlZTMycWtuaXZhQXg1ZDciLCJ1aWQiOiIwMHU0dWF3eHpwdDd6U1R4eDVkNyIsInNjcCI6WyJvcGVuaWQiXSwiYXV0aF90aW1lIjoxNjczNTQyMDM2LCJzdWIiOiJsdWlnaS5icm9zQHRlc3QuY29tIiwicm9sZXMiOlsiRXZlcnlvbmUiLCJtZW1iZXIiXX0.d5-ADeK-FRTqoRZ_PQDA1VmytRLN-igHqLcGzizCQUZ7sk5-P0txTvZN50e-xwOGQHNw-gOYQuLzifdXFeGbi42czjFZml46TrhlMyRUgT46C4lKET7zxEqNiH-5Hm-2KZ5nnNoGnr_0UPZ4XhHEGuL51TipIL7OKh1IW1wu2E_1i0c0r5K0ZRuOo2L0E9wxjsgq457omalr65YcAq-hO5dtTOtQgcPH9So9uLiuKfb-WDx6P5Kr1dPL4Cp2tS6Sqhimlxy5CiwlVQ_H723L_y4hgYp1czbzsqCMSFiNn2KeTEEUzU_yBNqUX-BWohupjU_6CtT5qVq-oRXPrXqnYA"
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
                    "authorization": "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ii1LSTNROW5OUjdiUm9meG1lWm9YcWJIWkdldyIsImtpZCI6Ii1LSTNROW5OUjdiUm9meG1lWm9YcWJIWkdldyJ9.eyJhdWQiOiIwMGM1YjQzOC01MjdkLTQ5NzQtYWQzMS1kYjc1ZTdhY2FiNTYiLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC85MWRkMjc0YS1iYjJhLTRlM2EtOWE1Zi0wOWM0YTIzOTBhZWYvIiwiaWF0IjoxNjczNTQxMDcyLCJuYmYiOjE2NzM1NDEwNzIsImV4cCI6MTY3MzU0NDk3MiwiYWlvIjoiRTJaZ1lHZzFpSzc0RTNLTE9aVHQ2TGRLMjRhSEFBPT0iLCJhcHBpZCI6IjAwYzViNDM4LTUyN2QtNDk3NC1hZDMxLWRiNzVlN2FjYWI1NiIsImFwcGlkYWNyIjoiMSIsImlkcCI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0LzkxZGQyNzRhLWJiMmEtNGUzYS05YTVmLTA5YzRhMjM5MGFlZi8iLCJvaWQiOiI2OWJlZmVkMy0xOTg1LTRhODMtYTE4Mi05YmNjZmIyMTc0MzYiLCJyaCI6IjAuQVM4QVNpZmRrU3E3T2s2YVh3bkVvamtLN3ppMHhRQjlVblJKclRIYmRlZXNxMVl2QUFBLiIsInJvbGVzIjpbImNvbW1zIl0sInN1YiI6IjY5YmVmZWQzLTE5ODUtNGE4My1hMTgyLTliY2NmYjIxNzQzNiIsInRpZCI6IjkxZGQyNzRhLWJiMmEtNGUzYS05YTVmLTA5YzRhMjM5MGFlZiIsInV0aSI6InFidHRMMGx2NWt1Tm9qRGl0Q2dIQWciLCJ2ZXIiOiIxLjAifQ.J7Fk_1yz3vZnB1MleNcYm2fkm84WDnHcnIChMY_qcq2a9-XcQHFp8ZI9ypN0Btf_XUjCUk9yKD8TXWaRyf3EfWNpn2vve7Hk5Dw_1OgXSA8-DJZx6Jp2IED2ZdbOsEy0z4Q1cDK5Tn4xOirL9jlC237UU9bXC1Y7QXQj7hoA7WRg8Ft8IpB3k24Fl90JMKX7IHjrgqac9bnchwVo35-_WUVN96Q0FyhkXWiVmAf90s0NERX20TIbZsIu-O-NbBfAH_PxbsGekn7Kxc1TkR46uD9iYNpMlOBctAZAKvXNdIXKCGS-ak8gPJ8hjbbtIy-0qt4qzG-_5A3aJYZlkEqxNw"
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