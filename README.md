[![Project Sandbox](https://docs.outscale.com/fr/userguide/_images/Project-Sandbox-yellow.svg)](https://docs.outscale.com/en/userguide/Open-Source-Projects.html)
# osc-ricochet-2

not a vaporware, but a cloudy stuff, about sending back request from where it come from.

using this project, while expecting the same result as outscale API, might have unforeseen consequences.
but you're a free man, so you can try.


# configuration

if you want Ricochet to Rise and Shine, you need to have the right conf in the right place.

1rst argumnent of ricochet is the configuration path.

Example:
```json
{
    "auth_type": "headarches", // either exist, headache or none, none ignore all auth, exist, check if the user exist but don't go futher, and headache do the full auth
    "tls": false, // currently broken if true
    "in_convertion": true, // support for FCU/ICU and other non outscale API
    "password_as_ak": true, // password auth, is now consider as strong as ak/sk
    "users": [ // can have multy users
	{
	    "access_key": "11112211111110000000",
	    "secret_key": "0000001111112222223333334444445555555666",
	    "login": "joe",
	    "pass": "ashita wa dochida"
	},
	{
	    "access_key": "11112211111110000333",
	    "secret_key": "1000001111112222223333334444445555555666",
	    "login": "titi",
	    "pass": "toto"
	}
    ]
}
```

# build

```
cargo build
```

# usage

```
cargo run [-- CONFIG.json]
```

for config see [this](./ricochet-headarches.json) and [that](./ricochet.json) as example

# ASCII Art
```
[oapi-cli]
    |
    V
(createVms)    ->    [ricochet-2]
                           |
                           V
                     (create a VM)
                           |
                           V
[oapi-cli]    <----   (Send return)
    |
    V
(Print Result)
------- Some time later with a different client ----
 [curl]
    |
    V
(ReadVms)      ->    [ricochet-2]
                         |
                         V
 [curl]     <- (Send earlier create VM)
    |
    V
(print result)
```

# contribution

You can open a PR, or an issue
