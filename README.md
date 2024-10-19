# KeycloakLink
Paclet to connect to Keycloak APIs using Wolfram Language

## How to Run

### Load the Required Paclets

First, install and load the necessary paclets:

```wolfram
PacletInstall["WTC/Utilities"]
PacletDirectoryLoad["<path/to/your/paclet/folder>"];
Get["KeycloakLink`"];
```

### Establish a Connection

Open a connection to your Keycloak server:

```wolfram
conn = OpenKeycloakConnection[
    "https://localhost:8443", "master", 
    Authentication -> <|
        "grant_type" -> "password",
        "auth_details" -> <|
            "username" -> "******",
            "password" -> "******",
            "client_id" -> "******",
            "client_secret" -> "******"
        |>,
        "scope" -> "openid roles profile"
    |>
]
```

### Connection Properties

Retrieve various properties of the connection:

```wolfram
conn["Properties"]
conn["ID"]
conn["Requests"]
conn["Authentication"]
```

### Execute Keycloak Commands

List all realms:

```wolfram
KeycloakExecute[conn, "ListRealm"]
```

Create a new realm:

```wolfram
KeycloakExecute[conn, "CreateRealm", "Body" -> ToJSON[<|"realm" -> "test1234", "enabled" -> True|>]]
```

Get client scope for a specific realm:

```wolfram
KeycloakExecute[conn, "GetClientScope", "DynamicPath" -> <|"realm" -> "test1234"|>]
```

Execute a command with token refresh:

```wolfram
KeycloakExecuteWithRefresh[conn, "GetClientScope", "DynamicPath" -> <|"realm" -> "test1234"|>]
```

Delete a realm:

```wolfram
KeycloakExecuteWithRefresh[conn, "DeleteRealm", "DynamicPath" -> <|"realm" -> "test1234"|>]
```

Verify JWT Token:

```wolfram
KeycloakLink`Common`ParseJWTToken[conn["TokenDetails"]["access_token"], "VerifySignature" -> True, "Issuer" -> "https://localhost"]
```
