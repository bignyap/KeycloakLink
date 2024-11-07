(* ::Package:: *)

BeginPackage["KeycloakLink`Connection`"]


Begin["`Private`"]


Needs["KeycloakLink`"]
Needs["WTC`Utilities`"]
Needs["WTC`Utilities`Common`"]


SetUsage[OpenKeycloakConnection, StringJoin[
    "OpenKeycloakConnection[hostUri, realm, opts] opens a connection to a Keycloak server at the specified hostUri and realm with the given options opts.",
    "\nOptions include:",
    "\n| Option | Default | Description |",
    "\n| Authentication | Automatic | The authentication method to use |",
    "\n| 'Name' | CreateUUID[] | A unique identifier for the connection |"
]]


$ErrorMessage["OpenKeycloakConnection"]["HostUnreachable"]:=
    FailObject["HostUnreachable", "Could not reach the host", "StatusCode" -> 400]


Options[OpenKeycloakConnection] = {
    Authentication -> Automatic,
    "Name" :> CreateUUID[]
}


OpenKeycloakConnection[
    hostUri_String, realm_String, 
    OptionsPattern[]
]:= Catch[
    Module[{
            keycloakInfo,
            keycloakObject,
            authentication = OptionValue[Authentication]
        },
        keycloakInfo = GetKeyclaokConfiguration[hostUri, realm];
        If[
            !AssociationQ[keycloakInfo],
            Throw[$ErrorMessage["OpenKeycloakConnection"]["HostUnreachable"]]
        ];
        keycloakObject = <|
            "ID" -> OptionValue["Name"], 
            "Realm" -> realm,
            "Host" -> hostUri, 
            "Issuer" -> keycloakInfo["issuer"], 
            "AuthURL" -> URLBuild[{hostUri, "auth"}],
            "AdminURL" -> URLBuild[{hostUri, "auth", "admin", "realms"}],
            "Authentication" -> authentication,
            "Information" -> <||>
        |>;
        If[
            !KeyExistsQ[authentication, "realm"],
            authentication["realm"] = realm
        ];
        keycloakObject["Information"]["Authentication"] = authentication;
        keycloakObject["Information"]["KeyclaokConfig"] = keycloakInfo;
        keycloakObject = KeycloakObject[keycloakObject];
        ThrowErrorWithCleanup[
            RefreshKeycloakConnection[keycloakObject]
        ];
        keycloakObject
    ]
]


SetUsage[GetKeyclaokConfiguration, StringJoin[
    "GetKeyclaokConfiguration[hostUrl, realm] retrieves the Keycloak configuration for the specified hostUrl and realm."
]]


GetKeyclaokConfiguration[
    hostUrl_String, 
    realm_String
]:= SendHTTPRequest[
    "BaseURL" -> URLBuild[{
        hostUrl, "auth", "realms", realm, 
        ".well-known", "openid-configuration"
    }],
    "OutputFormat" -> "Association"
]


End[]


EndPackage[]