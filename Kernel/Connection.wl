(* ::Package:: *)

BeginPackage["KeycloakLink`Connection`"]


Begin["`Private`"]


Needs["KeycloakLink`"]
Needs["WTC`Utilities`"]
Needs["WTC`Utilities`Common`"]


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