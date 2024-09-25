(* ::Package:: *)

BeginPackage["KeycloakLink`Connection`"]


Begin["`Private`"]


Needs["KeycloakLink`"]
Needs["WTC`Utilities`"]
Needs["WTC`Utilities`Common`"]


$ErrorMessage["OpenKeycloakConnection"]["HostUnreachable"]:=
    FailObject["HostUnreachable", "Could not reach the host", "StatusCode" -> 400]


Options[OpenKeycloakConnection] = {
    Authentication -> Automatic
}


OpenKeycloakConnection[hostUri_String, realm_String]:= Catch[
    Module[{
            keycloakInfo,
            uuid = CreateUUID[],
            keycloakObject,
            authentication = OptionValue[Authentication]
        },
        keycloakInfo = GetKeyclaokConfiguration[hostUri, realm];
        If[
            !AssociationQ[keycloakInfo],
            Throw[$ErrorMessage["OpenKeycloakConnection"]["HostUnreachable"]]
        ];
        keycloakObject = KeycloakObject[
            <|
                "ID" -> uuid, 
                "AuthURL" -> URLBuild[{hostUri, "auth"}], 
                "Authentication" -> authentication,
                "KeyclaokConfig" -> keycloakInfo
            |>
        ];
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
    URLBuild[{
        hostUrl, "auth", "realms", realm, 
        ".well-known", "openid-configuration"
    }],
    "OutputFormat" -> "Association"
]


End[]


EndPackage[]