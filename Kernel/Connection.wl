(* ::Package:: *)

BeginPackage["KeycloakLink`Connection`"]


Begin["`Private`"]


Options[OpenKeycloakConnection] = Join[
    Options[],
    {
        "HostURL" -> "https://localhost:8443",
        "Authentication" -> <||>
    }
]


OpenKeycloakConnection[OptionsPattern[]]:= Catch[
    Module[{
            uuid = CreateUUID[],
            keycloakObject,
            baseUri = OptionValue["HostURL"],
            authentication = OptionValue["Authentication"]
        },
        keycloakObject = KeycloakObject[
            <|
                "ID" -> uuid, 
                "AuthURL" -> URLBuild[{baseUri, "auth"}], 
                "Authentication" -> authentication
            |>
        ];

    ]
]


End[]


EndPackage[]