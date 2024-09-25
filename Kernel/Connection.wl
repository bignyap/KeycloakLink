(* ::Package:: *)

BeginPackage["KeycloakLink`Connection`"]


Begin["`Private`"]


Options[OpenKeycloakConnection] = {
    "HostURL" -> "https://localhost",
    "Authentication" -> <||>
}


OpenKeycloakConnection[opts:OptionsPattern[]]:= Catch[
    Module[{
            uuid = CreateUUID[],
            keycloakObject,
            baseUri = OptionValue["HostURL"],
            authentication = OptionValue["Authentication"]
        },
        keycloakObject = KeycloakObject[
            "AuthURL" -> URLRead[]
        ]
    ]
]


End[]


EndPackage[]