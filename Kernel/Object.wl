(* ::Package:: *)

BeginPackage["KeycloakLink`Object`"]


Begin["`Private`"]


Needs["KeycloakLink`"]
Needs["KeycloakLink`Common`"]
Needs["KeycloakLink`Utils`"]
Needs["WTC`Utilities`"]
Needs["WTC`Utilities`Common`"]


KeycloakObject::usage = ""


KeycloakObject/:MakeBoxes[p:KeycloakObject[keycloakAssoc_?KeycloakObjectQ], fmt:(StandardForm|TraditionalForm)]:=
	Module[{
			alwaysGrid, sometimesGrid, 
			icon
		},
		alwaysGrid = {
			BoxForm`SummaryItem[{"ID  ", keycloakAssoc["ID"]}],
            BoxForm`SummaryItem[{"AuthType  ", "OpenIDConnect"}]
		}; 
		sometimesGrid = {
			{
				BoxForm`SummaryItem[{"Name  ", Lookup[keycloakAssoc, "Name", keycloakAssoc["ID"]]}],
				BoxForm`SummaryItem[{"Issuer  ", keycloakAssoc["Issuer"]}]
			},
			{
                BoxForm`SummaryItem[{"Timestamp ", DateString[Now]}],
				BoxForm`SummaryItem[{"Tokenndpoint ", keycloakAssoc["Information"]["KeyclaokConfig"]["token_endpoint"]}]
			}
		};
		icon =  Graphics[
			{
				Green, Disk[], 
				Text[Style["Keycloak", Bold, Gray], {0, 0}, Automatic, {2, 1}]
			},
			ImageSize -> Dynamic[{ (* this seems to be the standard icon size *)
				Automatic, 
				3.5 CurrentValue["FontCapHeight"]/AbsoluteCurrentValue[Magnification]
			}]
		]; 
		BoxForm`ArrangeSummaryBox[
			KeycloakObject (* Head *), 
			keycloakAssoc (* Actual Data *), 
			icon (* Icon *), 
			alwaysGrid (* Shows in the Object *), 
			sometimesGrid (* Optional elements showed in the object *), 
			fmt (* What format to be used *),
			"Interpretable" -> Automatic
		]
	]


$defaultProp = {"Authentication", "ID", "Information", "Name", "Requests", "Host"}


$supportedRequests = {
    "CreateRealm", "UpdateRealm", "ListRealm", "DeleteRealm",
    "CreateClient", "DeleteClient", "GetClientScope", 
    "UpdateClientScope", "UpdateClientScopeProtocol", "CreateRealmRole", 
    "CreateGroup", "ListGroup", "ListRealmRole", "ListClient", 
    "ListRealmUsers", "GetServiceAccountUser", "UpdateGroupRole", 
    "UpdateClientRole", "CreateKeycloakUser", "ListKeycloakUser", 
    "ResetPassword", "UpdateGroupClientRole", 
    "UpdateGroupRoleForManagement", "AvailableClientRoles", 
    "AvailableRealmManagementRoles", "IntrospectAccessToken", 
    "GetClientSecrets"
}


KeycloakObject/:KeycloakObject[keycloakAssoc_?AssociationQ]["Properties"]:= $defaultProp


KeycloakObject/:KeycloakObject[keycloakAssoc_?AssociationQ][
	prop:Alternatives[
		"ID", "Information", "Authentication",
		"Issuer", "Timestamp", "AuthType", "Host"
	]
]:= keycloakAssoc[prop]

KeycloakObject/:KeycloakObject[keycloakAssoc_?AssociationQ]["Name"]:= 
    Lookup[keycloakAssoc, "Name", keycloakAssoc["ID"]]

KeycloakObject/:KeycloakObject[keycloakAssoc_?AssociationQ]["Authentication"]:= 
    keycloakAssoc["Information"]["Authentication"]

KeycloakObject/:KeycloakObject[keycloakAssoc_?AssociationQ]["Requests"]:= $supportedRequests

KeycloakObject/:KeycloakObject[keycloakAssoc_?AssociationQ]["TokenDetails"]:= 
    keycloakAssoc["Information"]["TokenDetails"]


KeycloakObjectQ[
    KeycloakObject[keycloakAssoc_?AssociationQ]
]:= KeycloakObjectQ[keycloakAssoc]

KeycloakObjectQ[keycloakAssoc_?AssociationQ]:= AllTrue[
    {"ID", "Issuer", "Authentication", "Host"}, 
    KeyExistsQ[keycloakAssoc, #]&
]

KeycloakObjectQ[___]:= False


KeycloakObject/:Normal[KeycloakObject[keycloakAssoc_?AssociationQ]]:= keycloakAssoc


SetAttributes[RefreshKeycloakConnection, HoldAll]

RefreshKeycloakConnection[obj_]:= Catch[
    If[
        !KeycloakObjectQ[obj],
        Throw[$Failed]
    ];
    Module[{
            tokenDetails = KeycloakExecute[ obj, "Token" ]
        },
        ThrowErrorWithCleanup[tokenDetails];
        obj = Replace[obj, pp_KeycloakObject :> Normal[pp]];
        obj["Information"]["TokenDetails"] = tokenDetails;
        obj["Information"]["ParsedToken"] = KeycloakLink`Common`ParseJWTToken[
            tokenDetails["access_token"]
        ];
        obj = KeycloakObject[obj]
    ];
    obj
]


$ErrorMessage["KeycloakExecute"]["RequestNotDefined"]:=
    FailObject[
        "RequestNotDefined", 
        "Request type is not defined. You can add the service to $KeycloakServices and try to execute again", 
        "StatusCode" -> 400
    ]

$ErrorMessage["KeycloakExecute"]["AdditionalPathRequired", params_]:= 
    FailObject[
        "AdditionalPathRequired", 
        StringJoin[
            "Additional path parameters required namely: ",
            StringRiffle[params, ", "], ".\n",
            "You can specify it using \"DynamicPath\" option."
        ],
        "StatusCode" -> 400
    ]


Options[KeycloakExecute] = {
    "Body" -> None,
    "DynamicPath" -> <||>
}


KeycloakExecute[
    keyCloakObject_?KeycloakObjectQ, 
    "Token"
]:= KeycloakLink`Utils`mFormatHTTPResponse[
    KeycloakLink`Common`GetJWTFromKeycloak[
        "token_url" -> keyCloakObject["Information"]["KeyclaokConfig"]["token_endpoint"],
        "grant_type" -> keyCloakObject["Authentication"]["grant_type"], 
        "auth_details" -> keyCloakObject["Authentication"]["auth_details"],
        "realm" -> keyCloakObject["Authentication"]["realm"],
        "scope" -> keyCloakObject["Authentication"]["scope"],
        "OutputFormat" -> "Association"
    ]
]


KeycloakExecute[
    keyCloakObject_?KeycloakObjectQ, 
    requestName_String, 
    OptionsPattern[]
]:= Catch@Module[{
        tokenDetails = Lookup[
            keyCloakObject["Information"],
            "TokenDetails", <||>
        ],
        keycloakConfig = Lookup[
            keyCloakObject["Information"], 
            "KeyclaokConfig", <||>
        ],
        parsedToken = Lookup[
            keyCloakObject["Information"], 
            "ParsedToken", <||>
        ], 
        currentTime = UnixTime[] + 2,
        expiresAt, authParams, finalUri,
        body = OptionValue["Body"],
        dynamicPath = OptionValue["DynamicPath"]
    },
    If[
        !KeyExistsQ[$KeycloakServices, requestName],
        Throw[$ErrorMessage["KeycloakExecute"]["RequestNotDefined"]]
    ];
    expiresAt = Lookup[parsedToken["Payload"], "exp", 0];
    If[
        TrueQ[expiresAt <= currentTime],
        ThrowErrorWithCleanup[
            RefreshKeycloakConnection[keyCloakObject]
        ]
    ];
    authParams = {
        "Authorization" -> StringJoin[
            tokenDetails["token_type"], " ",
            tokenDetails["access_token"]
        ]
    };
    (
        If[
            Length[#] > 0,
            Throw[$ErrorMessage["KeycloakExecute"]["AdditionalPathRequired", #]]
        ]
    )&[
        Complement[
            Lookup[$KeycloakServices[requestName], "DynamicPath", {}],
            Keys[dynamicPath]
        ]
    ];
    finalUri = URLBuild[
        Flatten[{
            keyCloakObject["Host"], "auth", "realms",
            Lookup[$KeycloakServices[requestName], "Path", ""]
        }]
    ];
    If[
        Length[dynamicPath] > 0,
        finalUri = Echo@TemplateApply[
            Echo@finalUri,
            Echo@dynamicPath
        ]
    ];
    KeycloakLink`Utils`mFormatHTTPResponse[
        SendHTTPRequest[
            "BaseURL" -> finalUri,
            "Path" -> {},
            "Body" -> body,
            Authentication -> <|"Headers" -> authParams|>,
            FunctionOptions[
                $KeycloakServices[requestName], 
                SendHTTPRequest
            ]
        ]
    ]
]
    


End[]


EndPackage[]
