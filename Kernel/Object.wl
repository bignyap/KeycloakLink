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
		icon =  Import[KeycloakLink`Utils`KeycloakLinkAsset["Logo"]];
        (* Graphics[
			{
				Green, Disk[], 
				Text[Style["Keycloak", Bold, Gray], {0, 0}, Automatic, {2, 1}]
			},
			ImageSize -> Dynamic[{ (* this seems to be the standard icon size *)
				Automatic, 
				3.5 CurrentValue["FontCapHeight"]/AbsoluteCurrentValue[Magnification]
			}]
		];  *)
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
		"Issuer", "Timestamp", "AuthType", "Host",
        "AuthURL", "AdminURL", "Realm"
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
    "Query" -> {},
    "DynamicPath" -> <||>
}


KeycloakExecute[
    keycloakObject_?KeycloakObjectQ, 
    "Token"
]:= KeycloakLink`Utils`mFormatHTTPResponse[
    KeycloakLink`Common`GetJWTFromKeycloak[
        "token_url" -> keycloakObject["Information"]["KeyclaokConfig"]["token_endpoint"],
        "grant_type" -> keycloakObject["Authentication"]["grant_type"], 
        "auth_details" -> keycloakObject["Authentication"]["auth_details"],
        "realm" -> keycloakObject["Authentication"]["realm"],
        "scope" -> keycloakObject["Authentication"]["scope"],
        "OutputFormat" -> "Association"
    ]
]


KeycloakExecute[
   keycloakObject_?KeycloakObjectQ, 
    requestName_String, 
    OptionsPattern[]
]:= Catch@Module[{
        tokenDetails = Lookup[
            keycloakObject["Information"],
            "TokenDetails", <||>
        ],
        body = OptionValue["Body"],
        query = OptionValue["Query"],
        dynamicPath = OptionValue["DynamicPath"],
        authParams, finalUri
    },
    If[
        !KeyExistsQ[$KeycloakServices, requestName],
        Throw[$ErrorMessage["KeycloakExecute"]["RequestNotDefined"]]
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
            keycloakObject["AdminURL"],
            Lookup[$KeycloakServices[requestName], "Path", ""]
        }]
    ];
    If[
        Length[dynamicPath] > 0,
        finalUri = TemplateApply[
            finalUri,
            dynamicPath
        ]
    ];
    KeycloakLink`Utils`mFormatHTTPResponse[
        SendHTTPRequest[
            "BaseURL" -> finalUri,
            "Path" -> {},
            "Body" -> body,
            "Query" -> query,
            Authentication -> <|"Headers" -> authParams|>,
            FunctionOptions[
                $KeycloakServices[requestName], 
                SendHTTPRequest
            ]
        ]
    ]
]


SetAttributes[KeycloakExecuteWithRefresh, HoldFirst]


Options[KeycloakExecuteWithRefresh] = Options[KeycloakExecute]


KeycloakExecuteWithRefresh[
    keycloakObject_, 
    requestName_String, 
    opts:OptionsPattern[]
]:= Catch[
    If[
        !KeycloakObjectQ[keycloakObject],
        Throw[$Failed]
    ];
    Module[{
            parsedToken = Lookup[
                keycloakObject["Information"], 
                "ParsedToken", <||>
            ], 
            currentTime = UnixTime[] + 2,
            expiresAt
        },
        expiresAt = Lookup[parsedToken["Payload"], "exp", 0];
        If[
            TrueQ[expiresAt <= currentTime],
            ThrowErrorWithCleanup[
                RefreshKeycloakConnection[keycloakObject]
            ]
        ];
        KeycloakExecute[
            keycloakObject, requestName,
            FunctionOptions[{opts}, KeycloakExecute]
        ]
    ]
]
    


End[]


EndPackage[]
