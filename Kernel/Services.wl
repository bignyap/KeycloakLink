BeginPackage["KeycloakLink`Services`"]


Begin["`Private`"]


Needs["KeycloakLink`"]
Needs["WTC`Utilities`"]
Needs["WTC`Utilities`Common`"]


$KeycloakServices["Token"] = {
    "Path" -> {"token"},
    "Method" -> "POST",
    "ContentType" -> "application/x-www-form-urlencoded",
    VerifySecurityCertificates -> False,
    CookieFunction -> None
}


SetAttributes[RefreshKeycloakConnection, HoldFirst]


KeycloakObject/:RefreshKeycloakConnection[
    KeycloakObject[keyCloakObject_?KeycloakObjectQ]
]:= Catch@With[{
        tokenDetails = KeycloakExecute[keyCloakObject, "Token", ]
    },
    ThrowErrorWithCleanup[tokenDetails];
    keyCloakObject["TokenDetails"] = tokenDetails
]


KeycloakObject/:KeycloakExecute[ 
    "Token", body_
]:= SendHTTPRequest[
    FunctionOptions[
        $KeycloakServices["Token"], 
        SendHTTPRequest
    ],
    "Body" -> body
]


KeycloakObject/:KeycloakExecute[
    KeycloakObject[keyCloakObject_?KeycloakObjectQ], 
    requestName_String, 
    body_,
    OptionsPattern[]
]:= Catch@Module[{
        tokenDetails = Lookup[
            keyCloakObject["Information"],
            "TokenDetails", <||>
        ],
        expiresAt, 
        currentTime = UnixTime[] + 2,
        authParams
    },
    expiresAt = Lookup[tokenDetails, "expires_at", 0];
    If[
        expiresAt <= currentTime,
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
    SendHTTPRequest[
        "Body" -> body,
        Authentication -> <|"Headers" -> authParams|>,
        FunctionOptions[
            $KeycloakServices[requestName], 
            SendHTTPRequest
        ]
    ]
]


(* $KeycloakServices = <|
    "CreateRealm" -> CreateRealm,
    "UpdateRealm" -> UpdateRealm,
    "ListRealm" -> ListRealm,
    "DeleteRealm" -> DeleteRealm,
    "CreateClient" -> CreateClient,
    "DeleteClient" -> DeleteClient,
    "GetClientScope" -> GetClientScope,
    "UpdateClientScope" -> UpdateClientScope,
    "UpdateClientScopeProtocol" -> UpdateClientScopeProtocol,
    "CreateRealmRole" -> CreateRealmRole,
    "CreateGroup" -> CreateGroup,
    "ListGroup" -> ListGroup,
    "ListRealmRole" -> ListRealmRole,
    "ListClient" -> ListClient,
    "ListRealmUsers" -> ListRealmUsers,
    "GetServiceAccountUser" -> GetServiceAccountUser,
    "UpdateGroupRole" -> UpdateGroupRole,
    "UpdateClientRole" -> UpdateClientRole,
    "CreateKeycloakUser" -> CreateKeycloakUser,
    "ListKeycloakUser" -> ListKeycloakUser,
    "ResetPassword" -> ResetPassword,
    "UpdateGroupClientRole" -> UpdateGroupClientRole,
    "UpdateGroupRoleForManagement" -> UpdateGroupRoleForManagement,
    "AvailableClientRoles" -> AvailableClientRoles,
    "AvailableRealmManagementRoles" -> AvailableRealmManagementRoles,
    "IntrospectAccessToken" -> IntrospectAccessToken,
    "GetClientSecrets" -> GetClientSecrets
|>; *)





End[]


EndPackage[]