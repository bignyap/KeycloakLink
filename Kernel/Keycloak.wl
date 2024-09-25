(* ::Package:: *)

(* ::Subsubsection:: *)
(*Begin*)


BeginPackage["KeycloakLink`Keycloak`"]


Begin["`Private`"]


Needs["KeycloakLink`"]
Needs["WTC`Utilities`"]
Needs["WTC`Utilities`Common`"]


(* ::Subsubsection:: *)
(*Create Realm*)


CreateRealm::usage = ""


CreateRealm[realmDetails_Association, token_String, tokenType_String:"Bearer"]:= Catch@Module[{
		temp
	},
	temp = CallKeycloakEndpoint[
		"BaseURL" -> $KeyCloakConfig["AdminURL"],
		"Path" -> "",
		"Method" -> "POST",
		"Headers" -> {
			"Authorization" -> StringJoin[tokenType, " ", token],
			"Content-Type" -> "application/json"
		},
		VerifySecurityCertificates -> False,
		"Body" -> ToJSON[realmDetails],
		"IncludeToken" -> False
	];
	ThrowErrorWithCleanup[temp];
	temp = mFormatHTTPResponse[temp];
	ThrowErrorWithCleanup[temp];
	temp
]


(* ::Subsubsection:: *)
(*Update Realm*)


UpdateRealm[
	realm_String, token_String, tokenType_String:"Bearer"
]:= UpdateRealm[
	realm, $KeyCloakConfig["RealmSettings"], 
	token, tokenType
]

UpdateRealm[
	realm_String, newRealmDetails_Association, 
	token_String, tokenType_String:"Bearer"
]:= Catch@Module[{
		temp
	},
	temp = CallKeycloakEndpoint[
		"BaseURL" -> $KeyCloakConfig["AdminURL"],
		"Path" -> {realm},
		"Method" -> "PUT",
		"Headers" -> {
			"Authorization" -> StringJoin[tokenType, " ", token],
			"Content-Type" -> "application/json"
		},
		VerifySecurityCertificates -> False,
		"Body" -> ToJSON[newRealmDetails, "Compact" -> True],
		"IncludeToken" -> False
	];
	ThrowErrorWithCleanup[temp];
	temp = mFormatHTTPResponse[temp];
	ThrowErrorWithCleanup[temp];
	temp
]


(* ::Subsubsection:: *)
(*List Realm*)


Options[ListRealm] = {
	"briefRepresentation" -> False
}


ListRealm[token_String, tokenType_String:"Bearer", OptionsPattern[]]:= Catch@Module[{
		temp
	},
	temp = CallKeycloakEndpoint[
		"BaseURL" -> $KeyCloakConfig["AdminURL"],
		"Path" -> "",
		"Method" -> "GET",
		"Headers" -> {
			"Authorization" -> StringJoin[tokenType, " ", token],
			"Content-Type" -> "application/json"
		},
		"Query" -> {
			"briefRepresentation" -> OptionValue["briefRepresentation"]
		},
		VerifySecurityCertificates -> False,
		"IncludeToken" -> False
	];
	ThrowErrorWithCleanup[temp];
	temp = mFormatHTTPResponse[temp];
	ThrowErrorWithCleanup[temp];
	temp
]


(* ::Subsubsection:: *)
(*Delete Realm*)


DeleteRealm[realm_String, token_String, tokenType_String:"Bearer"]:= Catch@Module[{
		temp
	},
	temp = CallKeycloakEndpoint[
		"BaseURL" -> $KeyCloakConfig["AdminURL"],
		"Path" -> {realm},
		"Method" -> "DELETE",
		"Headers" -> {
			"Authorization" -> StringJoin[tokenType, " ", token],
			"Content-Type" -> "application/json"
		},
		VerifySecurityCertificates -> False,
		"IncludeToken" -> False
	];
	ThrowErrorWithCleanup[temp];
	temp = mFormatHTTPResponse[temp];
	ThrowErrorWithCleanup[temp];
	temp
]


(* ::Subsubsection:: *)
(*Create Client*)


CreateClient[
	realm_String, clientDetails_Association, 
	token_String, tokenType_String:"Bearer"
]:= CreateClient[realm, {clientDetails}, token, tokenType]


CreateClient[
	realm_String, clientDetails:List[_?AssociationQ..], 
	token_String, tokenType_String:"Bearer"
]:= Catch@Map[
	With[{
			res = CreateClient[realm, #, token, tokenType]
		},
		ThrowErrorWithCleanup[res];
		res
	]&, clientDetails
]


CreateClient[
	realm_String, clientDetails_Association, 
	token_String, tokenType_String:"Bearer"
]:= Catch@Module[{
		temp
	},
	temp = CallKeycloakEndpoint[
		"BaseURL" -> $KeyCloakConfig["AdminURL"],
		"Path" -> {realm, "clients"},
		"Method" -> "POST",
		"Headers" -> {
			"Authorization" -> StringJoin[tokenType, " ", token],
			"Content-Type" -> "application/json"
		},
		VerifySecurityCertificates -> False,
		"Body" -> ToJSON[clientDetails],
		"IncludeToken" -> False
	];
	ThrowErrorWithCleanup[temp];
	temp = mFormatHTTPResponse[temp];
	ThrowErrorWithCleanup[temp];
	temp
]


(* ::Subsubsection:: *)
(*Delete Client*)


DeleteClient[
	realm_String, clientID_String, 
	token_String, tokenType_String:"Bearer"
]:= Catch@Module[{
		temp
	},
	temp = CallKeycloakEndpoint[
		"BaseURL" -> $KeyCloakConfig["AdminURL"],
		"Path" -> {realm, "clients", clientID},
		"Method" -> "DELETE",
		"Headers" -> {
			"Authorization" -> StringJoin[tokenType, " ", token],
			"Content-Type" -> "application/json"
		},
		VerifySecurityCertificates -> False,
		"IncludeToken" -> False
	];
	ThrowErrorWithCleanup[temp];
	temp = mFormatHTTPResponse[temp];
	ThrowErrorWithCleanup[temp];
	temp
]


(* ::Subsubsection:: *)
(*Get Client Scope*)


GetClientScope[
	realm_String, token_String, 
	tokenType_String
]:= Catch@Module[{
		temp
	},
	temp = CallKeycloakEndpoint[
		"BaseURL" -> $KeyCloakConfig["AdminURL"],
		"Path" -> {realm, "client-scopes"},
		"Method" -> "GET",
		"Headers" -> {
			"Authorization" -> StringJoin[tokenType, " ", token],
			"Content-Type" -> "application/json"
		},
		VerifySecurityCertificates -> False,
		"IncludeToken" -> False
	];
	ThrowErrorWithCleanup[temp];
	temp = mFormatHTTPResponse[temp];
	ThrowErrorWithCleanup[temp];
	temp
]


(* ::Subsubsection:: *)
(*Update Client Scope*)


UpdateClientScope[
	realm_String, scopeID_String, 
	scopeDetails_Association, 
	token_String, tokenType_String
]:= Catch@Module[{
		temp
	},
	temp = CallKeycloakEndpoint[
		"BaseURL" -> $KeyCloakConfig["AdminURL"],
		"Path" -> {realm, "client-scopes", scopeID},
		"Method" -> "PUT",
		"Headers" -> {
			"Authorization" -> StringJoin[tokenType, " ", token],
			"Content-Type" -> "application/json"
		},
		"Body" -> ToJSON[scopeDetails],
		VerifySecurityCertificates -> False,
		"IncludeToken" -> False
	];
	ThrowErrorWithCleanup[temp];
	temp = mFormatHTTPResponse[temp];
	ThrowErrorWithCleanup[temp];
	temp
]


(* ::Subsubsection:: *)
(*Update Scope Protocol*)


UpdateClientScopeProtocol[
	realm_String, scopeID_String, 
	protocolDetails_Association, 
	token_String, tokenType_String
]:= Catch@Module[{
		temp
	},
	temp = CallKeycloakEndpoint[
		"BaseURL" -> $KeyCloakConfig["AdminURL"],
		"Path" -> {realm, "client-scopes", scopeID, "protocol-mappers", "models", protocolDetails["id"]},
		"Method" -> "PUT",
		"Headers" -> {
			"Authorization" -> StringJoin[tokenType, " ", token],
			"Content-Type" -> "application/json"
		},
		"Body" -> ToJSON[protocolDetails],
		VerifySecurityCertificates -> False,
		"IncludeToken" -> False
	];
	ThrowErrorWithCleanup[temp];
	temp = mFormatHTTPResponse[temp];
	ThrowErrorWithCleanup[temp];
	temp
]


(* ::Subsubsection:: *)
(*Create Realm Role*)


CreateRealmRole[
	realm_String, roleDetails_Association, 
	token_String, tokenType_String:"Bearer"
]:= CreateRealmRole[realm, {roleDetails}, token, tokenType]


CreateRealmRole[
	realm_String, roleDetails:List[_?AssociationQ..], 
	token_String, tokenType_String
]:= Catch@Map[
	With[{
			res = CreateRealmRole[realm, #, token, tokenType]
		},
		ThrowErrorWithCleanup[res];
		res
	]&, roleDetails
]


CreateRealmRole[
	realm_String, roleDetails_Association, 
	token_String, tokenType_String
]:= Catch@Module[{
		temp
	},
	temp = CallKeycloakEndpoint[
		"BaseURL" -> $KeyCloakConfig["AdminURL"],
		"Path" -> {realm, "roles"},
		"Method" -> "POST",
		"Headers" -> {
			"Authorization" -> StringJoin[tokenType, " ", token],
			"Content-Type" -> "application/json"
		},
		VerifySecurityCertificates -> False,
		"Body" -> ToJSON[roleDetails],
		"IncludeToken" -> False
	];
	ThrowErrorWithCleanup[temp];
	temp = mFormatHTTPResponse[temp];
	ThrowErrorWithCleanup[temp];
	temp
]


(* ::Subsubsection:: *)
(*Create Group*)


CreateGroup[
	realm_String, groupDetails_Association, 
	token_String, tokenType_String:"Bearer"
]:= CreateGroup[realm, {groupDetails}, token, tokenType]


CreateGroup[
	realm_String, groupDetails:List[_?AssociationQ..], 
	token_String, tokenType_String:"Bearer"
]:= Catch@Map[
	With[{
			res = CreateGroup[realm, #, token, tokenType]
		},
		ThrowErrorWithCleanup[res];
		res
	]&, groupDetails
]


CreateGroup[
	realm_String, groupDetails_Association, 
	token_String, tokenType_String:"Bearer"
]:= Catch@Module[{
		temp
	},
	temp = CallKeycloakEndpoint[
		"BaseURL" -> $KeyCloakConfig["AdminURL"],
		"Path" -> {realm, "groups"},
		"Method" -> "POST",
		"Headers" -> {
			"Authorization" -> StringJoin[tokenType, " ", token],
			"Content-Type" -> "application/json"
		},
		VerifySecurityCertificates -> False,
		"Body" -> ToJSON[groupDetails],
		"IncludeToken" -> False
	];
	ThrowErrorWithCleanup[temp];
	temp = mFormatHTTPResponse[temp];
	ThrowErrorWithCleanup[temp];
	temp
]


(* ::Subsubsection:: *)
(*List Group*)


ListGroup[
	realm_String, token_String, 
	tokenType_String:"Bearer"
]:= Catch@Module[{
		temp
	},
	temp = CallKeycloakEndpoint[
		"BaseURL" -> $KeyCloakConfig["AdminURL"],
		"Path" -> {realm, "groups"},
		"Method" -> "GET",
		"Headers" -> {
			"Authorization" -> StringJoin[tokenType, " ", token],
			"Content-Type" -> "application/json"
		},
		VerifySecurityCertificates -> False,
		"IncludeToken" -> False
	];
	ThrowErrorWithCleanup[temp];
	temp = mFormatHTTPResponse[temp];
	ThrowErrorWithCleanup[temp];
	temp
]


(* ::Subsubsection:: *)
(*List Realm Role*)


ListRealmRole[
	realm_String, token_String, 
	tokenType_String:"Bearer"
]:= Catch@Module[{
		temp
	},
	temp = CallKeycloakEndpoint[
		"BaseURL" -> $KeyCloakConfig["AdminURL"],
		"Path" -> {realm, "roles"},
		"Method" -> "GET",
		"Headers" -> {
			"Authorization" -> StringJoin[tokenType, " ", token],
			"Content-Type" -> "application/json"
		},
		VerifySecurityCertificates -> False,
		"IncludeToken" -> False
	];
	ThrowErrorWithCleanup[temp];
	temp = mFormatHTTPResponse[temp];
	ThrowErrorWithCleanup[temp];
	temp
]


(* ::Subsubsection:: *)
(*List Realm Users*)


ListRealmUsers[
	realm_String, token_String, 
	tokenType_String:"Bearer"
]:= Catch@Module[{
		temp
	},
	temp = CallKeycloakEndpoint[
		"BaseURL" -> $KeyCloakConfig["AdminURL"],
		"Path" -> {realm, "users"},
		"Method" -> "GET",
		"Headers" -> {
			"Authorization" -> StringJoin[tokenType, " ", token],
			"Content-Type" -> "application/json"
		},
		VerifySecurityCertificates -> False,
		"IncludeToken" -> False
	];
	ThrowErrorWithCleanup[temp];
	temp = mFormatHTTPResponse[temp];
	ThrowErrorWithCleanup[temp];
	temp
]


(* ::Subsubsection:: *)
(*List Client*)


ListClient[
	realm_String, token_String, 
	tokenType_String:"Bearer"
]:= Catch@Module[{
		temp
	},
	temp = CallKeycloakEndpoint[
		"BaseURL" -> $KeyCloakConfig["AdminURL"],
		"Path" -> {realm, "clients"},
		"Method" -> "GET",
		"Headers" -> {
			"Authorization" -> StringJoin[tokenType, " ", token],
			"Content-Type" -> "application/json"
		},
		VerifySecurityCertificates -> False,
		"IncludeToken" -> False
	];
	ThrowErrorWithCleanup[temp];
	temp = mFormatHTTPResponse[temp];
	ThrowErrorWithCleanup[temp];
	temp
]


(* ::Subsubsection:: *)
(*Get Service Account User*)


GetServiceAccountUser[
	realm_String, clientId:List[_?StringQ..],
	token_String, tokenType_String:"Bearer"
]:= Catch@Association[
	Map[
		With[{
				res = GetServiceAccountUser[realm, #, token, tokenType]
			},
			ThrowErrorWithCleanup[res];
			# -> res
		]&, clientId
	]
]


GetServiceAccountUser[
	realm_String, clientId_String,
	token_String, tokenType_String:"Bearer"
]:= Catch@Module[{
		temp, serviceAccountUser
	},
	temp = CallKeycloakEndpoint[
		"BaseURL" -> $KeyCloakConfig["AdminURL"],
		"Path" -> {realm, "clients", clientId},
		"Method" -> "GET",
		"Headers" -> {
			"Authorization" -> StringJoin[tokenType, " ", token],
			"Content-Type" -> "application/json"
		},
		VerifySecurityCertificates -> False,
		"IncludeToken" -> False
	];
	ThrowErrorWithCleanup[temp];
	temp = mFormatHTTPResponse[temp];
	ThrowErrorWithCleanup[temp];
	serviceAccountUser = iGetServiceAccountUser[realm, temp["id"], token, tokenType];
	ThrowErrorWithCleanup[serviceAccountUser];
	<|
		temp,
		"service-account-user" -> serviceAccountUser
	|>
]


iGetServiceAccountUser[
	realm_String, uniqueId_String,
	token_String, tokenType_String:"Bearer"
]:= Catch@Module[{
		temp
	},
	temp = CallKeycloakEndpoint[
		"BaseURL" -> $KeyCloakConfig["AdminURL"],
		"Path" -> {realm, "clients", uniqueId, "service-account-user"},
		"Method" -> "GET",
		"Headers" -> {
			"Authorization" -> StringJoin[tokenType, " ", token],
			"Content-Type" -> "application/json"
		},
		VerifySecurityCertificates -> False,
		"IncludeToken" -> False
	];
	ThrowErrorWithCleanup[temp];
	temp = mFormatHTTPResponse[temp];
	ThrowErrorWithCleanup[temp];
	temp
]


(* ::Subsubsection:: *)
(*Update Group Role*)


UpdateGroupRole[
	realm_String, groupsDetails:{(_?StringQ -> List[_?AssociationQ..])..},
	token_String, tokenType_String:"Bearer"
]:= Catch@KeyValueMap[
	With[{
			res = UpdateGroupRole[realm, #1, #2, token, tokenType]
		},
		ThrowErrorWithCleanup[res];
		res
	]&, <|groupsDetails|>
]


UpdateGroupRole[
	realm_String, groupID_String, 
	roleDetails:List[_?AssociationQ..], 
	token_String, tokenType_String:"Bearer"
]:= Catch@Module[{
		temp
	},
	temp = CallKeycloakEndpoint[
		"BaseURL" -> $KeyCloakConfig["AdminURL"],
		"Path" -> {realm, "groups", groupID, "role-mappings", "realm"},
		"Method" -> "POST",
		"Headers" -> {
			"Authorization" -> StringJoin[tokenType, " ", token],
			"Content-Type" -> "application/json"
		},
		"Body" -> ToJSON[roleDetails],
		VerifySecurityCertificates -> False,
		"IncludeToken" -> False
	];
	ThrowErrorWithCleanup[temp];
	temp = mFormatHTTPResponse[temp];
	ThrowErrorWithCleanup[temp];
	temp
]


(* ::Subsubsection:: *)
(*Update Realm Management Role*)


UpdateGroupRoleForManagement[
	realm_String, groupID_String, 
	token_String, tokenType_String:"Bearer"
]:= Catch[
	Module[{
			managementRoles
		},
		managementRoles = AvailableRealmManagementRoles[realm, groupID, "groups", token, tokenType];
		ThrowErrorWithCleanup[managementRoles];
		Map[
			ThrowErrorWithCleanup[
				UpdateGroupClientRole[
					realm, groupID, #["clientId"],
					<|
						"id" -> #["id"], 
						"name" -> #["role"], 
						"description" -> #["description"]
					|>,
					token, tokenType
				]
			]&, managementRoles
		]
	]
]


UpdateGroupClientRole[
	realm_String, groupID_String, clientID_String,
	roleDetails_Association, 
	token_String, tokenType_String:"Bearer"
]:= Catch@Module[{
		temp
	},
	temp = CallKeycloakEndpoint[
		"BaseURL" -> $KeyCloakConfig["AdminURL"],
		"Path" -> {realm, "groups", groupID, "role-mappings", "clients", clientID},
		"Method" -> "POST",
		"Headers" -> {
			"Authorization" -> StringJoin[tokenType, " ", token],
			"Content-Type" -> "application/json"
		},
		"Body" -> ToJSON[{roleDetails}],
		VerifySecurityCertificates -> False,
		"IncludeToken" -> False
	];
	ThrowErrorWithCleanup[temp];
	temp = mFormatHTTPResponse[temp];
	ThrowErrorWithCleanup[temp];
	temp
]


(* ::Subsubsection:: *)
(*Update Client Role*)


UpdateClientRole[
	realm_String, clientDetails:{(_?StringQ -> List[_?AssociationQ..])..},
	token_String, tokenType_String:"Bearer"
]:= Catch@Map[
	With[{
			res = UpdateClientRole[realm, #[[1]], #[[2]], token, tokenType]
		},
		ThrowErrorWithCleanup[res];
		res
	]&, clientDetails
]


UpdateClientRole[
	realm_String, serviceUserID_String, 
	roleDetails:List[_?AssociationQ..], 
	token_String, tokenType_String:"Bearer"
]:= Catch@Module[{
		temp
	},
	temp = CallKeycloakEndpoint[
		"BaseURL" -> $KeyCloakConfig["AdminURL"],
		"Path" -> {realm, "users", serviceUserID, "role-mappings", "realm"},
		"Method" -> "POST",
		"Headers" -> {
			"Authorization" -> StringJoin[tokenType, " ", token],
			"Content-Type" -> "application/json"
		},
		"Body" -> ToJSON[roleDetails],
		VerifySecurityCertificates -> False,
		"IncludeToken" -> False
	];
	ThrowErrorWithCleanup[temp];
	temp = mFormatHTTPResponse[temp];
	ThrowErrorWithCleanup[temp];
	temp
]


(* ::Subsubsection:: *)
(*Create KeyCloak User*)


CreateKeycloakUser[
	realm_String, userDetails:List[_?AssociationQ..], 
	token_String, tokenType_String:"Bearer"
]:= Map[
	<|
		#, "success" -> CreateKeycloakUser[realm, #, token, tokenType]
	|>&, userDetails
]


CreateKeycloakUser[
	realm_String, userDetails_Association, 
	token_String, tokenType_String:"Bearer"
]:= Catch@Module[{
		temp
	},
	temp = CallKeycloakEndpoint[
		"BaseURL" -> $KeyCloakConfig["AdminURL"],
		"Path" -> {realm, "users"},
		"Method" -> "POST",
		"Headers" -> {
			"Authorization" -> StringJoin[tokenType, " ", token],
			"Content-Type" -> "application/json"
		},
		VerifySecurityCertificates -> False,
		"Body" -> ToJSON[userDetails],
		"IncludeToken" -> False
	];
	ThrowErrorWithCleanup[temp];
	temp = mFormatHTTPResponse[temp];
	ThrowErrorWithCleanup[temp];
	temp
]


(* ::Subsubsection:: *)
(*Create KeyCloak User*)


Options[ResetPassword] = {
	"temporary" -> "true"
}


ResetPassword[
	realm_String, usrPwdAssoc_Association, 
	token_String, tokenType_String:"Bearer",
	opts:OptionsPattern[]
]:= Catch@KeyValueMap[
	With[{
			res = ResetPassword[realm, #1, #2, token, tokenType, opts]
		},
		ThrowErrorWithCleanup[res];
		res
	]&, usrPwdAssoc
]


ResetPassword[
	realm_String, userId_String, newPass_String,
	token_String, tokenType_String:"Bearer", 
	OptionsPattern[]
]:= Catch@Module[{
		temp
	},
	temp = CallKeycloakEndpoint[
		"BaseURL" -> $KeyCloakConfig["AdminURL"],
		"Path" -> {realm, "users", userId, "reset-password"},
		"Method" -> "PUT",
		"Headers" -> {
			"Authorization" -> StringJoin[tokenType, " ", token],
			"Content-Type" -> "application/json"
		},
		VerifySecurityCertificates -> False,
		"Body" -> ToJSON[<|
			"temporary" -> OptionValue["temporary"], 
			"type" -> "password", 
			"value" -> newPass
		|>],
		"IncludeToken" -> False
	];
	ThrowErrorWithCleanup[temp];
	temp = mFormatHTTPResponse[temp];
	ThrowErrorWithCleanup[temp];
	temp
]


(* ::Subsubsection:: *)
(*ListKeycloakUser*)


Options[ListKeycloakUser] = {
	"page_number" -> All,
	"items_per_page" -> 100,
	"search" -> None
}


ListKeycloakUser[
	realm_String, token_String, 
	tokenType_String:"Bearer", 
	OptionsPattern[]
]:= Catch@Module[{
		temp, finalRes = {},
		pNumber = OptionValue["page_number"],
		itemsPerPage = OptionValue["items_per_page"],
		currPage = 1
	},
	If[
		!IntegerQ[pNumber],
		pNumber = Infinity (* Set it to a very high number to get all the users *)
	];
	While[
		currPage <= pNumber,
		temp = ListKeycloakUser[
			realm, token, tokenType,
			currPage, itemsPerPage, 
			"search" -> OptionValue["search"]

		];
		ThrowErrorWithCleanup[temp];
		finalRes = Join[finalRes, temp];
		If[
			Length[temp] < itemsPerPage,
			Break[],
			currPage = currPage + 1
		];
	];
	finalRes
]


ListKeycloakUser[
	realm_String, token_String, tokenType_String:"Bearer", 
	page_Integer, items_Integer, OptionsPattern[]
]:= Catch@Module[{
		temp
	},
	temp = CallKeycloakEndpoint[
		"BaseURL" -> $KeyCloakConfig["AdminURL"],
		"Path" -> {realm, "ui-ext", "brute-force-user"},
		"Query" -> {
			"briefRepresentation" -> "true",
			"first" -> (page - 1)*items,
			"max" -> items,
			"search" -> OptionValue["search"]
		},
		"Method" -> "GET",
		"Headers" -> {
			"Authorization" -> StringJoin[tokenType, " ", token],
			"Content-Type" -> "application/json"
		},
		VerifySecurityCertificates -> False,
		"IncludeToken" -> False,
		"RemoveEmptyQueries" -> True
	];
	ThrowErrorWithCleanup[temp];
	temp = mFormatHTTPResponse[temp];
	ThrowErrorWithCleanup[temp];
	temp
]


(* ::Subsubsection:: *)
(*List Client Roles*)


Options[AvailableClientRoles] = {
	"page_number" -> All,
	"items_per_page" -> 100,
	"search" -> None
}


AvailableClientRoles[
	realm_String, id_String, type:("users"|"groups"),
	token_String, tokenType_String:"Bearer", 
	OptionsPattern[]
]:= Catch@Module[{
		temp, finalRes = {},
		pNumber = OptionValue["page_number"],
		itemsPerPage = OptionValue["items_per_page"],
		currPage = 1
	},
	If[
		!IntegerQ[pNumber],
		pNumber = Infinity (* Set it to a very high number to get all the users *)
	];
	While[
		currPage <= pNumber,
		temp = AvailableClientRoles[
			realm, id, type, token, tokenType,
			currPage, itemsPerPage, 
			"search" -> OptionValue["search"]

		];
		ThrowErrorWithCleanup[temp];
		finalRes = Join[finalRes, temp];
		If[
			Length[temp] < itemsPerPage,
			Break[],
			currPage = currPage + 1
		];
	];
	finalRes
]


AvailableClientRoles[
	realm_String, id_String, type:("users"|"groups"),
	token_String, tokenType_String:"Bearer", 
	page_Integer, items_Integer, OptionsPattern[]
]:= Catch@Module[{
		temp
	},
	temp = CallKeycloakEndpoint[
		"BaseURL" -> $KeyCloakConfig["AdminURL"],
		"Path" -> {realm, "ui-ext", "available-roles", type, id},
		"Query" -> {
			"briefRepresentation" -> "true",
			"first" -> (page - 1)*items,
			"max" -> items,
			"search" -> "realm-management"
		},
		"Method" -> "GET",
		"Headers" -> {
			"Authorization" -> StringJoin[tokenType, " ", token],
			"Content-Type" -> "application/json"
		},
		VerifySecurityCertificates -> False,
		"IncludeToken" -> False,
		"RemoveEmptyQueries" -> True
	];
	ThrowErrorWithCleanup[temp];
	temp = mFormatHTTPResponse[temp];
	ThrowErrorWithCleanup[temp];
	temp
]


AvailableRealmManagementRoles[
	realm_String, id_String, type:("users"|"groups"),
	token_String, tokenType_String:"Bearer"
]:= AvailableClientRoles[realm, id, type, token, tokenType, "search" -> "realm-management"]


(* ::Subsubsection:: *)
(*Introspect Token*)


$ErrorMessage["IntrospectAccessToken"]["InvalidToken", errorCode_String]:=
    FailObject["InvalidToken", "Could not validate the access token", "StatusCode" -> errorCode]


IntrospectAccessToken[accessToken_String]:= Catch@Module[{
	  temp
	},
	temp = CallKeycloakEndpoint[
        "BaseURL" -> $KeyCloakConfig["AuthURL"],
        "Path" -> $KeyCloakConfig["Path"]["Introspect"],
        "Method" -> "POST", 
         "Body" -> {
            "client_id" -> $KeyCloakConfig["ClientID"],
            "client_secret" -> $KeyCloakConfig["ClientSecret"],
            "token" -> accessToken
        },
        "ContentType" -> "application/x-www-form-urlencoded",
        "IncludeToken" -> False,
        VerifySecurityCertificates -> False,
        CookieFunction -> None
    ];
	ThrowErrorWithCleanup[temp];
	temp = mFormatHTTPResponse[temp];
	ThrowErrorWithCleanup[temp];
	temp
]


(* ::Subsubsection:: *)
(*Get Client Secret*)


GetClientSecrets[realm_String, token_String, tokenType_String]:= Catch[
	Module[{
			clients = ListClient[realm, token, tokenType]
		},
		ThrowErrorWithCleanup[clients];
		clients = Select[clients, #["serviceAccountsEnabled"]&];
		If[
			Length[clients] > 0,
			KeyTake[clients, {"clientId", "secret"}],
			{}
		]
	]
]


(* ::Subsubsection:: *)
(*End*)


End[]


EndPackage[]
