(* ::Package:: *)

(* ::Subsubsection:: *)
(*Begin*)


BeginPackage["KeycloakLink`Token`"]


Begin["`Private`"]


Needs["KeycloakLink`"]
Needs["KeycloakLink`Common`"]
Needs["WTC`Utilities`"]
Needs["WTC`Utilities`Common`"]


(* ::Subsubsection:: *)
(*Get JWT*)


SetUsage[GetJWTFromKeycloak, StringJoin[
    "GetJWTFromKeycloak[opts] retrieves a JSON Web Token (JWT) from Keycloak using the specified options opts.",
    "\nOptions include:",
    "\n| Option | Default | Description |",
    "\n| 'token_url' | None | The URL to request the token from |",
    "\n| 'grant_type' | None | The grant type to use for authentication |",
    "\n| 'auth_details' | None | Authentication details required for the grant type |",
    "\n| 'realm' | None | The realm to authenticate against |",
    "\n| 'scope' | None | The scope of the token |"
]]


$ErrorMessage["GetJWTFromKeycloak"]["RealmMissing"]:=
	FailObject["RealmMissing", "Realm missing", "StatusCode" -> 400]
	
$ErrorMessage["GetJWTFromKeycloak"]["WrongURL"]:=
	FailObject["RealmMissing", "Wrong URI", "StatusCode" -> 400]
	
$ErrorMessage["GetJWTFromKeycloak"]["AccessTokenNotFound", errorCode_Integer]:=
    FailObject["AccessTokenNotFound", "Could not retrieve the access token", "StatusCode" -> errorCode]
    
$ErrorMessage["GetJWTFromKeycloak"]["GrantTypeNotSupported"]:=
    FailObject["GrantTypeNotSupported", "Grant type not supported", "StatusCode" -> 400]
    
$ErrorMessage["GetJWTFromKeycloak"]["MissingAuthDetails", keys_List]:=
	FailObject[
		"MissingAuthDetails", 
		StringJoin[
			"Required parameters are missing", 
			StringRiffle[keys, ", "]
		], 
		"StatusCode" -> 400
	]
	
$ErrorMessage["GetJWTFromKeycloak"]["WrongAuthDetails", key_String]:= 
	FailObject[
		"WrongAuthDetails", 
		StringJoin["Wrong input provided for key: ", key], 
		"StatusCode" -> 400
	]
	
$ErrorMessage["GetJWTFromKeycloak"]["WrongInput"]:=
    FailObject["WrongInput", "Could not retrieve the access token. Wrong inputs provided", "StatusCode" -> 404]


Options[GetJWTFromKeycloak] = Join[
	Options[SendHTTPRequest],
	{
		"token_url" -> None,
		"grant_type" -> None, 
		"auth_details" -> None,
		"realm" -> None,
		"scope" -> None
	}
]


GetJWTFromKeycloak[opts:OptionsPattern[]]:= Catch@Module[{
		body = {},
		authDetils = OptionValue["auth_details"],
		realm = OptionValue["realm"],
		tokenUri = OptionValue["token_url"],
		grantType = OptionValue["grant_type"],
		scope = OptionValue["scope"]
	},
	If[
		kStringMatchQ[realm],
		Throw[$ErrorMessage["GetJWTFromKeycloak"]["RealmMissing"]]
	];
	If[
		kStringMatchQ[tokenUri],
		Throw[$ErrorMessage["GetJWTFromKeycloak"]["WrongURL"]]
	];
	ThrowErrorWithCleanup[iVerifyAuthKeys[grantType, authDetils]];
	body = Join[authDetils, <|"grant_type" -> grantType|>];
	If[
		StringQ[scope] && StringLength[scope] > 0,
		body = Join[body, <|"scope" -> scope|>]
	];
	SendHTTPRequest[
		"BaseURL" -> tokenUri,
		"Path" -> {},
		"Body" -> body,
		TimeConstrained -> 5,
	    FunctionOptions[
	        Flatten[{$KeycloakServices["Token"], opts}], 
	        SendHTTPRequest
	    ]
	]
]


kStringMatchQ = Function[
	expr, {
		Catch[
			Map[
				If[
					TrueQ[#[expr]],
					Throw[False]
				]&, {
					StringQ, 
					Function[str, StringLength[str] > 0]
				}
			];
			True
		]
	}
] 


$requiredParameters = <|
	"password" -> {
		"username" -> kStringMatchQ,
		"password" -> kStringMatchQ,
		"client_id" -> kStringMatchQ,
		"client_secret" -> kStringMatchQ
	},
	"client_credentials" -> {
		"client_id" -> kStringMatchQ,
		"client_secret" -> kStringMatchQ
	},
	"refresh_token" -> {
		"client_id" -> kStringMatchQ,
		"client_secret" -> kStringMatchQ,
		"refresh_token" -> kStringMatchQ
	}
|>


iVerifyAuthKeys[
	grantType:Alternatives@@Keys[$requiredParameters], 
	authDetails_Association
]:= Catch[
	If[
		Length[#] > 0,
		Throw[$ErrorMessage["GetJWTFromKeycloak"]["MissingAuthDetails", #]]
	]&[
		Complement[
			Keys[$requiredParameters[grantType]],
			Keys[authDetails]
		]
	];
	KeyValueMap[
		If[
			TrueQ[$requiredParameters[grantType][#1][#2]],
			Throw[$ErrorMessage["GetJWTFromKeycloak"]["WrongAuthDetails", #1]]
		]&, authDetails
	];
]


iVerifyAuthKeys[___]:= $ErrorMessage["GetJWTFromKeycloak"]["GrantTypeNotSupported"]


(* ::Subsubsection:: *)
(*Verify JWT Token In Header*)


SetUsage[VerifyJWTTokenInHeader, StringJoin[
    "VerifyJWTTokenInHeader[] verifies the JWT token present in the HTTP request headers.",
    "\nVerifyJWTTokenInHeader[header] verifies the JWT token in the specified header."
]]


VerifyJWTTokenInHeader[]:= VerifyJWTTokenInHeader[HTTPRequestData["Headers"]]


VerifyJWTTokenInHeader[header_]:= Catch@Module[{
	  cookie, authorization, jwtToken,
      parsedToken
	},
	authorization = Lookup[header, "authorization", ""];
	authorization = StringCases[authorization, "Bearer " ~~ bearerToken__ :> bearerToken];
	authorization = First[authorization, ""];
	cookie = Lookup[header, "cookie", ""];
	cookie = StringCases[cookie, ___~~Shortest["BearerToken="~~bearerToken__~~";"]~~___ :> bearerToken];
	cookie = First[cookie, ""];
	jwtToken = SelectFirst[{authorization, cookie}, StringLength[#]>0&, Missing[]];
	If[
	    MissingQ[jwtToken],
	    Throw[$ErrorMessage["GetAccessToken"]["AccessTokenNotFound", 401]]
	];
    jwtToken = StringTrim[jwtToken, ";"];

    parsedToken = ParseJWTToken[jwtToken];
    ThrowErrorWithCleanup[parsedToken];
	Join[
        <|
	        "access_token" -> jwtToken,
	        "token_type" -> "Bearer"
	    |>,
        parsedToken
    ]
]


(* ::Subsubsection::Closed:: *)
(*End*)


End[]


EndPackage[]
