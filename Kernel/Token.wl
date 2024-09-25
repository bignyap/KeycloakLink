(* ::Package:: *)

(* ::Subsubsection:: *)
(*Begin*)


BeginPackage["KeycloakLink`Token`"]


Begin["`Private`"]


Needs["KeycloakLink`"]
Needs["WTC`Utilities`"]
Needs["WTC`Utilities`Common`"]


(* ::Subsubsection:: *)
(*Get JWT From Keycloak*)


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


Options[GetJWTFromKeycloak] = {
    "auth_url" -> None,
    "grant_type" -> None, 
    "auth_details" -> None,
    "realm" -> None,
    "scope" -> None
}


GetJWTFromKeycloak[OptionsPattern[]]:= Catch@Module[{
		body = {},
		authDetils = OptionValue["auth_details"],
		realm = OptionValue["realm"],
		authUri = OptionValue["auth_url"],
		grantType = OptionValue["grant_type"],
		scope = OptionValue["scope"]
	},
	If[
		StringQ[realm] && StringLength[realm] > 0,
		Throw[$ErrorMessage["GetJWTFromKeycloak"]["RealmMissing"]]
	];
	If[
		StringQ[authUri] && StringLength[authUri] > 0,
		Throw[$ErrorMessage["GetJWTFromKeycloak"]["WrongURL"]]
	];
	ThrowErrorWithCleanup[iVerifyAuthKeys[grantType, authDetils]];
	body = Join[authDetils, <|"grant_type" -> grantType|>];
	If[
		StringQ[scope] && StringLength[scope] > 0,
		body = Join[body, <|"scope" -> scope|>]
	];
	KeycloakExecute["Token", Normal@body]
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


(* ::Subsubsection::Closed:: *)
(*Verify JWT Token In Header*)


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
