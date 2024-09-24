GetAccessTokenFromKeycloak


BeginPackage["KeycloakLink`Token`"]


Begin["`Private`"]


Needs["KeycloakLink`"]
Needs["WTC`Utilities`"]
Needs["WTC`Utilities`Common`"]


$ErrorMessage["GetAccessToken"]["GrantTypeNotSupported"]:=
    FailObject["GrantTypeNotSupported", "Grant type not supported", "StatusCode" -> 403]
$ErrorMessage["GetAccessToken"]["WrongInput"]:=
    FailObject["WrongInput", "Could not retrieve the access token. Wrong inputs provided", "StatusCode" -> 404]


Options[GetAccessTokenFromKeycloak] = {
    "grant_type" :> $KeyCloakConfig["GrantType"], 
    "auth_details" :> $KeyCloakConfig["AuthDetails"],
    "use_default" -> False,
    "realm" -> ""
}


GetAccessTokenFromKeycloak[OptionsPattern[]]:= Catch@Block[{
        accessToken, 
        grantType, body, verifiedQ,
        authDetils = OptionValue["auth_details"],
        realm = OptionValue["realm"]
    },
    If[
        StringQ[realm] && StringLength[realm] > 0,
        $KeyCloakConfig["Realm"] = realm
    ];
    grantType = OptionValue["grant_type"];
    If[
        !OptionValue["use_default"],
        verifiedQ = iVerifyAuthKeys[body["grant_type"], authDetils];
		If[
			!verifiedQ,
			Throw[$ErrorMessage["GetAccessToken"]["WrongInput"]]
		]
    ];
    body = iAuthenticationDetail[grantType, authDetils];
    ThrowErrorWithCleanup[body];
    body = Join[body,
        {
            "grant_type" -> grantType,
            "scope" -> $KeyCloakConfig["Scope"]
        }
    ];
    accessToken = CallKeycloakEndPoint[
        "BaseURL" -> $KeyCloakConfig["AuthURL"],
        "Path" -> $KeyCloakConfig["Path"]["Token"],
        "Method" -> "POST", 
        "Body" -> Normal@body,
        "ContentType" -> "application/x-www-form-urlencoded",
        "IncludeToken" -> False,
        VerifySecurityCertificates -> False,
        CookieFunction -> None
    ];
    ThrowErrorWithCleanup[accessToken];
    accessToken = FormatHTTPResponse[
        accessToken, "OutputFormat" -> "Association", 
        "FailureMessage" -> $ErrorMessage["GetAccessToken"]["AccessTokenNotFound", accessToken["StatusCode"]]
    ];
    ThrowErrorWithCleanup[accessToken];
    accessToken
]


iAuthenticationDetail["password", authDetails_Association]:= {
    "username" -> Lookup[authDetails, "username", $KeyCloakConfig["Username"]],
    "password" -> Lookup[authDetails, "password", $KeyCloakConfig["Password"]],
    "client_id" -> Lookup[authDetails, "client_id", $KeyCloakConfig["DefaultClientID"]],
    "client_secret" -> Lookup[authDetails, "client_secret", ""]
    (* Replace[Environment["ENVOY_OAUTH_CLIENT_SECRET"], $Failed -> ""] *)
}


iAuthenticationDetail["client_credentials", authDetails_Association]:= {
    "client_id" -> Lookup[authDetails, "client_id", $KeyCloakConfig["ClientID"]],
    "client_secret" -> Lookup[authDetails, "client_secret", $KeyCloakConfig["ClientSecret"]]
}


iAuthenticationDetail["refresh_token", authDetails_Association]:= {
    "client_id" -> Lookup[authDetails, "client_id", $KeyCloakConfig["ClientID"]],
    "client_secret" -> Lookup[authDetails, "client_secret", $KeyCloakConfig["ClientSecret"]],
    "refresh_token" -> Lookup[authDetails, "refresh_token", ""]
}


iAuthenticationDetail[___]:= Throw[$ErrorMessage["GetAccessToken"]["GrantTypeNotSupported"]]


iVerifyAuthKeys[grantType_String, authDetails_Association]:= TrueQ@ContainsAll[Keys[authDetails], iAuthenticationDetail[grantType, <||>]]


GetAccessTokenFromHeader[]:= GetAccessTokenFromHeader[HTTPRequestData["Headers"]]


GetAccessTokenFromHeader[header_]:= Catch@Module[{
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