(* ::Package:: *)
BeginPackage["KeycloakLink`UserInfo`"]


Begin["`Private`"]


Needs["KeycloakLink`"]
Needs["WTC`Utilities`"]
Needs["WTC`Utilities`Common`"]


$ErrorMessage["GetUserInfo"]["NotFound", errorCode_Integer]:=
    FailObject["NotFound", "User not found", "StatusCode" -> errorCode]
$ErrorMessage["GetUserInfo"]["NotSupported"]:=
    FailObject["NotSupported", "Authentication system is currently not supported"]
$ErrorMessage["GetUserInfo"]["UserUUIDMissing"]:=
    FailObject["UserUUIDMissing", "UserUUID missing from authorization token.", "StatusCode" -> 403]
$ErrorMessage["GetUserInfo"]["ConnectionError"]:=
    FailObject["ConnectionError", "Error while connecting to Canvas", "StatusCode" -> 403]


Options[GetUserInfo] = {
    "include_access_token" -> True
}


GetUserInfo[opts:OptionsPattern[]]:= Catch[
	(
		ThrowErrorWithCleanup[#];
		GetUserInfo[#, opts]
	)&[GetAccessToken[]]
]


GetUserInfo[accessToken_Association, OptionsPattern[]]:= Catch@Module[{
	    userInfo, startTime = AbsoluteTime[Now],
	    authSystem = $KeycloakConfig["AuthSystem"],
        userInfoCachinQ =  MemberQ[{"HTTPRequest", "LTI"}, $KeycloakConfig["AccessTokenSource"]],
        includeToken = OptionValue["include_access_token"]
	},
	(* Get the userinfo from cache *)
	If[
	    userInfoCachinQ,
        userInfo = GetUserInfoFromCache[accessToken];
        If[
            AssociationQ[userInfo],
            If[
                includeToken,
                userInfo = <|userInfo, accessToken|>
            ];
            Throw[userInfo]
        ]
	];
	userInfo = GetUserInfo[authSystem, accessToken];
	ThrowErrorWithCleanup[userInfo];
    userInfo = iParseUserInfoResponse[authSystem, userInfo];
    ThrowErrorWithCleanup[userInfo];
	If[
	    userInfoCachinQ,
	    CacheUserInfo[userInfo]
	];
	KeycloakLink`$recordUserInfoTiming = (AbsoluteTime[Now] - startTime);
    If[
        includeToken,
        userInfo = <|userInfo, accessToken|>
    ];
	userInfo
]


GetUserInfo[accessToken_Association]:= Catch@Module[{
	    temp
	},
    temp = CallKeycloakEndPoint[
        "BaseURL" -> $KeycloakConfig["AuthURL"],
        "Path" -> $KeycloakConfig["Path"]["UserInfo"],
        "Method" -> "GET",
        CookieFunction -> None,
        "Headers" -> {
            "Authorization" -> StringJoin[
                accessToken["token_type"], " ", 
                accessToken["access_token"]
            ]
        },
        VerifySecurityCertificates -> False,
        "ContentType" -> "application/x-www-form-urlencoded",
        "IncludeToken" -> False
    ];
    ThrowErrorWithCleanup[temp];
	temp = FormatHTTPResponse[temp, "OutputFormat" -> "Association"];
	ThrowErrorWithCleanup[temp];
	temp
]


iParseUserInfoResponse["Keycloak", userInfo_Association]:= Catch@Module[{
        userName, fName, lName, initials,
        finalInfo, email, userUUID,
        validEntry = Function[x, And[StringLength[x] > 0, Not[StringMatchQ[x, "NOT_FOUND"]]]]
	},
	userUUID = userInfo["sub"];
	If[
        !StringQ[userUUID],
        userInfo = Join[userInfo, <|"sub" -> userInfo["mail"]|>];
        userUUID = userInfo["sub"];
	];
	If[
        !StringQ[userUUID],
        Throw[$ErrorMessage["GetUserInfo"]["UserUUIDMissing"]]
	];
	email = SelectFirst[
        Lookup[userInfo, {"email", "sub"}, ""],
        validEntry[#]&, ""
	];
	userName = SelectFirst[
        Lookup[userInfo, {"displayName", "name", "preferred_username", "email", "sub"}, ""],
        validEntry[#]&, ""
	];
	{fName, lName} = Lookup[userInfo, {"given_name", "family_name"}, ""];
	If[
        SameQ[userName, ""],
        userName = StringTrim[StringJoin[fName, " ", lName]]
	];
	initials = ToUpperCase[StringTake[userName, UpTo[2]]];
	(*Lookup[userInfo, "initials", ToUpperCase[StringTake[userName, UpTo[2]]]]*)
	finalInfo = <|
        "Username" -> userName,
        "PreferredName" -> Lookup[userInfo, "preferred_username", userName],
        "UserUUID" -> userUUID,
        "UserEmail" -> email,
        "Groups" -> Lookup[userInfo, "memberOf", {}],
        "Initials" -> initials,
        "FirstName" -> fName,
        "LastName" -> lName
	|>;
	If[
        TrueQ[$KeycloakConfig["ShowFullUserDetails"]],
        Join[userInfo, finalInfo],
        finalInfo
	]
]


End[]


EndPackage[]
