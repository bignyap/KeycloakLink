CacheUserInfo


GetUserInfoFromCache


ParseJWTToken


mFormatHTTPResponse


iFailObject


BeginPackage["KeycloakLink`Utils`"]


Begin["`Private`"]


Needs["KeycloakLink`"]
Needs["WTC`Utilities`"]
Needs["WTC`Utilities`Common`"]


mFormatHTTPResponse[temp_HTTPResponse]:= FormatHTTPResponse[
	temp, "OutputFormat" -> "Association", 
	"FailureMessage" -> iFailObject[temp]
]


iFailObject[temp_HTTPResponse]:= FailObject[
	temp["StatusCodeDescription"], temp["Body"], 
	"StatusCode" -> temp["StatusCode"]
]


CacheUserInfo[temp_Association]:= Catch@Module[{
	  userID, email, folder,
	  cacheFile
	},
	{userID, email} = Lookup[temp, {"userid", "sub"}, Missing[]];
	email = SelectFirst[{userID, email}, Not[MissingQ[#]]&, Missing[]];
	If[MissingQ[email], Throw[$Failed]];
	email = First[StringSplit[email, "@"], Missing[]];
	If[
	    MissingQ[email],
	    Throw[$Failed]
	];
	folder = FileNameJoin[{$KeycloakConfig["CacheDirectory"], "cache"}];
	If[
	    !DirectoryQ[folder],
	    CreateDirectory[folder]
	];
	cacheFile = FileNameJoin[{folder, email<>".mx"}];
	Export[cacheFile,
        <|
            "Created" -> AbsoluteTime[Now],
            "UserInfo" -> temp
        |>, OverwriteTarget -> True
	]
]


CacheUserInfo[___]:= $Failed


GetUserInfoFromCache[parsedToken_Association]:= Catch@Module[{
	  email, cacheFile,
	  res
	},
	email = Lookup[
	    Lookup[parsedToken, "Payload", <||>],
	    "sub", Missing[]
	];
	If[
	    MissingQ[email],
	    Throw[$Failed]
	];
	email = First[StringSplit[email, "@"], Missing[]];
	If[
	    MissingQ[email],
	    Throw[$Failed]
	];
	cacheFile = FileNameJoin[{$KeycloakConfig["CacheDirectory"], "cache", email<>".mx"}];
	If[
	    !FileExistsQ[cacheFile],
	    Throw[$Failed]
	];
	res = Import[cacheFile];
	If[
	    Greater[res["Created"] - AbsoluteTime[Now], 1800],
	    Throw[$Failed]
	];
	res["UserInfo"]
]


$ErrorMessage["ParseJWTToken"]["InvalidToken"]:=
    FailObject["InvalidToken", "Access token is not valid", "StatusCode" -> 403]
$ErrorMessage["ParseJWTToken"]["UnsupportedAlgorithm"]:= 
	FailObject["UnsupportedAlgorithm", "Hash algorithm not supported", "StatusCode" -> 403]
$ErrorMessage["ParseJWTToken"]["InvalidIssuer"]:=
	FailObject["InvalidIssuer", "Token not issued from verified issuer", "StatusCode" -> 403]
$ErrorMessage["ParseJWTToken"]["InvalidCert"]:=
	FailObject["InvalidCert", "Certificate not found", "StatusCode" -> 403]
$ErrorMessage["ParseJWTToken"]["InvalidSignature"]:= 
	FailObject["InvalidSignature", "Signature is not valid", "StatusCode" -> 403]

Options[ParseJWTToken] = {
	"CheckExpiration" :> $KeycloakConfig["CheckAccessTokenExpiration"],
	"VerifySignature" :> False,
	"Issuer" :> $KeycloakConfig["BaseURL"]
}


ParseJWTToken[token_String, OptionsPattern[]]:= Catch[
    Module[{
            split, header, payload, signature,
            validQ, signatureInput, publicKey,
			algorithm, issuer, kid, validSignatureQ
        },
		(* Token needs to have 3 parts *)
        split = StringSplit[token, "."];
		If[
			!SameQ[Length[split], 3],
			Throw[$ErrorMessage["ParseJWTToken"]["InvalidToken"]]
		];
		{header, payload, signature} = split;
        
		(* Import the header *)
		header = ImportString[iPaddedString[header], {"Base64", "String"}];
        header = ImportString[header, "RawJSON"];
        
		(* Import the payload *)
		payload = ImportString[iPaddedString[payload], {"Base64", "String"}];
        payload = ImportString[payload, "RawJSON"];

		(* Import the signature *)
		signature = FromDigits[Normal[ModifiedBase64Decode[signature]]];

		(* Verify issuer *)
		(* issuer = payload["iss"];
		If[
			!TrueQ[iCheckIssuer[issuer]],
			Throw[$ErrorMessage["ParseJWTToken"]["InvalidIssuer"]]
		]; *)
        
		(* Check expiration *)
		validQ = TrueQ[iCheckExpiryQ[payload["exp"]]];
        If[
            OptionValue["CheckExpiration"],
            If[
                !validQ,
                Throw[$ErrorMessage["ParseJWTToken"]["InvalidToken"]]
            ]
        ];

		(* Verify signature *)
		validSignatureQ = False;
		If[
            OptionValue["VerifySignature"],

			(* Import the public key *)
			kid = header["kid"];
			publicKey = iGetPublicKey[issuer, kid];
			ThrowErrorWithCleanup[publicKey];
			publicKey = Lookup[publicKey, {"n", "e"}, ""];

			(* check the signature *)
			signatureInput = StringJoin[split[[1]], ".", split[[2]]];
			algorithm = iGetSigAlgorithm[header["alg"]];
			validSignatureQ = iVerifySignature[
				signatureInput, signature, 
				algorithm, publicKey
			];
			ThrowErrorWithCleanup[validSignatureQ];
            If[
                !validSignatureQ,
                Throw[$ErrorMessage["ParseJWTToken"]["InvalidSignature"]]
            ]
        ];

		(* Return the parsed JWT *)
        <|
            "Header" -> header,
            "Payload" -> payload,
            "Signature" -> validSignatureQ
        |>
    ]
]


ParseJWTToken[___]:= $ErrorMessage["ParseJWTToken"]["InvalidToken"]


ModifiedBase64Decode[str_String]:= 
	Developer`DecodeBase64ToByteArray[iPaddedString[fixURLDecode[str]]]


iGetSigAlgorithm[alg_String]:= Replace[
	alg, {
		"RS256" -> "SHA256",
		"RS384" -> "SHA384",
		"RS512" -> "SHA512"
	}
]


iCheckIssuer[issuer_String]:= SameQ[
	Replace[URLParse[issuer]["Domain"], {"localhost" -> "idp"}],
	URLParse[$KeyCloakConfig["AuthURL"]]["Domain"]
]


iGetPublicKey[
	issuer_String, kid_String
]:= Catch[
	Module[{
			certUri = URLBuild[{
				issuer, 
				$KeyCloakConfig["Path"]["OpenID"],
				"certs"
			}],
			response, keys
		},
		response = URLRead[certUri, VerifySecurityCertificates -> False];
		ThrowErrorWithCleanup[response];
		If[
			response["StatusCode"] != 200,
			Throw@FailObject[
				"InvalidCertIssuer", 
				response["Body"], 
				"StatusCode" -> 403
			]
		];
		keys = FromJSON[response["Body"]];
		keys = Lookup[
			keys, "keys",
			$ErrorMessage["ParseJWTToken"]["InvalidCert"]
		];
		SelectFirst[
			keys, SameQ[#["kid"], kid]&,
			$ErrorMessage["ParseJWTToken"]["InvalidCert"]
		]
	]
]


iVerifySignature[
	signatureInput_String, signature_String, 
	algorithm_String, publicKey_List
]:= Catch@Module[{
		hash, n, e
	},

	If[
		!MemberQ[
			{"SHA256", "SHA384", "SHA512"},
			algorithm
		],
		Throw[$ErrorMessage["ParseJWTToken"]["UnsupportedAlgorithm"]]
	];

	hash = Hash[signatureInput, algorithm, "Byte"];
	{n, e} = publicKey;
	
	SameQ[
		PowerMod[signature, e, n],
		FromDigits[hash, 256]
	]
]


iVerifySignature[___]:= $ErrorMessage["ParseJWTToken"]["InvalidToken"]


iPaddedString[text_String]:= Module[{
        paddingNeeded = Mod[StringLength[text], 4],
        padding
    },
    padding = If[
        paddingNeeded > 0,
        StringRiffle[Table["=", 4 - paddingNeeded], ""],
        ""
    ];
    StringJoin[text, padding]
]


(* iPaddedString[text_String]:= StringJoin[text, StringRepeat["=", Mod[4 - Mod[StringLength[text], 4], 4]]] *)


iCheckExpiryQ[expiration_Integer]:= TrueQ[Greater[FromUnixTime[expiration], Now]]


iCheckExpiryQ[___]:= False


fixURLEncode[str_String]:= StringReplace[str, {"+" -> "-", "/" -> "_"}]


fixURLDecode[str_String]:= StringReplace[str, {"-" -> "+", "_" -> "/"}]


iBase64URLEncode[str_String]:= StringTrim[fixURLEncode[str], "="]


iGenerateCodeChallenge[codeVerifier_String]:= iBase64URLEncode[Hash[codeVerifier, "SHA256", "Base64Encoding"]]


End[]


EndPackage[]