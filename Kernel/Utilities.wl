BeginPackage["KeycloakLink`Utilities`"]


ParseJWTToken


FailObject


Begin["`Private`"]


Needs["KeycloakLink`"]


$ErrorMessage["ParseJWTToken"]["InvalidToken"]:=
    FailObject["InvalidToken", "Access token is not valid", "StatusCode" -> 403]


Options[ParseJWTToken] = {
	"CheckExpiration" -> True
}


ParseJWTToken[token_String, OptionsPattern[]]:= Check[
    Catch@Module[{
            split, header, payload,
            validQ
        },
        split = StringSplit[token, "."];
		If[
			!SameQ[Length[split], 3],
			Throw[$ErrorMessage["ParseJWTToken"]["InvalidToken"]]
		];
        header = ImportString[iPaddedString[split[[1]]], {"Base64", "String"}];
        header = ImportString[header, "RawJSON"];
        payload = ImportString[iPaddedString[split[[2]]], {"Base64", "String"}];
        payload = ImportString[payload, "RawJSON"];
        validQ = TrueQ[iCheckExpiryQ[payload["exp"]]];
        If[
            OptionValue["CheckExpiration"],
            If[
                !validQ,
                Throw[$ErrorMessage["ParseJWTToken"]["InvalidToken"]]
            ]
        ];
        <|
            "Header" -> header,
            "Payload" -> payload,
            "Signature" -> validQ
        |>
    ],
    $ErrorMessage["ParseJWTToken"]["InvalidToken"]
]


ParseJWTToken[___]:= $ErrorMessage["ParseJWTToken"]["InvalidToken"]


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


iCheckExpiryQ[expiration_Integer]:= TrueQ[Greater[FromUnixTime[expiration], Now]]


iCheckExpiryQ[___]:= False


iBase64URLEncode[str_String]:= StringTrim[StringReplace[str, {"+" -> "-", "/" -> "_"}], "="]


iGenerateCodeChallenge[codeVerifier_String]:= iBase64URLEncode[Hash[codeVerifier, "SHA256", "Base64Encoding"]]


Options[FailObject] = {
    "StatusCode" -> 400, 
    "ConvertToJSON" -> True,
    "Exposed" -> True
}

FailObject[
	msgName_String, msgTmp_String, 
	tempIn_Association, opts:OptionsPattern[]
]:= FailObject[msgName, TemplateApply[msgTmp, tempIn], opts]

FailObject[
	msgName_String, msg_String, 
	OptionsPattern[]
]:= Failure[
	msgName, <|
		"MessageTemplate" -> msg, 
		"TimeStamp" -> DateString[], 
		"StatusCode" -> OptionValue["StatusCode"],
		"ConvertToJSON" -> OptionValue["ConvertToJSON"]
	|>
]

FailObject[msgTag_String]:= FailObject[msgTag, msgTag]

FailObject[]:= FailObject["Failure", "Failure!!"]


End[]


EndPackage[]