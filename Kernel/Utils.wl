BeginPackage["KeycloakLink`Utils`"]


mFormatHTTPResponse


KeycloakLinkAsset


Begin["`Private`"]


Needs["KeycloakLink`"]
Needs["KeycloakLink`Common`"]
Needs["WTC`Utilities`"]
Needs["WTC`Utilities`Common`"]


SetUsage[ParseJWTToken, StringJoin[
    "ParseJWTToken[token, opts] parses a JSON Web Token (JWT) and verifies its validity using the specified options opts.",
    "\nOptions include:",
    "\n| Option | Default | Description |",
    "\n| 'CheckExpiration' | True | Whether to check the token's expiration |",
    "\n| 'VerifySignature' | False | Whether to verify the token's signature |",
    "\n| 'Issuer' | '' | The expected issuer of the token |",
    "\n| 'CachePublicKey' | True | Whether to cache the public key |",
    "\n| 'CacheDuration' | 3600 | Duration to cache the public key in seconds |"
]]


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
	"CheckExpiration" :> True,
	"VerifySignature" :> False,
	"Issuer" :> "",
	"CachePublicKey" -> True,
	"CacheDuration" -> 3600 (* In Seconds *)
}


ParseJWTToken[token_String, opts:OptionsPattern[]]:= Catch[
    Module[{
            split, header, payload, signature,
            validQ, signatureInput, publicKey,
			algorithm, issuer, kid, validSignatureQ,
			modulus, exponent
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

		(* Verify issuer *)
		issuer = Lookup[
			payload, "iss", 
			Throw[$ErrorMessage["ParseJWTToken"]["InvalidIssuer"]]
		];
		If[
			!TrueQ[iCheckIssuer[OptionValue["Issuer"], issuer]],
			Throw[$ErrorMessage["ParseJWTToken"]["InvalidIssuer"]]
		];
        
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
			publicKey = iGetPublicKey[
				issuer, kid, 
				FilterRules[{opts}, Options[iGetPublicKey]]
			];
			ThrowErrorWithCleanup[publicKey];
			{modulus, exponent} = Lookup[publicKey, {"n", "e"}, ""];

			(* check the signature *)
			signatureInput = StringJoin[split[[1]], ".", split[[2]]];
			algorithm = iGetSigAlgorithm[header["alg"]];
			validSignatureQ = iVerifySignature[
				signatureInput, signature, 
				algorithm, modulus, exponent
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


SetUsage[ModifiedBase64Decode, StringJoin[
    "ModifiedBase64Decode[str] decodes a Base64 URL-encoded string str."
]]


ModifiedBase64Decode[str_String]:= 
	Developer`DecodeBase64ToByteArray[iPaddedString[fixURLDecode[str]]]


iGetSigAlgorithm[alg_String]:= Replace[
	alg, {
		"RS256" -> "SHA256",
		"RS384" -> "SHA384",
		"RS512" -> "SHA512"
	}
]


iCheckIssuer[actualIssuer_String, foundIssuer_String]:= SameQ[
	domainWorkaroundForDev[foundIssuer],
	domainWorkaroundForDev[actualIssuer]
]

domainWorkaroundForDev[url_String]:= Replace[URLParse[url]["Domain"], {"localhost" -> "idp"}]


Options[iGetPublicKey] = {
	"CachePublicKey" -> True,
	"CacheDuration" -> 3600 (* In Seconds *)
}


iGetPublicKey[
	issuer_String, kid_String,
	OptionsPattern[]
]:= Catch[
	Module[{
			certUri = URLBuild[{issuer, "protocol", "openid-connect","certs"}],
			response, keys
		},
		response = If[
				TrueQ[OptionValue["CachePublicKey"]],
				Once[
					URLRead[certUri, VerifySecurityCertificates -> False],
					PersistenceTime -> OptionValue["CacheDuration"]
				],
				Unset[URLRead[certUri, VerifySecurityCertificates -> False]];
				URLRead[certUri, VerifySecurityCertificates -> False]
		];
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


(*
	Unfortunately, WL doesn't have built-in support for custom verification 
	with separate modulus and exponent without using certificates. 
	We'll need to manually perform the RSA signature verification process using lower-level functions.
	
	Steps to verify the signature:

	1. Hash the header and payload using SHA-256.
	2. Decrypt the signature using the RSA public key (derived from n and e)
	3. Compare the decrypted result with the hash of the header and payload.

	Read the official doc here: https://datatracker.ietf.org/doc/html/rfc7519#section-7.2
	Read the JWS signature validation doc here: https://datatracker.ietf.org/doc/html/rfc7515#section-5.2
*)


iVerifySignature[
	signatureInput_String, signature_String, 
	algorithm_String, modulus_String, exponent_String
]:= Catch@Module[{
		hash, rsaModulus, rsaExponent,
		decodedSignature, decryptedSignature,
		publicKeySize, signatureInteger,
		decryptedSignatureBytes
	},
	(*
		Verify if the the specified algorithm is supported.
	*)
	If[
		!MemberQ[
			{"SHA256", "SHA384", "SHA512"},
			algorithm
		],
		Throw[$ErrorMessage["ParseJWTToken"]["UnsupportedAlgorithm"]]
	];

	(* 
		Step 1: Decoding the Signature
		i. Decode the signature
		ii. Convert it to large integers (binary forms)
	*)
	decodedSignature = ModifiedBase64Decode[signature];
	signatureInteger = FromDigits[ImportByteArray[decodedSignature], 256];

	(* 
		Step 2: Extracting the Public Key or Exponent/Modulus
		i. Decode the modulus and convert it integer form
		ii. Decode the exponent and convert it integer form
	*)
	rsaModulus = FromDigits[ImportByteArray[ModifiedBase64Decode[modulus]], 256];
	rsaExponent = FromDigits[ImportByteArray[ModifiedBase64Decode[exponent]], 256];

	(*
		Step 3: Compute the public key size
		i.  rsaModulus is a large integer, the logarithm base 2 of the modulus gives the bit length
		ii. Divide by 8 converts it to bytes
	*)
	publicKeySize = Ceiling[Log[2, rsaModulus]] / 8;

	(*
		Step 4: Hashing the Input
	*)
	hash = Hash[signatureInput, algorithm, "ByteArray"];

	(*
		Step 5: Decrypting the Signature
		i. The RSA decryption is performed using modular exponentiation (PowerMod) 
		of the signatureInteger (the signature as an integer), 
		raised to the rsaExponent (the public key exponent), 
		modulo rsaModulus (the public key modulus).
	*)
	decryptedSignature = PowerMod[signatureInteger, rsaExponent, rsaModulus];

	(*
		Step 5: Converting Decrypted Signature
		The decrypted signature (which is an integer) is converted back into its byte array form, 
		since the result of RSA decryption is essentially the padded hash of the original message.
	*)
	decryptedSignatureBytes = IntegerDigits[decryptedSignature, 256, publicKeySize];
	
	(* 
		Stpe 6 : Signature Validation 
		The function compares the decrypted signature bytes with the computed hash of the original message. 
		The Take function extracts the relevant portion of the decrypted signature, 
		which should match the original hash if the signature is valid.
	*)
	TrueQ@SameQ[
		Take[decryptedSignatureBytes, -Length[hash]],
		Normal[hash]
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


KeycloakLinkAsset[srcName_]:= With[{paclet = PacletObject["KeycloakLink"]}, paclet["AssetLocation", srcName]]


mFormatHTTPResponse[temp_HTTPResponse]:= FormatHTTPResponse[
	temp, "OutputFormat" -> "Association", 
	"FailureMessage" -> iFailObject[temp]
]


mFormatHTTPResponse[expr_]:= expr


iFailObject[temp_HTTPResponse]:= FailObject[
	temp["StatusCodeDescription"], temp["Body"], 
	"StatusCode" -> temp["StatusCode"]
]


End[]


EndPackage[]