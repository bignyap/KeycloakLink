(* ::Package:: *)

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

$KeycloakServices["CreateRealm"] = {
    "Path" -> "",
    "Method" -> "POST",
    "ContentType" -> "application/json",
    VerifySecurityCertificates -> False
}

$KeycloakServices["UpdateRealm"] = {
    "Path" -> {"`realm`"},
    "Method" -> "PUT",
    "ContentType" -> "application/json",
    VerifySecurityCertificates -> False,
    "BodyTransormationFunction" -> (ToJSON[#, "Compact" -> True]&)
}

$KeycloakServices["ListRealm"] = {
    "Path" -> "",
    "Method" -> "GET",
    "ContentType" -> "application/json",
    VerifySecurityCertificates -> False
}

$KeycloakServices["DeleteRealm"] = {
    "Path" -> {"`realm`"},
    "Method" -> "DELETE",
    "ContentType" -> "application/json",
    VerifySecurityCertificates -> False
}

$KeycloakServices["CreateClient"] = {
    "Path" -> {"`realm`", "clients"},
    "Method" -> "POST",
    "ContentType" -> "application/json",
    VerifySecurityCertificates -> False
}

$KeycloakServices["DeleteClient"] = {
    "Path" -> {"`realm`", "clients", "`clientID`"},
    "Method" -> "DELETE",
    "ContentType" -> "application/json",
    VerifySecurityCertificates -> False
}

$KeycloakServices["GetClientScope"] = {
    "Path" -> {"`realm`", "client-scopes"},
    "Method" -> "GET",
    "ContentType" -> "application/json",
    VerifySecurityCertificates -> False
}

$KeycloakServices["UpdateClientScope"] = {
    "Path" -> {"`realm`", "client-scopes", "`scopeID`"},
    "Method" -> "PUT",
    "ContentType" -> "application/json",
    VerifySecurityCertificates -> False
}

$KeycloakServices["UpdateClientScopeProtocol"] = {
    "Path" -> {"`realm`", "client-scopes", "`scopeID`", "protocol-mappers", "models", "`protocolId`"},
    "Method" -> "PUT",
    "ContentType" -> "application/json",
    VerifySecurityCertificates -> False
}

$KeycloakServices["CreateRealmRole"] = {
    "Path" -> {"`realm`", "roles"},
    "Method" -> "POST",
    "ContentType" -> "application/json",
    VerifySecurityCertificates -> False
}

$KeycloakServices["CreateGroup"] = {
    "Path" -> {"`realm`", "groups"},
    "Method" -> "POST",
    "ContentType" -> "application/json",
    VerifySecurityCertificates -> False
}

$KeycloakServices["ListGroup"] = {
    "Path" -> {"`realm`", "groups"},
    "Method" -> "GET",
    "ContentType" -> "application/json",
    VerifySecurityCertificates -> False
}

$KeycloakServices["ListRealmRole"] = {
    "Path" -> {"`realm`", "roles"},
    "Method" -> "GET",
    "ContentType" -> "application/json",
    VerifySecurityCertificates -> False
}

$KeycloakServices["ListRealmUsers"] = {
    "Path" -> {"`realm`", "users"},
    "Method" -> "GET",
    "ContentType" -> "application/json",
    VerifySecurityCertificates -> False
}

$KeycloakServices["ListClient"] = {
    "Path" -> {"`realm`", "clients"},
    "Method" -> "GET",
    "ContentType" -> "application/json",
    VerifySecurityCertificates -> False
}

$KeycloakServices["GetServiceAccountUser"] = {
    "Path" -> {"`realm`", "clients", "`clientId`"},
    "Method" -> "GET",
    "ContentType" -> "application/json",
    VerifySecurityCertificates -> False
}

$KeycloakServices["UpdateGroupRole"] = {
    "Path" -> {"`realm`", "groups", "`groupID`", "role-mappings", "realm"},
    "Method" -> "POST",
    "ContentType" -> "application/json",
    VerifySecurityCertificates -> False
}

$KeycloakServices["UpdateGroupRoleForManagement"] = {
    "Path" -> {"`realm`", "groups", "`groupID`", "role-mappings", "clients", "`clientID`"},
    "Method" -> "POST",
    "ContentType" -> "application/json",
    VerifySecurityCertificates -> False
}

$KeycloakServices["UpdateClientRole"] = {
    "Path" -> {"`realm`", "users", "`serviceUserID`", "role-mappings", "realm"},
    "Method" -> "POST",
    "ContentType" -> "application/json",
    VerifySecurityCertificates -> False
}

$KeycloakServices["CreateKeycloakUser"] = {
    "Path" -> {"`realm`", "users"},
    "Method" -> "POST",
    "ContentType" -> "application/json",
    VerifySecurityCertificates -> False
}

$KeycloakServices["ResetPassword"] = {
    "Path" -> {"`realm`", "users", "`userId`", "reset-password"},
    "Method" -> "PUT",
    "ContentType" -> "application/json",
    VerifySecurityCertificates -> False
}

$KeycloakServices["ListKeycloakUser"] = {
    "Path" -> {"`realm`", "ui-ext", "brute-force-user"},
    "Method" -> "GET",
    "ContentType" -> "application/json",
    VerifySecurityCertificates -> False,
    "RemoveEmptyQueries" -> True
}

$KeycloakServices["AvailableClientRoles"] = {
    "Path" -> {"`realm`", "ui-ext", "available-roles", "`type`", "`id`"},
    "Method" -> "GET",
    "ContentType" -> "application/json",
    VerifySecurityCertificates -> False,
    "RemoveEmptyQueries" -> True
}

$KeycloakServices["AvailableRealmManagementRoles"] = {
    "Path" -> {"`realm`", "ui-ext", "available-roles", "`type`", "`id`"},
    "Method" -> "GET",
    "ContentType" -> "application/json",
    VerifySecurityCertificates -> False,
    "RemoveEmptyQueries" -> True
}

$KeycloakServices["IntrospectAccessToken"] = {
    "Path" -> {"introspect"},
    "Method" -> "POST",
    "ContentType" -> "application/x-www-form-urlencoded",
    VerifySecurityCertificates -> False,
    CookieFunction -> None
}

$KeycloakServices["GetClientSecrets"] = {
    "Path" -> {"`realm`", "clients"},
    "Method" -> "GET",
    "ContentType" -> "application/json",
    VerifySecurityCertificates -> False
}

End[]

EndPackage[]