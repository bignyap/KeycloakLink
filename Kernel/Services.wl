(* ::Package:: *)

BeginPackage["KeycloakLink`Services`"]

Begin["`Private`"]

Needs["KeycloakLink`"]
Needs["WTC`Utilities`"]
Needs["WTC`Utilities`Common`"]

$KeycloakServices = <||>

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
    "Path" -> {TemplateSlot["realm"]},
    "Method" -> "PUT",
    "ContentType" -> "application/json",
    VerifySecurityCertificates -> False,
    "BodyTransormationFunction" -> (ToJSON[#, "Compact" -> True]&),
    "DynamicPath" -> {"realm"}
}

$KeycloakServices["ListRealm"] = {
    "Path" -> "",
    "Method" -> "GET",
    "ContentType" -> "application/json",
    VerifySecurityCertificates -> False
}

$KeycloakServices["DeleteRealm"] = {
    "Path" -> {TemplateSlot["realm"]},
    "Method" -> "DELETE",
    "ContentType" -> "application/json",
    VerifySecurityCertificates -> False,
    "DynamicPath" -> {"realm"}
}

$KeycloakServices["UserInfo"] = {
    "Path" -> {},
    "Method" -> "GET",
    "ContentType" -> "application/json",
    VerifySecurityCertificates -> False 
}

$KeycloakServices["CreateClient"] = {
    "Path" -> {TemplateSlot["realm"], "clients"},
    "Method" -> "POST",
    "ContentType" -> "application/json",
    VerifySecurityCertificates -> False,
    "DynamicPath" -> {"realm"}
}

$KeycloakServices["DeleteClient"] = {
    "Path" -> {TemplateSlot["realm"], "clients", TemplateSlot["clientID"]},
    "Method" -> "DELETE",
    "ContentType" -> "application/json",
    VerifySecurityCertificates -> False,
    "DynamicPath" -> {"realm", "clientID"}
}

$KeycloakServices["GetClientScope"] = {
    "Path" -> {TemplateSlot["realm"], "client-scopes"},
    "Method" -> "GET",
    "ContentType" -> "application/json",
    VerifySecurityCertificates -> False,
    "DynamicPath" -> {"realm"}
}

$KeycloakServices["UpdateClientScope"] = {
    "Path" -> {TemplateSlot["realm"], "client-scopes", TemplateSlot["scopeID"]},
    "Method" -> "PUT",
    "ContentType" -> "application/json",
    VerifySecurityCertificates -> False,
    "DynamicPath" -> {"realm", "scopeID"}
}

$KeycloakServices["UpdateClientScopeProtocol"] = {
    "Path" -> {TemplateSlot["realm"], "client-scopes", TemplateSlot["scopeID"], "protocol-mappers", "models", TemplateSlot["protocolId"]},
    "Method" -> "PUT",
    "ContentType" -> "application/json",
    VerifySecurityCertificates -> False,
    "DynamicPath" -> {"realm", "scopeID", "protocolId"}
}

$KeycloakServices["CreateRealmRole"] = {
    "Path" -> {TemplateSlot["realm"], "roles"},
    "Method" -> "POST",
    "ContentType" -> "application/json",
    VerifySecurityCertificates -> False,
    "DynamicPath" -> {"realm"}
}

$KeycloakServices["CreateGroup"] = {
    "Path" -> {TemplateSlot["realm"], "groups"},
    "Method" -> "POST",
    "ContentType" -> "application/json",
    VerifySecurityCertificates -> False,
    "DynamicPath" -> {"realm"}
}

$KeycloakServices["ListGroup"] = {
    "Path" -> {TemplateSlot["realm"], "groups"},
    "Method" -> "GET",
    "ContentType" -> "application/json",
    VerifySecurityCertificates -> False,
    "DynamicPath" -> {"realm"}
}

$KeycloakServices["ListRealmRole"] = {
    "Path" -> {TemplateSlot["realm"], "roles"},
    "Method" -> "GET",
    "ContentType" -> "application/json",
    VerifySecurityCertificates -> False,
    "DynamicPath" -> {"realm"}
}

$KeycloakServices["ListRealmUsers"] = {
    "Path" -> {TemplateSlot["realm"], "users"},
    "Method" -> "GET",
    "ContentType" -> "application/json",
    VerifySecurityCertificates -> False,
    "DynamicPath" -> {"realm"}
}

$KeycloakServices["ListClient"] = {
    "Path" -> {TemplateSlot["realm"], "clients"},
    "Method" -> "GET",
    "ContentType" -> "application/json",
    VerifySecurityCertificates -> False,
    "DynamicPath" -> {"realm"}
}

$KeycloakServices["GetServiceAccountUser"] = {
    "Path" -> {TemplateSlot["realm"], "clients", TemplateSlot["clientId"]},
    "Method" -> "GET",
    "ContentType" -> "application/json",
    VerifySecurityCertificates -> False,
    "DynamicPath" -> {"realm", "clientId"}
}

$KeycloakServices["UpdateGroupRole"] = {
    "Path" -> {TemplateSlot["realm"], "groups", TemplateSlot["groupID"], "role-mappings", "realm"},
    "Method" -> "POST",
    "ContentType" -> "application/json",
    VerifySecurityCertificates -> False,
    "DynamicPath" -> {"realm", "groupID"}
}

$KeycloakServices["UpdateGroupRoleForManagement"] = {
    "Path" -> {TemplateSlot["realm"], "groups", TemplateSlot["groupID"], "role-mappings", "clients", TemplateSlot["clientID"]},
    "Method" -> "POST",
    "ContentType" -> "application/json",
    VerifySecurityCertificates -> False,
    "DynamicPath" -> {"realm", "groupID", "clientID"}
}

$KeycloakServices["UpdateClientRole"] = {
    "Path" -> {TemplateSlot["realm"], "users", TemplateSlot["serviceUserID"], "role-mappings", "realm"},
    "Method" -> "POST",
    "ContentType" -> "application/json",
    VerifySecurityCertificates -> False,
    "DynamicPath" -> {"realm", "serviceUserID"}
}

$KeycloakServices["CreateKeycloakUser"] = {
    "Path" -> {TemplateSlot["realm"], "users"},
    "Method" -> "POST",
    "ContentType" -> "application/json",
    VerifySecurityCertificates -> False,
    "DynamicPath" -> {"realm"}
}

$KeycloakServices["ResetPassword"] = {
    "Path" -> {TemplateSlot["realm"], "users", TemplateSlot["userId"], "reset-password"},
    "Method" -> "PUT",
    "ContentType" -> "application/json",
    VerifySecurityCertificates -> False,
    "DynamicPath" -> {"realm", "userId"}
}

$KeycloakServices["ListKeycloakUser"] = {
    "Path" -> {TemplateSlot["realm"], "ui-ext", "brute-force-user"},
    "Method" -> "GET",
    "ContentType" -> "application/json",
    VerifySecurityCertificates -> False,
    "RemoveEmptyQueries" -> True,
    "DynamicPath" -> {"realm"}
}

$KeycloakServices["AvailableClientRoles"] = {
    "Path" -> {TemplateSlot["realm"], "ui-ext", "available-roles", TemplateSlot["type"], TemplateSlot["id"]},
    "Method" -> "GET",
    "ContentType" -> "application/json",
    VerifySecurityCertificates -> False,
    "RemoveEmptyQueries" -> True,
    "DynamicPath" -> {"realm", "type", "id"}
}

$KeycloakServices["AvailableRealmManagementRoles"] = {
    "Path" -> {TemplateSlot["realm"], "ui-ext", "available-roles", TemplateSlot["type"], TemplateSlot["id"]},
    "Method" -> "GET",
    "ContentType" -> "application/json",
    VerifySecurityCertificates -> False,
    "RemoveEmptyQueries" -> True,
    "DynamicPath" -> {"realm", "type", "id"}
}

$KeycloakServices["IntrospectAccessToken"] = {
    "Path" -> {"introspect"},
    "Method" -> "POST",
    "ContentType" -> "application/x-www-form-urlencoded",
    VerifySecurityCertificates -> False,
    CookieFunction -> None
}

$KeycloakServices["GetClientSecrets"] = {
    "Path" -> {TemplateSlot["realm"], "clients"},
    "Method" -> "GET",
    "ContentType" -> "application/json",
    VerifySecurityCertificates -> False,
    "DynamicPath" -> {"realm"}
}

End[]

EndPackage[]