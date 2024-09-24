BeginPackage["KeycloakLink`Services`"]


$KeycloakServices


$KeycloakBaseURL


Begin["`Private`"]


Needs["KeycloakLink`"]


$KeycloakBaseURL = "https://localhost:8443/auth/admin"


$KeycloakServices = <|
    "CreateRealm" -> CreateRealm,
    "UpdateRealm" -> UpdateRealm,
    "ListRealm" -> ListRealm,
    "DeleteRealm" -> DeleteRealm,
    "CreateClient" -> CreateClient,
    "DeleteClient" -> DeleteClient,
    "GetClientScope" -> GetClientScope,
    "UpdateClientScope" -> UpdateClientScope,
    "UpdateClientScopeProtocol" -> UpdateClientScopeProtocol,
    "CreateRealmRole" -> CreateRealmRole,
    "CreateGroup" -> CreateGroup,
    "ListGroup" -> ListGroup,
    "ListRealmRole" -> ListRealmRole,
    "ListClient" -> ListClient,
    "ListRealmUsers" -> ListRealmUsers,
    "GetServiceAccountUser" -> GetServiceAccountUser,
    "UpdateGroupRole" -> UpdateGroupRole,
    "UpdateClientRole" -> UpdateClientRole,
    "CreateKeycloakUser" -> CreateKeycloakUser,
    "ListKeycloakUser" -> ListKeycloakUser,
    "ResetPassword" -> ResetPassword,
    "UpdateGroupClientRole" -> UpdateGroupClientRole,
    "UpdateGroupRoleForManagement" -> UpdateGroupRoleForManagement,
    "AvailableClientRoles" -> AvailableClientRoles,
    "AvailableRealmManagementRoles" -> AvailableRealmManagementRoles,
    "IntrospectAccessToken" -> IntrospectAccessToken,
    "GetClientSecrets" -> GetClientSecrets
|>;





End[]


EndPackage[]