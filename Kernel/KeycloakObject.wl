(* ::Package:: *)

BeginPackage["KeycloakLink`KeycloakObject`"]


Begin["`Private`"]


Needs["KeycloakLink`"]
Needs["WTC`Utilities`"]
Needs["WTC`Utilities`Common`"]


KeycloakObject


KeycloakObject/:MakeBoxes[p:KeycloakObject[keycloakAssoc_?KeycloakObjectQ], fmt:(StandardForm|TraditionalForm)]:=
	Module[{
			alwaysGrid, sometimesGrid, 
			icon
		},
		alwaysGrid = {
			BoxForm`SummaryItem[{"ID", keycloakAssoc["ID"]}],
			BoxForm`SummaryItem[{"AuthURL", keycloakAssoc["AuthURL"]}]
		}; 
		sometimesGrid = {
			{
				BoxForm`SummaryItem[{"Name", Lookup[keycloakAssoc, "Name", keycloakAssoc["UUID"]]}],
				BoxForm`SummaryItem[{"AuthType", "OpenIDConnect"}]
			},
			{
				BoxForm`SummaryItem[{"Information", keycloakAssoc["Information"]}],
				BoxForm`SummaryItem[{"Timestamp", DateString[Now]}]
			}
		};
		icon =  Graphics[
			{
				Green, Disk[], 
				Text[Style["Keycloak", 10*$ECSearchDPIScaling, Bold, Red], {0, 0}, Automatic, {2, 1}]
			},
			ImageSize -> Dynamic[{ (* this seems to be the standard icon size *)
				Automatic, 
				3.5 CurrentValue["FontCapHeight"]/AbsoluteCurrentValue[Magnification]
			}]
		]; 
		BoxForm`ArrangeSummaryBox[
			KeycloakObject (* Head *), 
			keycloakAssoc (* Actual Data *), 
			icon (* Icon *), 
			alwaysGrid (* Shows in the Object *), 
			sometimesGrid (* Optional elements showed in the object *), 
			fmt (* What format to be used *),
			"Interpretable" -> Automatic
		]
	]


$defaultProp = ("Authentication" | "ID" | "Information" | "Name" | "Requests")


$supportedRequests = {
    "CreateRealm", "UpdateRealm", "ListRealm", "DeleteRealm",
    "CreateClient", "DeleteClient", "GetClientScope", 
    "UpdateClientScope", "UpdateClientScopeProtocol", "CreateRealmRole", 
    "CreateGroup", "ListGroup", "ListRealmRole", "ListClient", 
    "ListRealmUsers", "GetServiceAccountUser", "UpdateGroupRole", 
    "UpdateClientRole", "CreateKeycloakUser", "ListKeycloakUser", 
    "ResetPassword", "UpdateGroupClientRole", 
    "UpdateGroupRoleForManagement", "AvailableClientRoles", 
    "AvailableRealmManagementRoles", "IntrospectAccessToken", 
    "GetClientSecrets"
}


KeycloakObject[keycloakAssoc_?AssociationQ][
	prop:Alternatives[
		"ID", "Name", "Information", 
		"AuthURL", "Timestamp", "AuthType"
	]
]:= keycloakAssoc[prop]

KeycloakObject[keycloakAssoc_?AssociationQ]["Authentication"]:= keycloakAssoc["Information"]["Authentication"]

KeycloakObject[keycloakAssoc_?AssociationQ]["Requests"]:= $supportedRequests

KeycloakObject[keycloakAssoc_?AssociationQ]["TokenDetails"]:= keycloakAssoc["Information"]["TokenDetails"]


KeycloakObject/:KeycloakObjectQ[
    KeycloakObject[keycloakAssoc_?AssociationQ]
]:= KeycloakObjectQ[keycloakAssoc]

KeycloakObjectQ[keycloakAssoc_?AssociationQ]:= AllTrue[
    {"ID", "AuthURL", "Authentication"}, 
    KeyExistsQ[keycloakAssoc, #]&
]

KeycloakObjectQ[___]:= False


End[]


EndPackage[]
