package goauth

import (
	"os/user"
)

type OSAuthFlags uint32

const (
	UXAUTHFL_IGNORE_USER_MAPPER_ON_UNIX OSAuthFlags = (1 << iota)
	UXAUTHFL_IGNORE_GROUP_MAPPER_ON_UNIX
	UXAUTHFL_SKIP_USER_CHECK
	UXAUTHFL_SKIP_GROUP_CHECK
	UXAUTHFL_SKIP_AUXILIARY_GROUPS_CHECK
	UXAUTHFL_REJECT_CREDENTIAL_OS_USER_ID
	UXAUTHFL_REJECT_CREDENTIAL_USER_ID
	UXAUTHFL_REJECT_MAPPED_OS_USER_ID
	UXAUTHFL_REJECT_MAPPED_USER_ID
	UXAUTHFL_REJECT_INTERNED_OS_USER_ID
	UXAUTHFL_REJECT_INTERNED_USER_ID
	UXAUTHFL_DISALLOW_USER_BY_ID
	UXAUTHFL_DISALLOW_USER_BY_NAME
	UXAUTHFL_DISALLOW_GROUP_BY_ID
	UXAUTHFL_DISALLOW_GROUP_BY_NAME
	UXAUTHFL_ALLOW_FAILED_GROUP
	UXAUTHFL_ALLOW_FAILED_AUXILIARY_GROUP
	UXAUTHFL_USER_NAME_BEFORE_ID
	UXAUTHFL_GROUP_NAME_BEFORE_ID
	UXAUTHFL_IGNORE_MAPPERS_ON_UNIX OSAuthFlags = UXAUTHFL_IGNORE_USER_MAPPER_ON_UNIX |
			UXAUTHFL_IGNORE_GROUP_MAPPER_ON_UNIX
	UXAUTHFL_REJECT_CREDENTIAL_IDS OSAuthFlags = UXAUTHFL_REJECT_CREDENTIAL_OS_USER_ID |
			UXAUTHFL_REJECT_CREDENTIAL_USER_ID
	UXAUTHFL_REJECT_MAPPED_IDS OSAuthFlags = UXAUTHFL_REJECT_MAPPED_OS_USER_ID | UXAUTHFL_REJECT_MAPPED_USER_ID
	UXAUTHFL_REJECT_INTERNED_IDS OSAuthFlags = UXAUTHFL_REJECT_INTERNED_OS_USER_ID | UXAUTHFL_REJECT_INTERNED_USER_ID
)

type OSAuthenticator[
	ContextT any,
	CredentialUidT any,
	CredentialGidT any,
	MappedUidT any,
	MappedGidT any,
	InternedUidT any,
	InternedGidT any,
] struct {
	Flags OSAuthFlags
	UserMapper func(OSAuthFlags, ContextT, CredentialUidT) (MappedUidT, error)
	GroupMapper func(OSAuthFlags, ContextT, CredentialGidT) (MappedGidT, error)
	UserLookup func(OSAuthFlags, ContextT, CredentialUidT, MappedUidT, int) (InternedUidT, error)
	GroupLookup func(OSAuthFlags, ContextT, CredentialGidT, MappedGidT, int) (InternedGidT, error)
	Verifier func(
		OSAuthFlags,
		ContextT,
		CredentialUidT,
		MappedUidT,
		InternedUidT,
		CredentialGidT,
		MappedGidT,
		InternedGidT,
		[]CredentialGidT,
		[]MappedGidT,
		[]InternedGidT,
		int,
	) (Principal, error)
}

func(auth *OSAuthenticator[
	ContextT,
	CredentialUidT,
	CredentialGidT,
	MappedUidT,
	MappedGidT,
	InternedUidT,
	InternedGidT,
]) Authenticate(context ContextT, credentials Credentials) (result Principal, err error) {
	if (auth.Flags & UXAUTHFL_REJECT_CREDENTIAL_OS_USER_ID) == 0 {
		cred, ok := credentials.(*OSUserIDCredentials[CredentialUidT, CredentialGidT])
		if ok {
			result, err = auth.authWithCredentialOSUserID(context, cred)
		}
	}
	if result == nil && err == nil && (auth.Flags & UXAUTHFL_REJECT_CREDENTIAL_USER_ID) == 0 {
		cred, ok := credentials.(*UserIDCredentials[CredentialUidT])
		if ok {
			result, err = auth.authWithCredentialUserID(context, cred)
		}
	}
	if result == nil && err == nil && (auth.Flags & UXAUTHFL_REJECT_MAPPED_OS_USER_ID) == 0 {
		cred, ok := credentials.(*OSUserIDCredentials[MappedUidT, MappedGidT])
		if ok {
			result, err = auth.authWithMappedOSUserID(context, cred)
		}
	}
	if result == nil && err == nil && (auth.Flags & UXAUTHFL_REJECT_MAPPED_USER_ID) == 0 {
		cred, ok := credentials.(*UserIDCredentials[MappedUidT])
		if ok {
			result, err = auth.authWithMappedUserID(context, cred)
		}
	}
	if result == nil && err == nil && (auth.Flags & UXAUTHFL_REJECT_INTERNED_OS_USER_ID) == 0 {
		cred, ok := credentials.(*OSUserIDCredentials[InternedUidT, InternedGidT])
		if ok {
			result, err = auth.authWithInternedOSUserID(context, cred)
		}
	}
	if result == nil && err == nil && (auth.Flags & UXAUTHFL_REJECT_INTERNED_USER_ID) == 0 {
		cred, ok := credentials.(*UserIDCredentials[InternedUidT])
		if ok {
			result, err = auth.authWithInternedUserID(context, cred)
		}
	}
	return
}

func(auth *OSAuthenticator[
	ContextT,
	CredentialUidT,
	CredentialGidT,
	MappedUidT,
	MappedGidT,
	InternedUidT,
	InternedGidT,
]) authWithCredentialOSUserID(
	context ContextT,
	credentials *OSUserIDCredentials[CredentialUidT, CredentialGidT],
) (result Principal, err error) {
	// UID
	var mappedUID MappedUidT
	var internedUID InternedUidT
	if (auth.Flags & UXAUTHFL_SKIP_USER_CHECK) == 0 {
		mappedUID, internedUID, err = auth.mapUser(context, credentials.UID)
		if err != nil {
			return
		}
	}
	// GID
	var mappedGID MappedGidT
	var internedGID InternedGidT
	if (auth.Flags & UXAUTHFL_SKIP_GROUP_CHECK) == 0 {
		mappedGID, internedGID, err = auth.mapGroup(context, credentials.GID)
		if err != nil {
			if (auth.Flags & UXAUTHFL_ALLOW_FAILED_GROUP) == 0 {
				return
			}
			err = nil
		}
	}
	// GIDs
	var mappedGIDs []MappedGidT
	var internedGIDs []InternedGidT
	if (auth.Flags & UXAUTHFL_SKIP_AUXILIARY_GROUPS_CHECK) == 0 {
		for _, gid := range credentials.GIDs {
			mappedGID, internedGID, err = auth.mapGroup(context, gid)
			if err != nil {
				if (auth.Flags & UXAUTHFL_ALLOW_FAILED_AUXILIARY_GROUP) == 0 {
					return
				}
				err = nil
			} else {
				mappedGIDs = append(mappedGIDs, mappedGID)
				internedGIDs = append(internedGIDs, internedGID)
			}
		}
	}
	// verify
	if auth.Verifier != nil {
		result, err = auth.Verifier(
			auth.Flags,
			context,
			credentials.UID,
			mappedUID,
			internedUID,
			credentials.GID,
			mappedGID,
			internedGID,
			credentials.GIDs,
			mappedGIDs,
			internedGIDs,
			0,
		)
	}
	if result == nil && err == nil {
		result = &NullPrincipal{}
	}
	return
}

func(auth *OSAuthenticator[
	ContextT,
	CredentialUidT,
	CredentialGidT,
	MappedUidT,
	MappedGidT,
	InternedUidT,
	InternedGidT,
]) authWithCredentialUserID(
	context ContextT,
	credentials *UserIDCredentials[CredentialUidT],
) (result Principal, err error) {
	var mappedUID MappedUidT
	var internedUID InternedUidT
	if (auth.Flags & UXAUTHFL_SKIP_USER_CHECK) == 0 {
		mappedUID, internedUID, err = auth.mapUser(context, credentials.UID)
		if err != nil {
			return
		}
	}
	var credGID CredentialGidT
	var mappedGID MappedGidT
	var internedGID InternedGidT
	if auth.Verifier != nil {
		result, err = auth.Verifier(
			auth.Flags,
			context,
			credentials.UID,
			mappedUID,
			internedUID,
			credGID,
			mappedGID,
			internedGID,
			nil,
			nil,
			nil,
			0,
		)
	}
	if result == nil && err == nil {
		result = &NullPrincipal{}
	}
	return
}

func(auth *OSAuthenticator[
	ContextT,
	CredentialUidT,
	CredentialGidT,
	MappedUidT,
	MappedGidT,
	InternedUidT,
	InternedGidT,
]) mapUser(context ContextT, credUID CredentialUidT) (mappedUser MappedUidT, internedUser InternedUidT, err error) {
	if auth.UserMapper != nil {
		mappedUser, err = auth.UserMapper(auth.Flags, context, credUID)
	}
	if err == nil {
		internedUser, err = auth.internUser(context, credUID, mappedUser, 0)
	}
	return
}

func(auth *OSAuthenticator[
	ContextT,
	CredentialUidT,
	CredentialGidT,
	MappedUidT,
	MappedGidT,
	InternedUidT,
	InternedGidT,
]) mapGroup(context ContextT, credGID CredentialGidT) (mappedGroup MappedGidT, internedGroup InternedGidT, err error) {
	if auth.GroupMapper != nil {
		mappedGroup, err = auth.GroupMapper(auth.Flags, context, credGID)
	}
	if err == nil {
		internedGroup, err = auth.internGroup(context, credGID, mappedGroup, 0)
	}
	return
}

func(auth *OSAuthenticator[
	ContextT,
	CredentialUidT,
	CredentialGidT,
	MappedUidT,
	MappedGidT,
	InternedUidT,
	InternedGidT,
]) authWithMappedOSUserID(
	context ContextT,
	credentials *OSUserIDCredentials[MappedUidT, MappedGidT],
) (result Principal, err error) {
	// UID
	var credUID CredentialUidT
	var internedUID InternedUidT
	if (auth.Flags & UXAUTHFL_SKIP_USER_CHECK) == 0 {
		internedUID, err = auth.internUser(context, credUID, credentials.UID, 1)
		if err != nil {
			return
		}
	}
	// GID
	var credGID CredentialGidT
	var internedGID InternedGidT
	if (auth.Flags & UXAUTHFL_SKIP_GROUP_CHECK) == 0 {
		internedGID, err = auth.internGroup(context, credGID, credentials.GID, 1)
		if err != nil {
			if (auth.Flags & UXAUTHFL_ALLOW_FAILED_GROUP) == 0 {
				return
			}
			err = nil
		}
	}
	// GIDs
	var internedGIDs []InternedGidT
	if (auth.Flags & UXAUTHFL_SKIP_AUXILIARY_GROUPS_CHECK) == 0 {
		for _, gid := range credentials.GIDs {
			internedGID, err = auth.internGroup(context, credGID, gid, 1)
			if err != nil {
				if (auth.Flags & UXAUTHFL_ALLOW_FAILED_AUXILIARY_GROUP) == 0 {
					return
				}
				err = nil
			} else {
				internedGIDs = append(internedGIDs, internedGID)
			}
		}
	}
	// verify
	if auth.Verifier != nil {
		result, err = auth.Verifier(
			auth.Flags,
			context,
			credUID,
			credentials.UID,
			internedUID,
			credGID,
			credentials.GID,
			internedGID,
			nil,
			credentials.GIDs,
			internedGIDs,
			1,
		)
	}
	if result == nil && err == nil {
		result = &NullPrincipal{}
	}
	return
}

func(auth *OSAuthenticator[
	ContextT,
	CredentialUidT,
	CredentialGidT,
	MappedUidT,
	MappedGidT,
	InternedUidT,
	InternedGidT,
]) authWithMappedUserID(
	context ContextT,
	credentials *UserIDCredentials[MappedUidT],
) (result Principal, err error) {
	var credUID CredentialUidT
	var internedUID InternedUidT
	if (auth.Flags & UXAUTHFL_SKIP_USER_CHECK) == 0 {
		internedUID, err = auth.internUser(context, credUID, credentials.UID, 1)
		if err != nil {
			return
		}
	}
	var credGID CredentialGidT
	var mappedGID MappedGidT
	var internedGID InternedGidT
	if auth.Verifier != nil {
		result, err = auth.Verifier(
			auth.Flags,
			context,
			credUID,
			credentials.UID,
			internedUID,
			credGID,
			mappedGID,
			internedGID,
			nil,
			nil,
			nil,
			1,
		)
	}
	if result == nil && err == nil {
		result = &NullPrincipal{}
	}
	return
}

func(auth *OSAuthenticator[
	ContextT,
	CredentialUidT,
	CredentialGidT,
	MappedUidT,
	MappedGidT,
	InternedUidT,
	InternedGidT,
]) internUser(
	context ContextT,
	credUID CredentialUidT,
	mappedUID MappedUidT,
	skippedPhases int,
) (internedUser InternedUidT, err error) {
	if auth.UserLookup != nil {
		internedUser, err = auth.UserLookup(auth.Flags, context, credUID, mappedUID, skippedPhases)
	}
	return
}

func(auth *OSAuthenticator[
	ContextT,
	CredentialUidT,
	CredentialGidT,
	MappedUidT,
	MappedGidT,
	InternedUidT,
	InternedGidT,
]) internGroup(
	context ContextT,
	credGID CredentialGidT,
	mappedGID MappedGidT,
	skippedPhases int,
) (internedGroup InternedGidT, err error) {
	if auth.GroupLookup != nil {
		internedGroup, err = auth.GroupLookup(auth.Flags, context, credGID, mappedGID, skippedPhases)
	}
	return
}

func(auth *OSAuthenticator[
	ContextT,
	CredentialUidT,
	CredentialGidT,
	MappedUidT,
	MappedGidT,
	InternedUidT,
	InternedGidT,
]) authWithInternedOSUserID(
	context ContextT,
	credentials *OSUserIDCredentials[InternedUidT, InternedGidT],
) (result Principal, err error) {
	// UID
	var credUID CredentialUidT
	var mappedUID MappedUidT
	var internedUID InternedUidT
	if (auth.Flags & UXAUTHFL_SKIP_USER_CHECK) == 0 {
		internedUID = credentials.UID
	}
	// GID
	var credGID CredentialGidT
	var mappedGID MappedGidT
	var internedGID InternedGidT
	if (auth.Flags & UXAUTHFL_SKIP_GROUP_CHECK) == 0 {
		internedGID = credentials.GID
	}
	// GIDs
	var internedGIDs []InternedGidT
	if (auth.Flags & UXAUTHFL_SKIP_AUXILIARY_GROUPS_CHECK) == 0 {
		internedGIDs = credentials.GIDs
	}
	// verify
	if auth.Verifier != nil {
		result, err = auth.Verifier(
			auth.Flags,
			context,
			credUID,
			mappedUID,
			internedUID,
			credGID,
			mappedGID,
			internedGID,
			nil,
			nil,
			internedGIDs,
			2,
		)
	}
	if result == nil && err == nil {
		result = &NullPrincipal{}
	}
	return
}

func(auth *OSAuthenticator[
	ContextT,
	CredentialUidT,
	CredentialGidT,
	MappedUidT,
	MappedGidT,
	InternedUidT,
	InternedGidT,
]) authWithInternedUserID(
	context ContextT,
	credentials *UserIDCredentials[InternedUidT],
) (result Principal, err error) {
	var credUID CredentialUidT
	var mappedUID MappedUidT
	var internedUID InternedUidT
	if (auth.Flags & UXAUTHFL_SKIP_USER_CHECK) == 0 {
		internedUID = credentials.UID
	}
	var credGID CredentialGidT
	var mappedGID MappedGidT
	var internedGID InternedGidT
	if auth.Verifier != nil {
		result, err = auth.Verifier(
			auth.Flags,
			context,
			credUID,
			mappedUID,
			internedUID,
			credGID,
			mappedGID,
			internedGID,
			nil,
			nil,
			nil,
			2,
		)
	}
	if result == nil && err == nil {
		result = &NullPrincipal{}
	}
	return
}

func MapGenericUserOrGroupToGeneric[ContextT any](
	flags OSAuthFlags,
	context ContextT,
	uidOrGid string,
) (mapped string, err error) {
	mapped = uidOrGid
	return
}

func LookupGenericUser[ContextT any, CredentialUidT any](
	flags OSAuthFlags,
	context ContextT,
	credUID CredentialUidT,
	mappedUID string,
	skippedPhases int,
) (internedUID *user.User, err error) {
	if (flags & UXAUTHFL_USER_NAME_BEFORE_ID) != 0 {
		internedUID, err = user.Lookup(mappedUID)
		if internedUID == nil {
			internedUID, err = user.LookupId(mappedUID)
		}
	} else {
		internedUID, err = user.LookupId(mappedUID)
		if internedUID == nil {
			internedUID, err = user.Lookup(mappedUID)
		}
	}
	return
}

func LookupGenericGroup[ContextT any, CredentialGidT any](
	flags OSAuthFlags,
	context ContextT,
	credGID CredentialGidT,
	mappedGID string,
	skippedPhases int,
) (internedGID *user.Group, err error) {
	if (flags & UXAUTHFL_GROUP_NAME_BEFORE_ID) != 0 {
		internedGID, err = user.LookupGroup(mappedGID)
		if internedGID == nil {
			internedGID, err = user.LookupGroupId(mappedGID)
		}
	} else {
		internedGID, err = user.LookupGroupId(mappedGID)
		if internedGID == nil {
			internedGID, err = user.LookupGroup(mappedGID)
		}
	}
	return
}

var _ Authenticator[int] = &OSAuthenticator[int, uint32, uint64, float32, float64, bool, string]{}
