package goauth

func MapUNIXUserToGeneric[ContextT any](
	flags OSAuthFlags,
	context ContextT,
	uid UID,
) (mapped string, err error) {
	err = OSOperationUnavailableError {
		Operation: "MapUNIXUserToGeneric",
	}
	return
}

func MakeMapUNIXUserToGeneric[ContextT any](
	delegate func(OSAuthFlags, ContextT, UID) (string, error),
) func(OSAuthFlags, ContextT, UID) (string, error) {
	return func(
		flags OSAuthFlags,
		context ContextT,
		uid UID,
	) (mapped string, err error) {
		theDelegate := delegate
		if theDelegate == nil {
			theDelegate = MapUNIXUserToGeneric[ContextT]
		}
		mapped, err = theDelegate(flags, context, uid)
		return
	}
}

func MapUNIXGroupToGeneric[ContextT any](
	flags OSAuthFlags,
	context ContextT,
	gid GID,
) (mapped string, err error) {
	err = OSOperationUnavailableError {
		Operation: "MapUNIXGroupToGeneric",
	}
	return
}

func MakeMapUNIXGroupToGeneric[ContextT any](
	delegate func(OSAuthFlags, ContextT, GID) (string, error),
) func(OSAuthFlags, ContextT, GID) (string, error) {
	return func(
		flags OSAuthFlags,
		context ContextT,
		gid GID,
	) (mapped string, err error) {
		theDelegate := delegate
		if theDelegate == nil {
			theDelegate = MapUNIXUserToGeneric[ContextT]
		}
		mapped, err = theDelegate(flags, context, gid)
		return
	}
}
