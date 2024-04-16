// +build aix android darwin dragonfly freebsd hurd illumos ios linux netbsd openbsd solaris

package goauth

import (
	"strconv"
)

func MapUNIXUserToGeneric[ContextT any](
	flags OSAuthFlags,
	context ContextT,
	uid UID,
) (mapped string, err error) {
	mapped = strconv.FormatUint(uint64(uid), 10)
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
		if theDelegate == nil || (flags & UXAUTHFL_IGNORE_USER_MAPPER_ON_UNIX) != 0 {
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
	mapped = strconv.FormatUint(uint64(gid), 10)
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
		if theDelegate == nil || (flags & UXAUTHFL_IGNORE_USER_MAPPER_ON_UNIX) != 0 {
			theDelegate = MapUNIXGroupToGeneric[ContextT]
		}
		mapped, err = theDelegate(flags, context, gid)
		return
	}
}
