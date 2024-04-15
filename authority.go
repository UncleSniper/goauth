package goauth

import (
	"sync"
)

type ProtoID uint32

const UNKNOWN_PROTO_ID ProtoID = 0
const UNKNOWN_PROTO_NAME string = "unknown"

var name2protoID map[string]ProtoID
var protoID2name []string
var protoIDLock sync.Mutex

func initProtos() {
	name2protoID = make(map[string]ProtoID)
	name2protoID[UNKNOWN_PROTO_NAME] = 0
	protoID2name = []string {
		UNKNOWN_PROTO_NAME,
	}
}

func InternProtocol(name string) ProtoID {
	protoIDLock.Lock()
	if name2protoID == nil {
		initProtos()
	}
	id, ok := name2protoID[name]
	if !ok {
		id = ProtoID(len(protoID2name))
		name2protoID[name] = id
		protoID2name = append(protoID2name, name)
	}
	protoIDLock.Unlock()
	return id
}

func ProtocolName(id ProtoID) (name string, ok bool) {
	protoIDLock.Lock()
	if name2protoID == nil {
		initProtos()
	}
	if id < ProtoID(len(protoID2name)) {
		name = protoID2name[id]
		ok = true
	}
	protoIDLock.Unlock()
	return
}

type DomainID uint32

const NOWHERE_DOMAIN_ID DomainID = 0
const NOWHERE_DOMAIN_NAME string = "nowhere"

var name2domainID map[string]DomainID
var domainID2name []string
var domainIDLock sync.Mutex

func initDomains() {
	name2domainID = make(map[string]DomainID)
	name2domainID[NOWHERE_DOMAIN_NAME] = 0
	domainID2name = []string {
		NOWHERE_DOMAIN_NAME,
	}
}

func InternDomain(name string) DomainID {
	domainIDLock.Lock()
	if name2domainID == nil {
		initDomains()
	}
	id, ok := name2domainID[name]
	if !ok {
		id = DomainID(len(domainID2name))
		name2domainID[name] = id
		domainID2name = append(domainID2name, name)
	}
	domainIDLock.Unlock()
	return id
}

func DomainName(id DomainID) (name string, ok bool) {
	domainIDLock.Lock()
	if name2domainID == nil {
		initDomains()
	}
	if id < DomainID(len(domainID2name)) {
		name = domainID2name[id]
		ok = true
	}
	domainIDLock.Unlock()
	return
}
