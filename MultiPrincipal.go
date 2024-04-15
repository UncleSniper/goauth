package goauth

type MultiPrincipal struct {
	PrincipalBase
	Principals []Principal
}

func FindPrincipals[WantedT Principal](domain DomainID, root ...Principal) []WantedT {
	var wanted []WantedT
	for _, principal := range root {
		if principal != nil {
			wanted = findPrincipalsRec[WantedT](domain, principal, wanted)
		}
	}
	return wanted
}

func findPrincipalsRec[WantedT Principal](domain DomainID, root Principal, wanted []WantedT) []WantedT {
	if domain == NOWHERE_DOMAIN_ID || root.Domain() == domain {
		cast, isWanted := root.(WantedT)
		if isWanted {
			wanted = append(wanted, cast)
		}
	}
	multi, isMulti := root.(*MultiPrincipal)
	if isMulti {
		for _, child := range multi.Principals {
			if child != nil {
				wanted = findPrincipalsRec[WantedT](domain, child, wanted)
			}
		}
	}
	return wanted
}

var _ Principal = &MultiPrincipal{}
