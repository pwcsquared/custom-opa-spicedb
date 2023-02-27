package builtins

import (
	"github.com/open-policy-agent/opa/rego"
)

func Register() {
	rego.RegisterBuiltin3(checkPermissionBuiltinDecl, checkPermissionBuiltinImpl)
	rego.RegisterBuiltin3(lookupResourcesBuiltinDecl, lookupResourcesBuiltinImpl)
}
