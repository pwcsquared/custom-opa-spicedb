package builtins

import (
	"errors"
	authzedpb "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/types"
	"github.com/pwcsquared/custom-opa-spicedb/plugins/authzed"
        "github.com/thoas/go-funk"
	"strings"
)

var lookupResourcesBuiltinDecl = &rego.Function{
	Name: "authzed.lookup_resources",
	Decl: types.NewFunction(
		types.Args(types.S, types.S, types.S), // resource_type, permission, subject
		types.B),                              // Returns a set?
}

// lookupResourcesBuiltinImpl checks the given permission requests against spicedb.
func lookupResourcesBuiltinImpl(bctx rego.BuiltinContext, resourceTerm, permissionTerm, subjectTerm *ast.Term) (*ast.Term, error) {

	// repository
	var resourceType string
	if err := ast.As(resourceTerm.Value, &resourceType); err != nil {
		return nil, err
	}

	// clone
	var permission string
	if err := ast.As(permissionTerm.Value, &permission); err != nil {
		return nil, err
	}

	// user:jake#...
	var subject string
	if err := ast.As(subjectTerm.Value, &subject); err != nil {
		return nil, err
	}

	objectType, objectId, subjectFound := strings.Cut(subject, ":")
	if !subjectFound {
		return nil, errors.New("could not parse authzdb subject")
	}

	subjectReference := &authzedpb.SubjectReference{Object: &authzedpb.ObjectReference{
		ObjectType: objectType,
		ObjectId:   objectId,
	}}

	client := authzed.GetAuthzedClient()
	if client == nil {
		return nil, errors.New("authzed client not configured")
	}

	resp, err := client.LookupResources(bctx.Context, &authzedpb.LookupResourcesRequest{
		ResourceObjectType: resourceType,
		Permission: permission,
		Subject: subjectReference,
	})

	if err != nil {
		return nil, err
	}

        // for each resp, acc resource_object_id
        ids := funk.Map(resp, func(r authzedpb.LookupResourcesResponse) string {
                return r.ResourceObjectId
        })

        result, idsErr := ast.InterfaceToValue(ids)

        if idsErr != nil { 
                return nil, idsErr
        }

	return ast.NewTerm(result), nil
}
