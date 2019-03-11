package policy

import (
	"regexp"
	"strings"

	"github.com/pkg/errors"
)

var (
	replacer = strings.NewReplacer(".*", ".*", "*", ".*")
)

// Assertion represents the refined assertion data use in policy checking
type Assertion struct {
	Reg            *regexp.Regexp
	ResourceDomain string
	Effect         error
}

// NewAssertion returns the Assertion object or error
func NewAssertion(action, resource, effect string) (*Assertion, error) {
	domres := strings.SplitN(resource, ":", 2)
	if len(domres) < 2 {
		return nil, errors.Wrap(ErrInvalidPolicyResource, "assestion format not correct")
	}

	reg, err := regexp.Compile("^" + replacer.Replace(strings.ToLower(action+"-"+domres[1])) + "$")
	if err != nil {
		return nil, errors.Wrap(err, "assestion format not correct")
	}

	return &Assertion{
		ResourceDomain: domres[0],
		Reg:            reg,
		Effect: func() error {
			if strings.EqualFold("deny", effect) {
				return errors.Wrap(ErrDenyByPolicy, "policy deny")
			}
			return nil
		}(),
	}, nil
}
