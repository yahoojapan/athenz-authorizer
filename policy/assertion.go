package policy

import (
	"regexp"
	"strings"

	"github.com/pkg/errors"
)

var (
	replacer = strings.NewReplacer(".*", ".*", "*", ".*")
)

type Assertion struct {
	// Action         *regexp.Regexp
	// Resource       *regexp.Regexp
	Reg            *regexp.Regexp
	ResourceDomain string
	Effect         error
}

func NewAssertion(action, resource, effect string) (*Assertion, error) {
	domres := strings.SplitN(resource, ":", 2)
	if len(domres) < 2 {
		return nil, errors.Wrap(ErrInvalidPolicyResource, "assestion format not correct")
	}

	// actReg, err := regexp.Compile("^" + replacer.Replace(strings.ToLower(action)) + "$")
	// if err != nil {
	// 	return nil, errors.Wrap(err, "assestion format not correct")
	// }
	//
	// resReg, err := regexp.Compile("^" + replacer.Replace(strings.ToLower(domres[1])) + "$")
	// if err != nil {
	// 	return nil, errors.Wrap(err, "assestion format not correct")
	// }
	reg, err := regexp.Compile("^" + replacer.Replace(strings.ToLower(action+"-"+domres[1])) + "$")
	if err != nil {
		return nil, errors.Wrap(err, "assestion format not correct")
	}

	return &Assertion{
		// Action:         actReg,
		ResourceDomain: domres[0],
		Reg:            reg,
		// Resource:       resReg,
		Effect: func() error {
			if strings.EqualFold("deny", effect) {
				return errors.Wrap(ErrDenyByPolicy, "policy deny")
			}
			return nil
		}(),
	}, nil
}
