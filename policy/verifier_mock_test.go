package policy

type VerifierMock struct {
	VerifyFunc func(i, s string) error
}

func (vm VerifierMock) Verify(input, signature string) error {
	return vm.VerifyFunc(input, signature)
}
