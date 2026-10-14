package outbound

// Do not derive authentication validity from untrusted message text (even a
// familiar phrase). Status and numeric business code are evidence, not a verdict.
func blackstoneAdmissionError(status int, response map[string]any, stage string) error {
	return &blackstoneFailure{stage: stage, last: "response_read", causeClass: "unclassified", status: status, business: blackstoneNumericCode(response)}
}
