package drift

type Policy struct {
	FailOnDrift  bool
	AllowExtra   bool
	AllowMissing bool
	AllowReorder bool
}
