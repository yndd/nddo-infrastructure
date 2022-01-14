package speedyhandler

// Option can be used to manipulate Options.
type Option func(Handler)

type Handler interface {
	Init(string)
	Delete(string)
	ResetSpeedy(string)
	GetSpeedy(crName string) int
	IncrementSpeedy(crName string)
}
