package o3

// Group represents a Threema chat group
type Group struct {
	CreatorID IDString
	GroupID   [8]byte
	Name      string
	Members   []IDString
}
