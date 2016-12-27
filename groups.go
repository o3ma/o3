package o3

// Group represents a Threema chat group
type Group struct {
	CreatorID IdString
	GroupID   [8]byte
	Name      string
	Members   []IdString
}
