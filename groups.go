package o3

import (
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

// Group represents a Threema chat group
type Group struct {
	GroupID   [8]byte
	CreatorID IDString
	Name      string
	createdAt time.Time
	Members   []IDString
	deleted   bool
}

// GroupDirectory stores all known groups in a single, easily serialized and unserialized structure
type GroupDirectory struct {
	groups []Group
}

func isIDinGroup(group Group, id IDString) (int, bool) {
	for i, member := range group.Members {
		if member == id {
			return i, true
		}
	}
	return -1, false
}

// Upsert ads a group to the GroupDirectory or updates non zero values if it is already in the directory
func (gd *GroupDirectory) Upsert(group Group) {
	// make sure the group creator is in the member list
	_, creatorInGroup := isIDinGroup(group, group.CreatorID)
	if !creatorInGroup {
		group.Members = append(group.Members, group.CreatorID)
	}
	for _, groupInDir := range gd.groups {
		if (groupInDir.CreatorID == group.CreatorID) && (groupInDir.GroupID == group.GroupID) {
			if group.Members != nil {
				groupInDir.Members = group.Members
			}
			if group.Name != "" {
				groupInDir.Name = group.Name
			}
		}
	}
	gd.groups = append(gd.groups, group)
}

// Get returns the group identified by the (creatorID, groupID) tuple
// ok is false if no such group is in the directory
func (gd *GroupDirectory) Get(creatorID IDString, groupID [8]byte) (Group, bool) {
	for _, groupInDir := range gd.groups {
		if (groupInDir.CreatorID == creatorID) && (groupInDir.GroupID == groupID) {
			return groupInDir, true
		}
	}
	return Group{}, false
}

// SaveToFile stores a GroupDirectory in a Threema-compatible CSV format as contained in a backup from the app
func (gd *GroupDirectory) SaveToFile(filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writeCSV(file, gd.slice())

	return nil
}

// LoadFromFile will import a GroupDirectory from either a groups.csv file extracted
// from a Threema app backup, or one created by SaveToFile()
func (gd *GroupDirectory) LoadFromFile(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	r := csv.NewReader(file)
	lines, err := r.ReadAll()
	if err != nil {
		return err
	}
	return gd.importGroups(lines)
}

// encoding/csv doesn't do it for witing because we can't force it to put quotes around every field
func writeCSV(w io.Writer, data [][]string) {
	for _, row := range data {
		sep := ""
		for _, cell := range row {
			fmt.Fprintf(w, `%s"%s"`, sep, strings.Replace(cell, `"`, `""`, -1))
			sep = ","
		}
		fmt.Fprintf(w, "\n")
	}
}

func (gd *GroupDirectory) slice() [][]string {
	buf := make([][]string, len(gd.groups))

	i := 0
	for _, g := range gd.groups {
		buf[i] = make([]string, 6)
		buf[i][0] = hex.EncodeToString(g.GroupID[:])
		buf[i][1] = string(g.CreatorID[:])
		buf[i][2] = g.Name
		buf[i][3] = strconv.FormatInt(g.createdAt.Unix(), 10)
		idstrs := make([]string, len(g.Members))
		for y := range g.Members {
			idstrs[y] = g.Members[y].String()
		}
		buf[i][4] = strings.Join(idstrs, ";")
		if g.deleted {
			buf[i][5] = "1"
		} else {
			buf[i][5] = "0"
		}
		i++
	}
	return buf
}

func (gd *GroupDirectory) importGroups(groups [][]string) error {
	gd.groups = make([]Group, len(groups))

	for i, c := range groups {
		g := Group{}
		id, err := readGroupID(stripQuotes(c[0]))
		if err != nil {
			return err
		}
		g.GroupID = id
		g.CreatorID = NewIDString(stripQuotes(c[1]))
		g.Name = stripQuotes(c[2])
		g.createdAt, err = readTime(stripQuotes(c[3]))
		if err != nil {
			return err
		}
		g.Members = readMembers(stripQuotes(c[4]))
		g.deleted = readDeleted(stripQuotes(c[5]))

		gd.groups[i] = g
	}
	return nil
}

func stripQuotes(s string) string {
	return strings.Replace(s, "\"", "", -1)
}

func readGroupID(g string) ([8]byte, error) {
	var buf [8]byte
	b, err := hex.DecodeString(stripQuotes(g))
	if err != nil {
		return buf, err
	}
	if len(b) == 8 {
		copy(buf[:8], b)
	} else {
		return buf, fmt.Errorf("could not parse group id %s", g)
	}
	return buf, nil
}

func readMembers(m string) []IDString {
	m = stripQuotes(m)
	ids := strings.Split(m, ";")
	buf := make([]IDString, len(ids))
	for i, v := range ids {
		buf[i] = NewIDString(v)
	}
	return buf
}

func readTime(t string) (time.Time, error) {

	i, err := strconv.ParseInt(stripQuotes(t), 10, 64)
	if err != nil {
		return time.Unix(0, 0), err
	}
	return time.Unix(i, 0), nil
}

func readDeleted(d string) bool {
	s := stripQuotes(d)
	if s == "0" {
		return false
	}
	return true
}
