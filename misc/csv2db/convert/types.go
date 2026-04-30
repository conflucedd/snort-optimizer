package convert

import (
	"math"
	"strconv"
)

type ColumnType int

const (
	ColInteger ColumnType = iota
	ColReal
	ColText
)

type ColumnInfo struct {
	Name string
	Type ColumnType
}

func inferTypes(cols []string, rows [][]string) []ColumnInfo {
	infos := make([]ColumnInfo, len(cols))
	for ci, name := range cols {
		infos[ci] = ColumnInfo{Name: name, Type: inferColumn(ci, rows)}
	}
	return infos
}

func inferColumn(ci int, rows [][]string) ColumnType {
	allInt := true
	allFloat := true
	for _, row := range rows {
		v := row[ci]
		if v == "" {
			continue
		}
		if _, err := strconv.ParseInt(v, 10, 64); err != nil {
			allInt = false
		}
		if _, err := strconv.ParseFloat(v, 64); err != nil {
			allFloat = false
			break
		}
	}
	if allInt {
		return ColInteger
	}
	if allFloat {
		return ColReal
	}
	return ColText
}

func colTypeSQL(t ColumnType) string {
	switch t {
	case ColInteger:
		return "INTEGER"
	case ColReal:
		return "REAL"
	default:
		return "TEXT"
	}
}

func convertValue(v string, t ColumnType) (any, error) {
	switch t {
	case ColInteger:
		if v == "" {
			return nil, nil
		}
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return nil, err
		}
		return n, nil
	case ColReal:
		if v == "" {
			return nil, nil
		}
		f, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return nil, err
		}
		if math.IsInf(f, 0) {
			return nil, nil
		}
		return f, nil
	default:
		return v, nil
	}
}
