package convert

import (
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

type NVT struct {
	gorm.Model
	OID            string `gorm:"unique"`
	Name           string
	NameCN         string
	Family         string
	FamilyCN       string
	CVSSBase       float64
	CVSSBaseVector string
	Summary        string
	SummaryCN      string
	Insight        string
	InsightCN      string
	Affected       string
	AffectedCN     string
	Impact         string
	ImpactCN       string
	Solution       string
	SolutionCN     string
	SolutionType   string
	SolutionTypeCN string
	VulDetect      string
	VulDetectCN    string
	Refs           string
}

type Host struct {
	gorm.Model
	AssetID string `gorm:"unique"`
	IP      string
	Start   string
	End     string
}

type Result struct {
	gorm.Model
	ResultID      string `gorm:"unique"`
	OID           string
	AssetID       string
	Port          string
	Detection     string
	Threat        string
	Severity      float64
	Description   string
	DescriptionCN string
}

func initDB() (*gorm.DB, error) {
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	// db, err := gorm.Open(sqlite.Open("tmp.db"), &gorm.Config{})
	if err != nil {
		return nil, err
	}

	db.AutoMigrate(&NVT{})
	db.AutoMigrate(&Host{})
	db.AutoMigrate(&Result{})

	return db, nil
}
