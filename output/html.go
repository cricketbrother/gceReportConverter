package output

import (
	"embed"
	"html/template"
	"log"
	"os"
	"path/filepath"
	"strings"
)

type HTMLReport struct {
	Date            string
	ScanStart       string
	ScanEnd         string
	BaseInfo        BaseInfo
	Results         []Result
	VulHostsResults []VulHostResults
}

type BaseInfo struct {
	Hosts        int64
	VulHosts     int64
	High         int64
	Medium       int64
	Low          int64
	Log          int64
	TotalResults int64
	VulHostsInfo []VulHostInfo
}

func (b *BaseInfo) Total() int64 {
	return b.High + b.Medium + b.Low + b.Log
}

type VulHostInfo struct {
	IP           string
	High         int64
	Medium       int64
	Low          int64
	Log          int64
	TotalResults int64
}

func (h *VulHostInfo) Total() int64 {
	return h.High + h.Medium + h.Low + h.Log
}

type Result struct {
	ResultID       string
	NameCN         string
	IP             string
	Port           string
	Threat         string
	Severity       string
	SolutionTypeCN string
	SolutionCN     string
	SummaryCN      string
	FamilyCN       string
	InsightCN      string
	AffectedCN     string
	ImpactCN       string
	CVSSBase       string
	CVSSBaseVector string
	Detection      string
	DescriptionCN  string
	VulDetectCN    string
	Refs           string
}

type VulHostResults struct {
	IP           string
	Start        string
	End          string
	High         int64
	Medium       int64
	Low          int64
	Log          int64
	TotalResults int64
	Results      []Result
}

func (v *VulHostResults) Total() int64 {
	return v.High + v.Medium + v.Low + v.Log
}

func Increase(i int) int {
	return i + 1
}

func ReplaceNewlineChar(s string) template.HTML {
	if s == "" {
		return template.HTML("--")
	}
	return template.HTML(strings.ReplaceAll(s, "\n", "<br>"))
}

func ColorByThreat(threat string) string {
	switch threat {
	case "高":
		return "bg-danger"
	case "中":
		return "bg-warning"
	case "低":
		return "bg-info"
	case "信息":
		return "bg-secondary"
	default:
		return ""
	}
}

func SetRefsLink(refs string) template.HTML {
	if refs == "" {
		return template.HTML("--")
	}

	var refLinks []string
	for _, ref := range strings.Split(refs, "\n") {
		if strings.HasPrefix(ref, "http") {
			refLinks = append(refLinks, "<a href=\""+ref+"\" target=\"_blank\" rel=\"noopener\" class=\"text-break\">"+ref+"</a>")
		} else {
			refLinks = append(refLinks, ref)
		}
	}

	return template.HTML(strings.Join(refLinks, "<br>"))
}

//go:embed template*.html
var tmplFS embed.FS

func createHTMLReport(p string, t string, d any) error {
	tmpl := template.New("report").
		Funcs(template.FuncMap{"Increase": Increase}).
		Funcs(template.FuncMap{"ReplaceNewlineChar": ReplaceNewlineChar}).
		Funcs(template.FuncMap{"ColorByThreat": ColorByThreat}).
		Funcs(template.FuncMap{"SetRefsLink": SetRefsLink})

	tmplContent, err := tmplFS.ReadFile(t)
	if err != nil {
		return err
	}

	tmpl, err = tmpl.Parse(string(tmplContent))
	if err != nil {
		return err
	}

	file, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}

	err = tmpl.Execute(file, d)
	if err != nil {
		return err
	}

	return nil
}

func CreateHTMLReport(path string, data *HTMLReport) error {
	hostReportDir := filepath.Join(filepath.Dir(path), "host")
	err := os.MkdirAll(hostReportDir, 0755)
	if err != nil {
		return err
	}

	for _, vulHostResults := range data.VulHostsResults {
		log.Printf("Creating HTML report for host %s\n", vulHostResults.IP)
		hostReportPath := filepath.Join(hostReportDir, vulHostResults.IP+".html")
		err := createHTMLReport(hostReportPath, "template1.html", vulHostResults)
		if err != nil {
			log.Printf("Failed to create HTML report for host %s\n", vulHostResults.IP)
			return err
		}
		log.Printf("HTML report for host %s created successfully\n", vulHostResults.IP)
	}

	log.Println("Creating HTML report for the whole scan")
	err = createHTMLReport(path, "template2.html", data)
	if err != nil {
		log.Println("Failed to create HTML report for the whole scan")
		return err
	}
	log.Println("HTML report for the whole scan created successfully")

	return nil
}
