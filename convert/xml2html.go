package convert

import (
	"gceReportConverter/input"
	"gceReportConverter/output"
	"gceReportConverter/translate"
	"html"
	"strconv"
	"strings"
	"time"

	"github.com/dlclark/regexp2"

	"github.com/beevik/etree"
)

func time2beijing(s string) string {
	var t time.Time
	if strings.HasSuffix(s, "Z") {
		t, _ = time.Parse("2006-01-02T15:04:05Z", s)
	} else {
		t, _ = time.Parse("2006-01-02T15:04:05-07:00", s)
	}

	loc, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		loc = time.FixedZone("CST", 8*60*60)
	}

	return t.In(loc).Format("2006-01-02 15:04:05")
}

func fixTextFormat(text string) string {
	r1 := regexp2.MustCompile(`(?<!\n)\n(?!\n)(\s+)`, 0)
	text, _ = r1.Replace(text, " ", -1, -1)

	r2 := regexp2.MustCompile(`\n(\s*)\n(\s+)`, 0)
	text, _ = r2.Replace(text, "<br>", -1, -1)

	return text
}

func getTag(tags, key string) string {
	tags = fixTextFormat(html.EscapeString(tags))
	for _, tag := range strings.Split(tags, "|") {
		if strings.HasPrefix(strings.TrimPrefix(tag, " "), key+"=") {
			return strings.Split(tag, key+"=")[1]
		}
	}
	return ""
}

func translateSolutionType(solutionType string) string {
	switch solutionType {
	case "Workaround":
		return "解决方案"
	case "Mitigation":
		return "缓解措施"
	case "VendorFix":
		return "厂商补丁"
	case "NoneAvailable":
		return "无可用解决方案"
	case "WillNotFix":
		return "不会修复"
	default:
		return "未知"
	}
}

func parseDetection(detection *etree.Element) string {
	if detection == nil {
		return ""
	}

	var detectionDetails []string
	for _, detail := range detection.SelectElement("result").SelectElement("details").SelectElements("detail") {
		detectionDetails = append(detectionDetails, translateDetectionDetailName(detail.SelectElement("name").Text())+": "+detail.SelectElement("value").Text())
	}
	return strings.Join(detectionDetails, "\n")
}

func translateDetectionDetailName(name string) string {
	switch name {
	case "product":
		return "产品"
	case "location":
		return "位置"
	case "source_oid":
		return "来源OID"
	case "source_name":
		return "来源名称"
	default:
		return name
	}
}

func translateThreat(threat string) string {
	switch threat {
	case "Log":
		return "信息"
	case "Low":
		return "低"
	case "Medium":
		return "中"
	case "High":
		return "高"
	default:
		return "未知"
	}
}

func parseRefs(refs *etree.Element) string {
	if refs == nil {
		return ""
	}

	var refObjects []string
	for _, ref := range refs.SelectElements("ref") {
		refType := ref.SelectAttrValue("type", "")
		if refType == "url" {
			refObjects = append(refObjects, ref.SelectAttrValue("id", ""))
		} else if refType == "cve" {
			refObjects = append(refObjects, "https://cve.mitre.org/cgi-bin/cvename.cgi?name="+ref.SelectAttrValue("id", ""))
		}
	}
	return strings.Join(refObjects, "\n")
}

func ConvertXMLToHTML(xmlPath string, htmlPath string) error {
	// Read the XML file
	xmlDoc, err := input.ReadXMLFile(xmlPath)
	if err != nil {
		return err
	}

	// Parse the XML file
	db, err := initDB()
	if err != nil {
		return err
	}

	root := xmlDoc.SelectElement("report")

	results := root.SelectElement("report").SelectElement("results").SelectElements("result")
	for _, r := range results {
		tags := r.SelectElement("nvt").SelectElement("tags").Text()

		cvssBase, _ := strconv.ParseFloat(r.SelectElement("nvt").SelectElement("cvss_base").Text(), 64)

		var nvt = &NVT{
			OID:            r.SelectElement("nvt").SelectAttrValue("oid", ""),
			Name:           html.EscapeString(r.SelectElement("nvt").SelectElement("name").Text()),
			Family:         r.SelectElement("nvt").SelectElement("family").Text(),
			CVSSBase:       cvssBase,
			CVSSBaseVector: getTag(tags, "cvss_base_vector"),
			Summary:        html.EscapeString(getTag(tags, "summary")),
			Insight:        html.EscapeString(getTag(tags, "insight")),
			Affected:       html.EscapeString(getTag(tags, "affected")),
			Impact:         html.EscapeString(getTag(tags, "impact")),
			Solution:       html.EscapeString(getTag(tags, "solution")),
			SolutionType:   getTag(tags, "solution_type"),
			SolutionTypeCN: translateSolutionType(getTag(tags, "solution_type")),
			VulDetect:      html.EscapeString(getTag(tags, "vuldetect")),
			Refs:           html.EscapeString(parseRefs(r.SelectElement("nvt").SelectElement("refs"))),
		}

		severity, _ := strconv.ParseFloat(r.SelectElement("severity").Text(), 64)

		var result = &Result{
			ResultID:      r.SelectAttrValue("id", ""),
			OID:           nvt.OID,
			AssetID:       r.SelectElement("host").SelectElement("asset").SelectAttrValue("asset_id", ""),
			Port:          r.SelectElement("port").Text(),
			Detection:     parseDetection(r.SelectElement("detection")),
			Threat:        translateThreat(r.SelectElement("threat").Text()),
			Severity:      severity,
			Description:   fixTextFormat(html.EscapeString(r.SelectElement("description").Text())),
			DescriptionCN: fixTextFormat(html.EscapeString(translate.ENUS2ZHCN(r.SelectElement("description").Text()))),
		}

		db.FirstOrCreate(&nvt, NVT{OID: nvt.OID})
		db.FirstOrCreate(&result, Result{ResultID: result.ResultID})
	}

	hosts := root.SelectElement("report").SelectElements("host")
	for _, h := range hosts {
		var host = &Host{
			AssetID: h.SelectElement("asset").SelectAttrValue("asset_id", ""),
			IP:      h.SelectElement("ip").Text(),
			Start:   time2beijing(h.SelectElement("start").Text()),
			End:     time2beijing(h.SelectElement("end").Text()),
		}

		db.FirstOrCreate(&host, Host{AssetID: host.AssetID})
	}

	nvts := []NVT{}
	db.Find(&nvts)
	for _, nvt := range nvts {
		nvt.NameCN = translate.ENUS2ZHCN(nvt.Name)
		nvt.FamilyCN = translate.ENUS2ZHCN(nvt.Family)
		nvt.SummaryCN = translate.ENUS2ZHCN(nvt.Summary)
		nvt.InsightCN = translate.ENUS2ZHCN(nvt.Insight)
		nvt.AffectedCN = translate.ENUS2ZHCN(nvt.Affected)
		nvt.ImpactCN = translate.ENUS2ZHCN(nvt.Impact)
		nvt.SolutionCN = translate.ENUS2ZHCN(nvt.Solution)
		nvt.VulDetectCN = translate.ENUS2ZHCN(nvt.VulDetect)
		db.Save(&nvt)
	}

	var htmlReport = &output.HTMLReport{
		Date:      time2beijing(root.SelectElement("creation_time").Text()),
		ScanStart: time2beijing(root.SelectElement("report").SelectElement("scan_start").Text()),
		ScanEnd:   time2beijing(root.SelectElement("report").SelectElement("scan_end").Text()),
	}

	htmlReport.BaseInfo.Hosts = db.Find(&[]Host{}).RowsAffected
	db.Model(&Result{}).Select("asset_id").Group("asset_id").Count(&htmlReport.BaseInfo.VulHosts)
	db.Model(&Result{}).Where("threat = ?", "高").Count(&htmlReport.BaseInfo.High)
	db.Model(&Result{}).Where("threat = ?", "中").Count(&htmlReport.BaseInfo.Medium)
	db.Model(&Result{}).Where("threat = ?", "低").Count(&htmlReport.BaseInfo.Low)
	db.Model(&Result{}).Where("threat = ?", "信息").Count(&htmlReport.BaseInfo.Log)
	htmlReport.BaseInfo.TotalResults = htmlReport.BaseInfo.Total()

	db.Table("hosts").
		Select("ip, sum(case when threat = '高' then 1 else 0 end) as high, sum(case when threat = '中' then 1 else 0 end) as medium, sum(case when threat = '低' then 1 else 0 end) as low, sum(case when threat = '信息' then 1 else 0 end) as log, count(*) as total_results").
		Joins("JOIN results ON hosts.asset_id = results.asset_id").
		Group("hosts.ip").
		Order("high desc, medium desc, low desc, log desc").
		Scan(&htmlReport.BaseInfo.VulHostsInfo)

	db.Table("nvts").
		Select("results.result_id, nvts.name_cn, hosts.ip, results.port, results.threat, cast(results.severity as text) as severity, nvts.solution_type_cn, nvts.solution_cn, nvts.summary_cn, nvts.family_cn, nvts.insight_cn, nvts.affected_cn, nvts.impact_cn, nvts.cvss_base, nvts.cvss_base_vector, results.detection, results.description_cn, nvts.vul_detect_cn, nvts.refs").
		Joins("JOIN results ON nvts.o_id = results.o_id").
		Joins("JOIN hosts ON results.asset_id = hosts.asset_id").
		Order("results.severity desc, nvts.name_cn asc, hosts.ip asc, results.port asc").
		Scan(&htmlReport.Results)

	var vulHostIPs []string
	db.Table("results").Select("hosts.ip").Joins("JOIN hosts ON hosts.asset_id = results.asset_id").Group("hosts.ip").Scan(&vulHostIPs)
	for _, ip := range vulHostIPs {
		var vulHostResults = &output.VulHostResults{
			IP: ip,
		}
		db.Table("hosts").Select("start").Where("ip = ?", ip).Scan(&vulHostResults.Start)
		db.Table("hosts").Select("end").Where("ip = ?", ip).Scan(&vulHostResults.End)
		db.Model(&Result{}).Where("threat = ?", "高").Joins("JOIN hosts ON results.asset_id = hosts.asset_id").Where("hosts.ip = ?", ip).Count(&vulHostResults.High)
		db.Model(&Result{}).Where("threat = ?", "中").Joins("JOIN hosts ON results.asset_id = hosts.asset_id").Where("hosts.ip = ?", ip).Count(&vulHostResults.Medium)
		db.Model(&Result{}).Where("threat = ?", "低").Joins("JOIN hosts ON results.asset_id = hosts.asset_id").Where("hosts.ip = ?", ip).Count(&vulHostResults.Low)
		db.Model(&Result{}).Where("threat = ?", "信息").Joins("JOIN hosts ON results.asset_id = hosts.asset_id").Where("hosts.ip = ?", ip).Count(&vulHostResults.Log)
		vulHostResults.TotalResults = vulHostResults.Total()
		db.Table("nvts").
			Select("results.result_id, nvts.name_cn, hosts.ip, results.port, results.threat, cast(results.severity as text) as severity, nvts.solution_type_cn, nvts.solution_cn, nvts.summary_cn, nvts.family_cn, nvts.insight_cn, nvts.affected_cn, nvts.impact_cn, nvts.cvss_base, nvts.cvss_base_vector, results.detection, results.description_cn, nvts.vul_detect_cn, nvts.refs").
			Joins("JOIN results ON nvts.o_id = results.o_id").
			Joins("JOIN hosts ON results.asset_id = hosts.asset_id").
			Where("hosts.ip = ?", ip).
			Order("results.severity desc, nvts.name_cn asc, hosts.ip asc, results.port asc").
			Scan(&vulHostResults.Results)

		htmlReport.VulHostsResults = append(htmlReport.VulHostsResults, *vulHostResults)
	}

	err = output.CreateHTMLReport(htmlPath, htmlReport)
	if err != nil {
		return err
	}
	return nil
}
