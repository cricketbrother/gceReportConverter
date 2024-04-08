package main

import (
	"fmt"
	"gceReportConverter/convert"
	"log"
	"os"
	"path/filepath"
	"strings"
)

func getAbsPath(file string) string {
	absFile, err := filepath.Abs(file)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	return absFile
}

func main() {
	var xmlFile string
	var htmlFile string
	var absXmlFile string
	var absHtmlFile string
	if len(os.Args) < 2 {
		fmt.Println("Usage: gceReportConverter <path/to/input.xml> <path/to/output/dir>")
		os.Exit(1)
	} else if len(os.Args) == 2 {
		xmlFile = os.Args[1]
		htmlFile = filepath.Join(filepath.Dir(xmlFile), "report", strings.TrimSuffix(filepath.Base(xmlFile), ".xml")+".html")
	} else {
		xmlFile = os.Args[1]
		htmlFile = filepath.Join(os.Args[2], strings.TrimSuffix(filepath.Base(xmlFile), ".xml")+".html")
	}
	if !strings.HasSuffix(xmlFile, ".xml") {
		log.Println("Input file must be an XML file.")
		os.Exit(1)
	}
	if _, err := os.Stat(xmlFile); os.IsNotExist(err) {
		log.Println("Input file does not exist.")
		os.Exit(1)
	}

	absXmlFile = getAbsPath(xmlFile)
	absHtmlFile = getAbsPath(htmlFile)
	log.Println("Src file: ", absXmlFile)
	log.Println("Dst file: ", absHtmlFile)

	log.Println("Converting XML to HTML...")
	err := convert.ConvertXMLToHTML(absXmlFile, absHtmlFile)
	if err != nil {
		log.Println(err)
	}
	log.Println("Conversion successful!")
}
