package input

import "github.com/beevik/etree"

func ReadXMLFile(path string) (*etree.Document, error) {
	doc := etree.NewDocument()
	if err := doc.ReadFromFile(path); err != nil {
		return nil, err
	}
	return doc, nil
}
