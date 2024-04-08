package translate

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
)

// type Response struct {
// 	Code   int    `json:"code"`
// 	Msg    string `json:"msg"`
// 	Result Result `json:"result"`
// }

// type Result struct {
// 	SourceText string `json:"sourceText"`
// 	TargetText string `json:"targetText"`
// 	Source     string `json:"source"`
// 	Target     string `json:"target"`
// }

// func ENUS2ZHCN(src string) string {
// 	// Remove line breaks
// 	// src = strings.ReplaceAll(src, "\n", "")
// 	// src = strings.ReplaceAll(src, "\r", "")
// 	srcs := strings.Split(src, ". ")
// 	dsts := []string{}
// 	for _, s := range srcs {
// 		url := "http://api.oioweb.cn/api/txt/QQFanyi?sourceText=" + url.QueryEscape(s+".")
// 		resp, err := http.Get(url)

// 		if err != nil {
// 			dsts = append(dsts, s)
// 			continue
// 		}
// 		defer resp.Body.Close()

// 		var response Response
// 		body, err := io.ReadAll(resp.Body)
// 		if err != nil {
// 			dsts = append(dsts, s)
// 			continue
// 		}

// 		err = json.Unmarshal(body, &response)
// 		if err != nil {
// 			dsts = append(dsts, s)
// 			continue
// 		}

// 		if response.Code != 200 {
// 			dsts = append(dsts, s)
// 			continue
// 		}

// 		dsts = append(dsts, response.Result.TargetText)
// 	}
// 	return strings.Join(dsts, "")
// }

type Model_specification struct {
}

type Model_tracking struct {
	Checkpoint_md5 string `json:"checkpoint_md5"`
	Launch_doc     string `json:"launch_doc"`
}

type Translation_engine_debug_info struct {
	Model_tracking Model_tracking `json:"model_tracking"`
}

type Sentence struct {
	Trans                         string                          `json:"trans"`
	Orig                          string                          `json:"orig"`
	Backend                       int                             `json:"backend"`
	Model_specification           []Model_specification           `json:"model_specification"`
	Translation_engine_debug_info []Translation_engine_debug_info `json:"translation_engine_debug_info"`
}

type Spell struct {
}

type Ld_result struct {
	Srclangs             []string  `json:"srclangs"`
	Srclangs_confidences []float64 `json:"srclangs_confidences"`
	Extended_srclangs    []string  `json:"extended_srclangs"`
}

type Response struct {
	Sentences  []Sentence `json:"sentences"`
	Src        string     `json:"src"`
	Confidence float64    `json:"confidence"`
	Spell      Spell      `json:"spell"`
	Ld_result  Ld_result  `json:"ld_result"`
}

func ENUS2ZHCN(src string) string {
	proxyURL, _ := url.Parse("http://localhost:10809")
	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
	}

	client := &http.Client{
		Transport: transport,
	}

	resp, err := client.Get("http://translate.google.com/translate_a/single?client=gtx&dt=t&dj=1&ie=UTF-8&sl=auto&tl=zh-CN&q=" + url.QueryEscape(src))

	if err != nil {
		return src
	}
	defer resp.Body.Close()

	var response Response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return src
	}

	err = json.Unmarshal(body, &response)
	if err != nil {
		return src
	}

	dst := ""
	for _, sentence := range response.Sentences {
		dst += sentence.Trans
	}

	return dst
}
