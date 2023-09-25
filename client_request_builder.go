package gpbclient

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io/ioutil"
	"net/http"
	"regexp"

	"github.com/sirupsen/logrus"
)

// Request Builder
type gpbRB struct {
	client *http.Client
	logger logrus.FieldLogger
	req    *http.Request
	body   []byte
	Error  error
}

func (rb *gpbRB) Get(url string) *gpbRB {
	return rb.runIfNoError(func() error {
		rb.logger.Printf("GPB. Get: url=%s", url)

		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			rb.logger.Error("GPB. Request not created")
			return err
		}

		rb.req = req
		return nil
	})
}

func (rb *gpbRB) Post(url string) *gpbRB {
	return rb.runIfNoError(func() error {
		rb.logger.Printf("GPB. Post: url=%s", url)

		req, err := http.NewRequest("POST", url, nil)
		if err != nil {
			rb.logger.Error("GPB. Request not created")
			return err
		}

		rb.req = req
		return nil
	})
}

func (rb *gpbRB) PostJson(url string, jsonBody map[string]interface{}) *gpbRB {
	return rb.runIfNoError(func() error {
		jsonValue, err := json.Marshal(jsonBody)
		if err != nil {
			rb.logger.Error("GPB. Body is not JSON")
			return err
		}

		rb.logger.Printf("GPB. PostJson: url=%s, body=%s", url, rb.maskBody(string(jsonValue)))

		req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonValue))
		if err != nil {
			rb.logger.Error("GPB. Request not created")
			return err
		}

		req.Header.Add("Content-Type", "application/json")
		rb.req = req

		return nil
	})
}

func (rb *gpbRB) SetBasicAuth(username, password string) *gpbRB {
	return rb.runIfNoError(func() error {
		if rb.req == nil {
			return errors.New("No request")
		}

		rb.req.SetBasicAuth(username, password)

		return nil
	})
}

func (rb *gpbRB) Send() *gpbRB {
	return rb.runIfNoError(func() error {
		if rb.req == nil {
			return errors.New("No request")
		}

		res, err := rb.client.Do(rb.req)
		if err != nil {
			rb.logger.Error("GPB. Request send failed")
			return err
		}
		defer res.Body.Close()

		body, err := ioutil.ReadAll(res.Body)
		if err != nil {
			rb.logger.Error("GPB. Read response failed")
			return err
		}

		rb.logger.Printf("GPB. Response: statusCode=%d, body=%s", res.StatusCode, string(body))

		if res.StatusCode != http.StatusOK {
			return errors.New("Bad status code")
		}

		rb.body = body

		return nil
	})
}

func (rb *gpbRB) UnmarshalJsonResponse(v interface{}) error {
	rb.runIfNoError(func() error {
		if rb.body == nil {
			return errors.New("Response body not set")
		}

		return json.Unmarshal(rb.body, v)
	})

	return rb.Error
}

func (rb *gpbRB) UnmarshalXmlResponse(v interface{}) error {
	rb.runIfNoError(func() error {
		if rb.body == nil {
			return errors.New("Response body not set")
		}

		return xml.Unmarshal(rb.body, v)
	})

	return rb.Error
}

func (rb *gpbRB) runIfNoError(fn func() error) *gpbRB {
	if rb.Error == nil {
		rb.Error = fn()
	}

	return rb
}

func (rb gpbRB) maskBody(data string) string {
	result := regexp.MustCompile(`"pan":"[^"]+([^"]{4})"`).
		ReplaceAllString(data, `"pan":"******$1"`)
	return regexp.MustCompile(`"csc":"([^"]+)"`).
		ReplaceAllString(result, `"csc":"***"`)
}

func NewRequestBuilder(client *http.Client, logger logrus.FieldLogger) *gpbRB {
	return &gpbRB{
		client: client,
		logger: logger,
	}
}
