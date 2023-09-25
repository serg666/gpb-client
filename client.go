package gpbclient

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"github.com/sirupsen/logrus"
)

type gpbSbpData struct {
	QrcId   *string `json:"qrcId"`
	Payload *string `json:"payload"`
}

type gpbSbpResponse struct {
	Code    string      `json:"code"`
	Message string      `json:"message"`
	TrxId   *string     `json:"transactionId"`
	Data    *gpbSbpData `json:"data"`
}

type gpbSbpRefundResponse struct {
	Code    string  `json:"code"`
	Message string  `json:"message"`
	TrxId   *string `json:"transactionId"`
}

type gpbSbpStatusData struct {
	QrcId   string  `json:"qrcId"`
	Code    string  `json:"code"`
	Message string  `json:"message"`
	Status  *string `json:"status"`
	TrxId   *string `json:"trxId"`
}

type gpbSbpStatusResponse struct {
	Code    string               `json:"code"`
	Message string               `json:"message"`
	TrxId   *string              `json:"transactionId"`
	Data    *[]*gpbSbpStatusData `json:"data"`
}

type gpbStateResponse struct {
	State string `json:"state"`
	Url   string `json:"url"`
	Post  struct {
		ThreeDSMethodData string `json:"threeDSMethodData"`
		TermUrl           string `json:"TermUrl"`
		PaReq             string `json:"PaReq"`
		MD                string `json:"MD"`
		CReq              string `json:"creq"`
	} `json:"post"`
	Result struct {
		Status       string  `json:"status"`
		ExtendedCode string  `json:"extendedCode"`
		ResponceCode *string `json:"responseCode"`
		RRN          *string `json:"rrn"`
		ApprovalCode *string `json:"approvalCode"`
	} `json:"result"`
}

type Refund struct {
	XMLName              xml.Name `xml:"Refund"`
	RRN                  string   `xml:"rrn"`
	AuthCode             string   `xml:"authCode"`
	TransmissionDateTime string   `xml:"transmissionDateTime"`
}

type Result struct {
	XMLName xml.Name `xml:"Result"`
	Code    string   `xml:"code"`
	Desc    string   `xml:"desc"`
	Refund  *Refund  `xml:"Refund"`
}

type RefundResponse struct {
	XMLName xml.Name `xml:"RefundResponse"`
	Version string   `xml:"version"`
	Result  Result   `xml:"Result"`
}

type Message struct {
	XMLName        xml.Name       `xml:"Message"`
	RefundResponse RefundResponse `xml:"RefundResponse"`
}

type gpbRefundResponse struct {
	XMLName xml.Name `xml:"MerchantAPI"`
	Message Message  `xml:"Message"`
}

type GPBClient struct {
	BaseUrl     string
	PayApi      string
	MerchantApi string
	PortalID    string
	MerchantID  string
	Password    string
	Client      *http.Client
}

type GPBSbpClient struct {
	BaseUrl    string
	PrivateKey []byte
	LegalID    string
	MerchantID string
	Password   string
	Account    string
	Client     *http.Client
}

type RefundPrepareSignature struct {
	TrxId                         string `json:"transactionId"`
	Amount                        int    `json:"amount"`
	Currency                      string `json:"currency"`
	Comment                       string `json:"comment"`
	RecipientBankId               string `json:"recipientBankId"`
	CallbackMerchantNotifications string `json:"callbackMerchantNotifications"`
}

type RefundConfirmSignature struct {
	TrxId string `json:"transactionId"`
}

type QrcDataSignature struct {
	Account                       string `json:"account"`
	MerchantId                    string `json:"merchantId"`
	TemplateVersion               string `json:"templateVersion"`
	QrcType                       string `json:"qrcType"`
	Amount                        int    `json:"amount"`
	Currency                      string `json:"currency"`
	PaymentPurpose                string `json:"paymentPurpose"`
	SubscriptionPurpose           string `json:"subscriptionPurpose"`
	RedirectUrl                   string `json:"redirectUrl"`
	CallbackMerchantNotifications string `json:"callbackMerchantNotifications"`
	QrTtl                         string `json:"qrTtl"`
	FraudScore                    string `json:"fraudScore"`
}

type QrcStatusSignature struct {
	QrcIds []string `json:"qrcIds"`
}

func (gpb GPBSbpClient) Refund(
	logger logrus.FieldLogger,
	amount uint,
	currency string,
	trxid string,
) (*gpbSbpRefundResponse, error) {
	url := fmt.Sprintf("%s/merchant/transfer/return/prepare", gpb.BaseUrl)

	jsonBody := map[string]interface{}{
		"transactionId": trxid,
		"amount":        amount,
		"currency":      currency,
	}

	jsonValue, err := json.Marshal(jsonBody)
	if err != nil {
		logger.Errorf("GPB SBP. Refund prepare marshal error: %v", err)
		return nil, err
	}

	var refundPrepareSignature RefundPrepareSignature

	if err := json.Unmarshal(jsonValue, &refundPrepareSignature); err != nil {
		logger.Errorf("GPB SBP. Refund prepare unmarshal error: %v", err)
		return nil, err
	}

	signature, err := gpb.getSignature(
		logger,
		refundPrepareSignature.TrxId,
		refundPrepareSignature.Amount,
		refundPrepareSignature.Currency,
		refundPrepareSignature.Comment,
		refundPrepareSignature.RecipientBankId,
		refundPrepareSignature.CallbackMerchantNotifications,
	)

	if err != nil {
		logger.Errorf("GPB SBP. Refund prepare signature error: %v", err)
		return nil, err
	}

	jsonBody["sign"] = base64.StdEncoding.EncodeToString(signature)

	prepare := &gpbSbpRefundResponse{}
	err = NewRequestBuilder(gpb.Client, logger).
		PostJson(url, jsonBody).
		SetBasicAuth(gpb.LegalID, gpb.Password).
		Send().
		UnmarshalJsonResponse(prepare)

	if err != nil {
		logger.Errorf("GPB SBP. Refund prepare: HTTP-request failed: %v", err)
		return nil, err
	}

	if prepare.Code != "000" {
		return prepare, nil
	}

	url = fmt.Sprintf("%s/merchant/transfer/return/confirm", gpb.BaseUrl)

	jsonBody = map[string]interface{}{
		"transactionId": *prepare.TrxId,
	}

	jsonValue, err = json.Marshal(jsonBody)
	if err != nil {
		logger.Errorf("GPB SBP. Refund confirm marshal error: %v", err)
		return nil, err
	}

	var refundConfirmSignature RefundConfirmSignature

	if err := json.Unmarshal(jsonValue, &refundConfirmSignature); err != nil {
		logger.Errorf("GPB SBP. Refund confirm unmarshal error: %v", err)
		return nil, err
	}

	signature, err = gpb.getSignature(logger, refundConfirmSignature.TrxId)

	if err != nil {
		logger.Errorf("GPB SBP. Refund confirm signature error: %v", err)
		return nil, err
	}

	jsonBody["sign"] = base64.StdEncoding.EncodeToString(signature)

	confirm := &gpbSbpRefundResponse{}
	err = NewRequestBuilder(gpb.Client, logger).
		PostJson(url, jsonBody).
		SetBasicAuth(gpb.LegalID, gpb.Password).
		Send().
		UnmarshalJsonResponse(confirm)

	if err != nil {
		logger.Errorf("GPB SBP. Refund confirm: HTTP-request failed: %v", err)
		return nil, err
	}

	return confirm, nil
}

func (gpb GPBSbpClient) QrcStatus(logger logrus.FieldLogger, qrcId string) (*gpbSbpStatusResponse, error) {
	url := fmt.Sprintf("%s/merchant/qrc-status", gpb.BaseUrl)

	jsonBody := map[string]interface{}{
		"qrcIds": [1]string{qrcId},
	}

	jsonValue, err := json.Marshal(jsonBody)
	if err != nil {
		logger.Errorf("GPB SBP. QrcStatus marshal: %v", err)
		return nil, err
	}

	var qrcStatusSignature QrcStatusSignature

	if err := json.Unmarshal(jsonValue, &qrcStatusSignature); err != nil {
		logger.Errorf("GPB SBP. QrcStatus unmarshal: %v", err)
		return nil, err
	}

	var qrcIds string
	for _, qrcId := range qrcStatusSignature.QrcIds {
		qrcIds += fmt.Sprintf("%v", qrcId)
	}

	signature, err := gpb.getSignature(logger, qrcIds)

	if err != nil {
		logger.Errorf("GPB SBP. QrcStatus get signature error: %v", err)
		return nil, err
	}

	jsonBody["sign"] = base64.StdEncoding.EncodeToString(signature)

	result := &gpbSbpStatusResponse{}
	err = NewRequestBuilder(gpb.Client, logger).
		PostJson(url, jsonBody).
		SetBasicAuth(gpb.LegalID, gpb.Password).
		Send().
		UnmarshalJsonResponse(result)

	if err != nil {
		logger.Errorf("GPB SBP. QrcStatus: HTTP-request failed: %v", err)
		return nil, err
	}

	return result, nil
}

func (gpb GPBSbpClient) getSignature(logger logrus.FieldLogger, args ...interface{}) ([]byte, error) {
	var strToBeSigned string

	for _, arg := range args {
		strToBeSigned += fmt.Sprintf("%v", arg)
	}

	logger.Printf("data to be signed: %s", strToBeSigned)

	block, _ := pem.Decode(gpb.PrivateKey)

	if block == nil || block.Type != "RSA PRIVATE KEY" {
		logger.Errorf("GPB SBP. get signature: block: %v type: %v", block, block.Type)
		return nil, errors.New("failed to decode PEM block containing private key")
	}

	pkey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %v", err)
	}

	rng := rand.Reader
	hashed := sha256.Sum256([]byte(strToBeSigned))

	return rsa.SignPKCS1v15(rng, pkey, crypto.SHA256, hashed[:])
}

func (gpb GPBSbpClient) QrcData(logger logrus.FieldLogger, jsonBody map[string]interface{}) (*gpbSbpResponse, error) {
	url := fmt.Sprintf("%s/merchant/qrc-data", gpb.BaseUrl)
	jsonBody["merchantId"] = gpb.MerchantID
	jsonBody["account"] = gpb.Account

	jsonValue, err := json.Marshal(jsonBody)
	if err != nil {
		logger.Errorf("GPB SBP. QrcData marshal: %v", err)
		return nil, err
	}

	var qrcDataSignature QrcDataSignature

	if err := json.Unmarshal(jsonValue, &qrcDataSignature); err != nil {
		logger.Errorf("GPB SBP. QrcData unmarshal: %v", err)
		return nil, err
	}

	signature, err := gpb.getSignature(
		logger,
		qrcDataSignature.Account,
		qrcDataSignature.MerchantId,
		qrcDataSignature.TemplateVersion,
		qrcDataSignature.QrcType,
		qrcDataSignature.Amount,
		qrcDataSignature.Currency,
		qrcDataSignature.PaymentPurpose,
		qrcDataSignature.SubscriptionPurpose,
		qrcDataSignature.RedirectUrl,
		qrcDataSignature.CallbackMerchantNotifications,
		qrcDataSignature.QrTtl,
		qrcDataSignature.FraudScore,
	)

	if err != nil {
		logger.Errorf("GPB SBP. QrcData get signature error: %v", err)
		return nil, err
	}

	jsonBody["sign"] = base64.StdEncoding.EncodeToString(signature)

	result := &gpbSbpResponse{}
	err = NewRequestBuilder(gpb.Client, logger).
		PostJson(url, jsonBody).
		SetBasicAuth(gpb.LegalID, gpb.Password).
		Send().
		UnmarshalJsonResponse(result)

	if err != nil {
		logger.Errorf("GPB SBP. QrcData: HTTP-request failed: %v", err)
		return nil, err
	}

	return result, nil
}

func (gpb GPBClient) Token(logger logrus.FieldLogger) (string, error) {
	var result map[string]interface{}
	err := NewRequestBuilder(gpb.Client, logger).
		Post(fmt.Sprintf("%s%s/%s/token", gpb.BaseUrl, gpb.PayApi, gpb.PortalID)).
		Send().
		UnmarshalJsonResponse(&result)

	if err != nil {
		logger.Errorf("GPB. Token: HTTP-request failed")
		return "", err
	}

	return result["token"].(string), nil
}

func (gpb GPBClient) InitPayment(
	logger logrus.FieldLogger,
	token string,
	jsonBody map[string]interface{},
) (*gpbStateResponse, error) {
	url := fmt.Sprintf("%s%s/%s/payment/%s/start", gpb.BaseUrl, gpb.PayApi, gpb.PortalID, token)
	jsonBody["merchantId"] = gpb.MerchantID

	result := &gpbStateResponse{}
	err := NewRequestBuilder(gpb.Client, logger).
		PostJson(url, jsonBody).
		Send().
		UnmarshalJsonResponse(result)

	if err != nil {
		logger.Errorf("GPB. InitPayment: HTTP-request failed: %v", err)
		return nil, err
	}

	return result, nil
}

func (gpb GPBClient) Accept(
	logger logrus.FieldLogger,
	token string,
	jsonBody map[string]interface{},
) (*gpbStateResponse, error) {
	url := fmt.Sprintf("%s%s/%s/payment/%s/accept", gpb.BaseUrl, gpb.PayApi, gpb.PortalID, token)

	result := &gpbStateResponse{}
	err := NewRequestBuilder(gpb.Client, logger).
		PostJson(url, jsonBody).
		Send().
		UnmarshalJsonResponse(result)

	if err != nil {
		logger.Errorf("GPB. Accept: HTTP-request failed: %v", err)
		return nil, err
	}

	return result, nil
}

func (gpb GPBClient) Accept3ds2Prepare(
	logger logrus.FieldLogger,
	token string,
	jsonBody map[string]interface{},
) (*gpbStateResponse, error) {
	url := fmt.Sprintf("%s%s/%s/payment/%s/3ds2-prepare/accept", gpb.BaseUrl, gpb.PayApi, gpb.PortalID, token)

	result := &gpbStateResponse{}
	err := NewRequestBuilder(gpb.Client, logger).
		PostJson(url, jsonBody).
		Send().
		UnmarshalJsonResponse(result)

	if err != nil {
		logger.Errorf("GPB. Accept3ds2Prepare: HTTP-request failed: %v", err)
		return nil, err
	}

	return result, nil
}

func (gpb GPBClient) MerchantReturn(logger logrus.FieldLogger, token, pares, md string) (*gpbStateResponse, error) {
	u := url.URL{
		Path: fmt.Sprintf("/%s/payment/%s/merchant-return", gpb.PortalID, token),
	}
	q := u.Query()
	q.Set("PaRes", pares)
	q.Set("MD", md)
	u.RawQuery = q.Encode()

	result := &gpbStateResponse{}
	err := NewRequestBuilder(gpb.Client, logger).
		Post(fmt.Sprintf("%s%s%s", gpb.BaseUrl, gpb.PayApi, u.String())).
		Send().
		UnmarshalJsonResponse(result)

	if err != nil {
		logger.Errorf("GPB. MerchantReturn: HTTP-request failed")
		return nil, err
	}

	return result, nil
}

func (gpb GPBClient) Refund(
	logger logrus.FieldLogger,
	amount uint,
	trxid string,
	rrn string,
) (*gpbRefundResponse, error) {
	result := &gpbRefundResponse{}

	u := url.URL{
		Path: "/refund",
	}
	q := u.Query()
	q.Set("trx_id", trxid)
	q.Set("p.rrn", rrn)
	q.Set("amount", strconv.Itoa(int(amount)))
	u.RawQuery = q.Encode()

	err := NewRequestBuilder(gpb.Client, logger).
		Post(fmt.Sprintf("%s%s%s", gpb.BaseUrl, gpb.MerchantApi, u.String())).
		SetBasicAuth(gpb.MerchantID, gpb.Password).
		Send().
		UnmarshalXmlResponse(result)

	if err != nil {
		logger.Errorf("GPB. Refund: HTTP-request failed")
		return nil, err
	}

	return result, nil
}

func (gpb GPBClient) GetState(logger logrus.FieldLogger, token string) (*gpbStateResponse, error) {
	result := &gpbStateResponse{}
	err := NewRequestBuilder(gpb.Client, logger).
		Get(fmt.Sprintf("%s%s/%s/payment/%s", gpb.BaseUrl, gpb.PayApi, gpb.PortalID, token)).
		Send().
		UnmarshalJsonResponse(result)
	if err != nil {
		logger.Errorf("GPB. GetState: HTTP-request failed")
		return nil, err
	}
	return result, nil
}
