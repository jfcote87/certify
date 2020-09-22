// Package certify is a partial implementation of the Certify
// web api (json version)
package certify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/jfcote87/ctxclient"
)

var baseURL = "https://api.certify.com/v1"

// ErrResponse describes the structure of 400-5XX
// responses from Certify
type ErrResponse struct {
	Code  string `json:"errorCode"`
	Value string `json:"errorValue"`
}

// ExpRpt describes certify expense report
type ExpRpt struct {
	ID                         string
	EmployeeDepartment         string
	FirstName                  string
	LastName                   string
	EmployeeID                 string
	NonReimAmount              float64
	ReimAmount                 float64
	TotalAmount                float64
	Currency                   string
	SubmittedDate              string
	InitialApprovalDate        string
	Processed                  bool
	ProcessedDate              string
	ApprovalCode               string
	InitialApproverEmail       string
	StartDt                    string
	EndDt                      string
	ExpenseReportName          string
	ExpenseReportDescription   string
	Status                     string
	LastAction                 string
	APSyncComplete             bool
	Reimbursed                 bool
	ReimbursedDate             string
	ReimbursementTransactionID string
	EmpGLD1Name                string
	EmpGLD1Code                string
	EmpGLD2Name                string
	EmpGLD2Code                string
	EmpGLD3Name                string
	EmpGLD3Code                string
	EmpGLD4Name                string
	EmpGLD4Code                string
	EmpGLD5Name                string
	EmpGLD5Code                string
	Expenses                   []Expense
}

// ExpRptResults describes the respone of an expense report
// query
type ExpRptResults struct {
	ResultHeader
	ExpenseReports []ExpRpt
}

// Expense describes a line item of an expense report
type Expense struct {
	ID                    string
	ExpenseReportID       string
	FirstName             string
	LastName              string
	Email                 string
	EmployeeID            string
	DepartmentName        string
	DepartmentCode        string
	ExpenseType           string
	ExpenseCategory       string
	ExpenseCategoryGLCode string
	Amount                float64
	Billable              bool
	Reimbursable          bool
	ReimAmount            float64
	SubmittedAmount       float64
	ExpenseDate           string
	PostingDate           string
	LodgingCheckInDate    string
	LodgingCheckOutDate   string
	RentalPickUpDate      string
	RentalDropOffDate     string
	Vendor                string
	Location              string
	TravelFrom            string
	TravelTo              string
	MileageFrom           string
	MileageTo             string
	MileageUnits          string
	ProcessedDate         string
	Processed             bool
	Currency              string
	SubmittedCurrency     string
	Reason                string
	VATAmount             float64
	HSTAmount             float64
	PSTAmount             float64
	ExpenseReportGLD1Name string
	ExpenseReportGLD1Code string
	ExpenseTextGLD1Label  string
	ExpenseTextGLD1       string
	ExpenseReportGLD2Name string
	ExpenseReportGLD2Code string
	ExpenseTextGLD2Label  string
	ExpenseTextGLD2       string
	ExpenseReportGLD3Name string
	ExpenseReportGLD3Code string
	ExpenseTextGLD3Label  string
	ExpenseTextGLD3       string
	ExpenseReportGLD4Name string
	ExpenseReportGLD4Code string
	ExpenseTextGLD4Label  string
	ExpenseTextGLD4       string
	ExpenseReportGLD5Name string
	ExpenseReportGLD5Code string
	ExpenseTextGLD5Label  string
	ExpenseTextGLD5       string
	ReceiptImageLink      string
	ReceiptID             string
	PaymentCardName       string
	CCLast                string
	CCTransactionID       string
}

// ExpenseResults are the result of an expense query
type ExpenseResults struct {
	ResultHeader
	Expenses []Expense `json:"Expenses"`
}

// CatResults is response from an Expense Category query
type CatResults struct {
	ResultHeader
	Cats []Cat `json:"ExpenseCategories,omitempty"`
}

// Cat describes an Expense Category record
type Cat struct {
	ID                            string  `json:"ID,omitempty"`
	Name                          string  `json:"Name,omitempty"`
	Description                   string  `json:"Description,omitempty"`
	Data                          string  `json:"Data,omitempty"`
	ExpenseTypeID                 int     `json:"ExpenseTypeID,omitempty"`
	MaxAmount                     float64 `json:"MaxAmount,omitempty"`
	MaxAmountCurrencyType         string  `json:"MaxAmountCurrencyType,omitempty"`
	SpendLimitPerUser             float64 `json:"SpendLimitPerUser,omitempty"`
	SpendLimitPerUserCurrencyType string  `json:"SpendLimitPerUserCurrencyType,omitempty"`
	SpendLimitPerUserTerm         string  `json:"SpendLimitPerUserTerm,omitempty"`
	GLCode                        string  `json:"GLCode,omitempty"`
	FilterDepartmentID            string  `json:"FilterDepartmentID,omitempty"`
	PrepaidCode                   string  `json:"PrepaidCode,omitempty"`
	RequireReceiptOverride        int     `json:"RequireReceiptOverride,omitempty"`
	RequireReceiptThresholdAmount float64 `json:"RequireReceiptThresholdAmount,omitempty"`
	DetailedMealAttendees         int     `json:"DetailedMealAttendees,omitempty"`
	PersonalExpenses              int     `json:"PersonalExpenses,omitempty"`
	RequireReason                 int     `json:"RequireReason,omitempty"`
	StrictFilteringException      int     `json:"StrictFilteringException,omitempty"`
	SupressBillable               int     `json:"SupressBillable,omitempty"`
	SupressBillableDefaultValue   int     `json:"SupressBillableDefaultValue,omitempty"`
	DeductCommuteUnits            int     `json:"DeductCommuteUnits,omitempty"`
	CashAdvances                  int     `json:"CashAdvances,omitempty"`
	DailyMealLimit                int     `json:"DailyMealLimit,omitempty"`
	Active                        int     `json:"Active"`
}

// Dept describes a department record
type Dept struct {
	ID                           string `json:"ID,omitempty"`
	Name                         string `json:"Name,omitempty"`
	Code                         string `json:"Code,omitempty"`
	Description                  string `json:"Description,omitempty"`
	Data                         string `json:"Data,omitempty"`
	SecondLvlApproval            int    `json:"ObtainsSecondLevelApproval,omitempty"`
	StrictFiltering              int    `json:"UseStringFiltering,omitempty"`
	HideDepartment               int    `json:"HideDepartment,omitempty"`
	HideBillable                 int    `json:"HideBillable,omitempty"`
	HideBillableDefaultValue     int    `json:"HideBillableDefaultValue,omitempty"`
	HideReimbursable             int    `json:"HideReimbursable,omitempty"`
	HideReimbursableDefaultValue int    `json:"HideReimbursableDefaultValue,omitempty"`
	InitialPage                  int    `json:"InitialPage,omitempty"`
	LastModifiedDate             string `json:"LastModifiedDate,omitempty"`
	Active                       int    `json:"Active,omitempty"`
}

// DeptResults is response from an Expense Category query
type DeptResults struct {
	ResultHeader
	Depts []Dept `json:"Departments,omitempty"`
}

// CmdResult from CRUD operation
type CmdResult struct {
	ID      string `json:"ID,omitempty"`
	Status  string `json:"Status,omitempty"`
	Message string `json:"Message,omitempty"`
}

// GetError checks for error message in result.  Returns
// nil if no error is found.
func (c *CmdResult) GetError() error {
	if c.Status != "Error" && c.Message == "" {
		return nil
	}
	return fmt.Errorf("ID: %s %s %s", c.ID, c.Status, c.Message)
}

// ResultHeader is the generic paging fields for a result
type ResultHeader struct {
	Page      int `json:"Page,omitempty"`
	PageCount int `json:"PageCount,omitempty"`
	Records   int `json:"Records,omitempty"`
	RecordCnt int `json:"RecordCnt,omitempty"`
}

// ExpRptGLD describe a GL dimension record
type ExpRptGLD struct {
	ID          string `json:"ID,omitempty"`
	Name        string `json:"Name"`
	Code        string `json:"Code"`
	Description string `json:"Description"`
	Data        string `json:"Data"`
	Active      int    `json:"Active"`
}

// ExpRptGLDResult is the result of a GET /exprptglds/{index} call
type ExpRptGLDResult struct {
	ResultHeader
	Dims []ExpRptGLD `json:"ExpRptGLDs,omitempty"`
}

// UserResult is the result of a GET /users call
type UserResult struct {
	ResultHeader
	Users []User `json:"Users,omitempty"`
}

// User describes user
type User struct {
	ID                string `json:"ID,omitempty"`
	UserName          string `json:"UserName,omitempty"`
	FirstName         string `json:"FirstName,omitempty"`
	LastName          string `json:"LastName,omitempty"`
	Email             string `json:"Email,omitempty"`
	EmployeeID        string `json:"EmployeeID,omitempty"`
	MobilePhone       string `json:"MobilePhone,omitempty"`
	Role              string `json:"Role,omitempty"`
	Treasurer         int    `json:"Rreasurer,omitempty"`
	FullAdministrator int    `json:"FullAdministrator,omitempty"`
	UserAdministrator int    `json:"UserAdministrator,omitempty"`
	DepartmentID      string `json:"DepartmentID,omitempty"`
	EmpGLD1ID         string `json:"EmpGLD1ID,omitempty"`
	EmpGLD2ID         string `json:"EmpGLD2ID,omitempty"`
	EmpGLD3ID         string `json:"EmpGLD3ID,omitempty"`
	EmpGLD4ID         string `json:"EmpGLD4ID,omitempty"`
	EmpGLD5ID         string `json:"EmpGLD5ID,omitempty"`
	Culture           string `json:"Culture,omitempty"`
	Language          string `json:"Language,omitempty"`
	Currency          string `json:"Currency,omitempty"`
	LastModifiedDate  string `json:"LastModifiedDate,omitempty"`
	WelcomeEmailSent  int    `json:"WelcomeEmailSent,omitempty"`
	Active            int    `json:"Active,omitempty"`
	FirstApproverID   string `json:"FirstApproverID,omitempty"`
	SedondApproverID  string `json:"SedondApproverID,omitempty"`
	AccountantID      string `json:"accountantID,omitempty"`
}

var allReportsCmd = &Command{
	Method: "GET",
	Path:   "/expensereports?reimbursed=1",
}

// Service adds auth headers
type Service struct {
	Cred    Credential
	BaseURL string
	F       ctxclient.Func
}

func (sv *Service) baseURL() string {
	if sv.BaseURL == "" {
		return baseURL
	}
	return sv.BaseURL
}

// Credential adds authorizing info to Request.  Allows user/pwd and
// OAuth(not implemented yet)
type Credential interface {
	Authorize(*http.Request) error
}

// KeySecret holds Cerify API key and secret for authorization.
type KeySecret struct {
	key    string
	secret string
}

// NewKeySecret creates a new authorizer using Certify Api key and secret
func NewKeySecret(key, secret string) *KeySecret {
	return &KeySecret{
		key:    key,
		secret: secret,
	}
}

// Authorize adds Certify defined authorization headers to the request
func (k *KeySecret) Authorize(r *http.Request) error {
	r.Header.Add("x-api-key", k.key)
	r.Header.Add("x-api-secret", k.secret)
	return nil
}

// RoundTrip adds authstring headers to request and calls default transport
func (sv *Service) RoundTrip(req *http.Request) (res *http.Response, err error) {
	r2 := *req
	r2.Header = make(http.Header)
	for k, v := range req.Header {
		r2.Header[k] = v
	}
	if err := sv.Cred.Authorize(&r2); err != nil {
		return nil, err
	}
	u2 := *r2.URL
	u2.Path = sv.baseURL() + u2.Path
	r2.URL = &u2
	return ctxclient.Transport(r2.Context()).RoundTrip(&r2)
}

// Command is used to create REST request
type Command struct {
	Method string
	Path   string
	Query  url.Values
	Body   interface{}
}

// Do sends a Command to certify and returns the raw response.  Should not be called
// except for debugging situations.
func (sv *Service) Do(ctx context.Context, cmd *Command) (*http.Response, error) {
	var body io.Reader
	if cmd.Body != nil {
		b, err := json.Marshal(cmd.Body)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(b)
	}
	r, _ := http.NewRequest(cmd.Method, sv.baseURL()+cmd.Path, body)
	if len(cmd.Query) > 0 {
		qvals := r.URL.Query()
		for k, v := range cmd.Query {
			for _, val := range v {
				qvals.Add(k, val)
			}
		}
		r.URL.RawQuery = qvals.Encode()
	}

	if err := sv.Cred.Authorize(r); err != nil {
		return nil, err
	}
	// add content-type header if POST or PUT
	if body != nil {
		r.Header.Add("Content-Type", "application/json")
	}

	return sv.F.Do(ctx, r)
}

// Result decodes the cmd response in the result interface{}
func (sv *Service) Result(ctx context.Context, cmd *Command, result interface{}) error {
	res, err := sv.Do(ctx, cmd)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	return json.NewDecoder(res.Body).Decode(result)
}
