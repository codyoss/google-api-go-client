// Copyright 2025 Google LLC.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Code generated file. DO NOT EDIT.

// Package merchantapi provides access to the Merchant API.
//
// For product documentation, see: https://developers.google.com/merchant/api
//
// # Library status
//
// These client libraries are officially supported by Google. However, this
// library is considered complete and is in maintenance mode. This means
// that we will address critical bugs and security issues but will not add
// any new features.
//
// When possible, we recommend using our newer
// [Cloud Client Libraries for Go](https://pkg.go.dev/cloud.google.com/go)
// that are still actively being worked and iterated on.
//
// # Creating a client
//
// Usage example:
//
//	import "google.golang.org/api/merchantapi/notifications_v1beta"
//	...
//	ctx := context.Background()
//	merchantapiService, err := merchantapi.NewService(ctx)
//
// In this example, Google Application Default Credentials are used for
// authentication. For information on how to create and obtain Application
// Default Credentials, see https://developers.google.com/identity/protocols/application-default-credentials.
//
// # Other authentication options
//
// To use an API key for authentication (note: some APIs do not support API
// keys), use [google.golang.org/api/option.WithAPIKey]:
//
//	merchantapiService, err := merchantapi.NewService(ctx, option.WithAPIKey("AIza..."))
//
// To use an OAuth token (e.g., a user token obtained via a three-legged OAuth
// flow, use [google.golang.org/api/option.WithTokenSource]:
//
//	config := &oauth2.Config{...}
//	// ...
//	token, err := config.Exchange(ctx, ...)
//	merchantapiService, err := merchantapi.NewService(ctx, option.WithTokenSource(config.TokenSource(ctx, token)))
//
// See [google.golang.org/api/option.ClientOption] for details on options.
package merchantapi // import "google.golang.org/api/merchantapi/notifications_v1beta"

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/googleapis/gax-go/v2/internallog"
	googleapi "google.golang.org/api/googleapi"
	internal "google.golang.org/api/internal"
	gensupport "google.golang.org/api/internal/gensupport"
	option "google.golang.org/api/option"
	internaloption "google.golang.org/api/option/internaloption"
	htransport "google.golang.org/api/transport/http"
)

// Always reference these packages, just in case the auto-generated code
// below doesn't.
var _ = bytes.NewBuffer
var _ = strconv.Itoa
var _ = fmt.Sprintf
var _ = json.NewDecoder
var _ = io.Copy
var _ = url.Parse
var _ = gensupport.MarshalJSON
var _ = googleapi.Version
var _ = errors.New
var _ = strings.Replace
var _ = context.Canceled
var _ = internaloption.WithDefaultEndpoint
var _ = internal.Version
var _ = internallog.New

const apiId = "merchantapi:notifications_v1beta"
const apiName = "merchantapi"
const apiVersion = "notifications_v1beta"
const basePath = "https://merchantapi.googleapis.com/"
const basePathTemplate = "https://merchantapi.UNIVERSE_DOMAIN/"
const mtlsBasePath = "https://merchantapi.mtls.googleapis.com/"

// OAuth2 scopes used by this API.
const (
	// Manage your product listings and accounts for Google Shopping
	ContentScope = "https://www.googleapis.com/auth/content"
)

// NewService creates a new Service.
func NewService(ctx context.Context, opts ...option.ClientOption) (*Service, error) {
	scopesOption := internaloption.WithDefaultScopes(
		"https://www.googleapis.com/auth/content",
	)
	// NOTE: prepend, so we don't override user-specified scopes.
	opts = append([]option.ClientOption{scopesOption}, opts...)
	opts = append(opts, internaloption.WithDefaultEndpoint(basePath))
	opts = append(opts, internaloption.WithDefaultEndpointTemplate(basePathTemplate))
	opts = append(opts, internaloption.WithDefaultMTLSEndpoint(mtlsBasePath))
	opts = append(opts, internaloption.EnableNewAuthLibrary())
	client, endpoint, err := htransport.NewClient(ctx, opts...)
	if err != nil {
		return nil, err
	}
	s := &Service{client: client, BasePath: basePath, logger: internaloption.GetLogger(opts)}
	s.Accounts = NewAccountsService(s)
	if endpoint != "" {
		s.BasePath = endpoint
	}
	return s, nil
}

// New creates a new Service. It uses the provided http.Client for requests.
//
// Deprecated: please use NewService instead.
// To provide a custom HTTP client, use option.WithHTTPClient.
// If you are using google.golang.org/api/googleapis/transport.APIKey, use option.WithAPIKey with NewService instead.
func New(client *http.Client) (*Service, error) {
	if client == nil {
		return nil, errors.New("client is nil")
	}
	return NewService(context.TODO(), option.WithHTTPClient(client))
}

type Service struct {
	client    *http.Client
	logger    *slog.Logger
	BasePath  string // API endpoint base URL
	UserAgent string // optional additional User-Agent fragment

	Accounts *AccountsService
}

func (s *Service) userAgent() string {
	if s.UserAgent == "" {
		return googleapi.UserAgent
	}
	return googleapi.UserAgent + " " + s.UserAgent
}

func NewAccountsService(s *Service) *AccountsService {
	rs := &AccountsService{s: s}
	rs.Notificationsubscriptions = NewAccountsNotificationsubscriptionsService(s)
	return rs
}

type AccountsService struct {
	s *Service

	Notificationsubscriptions *AccountsNotificationsubscriptionsService
}

func NewAccountsNotificationsubscriptionsService(s *Service) *AccountsNotificationsubscriptionsService {
	rs := &AccountsNotificationsubscriptionsService{s: s}
	return rs
}

type AccountsNotificationsubscriptionsService struct {
	s *Service
}

// Empty: A generic empty message that you can re-use to avoid defining
// duplicated empty messages in your APIs. A typical example is to use it as
// the request or the response type of an API method. For instance: service Foo
// { rpc Bar(google.protobuf.Empty) returns (google.protobuf.Empty); }
type Empty struct {
	// ServerResponse contains the HTTP response code and headers from the server.
	googleapi.ServerResponse `json:"-"`
}

// ListNotificationSubscriptionsResponse: Response message for the
// ListNotificationSubscription method.
type ListNotificationSubscriptionsResponse struct {
	// NextPageToken: A token, which can be sent as `page_token` to retrieve the
	// next page. If this field is omitted, there are no subsequent pages.
	NextPageToken string `json:"nextPageToken,omitempty"`
	// NotificationSubscriptions: The list of notification subscriptions requested
	// by the merchant.
	NotificationSubscriptions []*NotificationSubscription `json:"notificationSubscriptions,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the server.
	googleapi.ServerResponse `json:"-"`
	// ForceSendFields is a list of field names (e.g. "NextPageToken") to
	// unconditionally include in API requests. By default, fields with empty or
	// default values are omitted from API requests. See
	// https://pkg.go.dev/google.golang.org/api#hdr-ForceSendFields for more
	// details.
	ForceSendFields []string `json:"-"`
	// NullFields is a list of field names (e.g. "NextPageToken") to include in API
	// requests with the JSON null value. By default, fields with empty values are
	// omitted from API requests. See
	// https://pkg.go.dev/google.golang.org/api#hdr-NullFields for more details.
	NullFields []string `json:"-"`
}

func (s ListNotificationSubscriptionsResponse) MarshalJSON() ([]byte, error) {
	type NoMethod ListNotificationSubscriptionsResponse
	return gensupport.MarshalJSON(NoMethod(s), s.ForceSendFields, s.NullFields)
}

// NotificationSubscription: Represents a notification subscription owned by a
// Merchant account.
type NotificationSubscription struct {
	// AllManagedAccounts: If this value is true, the requesting account is
	// notified of the specified event for all managed accounts (can be subaccounts
	// or other linked accounts) including newly added accounts on a daily basis.
	AllManagedAccounts bool `json:"allManagedAccounts,omitempty"`
	// CallBackUri: URL to be used to push the notification to the merchant.
	CallBackUri string `json:"callBackUri,omitempty"`
	// Name: Output only. The `name` of the notification configuration. Generated
	// by the Content API upon creation of a new `NotificationSubscription`. The
	// `account` represents the merchant ID of the merchant that owns the
	// configuration. Format:
	// `accounts/{account}/notificationsubscriptions/{notification_subscription}`
	Name string `json:"name,omitempty"`
	// RegisteredEvent: The event that the merchant wants to be notified about.
	//
	// Possible values:
	//   "NOTIFICATION_EVENT_TYPE_UNSPECIFIED" - Notifications event type is
	// unspecified.
	//   "PRODUCT_STATUS_CHANGE" - Notification of product status changes, for
	// example when product becomes disapproved.
	RegisteredEvent string `json:"registeredEvent,omitempty"`
	// TargetAccount: The `name` of the account you want to receive notifications
	// for. Format: `accounts/{account}`
	TargetAccount string `json:"targetAccount,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the server.
	googleapi.ServerResponse `json:"-"`
	// ForceSendFields is a list of field names (e.g. "AllManagedAccounts") to
	// unconditionally include in API requests. By default, fields with empty or
	// default values are omitted from API requests. See
	// https://pkg.go.dev/google.golang.org/api#hdr-ForceSendFields for more
	// details.
	ForceSendFields []string `json:"-"`
	// NullFields is a list of field names (e.g. "AllManagedAccounts") to include
	// in API requests with the JSON null value. By default, fields with empty
	// values are omitted from API requests. See
	// https://pkg.go.dev/google.golang.org/api#hdr-NullFields for more details.
	NullFields []string `json:"-"`
}

func (s NotificationSubscription) MarshalJSON() ([]byte, error) {
	type NoMethod NotificationSubscription
	return gensupport.MarshalJSON(NoMethod(s), s.ForceSendFields, s.NullFields)
}

// ProductChange: The change that happened to the product including old value,
// new value, country code as the region code and reporting context.
type ProductChange struct {
	// NewValue: The new value of the changed resource or attribute. If empty, it
	// means that the product was deleted. Will have one of these values :
	// (`approved`, `pending`, `disapproved`, ``)
	NewValue string `json:"newValue,omitempty"`
	// OldValue: The old value of the changed resource or attribute. If empty, it
	// means that the product was created. Will have one of these values :
	// (`approved`, `pending`, `disapproved`, ``)
	OldValue string `json:"oldValue,omitempty"`
	// RegionCode: Countries that have the change (if applicable). Represented in
	// the ISO 3166 format.
	RegionCode string `json:"regionCode,omitempty"`
	// ReportingContext: Reporting contexts that have the change (if applicable).
	// Currently this field supports only (`SHOPPING_ADS`, `LOCAL_INVENTORY_ADS`,
	// `YOUTUBE_SHOPPING`, `YOUTUBE_CHECKOUT`, `YOUTUBE_AFFILIATE`) from the enum
	// value ReportingContextEnum
	// (/merchant/api/reference/rest/Shared.Types/ReportingContextEnum)
	//
	// Possible values:
	//   "REPORTING_CONTEXT_ENUM_UNSPECIFIED" - Not specified.
	//   "SHOPPING_ADS" - [Shopping
	// ads](https://support.google.com/merchants/answer/6149970).
	//   "DISCOVERY_ADS" - Deprecated: Use `DEMAND_GEN_ADS` instead. [Discovery and
	// Demand Gen ads](https://support.google.com/merchants/answer/13389785).
	//   "DEMAND_GEN_ADS" - [Demand Gen
	// ads](https://support.google.com/merchants/answer/13389785).
	//   "DEMAND_GEN_ADS_DISCOVER_SURFACE" - [Demand Gen ads on Discover
	// surface](https://support.google.com/merchants/answer/13389785).
	//   "VIDEO_ADS" - [Video
	// ads](https://support.google.com/google-ads/answer/6340491).
	//   "DISPLAY_ADS" - [Display
	// ads](https://support.google.com/merchants/answer/6069387).
	//   "LOCAL_INVENTORY_ADS" - [Local inventory
	// ads](https://support.google.com/merchants/answer/3271956).
	//   "VEHICLE_INVENTORY_ADS" - [Vehicle inventory
	// ads](https://support.google.com/merchants/answer/11544533).
	//   "FREE_LISTINGS" - [Free product
	// listings](https://support.google.com/merchants/answer/9199328).
	//   "FREE_LOCAL_LISTINGS" - [Free local product
	// listings](https://support.google.com/merchants/answer/9825611).
	//   "FREE_LOCAL_VEHICLE_LISTINGS" - [Free local vehicle
	// listings](https://support.google.com/merchants/answer/11544533).
	//   "YOUTUBE_AFFILIATE" - [Youtube
	// Affiliate](https://support.google.com/youtube/answer/13376398).
	//   "YOUTUBE_SHOPPING" - [YouTube
	// Shopping](https://support.google.com/merchants/answer/13478370).
	//   "CLOUD_RETAIL" - [Cloud
	// retail](https://cloud.google.com/solutions/retail).
	//   "LOCAL_CLOUD_RETAIL" - [Local cloud
	// retail](https://cloud.google.com/solutions/retail).
	//   "PRODUCT_REVIEWS" - [Product
	// Reviews](https://support.google.com/merchants/answer/14620732).
	//   "MERCHANT_REVIEWS" - [Merchant
	// Reviews](https://developers.google.com/merchant-review-feeds).
	//   "YOUTUBE_CHECKOUT" - YouTube Checkout .
	ReportingContext string `json:"reportingContext,omitempty"`
	// ForceSendFields is a list of field names (e.g. "NewValue") to
	// unconditionally include in API requests. By default, fields with empty or
	// default values are omitted from API requests. See
	// https://pkg.go.dev/google.golang.org/api#hdr-ForceSendFields for more
	// details.
	ForceSendFields []string `json:"-"`
	// NullFields is a list of field names (e.g. "NewValue") to include in API
	// requests with the JSON null value. By default, fields with empty values are
	// omitted from API requests. See
	// https://pkg.go.dev/google.golang.org/api#hdr-NullFields for more details.
	NullFields []string `json:"-"`
}

func (s ProductChange) MarshalJSON() ([]byte, error) {
	type NoMethod ProductChange
	return gensupport.MarshalJSON(NoMethod(s), s.ForceSendFields, s.NullFields)
}

// ProductStatusChangeMessage: The message that the merchant will receive to
// notify about product status change event
type ProductStatusChangeMessage struct {
	// Account: The target account that owns the entity that changed. Format :
	// `accounts/{merchant_id}`
	Account string `json:"account,omitempty"`
	// Attribute: The attribute in the resource that changed, in this case it will
	// be always `Status`.
	//
	// Possible values:
	//   "ATTRIBUTE_UNSPECIFIED" - Unspecified attribute
	//   "STATUS" - Status of the changed entity
	Attribute string `json:"attribute,omitempty"`
	// Changes: A message to describe the change that happened to the product
	Changes []*ProductChange `json:"changes,omitempty"`
	// EventTime: The time at which the event was generated. If you want to order
	// the notification messages you receive you should rely on this field not on
	// the order of receiving the notifications.
	EventTime string `json:"eventTime,omitempty"`
	// ExpirationTime: Optional. The product expiration time. This field will not
	// be set if the notification is sent for a product deletion event.
	ExpirationTime string `json:"expirationTime,omitempty"`
	// ManagingAccount: The account that manages the merchant's account. can be the
	// same as merchant id if it is standalone account. Format :
	// `accounts/{service_provider_id}`
	ManagingAccount string `json:"managingAccount,omitempty"`
	// Resource: The product name. Format: `accounts/{account}/products/{product}`
	Resource string `json:"resource,omitempty"`
	// ResourceId: The product id.
	ResourceId string `json:"resourceId,omitempty"`
	// ResourceType: The resource that changed, in this case it will always be
	// `Product`.
	//
	// Possible values:
	//   "RESOURCE_UNSPECIFIED" - Unspecified resource
	//   "PRODUCT" - Resource type : product
	ResourceType string `json:"resourceType,omitempty"`
	// ForceSendFields is a list of field names (e.g. "Account") to unconditionally
	// include in API requests. By default, fields with empty or default values are
	// omitted from API requests. See
	// https://pkg.go.dev/google.golang.org/api#hdr-ForceSendFields for more
	// details.
	ForceSendFields []string `json:"-"`
	// NullFields is a list of field names (e.g. "Account") to include in API
	// requests with the JSON null value. By default, fields with empty values are
	// omitted from API requests. See
	// https://pkg.go.dev/google.golang.org/api#hdr-NullFields for more details.
	NullFields []string `json:"-"`
}

func (s ProductStatusChangeMessage) MarshalJSON() ([]byte, error) {
	type NoMethod ProductStatusChangeMessage
	return gensupport.MarshalJSON(NoMethod(s), s.ForceSendFields, s.NullFields)
}

type AccountsNotificationsubscriptionsCreateCall struct {
	s                        *Service
	parent                   string
	notificationsubscription *NotificationSubscription
	urlParams_               gensupport.URLParams
	ctx_                     context.Context
	header_                  http.Header
}

// Create: Creates a notification subscription for a business. For standalone
// or subaccounts accounts, the business can create a subscription for self.
// For MCAs, the business can create a subscription for all managed accounts or
// for a specific subaccount. We will allow the following types of notification
// subscriptions to exist together (per business as a subscriber per event
// type): 1. Subscription for all managed accounts + subscription for self. 2.
// Multiple "partial" subscriptions for managed accounts + subscription for
// self. we will not allow (per business as a subscriber per event type): 1.
// Multiple self subscriptions. 2. Multiple "all managed accounts"
// subscriptions. 3. "All managed accounts" subscription and partial
// subscriptions at the same time. 4. Multiple partial subscriptions for the
// same target account.
//
//   - parent: The merchant account that owns the new notification subscription.
//     Format: `accounts/{account}`.
func (r *AccountsNotificationsubscriptionsService) Create(parent string, notificationsubscription *NotificationSubscription) *AccountsNotificationsubscriptionsCreateCall {
	c := &AccountsNotificationsubscriptionsCreateCall{s: r.s, urlParams_: make(gensupport.URLParams)}
	c.parent = parent
	c.notificationsubscription = notificationsubscription
	return c
}

// Fields allows partial responses to be retrieved. See
// https://developers.google.com/gdata/docs/2.0/basics#PartialResponse for more
// details.
func (c *AccountsNotificationsubscriptionsCreateCall) Fields(s ...googleapi.Field) *AccountsNotificationsubscriptionsCreateCall {
	c.urlParams_.Set("fields", googleapi.CombineFields(s))
	return c
}

// Context sets the context to be used in this call's Do method.
func (c *AccountsNotificationsubscriptionsCreateCall) Context(ctx context.Context) *AccountsNotificationsubscriptionsCreateCall {
	c.ctx_ = ctx
	return c
}

// Header returns a http.Header that can be modified by the caller to add
// headers to the request.
func (c *AccountsNotificationsubscriptionsCreateCall) Header() http.Header {
	if c.header_ == nil {
		c.header_ = make(http.Header)
	}
	return c.header_
}

func (c *AccountsNotificationsubscriptionsCreateCall) doRequest(alt string) (*http.Response, error) {
	reqHeaders := gensupport.SetHeaders(c.s.userAgent(), "application/json", c.header_)
	body, err := googleapi.WithoutDataWrapper.JSONBuffer(c.notificationsubscription)
	if err != nil {
		return nil, err
	}
	c.urlParams_.Set("alt", alt)
	c.urlParams_.Set("prettyPrint", "false")
	urls := googleapi.ResolveRelative(c.s.BasePath, "notifications/v1beta/{+parent}/notificationsubscriptions")
	urls += "?" + c.urlParams_.Encode()
	req, err := http.NewRequest("POST", urls, body)
	if err != nil {
		return nil, err
	}
	req.Header = reqHeaders
	googleapi.Expand(req.URL, map[string]string{
		"parent": c.parent,
	})
	c.s.logger.DebugContext(c.ctx_, "api request", "serviceName", apiName, "rpcName", "merchantapi.accounts.notificationsubscriptions.create", "request", internallog.HTTPRequest(req, body.Bytes()))
	return gensupport.SendRequest(c.ctx_, c.s.client, req)
}

// Do executes the "merchantapi.accounts.notificationsubscriptions.create" call.
// Any non-2xx status code is an error. Response headers are in either
// *NotificationSubscription.ServerResponse.Header or (if a response was
// returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *AccountsNotificationsubscriptionsCreateCall) Do(opts ...googleapi.CallOption) (*NotificationSubscription, error) {
	gensupport.SetOptions(c.urlParams_, opts...)
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, gensupport.WrapError(&googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		})
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, gensupport.WrapError(err)
	}
	ret := &NotificationSubscription{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	target := &ret
	b, err := gensupport.DecodeResponseBytes(target, res)
	if err != nil {
		return nil, err
	}
	c.s.logger.DebugContext(c.ctx_, "api response", "serviceName", apiName, "rpcName", "merchantapi.accounts.notificationsubscriptions.create", "response", internallog.HTTPResponse(res, b))
	return ret, nil
}

type AccountsNotificationsubscriptionsDeleteCall struct {
	s          *Service
	name       string
	urlParams_ gensupport.URLParams
	ctx_       context.Context
	header_    http.Header
}

// Delete: Deletes a notification subscription for a merchant.
//
// - name: The name of the notification subscription to be deleted.
func (r *AccountsNotificationsubscriptionsService) Delete(name string) *AccountsNotificationsubscriptionsDeleteCall {
	c := &AccountsNotificationsubscriptionsDeleteCall{s: r.s, urlParams_: make(gensupport.URLParams)}
	c.name = name
	return c
}

// Fields allows partial responses to be retrieved. See
// https://developers.google.com/gdata/docs/2.0/basics#PartialResponse for more
// details.
func (c *AccountsNotificationsubscriptionsDeleteCall) Fields(s ...googleapi.Field) *AccountsNotificationsubscriptionsDeleteCall {
	c.urlParams_.Set("fields", googleapi.CombineFields(s))
	return c
}

// Context sets the context to be used in this call's Do method.
func (c *AccountsNotificationsubscriptionsDeleteCall) Context(ctx context.Context) *AccountsNotificationsubscriptionsDeleteCall {
	c.ctx_ = ctx
	return c
}

// Header returns a http.Header that can be modified by the caller to add
// headers to the request.
func (c *AccountsNotificationsubscriptionsDeleteCall) Header() http.Header {
	if c.header_ == nil {
		c.header_ = make(http.Header)
	}
	return c.header_
}

func (c *AccountsNotificationsubscriptionsDeleteCall) doRequest(alt string) (*http.Response, error) {
	reqHeaders := gensupport.SetHeaders(c.s.userAgent(), "", c.header_)
	c.urlParams_.Set("alt", alt)
	c.urlParams_.Set("prettyPrint", "false")
	urls := googleapi.ResolveRelative(c.s.BasePath, "notifications/v1beta/{+name}")
	urls += "?" + c.urlParams_.Encode()
	req, err := http.NewRequest("DELETE", urls, nil)
	if err != nil {
		return nil, err
	}
	req.Header = reqHeaders
	googleapi.Expand(req.URL, map[string]string{
		"name": c.name,
	})
	c.s.logger.DebugContext(c.ctx_, "api request", "serviceName", apiName, "rpcName", "merchantapi.accounts.notificationsubscriptions.delete", "request", internallog.HTTPRequest(req, nil))
	return gensupport.SendRequest(c.ctx_, c.s.client, req)
}

// Do executes the "merchantapi.accounts.notificationsubscriptions.delete" call.
// Any non-2xx status code is an error. Response headers are in either
// *Empty.ServerResponse.Header or (if a response was returned at all) in
// error.(*googleapi.Error).Header. Use googleapi.IsNotModified to check
// whether the returned error was because http.StatusNotModified was returned.
func (c *AccountsNotificationsubscriptionsDeleteCall) Do(opts ...googleapi.CallOption) (*Empty, error) {
	gensupport.SetOptions(c.urlParams_, opts...)
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, gensupport.WrapError(&googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		})
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, gensupport.WrapError(err)
	}
	ret := &Empty{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	target := &ret
	b, err := gensupport.DecodeResponseBytes(target, res)
	if err != nil {
		return nil, err
	}
	c.s.logger.DebugContext(c.ctx_, "api response", "serviceName", apiName, "rpcName", "merchantapi.accounts.notificationsubscriptions.delete", "response", internallog.HTTPResponse(res, b))
	return ret, nil
}

type AccountsNotificationsubscriptionsGetCall struct {
	s            *Service
	name         string
	urlParams_   gensupport.URLParams
	ifNoneMatch_ string
	ctx_         context.Context
	header_      http.Header
}

// Get: Gets notification subscriptions for an account.
//
// - name: The `name` of the notification subscription.
func (r *AccountsNotificationsubscriptionsService) Get(name string) *AccountsNotificationsubscriptionsGetCall {
	c := &AccountsNotificationsubscriptionsGetCall{s: r.s, urlParams_: make(gensupport.URLParams)}
	c.name = name
	return c
}

// Fields allows partial responses to be retrieved. See
// https://developers.google.com/gdata/docs/2.0/basics#PartialResponse for more
// details.
func (c *AccountsNotificationsubscriptionsGetCall) Fields(s ...googleapi.Field) *AccountsNotificationsubscriptionsGetCall {
	c.urlParams_.Set("fields", googleapi.CombineFields(s))
	return c
}

// IfNoneMatch sets an optional parameter which makes the operation fail if the
// object's ETag matches the given value. This is useful for getting updates
// only after the object has changed since the last request.
func (c *AccountsNotificationsubscriptionsGetCall) IfNoneMatch(entityTag string) *AccountsNotificationsubscriptionsGetCall {
	c.ifNoneMatch_ = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
func (c *AccountsNotificationsubscriptionsGetCall) Context(ctx context.Context) *AccountsNotificationsubscriptionsGetCall {
	c.ctx_ = ctx
	return c
}

// Header returns a http.Header that can be modified by the caller to add
// headers to the request.
func (c *AccountsNotificationsubscriptionsGetCall) Header() http.Header {
	if c.header_ == nil {
		c.header_ = make(http.Header)
	}
	return c.header_
}

func (c *AccountsNotificationsubscriptionsGetCall) doRequest(alt string) (*http.Response, error) {
	reqHeaders := gensupport.SetHeaders(c.s.userAgent(), "", c.header_)
	if c.ifNoneMatch_ != "" {
		reqHeaders.Set("If-None-Match", c.ifNoneMatch_)
	}
	c.urlParams_.Set("alt", alt)
	c.urlParams_.Set("prettyPrint", "false")
	urls := googleapi.ResolveRelative(c.s.BasePath, "notifications/v1beta/{+name}")
	urls += "?" + c.urlParams_.Encode()
	req, err := http.NewRequest("GET", urls, nil)
	if err != nil {
		return nil, err
	}
	req.Header = reqHeaders
	googleapi.Expand(req.URL, map[string]string{
		"name": c.name,
	})
	c.s.logger.DebugContext(c.ctx_, "api request", "serviceName", apiName, "rpcName", "merchantapi.accounts.notificationsubscriptions.get", "request", internallog.HTTPRequest(req, nil))
	return gensupport.SendRequest(c.ctx_, c.s.client, req)
}

// Do executes the "merchantapi.accounts.notificationsubscriptions.get" call.
// Any non-2xx status code is an error. Response headers are in either
// *NotificationSubscription.ServerResponse.Header or (if a response was
// returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *AccountsNotificationsubscriptionsGetCall) Do(opts ...googleapi.CallOption) (*NotificationSubscription, error) {
	gensupport.SetOptions(c.urlParams_, opts...)
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, gensupport.WrapError(&googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		})
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, gensupport.WrapError(err)
	}
	ret := &NotificationSubscription{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	target := &ret
	b, err := gensupport.DecodeResponseBytes(target, res)
	if err != nil {
		return nil, err
	}
	c.s.logger.DebugContext(c.ctx_, "api response", "serviceName", apiName, "rpcName", "merchantapi.accounts.notificationsubscriptions.get", "response", internallog.HTTPResponse(res, b))
	return ret, nil
}

type AccountsNotificationsubscriptionsListCall struct {
	s            *Service
	parent       string
	urlParams_   gensupport.URLParams
	ifNoneMatch_ string
	ctx_         context.Context
	header_      http.Header
}

// List: Gets all the notification subscriptions for a merchant.
//
//   - parent: The merchant account who owns the notification subscriptions.
//     Format: `accounts/{account}`.
func (r *AccountsNotificationsubscriptionsService) List(parent string) *AccountsNotificationsubscriptionsListCall {
	c := &AccountsNotificationsubscriptionsListCall{s: r.s, urlParams_: make(gensupport.URLParams)}
	c.parent = parent
	return c
}

// PageSize sets the optional parameter "pageSize": The maximum number of
// notification subscriptions to return in a page. The default value for
// `page_size` is 100. The maximum value is `200`. Values above `200` will be
// coerced to `200`.
func (c *AccountsNotificationsubscriptionsListCall) PageSize(pageSize int64) *AccountsNotificationsubscriptionsListCall {
	c.urlParams_.Set("pageSize", fmt.Sprint(pageSize))
	return c
}

// PageToken sets the optional parameter "pageToken": Token (if provided) to
// retrieve the subsequent page. All other parameters must match the original
// call that provided the page token.
func (c *AccountsNotificationsubscriptionsListCall) PageToken(pageToken string) *AccountsNotificationsubscriptionsListCall {
	c.urlParams_.Set("pageToken", pageToken)
	return c
}

// Fields allows partial responses to be retrieved. See
// https://developers.google.com/gdata/docs/2.0/basics#PartialResponse for more
// details.
func (c *AccountsNotificationsubscriptionsListCall) Fields(s ...googleapi.Field) *AccountsNotificationsubscriptionsListCall {
	c.urlParams_.Set("fields", googleapi.CombineFields(s))
	return c
}

// IfNoneMatch sets an optional parameter which makes the operation fail if the
// object's ETag matches the given value. This is useful for getting updates
// only after the object has changed since the last request.
func (c *AccountsNotificationsubscriptionsListCall) IfNoneMatch(entityTag string) *AccountsNotificationsubscriptionsListCall {
	c.ifNoneMatch_ = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
func (c *AccountsNotificationsubscriptionsListCall) Context(ctx context.Context) *AccountsNotificationsubscriptionsListCall {
	c.ctx_ = ctx
	return c
}

// Header returns a http.Header that can be modified by the caller to add
// headers to the request.
func (c *AccountsNotificationsubscriptionsListCall) Header() http.Header {
	if c.header_ == nil {
		c.header_ = make(http.Header)
	}
	return c.header_
}

func (c *AccountsNotificationsubscriptionsListCall) doRequest(alt string) (*http.Response, error) {
	reqHeaders := gensupport.SetHeaders(c.s.userAgent(), "", c.header_)
	if c.ifNoneMatch_ != "" {
		reqHeaders.Set("If-None-Match", c.ifNoneMatch_)
	}
	c.urlParams_.Set("alt", alt)
	c.urlParams_.Set("prettyPrint", "false")
	urls := googleapi.ResolveRelative(c.s.BasePath, "notifications/v1beta/{+parent}/notificationsubscriptions")
	urls += "?" + c.urlParams_.Encode()
	req, err := http.NewRequest("GET", urls, nil)
	if err != nil {
		return nil, err
	}
	req.Header = reqHeaders
	googleapi.Expand(req.URL, map[string]string{
		"parent": c.parent,
	})
	c.s.logger.DebugContext(c.ctx_, "api request", "serviceName", apiName, "rpcName", "merchantapi.accounts.notificationsubscriptions.list", "request", internallog.HTTPRequest(req, nil))
	return gensupport.SendRequest(c.ctx_, c.s.client, req)
}

// Do executes the "merchantapi.accounts.notificationsubscriptions.list" call.
// Any non-2xx status code is an error. Response headers are in either
// *ListNotificationSubscriptionsResponse.ServerResponse.Header or (if a
// response was returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *AccountsNotificationsubscriptionsListCall) Do(opts ...googleapi.CallOption) (*ListNotificationSubscriptionsResponse, error) {
	gensupport.SetOptions(c.urlParams_, opts...)
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, gensupport.WrapError(&googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		})
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, gensupport.WrapError(err)
	}
	ret := &ListNotificationSubscriptionsResponse{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	target := &ret
	b, err := gensupport.DecodeResponseBytes(target, res)
	if err != nil {
		return nil, err
	}
	c.s.logger.DebugContext(c.ctx_, "api response", "serviceName", apiName, "rpcName", "merchantapi.accounts.notificationsubscriptions.list", "response", internallog.HTTPResponse(res, b))
	return ret, nil
}

// Pages invokes f for each page of results.
// A non-nil error returned from f will halt the iteration.
// The provided context supersedes any context provided to the Context method.
func (c *AccountsNotificationsubscriptionsListCall) Pages(ctx context.Context, f func(*ListNotificationSubscriptionsResponse) error) error {
	c.ctx_ = ctx
	defer c.PageToken(c.urlParams_.Get("pageToken"))
	for {
		x, err := c.Do()
		if err != nil {
			return err
		}
		if err := f(x); err != nil {
			return err
		}
		if x.NextPageToken == "" {
			return nil
		}
		c.PageToken(x.NextPageToken)
	}
}

type AccountsNotificationsubscriptionsPatchCall struct {
	s                        *Service
	name                     string
	notificationsubscription *NotificationSubscription
	urlParams_               gensupport.URLParams
	ctx_                     context.Context
	header_                  http.Header
}

// Patch: Updates an existing notification subscription for a merchant.
//
//   - name: Output only. The `name` of the notification configuration. Generated
//     by the Content API upon creation of a new `NotificationSubscription`. The
//     `account` represents the merchant ID of the merchant that owns the
//     configuration. Format:
//     `accounts/{account}/notificationsubscriptions/{notification_subscription}`.
func (r *AccountsNotificationsubscriptionsService) Patch(name string, notificationsubscription *NotificationSubscription) *AccountsNotificationsubscriptionsPatchCall {
	c := &AccountsNotificationsubscriptionsPatchCall{s: r.s, urlParams_: make(gensupport.URLParams)}
	c.name = name
	c.notificationsubscription = notificationsubscription
	return c
}

// UpdateMask sets the optional parameter "updateMask": List of fields being
// updated.
func (c *AccountsNotificationsubscriptionsPatchCall) UpdateMask(updateMask string) *AccountsNotificationsubscriptionsPatchCall {
	c.urlParams_.Set("updateMask", updateMask)
	return c
}

// Fields allows partial responses to be retrieved. See
// https://developers.google.com/gdata/docs/2.0/basics#PartialResponse for more
// details.
func (c *AccountsNotificationsubscriptionsPatchCall) Fields(s ...googleapi.Field) *AccountsNotificationsubscriptionsPatchCall {
	c.urlParams_.Set("fields", googleapi.CombineFields(s))
	return c
}

// Context sets the context to be used in this call's Do method.
func (c *AccountsNotificationsubscriptionsPatchCall) Context(ctx context.Context) *AccountsNotificationsubscriptionsPatchCall {
	c.ctx_ = ctx
	return c
}

// Header returns a http.Header that can be modified by the caller to add
// headers to the request.
func (c *AccountsNotificationsubscriptionsPatchCall) Header() http.Header {
	if c.header_ == nil {
		c.header_ = make(http.Header)
	}
	return c.header_
}

func (c *AccountsNotificationsubscriptionsPatchCall) doRequest(alt string) (*http.Response, error) {
	reqHeaders := gensupport.SetHeaders(c.s.userAgent(), "application/json", c.header_)
	body, err := googleapi.WithoutDataWrapper.JSONBuffer(c.notificationsubscription)
	if err != nil {
		return nil, err
	}
	c.urlParams_.Set("alt", alt)
	c.urlParams_.Set("prettyPrint", "false")
	urls := googleapi.ResolveRelative(c.s.BasePath, "notifications/v1beta/{+name}")
	urls += "?" + c.urlParams_.Encode()
	req, err := http.NewRequest("PATCH", urls, body)
	if err != nil {
		return nil, err
	}
	req.Header = reqHeaders
	googleapi.Expand(req.URL, map[string]string{
		"name": c.name,
	})
	c.s.logger.DebugContext(c.ctx_, "api request", "serviceName", apiName, "rpcName", "merchantapi.accounts.notificationsubscriptions.patch", "request", internallog.HTTPRequest(req, body.Bytes()))
	return gensupport.SendRequest(c.ctx_, c.s.client, req)
}

// Do executes the "merchantapi.accounts.notificationsubscriptions.patch" call.
// Any non-2xx status code is an error. Response headers are in either
// *NotificationSubscription.ServerResponse.Header or (if a response was
// returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *AccountsNotificationsubscriptionsPatchCall) Do(opts ...googleapi.CallOption) (*NotificationSubscription, error) {
	gensupport.SetOptions(c.urlParams_, opts...)
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, gensupport.WrapError(&googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		})
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, gensupport.WrapError(err)
	}
	ret := &NotificationSubscription{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	target := &ret
	b, err := gensupport.DecodeResponseBytes(target, res)
	if err != nil {
		return nil, err
	}
	c.s.logger.DebugContext(c.ctx_, "api response", "serviceName", apiName, "rpcName", "merchantapi.accounts.notificationsubscriptions.patch", "response", internallog.HTTPResponse(res, b))
	return ret, nil
}
