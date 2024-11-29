// Package rtsp contains a RTSP server.
package rtsp

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/bluenviron/gortsplib/v4"
	"github.com/bluenviron/gortsplib/v4/pkg/auth"
	"github.com/bluenviron/gortsplib/v4/pkg/base"
	"github.com/bluenviron/gortsplib/v4/pkg/liberrors"
	"github.com/google/uuid"

	"github.com/bluenviron/mediamtx/internal/certloader"
	"github.com/bluenviron/mediamtx/internal/conf"
	"github.com/bluenviron/mediamtx/internal/defs"
	"github.com/bluenviron/mediamtx/internal/externalcmd"
	"github.com/bluenviron/mediamtx/internal/logger"
	"github.com/bluenviron/mediamtx/internal/stream"
)

// ErrConnNotFound is returned when a connection is not found.
var ErrConnNotFound = errors.New("connection not found")

// ErrSessionNotFound is returned when a session is not found.
var ErrSessionNotFound = errors.New("session not found")

func printAddresses(srv *gortsplib.Server) string {
	var ret []string

	ret = append(ret, fmt.Sprintf("%s (TCP)", srv.RTSPAddress))

	if srv.UDPRTPAddress != "" {
		ret = append(ret, fmt.Sprintf("%s (UDP/RTP)", srv.UDPRTPAddress))
	}

	if srv.UDPRTCPAddress != "" {
		ret = append(ret, fmt.Sprintf("%s (UDP/RTCP)", srv.UDPRTCPAddress))
	}

	return strings.Join(ret, ", ")
}

type serverPathManager interface {
	Describe(req defs.PathDescribeReq) defs.PathDescribeRes
	AddPublisher(_ defs.PathAddPublisherReq) (defs.Path, error)
	AddReader(_ defs.PathAddReaderReq) (defs.Path, *stream.Stream, error)
}

type serverParent interface {
	logger.Writer
}

// Server is a RTSP server.
type Server struct {
	Address             string
	AuthMethods         []auth.ValidateMethod
	ReadTimeout         conf.StringDuration
	WriteTimeout        conf.StringDuration
	WriteQueueSize      int
	UseUDP              bool
	UseMulticast        bool
	RTPAddress          string
	RTCPAddress         string
	MulticastIPRange    string
	MulticastRTPPort    int
	MulticastRTCPPort   int
	IsTLS               bool
	ServerCert          string
	ServerKey           string
	RTSPAddress         string
	Protocols           map[conf.Protocol]struct{}
	RunOnConnect        string
	RunOnConnectRestart bool
	RunOnDisconnect     string
	ExternalCmdPool     *externalcmd.Pool
	PathManager         serverPathManager
	Parent              serverParent

	ctx       context.Context
	ctxCancel func()
	wg        sync.WaitGroup
	srv       *gortsplib.Server
	mutex     sync.RWMutex
	conns     map[*gortsplib.ServerConn]*conn
	sessions  map[*gortsplib.ServerSession]*session
	loader    *certloader.CertLoader
}

// Initialize initializes the server.
func (s *Server) Initialize() error {
	s.Log(logger.Debug, "server.go > Initialize: Begin")
	s.ctx, s.ctxCancel = context.WithCancel(context.Background())

	s.conns = make(map[*gortsplib.ServerConn]*conn)
	s.sessions = make(map[*gortsplib.ServerSession]*session)

	s.srv = &gortsplib.Server{
		Handler:        s,
		ReadTimeout:    time.Duration(s.ReadTimeout),
		WriteTimeout:   time.Duration(s.WriteTimeout),
		WriteQueueSize: s.WriteQueueSize,
		RTSPAddress:    s.Address,
	}

	if s.UseUDP {
		s.srv.UDPRTPAddress = s.RTPAddress
		s.srv.UDPRTCPAddress = s.RTCPAddress
	}

	if s.UseMulticast {
		s.srv.MulticastIPRange = s.MulticastIPRange
		s.srv.MulticastRTPPort = s.MulticastRTPPort
		s.srv.MulticastRTCPPort = s.MulticastRTCPPort
	}

	if s.IsTLS {
		var err error
		s.loader, err = certloader.New(s.ServerCert, s.ServerKey, s.Parent)
		if err != nil {
			s.Log(logger.Debug, "server.go > Initialize: End-1")
			return err
		}

		s.srv.TLSConfig = &tls.Config{GetCertificate: s.loader.GetCertificate()}
	}

	err := s.srv.Start()
	if err != nil {
		s.Log(logger.Debug, "server.go > Initialize: End-2")
		return err
	}

	s.Log(logger.Info, "listener opened on %s", printAddresses(s.srv))

	s.wg.Add(1)
	go s.run()
	s.Log(logger.Debug, "server.go > Initialize: End-99")

	return nil
}

// Log implements logger.Writer.
func (s *Server) Log(level logger.Level, format string, args ...interface{}) {
	label := func() string {
		if s.IsTLS {
			return "RTSPS"
		}
		return "RTSP"
	}()
	s.Parent.Log(level, "[%s] "+format, append([]interface{}{label}, args...)...)
}

// Close closes the server.
func (s *Server) Close() {
	s.Log(logger.Debug, "server.go > Close: Begin")
	updateDynamoDBStopTime(rtsp_server_id)
	s.Log(logger.Info, "listener is closing")
	s.ctxCancel()
	s.wg.Wait()
	if s.loader != nil {
		s.loader.Close()
	}
	s.Log(logger.Debug, "server.go > Close: End-1")
}

func (s *Server) run() {
	s.Log(logger.Debug, "server.go > run: Begin")
	defer s.wg.Done()

	serverErr := make(chan error)
	go func() {
		serverErr <- s.srv.Wait()
	}()

outer:
	select {
	case err := <-serverErr:
		s.Log(logger.Error, "%s", err)
		break outer

	case <-s.ctx.Done():
		s.srv.Close()
		<-serverErr
		break outer
	}

	s.ctxCancel()
	s.Log(logger.Debug, "server.go > run: End-99")
}

// OnConnOpen implements gortsplib.ServerHandlerOnConnOpen.
func (s *Server) OnConnOpen(ctx *gortsplib.ServerHandlerOnConnOpenCtx) {
	s.Log(logger.Debug, "server.go > OnConnOpen: Begin")
	c := &conn{
		isTLS:               s.IsTLS,
		rtspAddress:         s.RTSPAddress,
		authMethods:         s.AuthMethods,
		readTimeout:         s.ReadTimeout,
		runOnConnect:        s.RunOnConnect,
		runOnConnectRestart: s.RunOnConnectRestart,
		runOnDisconnect:     s.RunOnDisconnect,
		externalCmdPool:     s.ExternalCmdPool,
		pathManager:         s.PathManager,
		rconn:               ctx.Conn,
		rserver:             s.srv,
		parent:              s,
	}
	c.initialize()
	s.mutex.Lock()
	s.conns[ctx.Conn] = c
	s.mutex.Unlock()

	ctx.Conn.SetUserData(c)
	s.Log(logger.Debug, "server.go > OnConnOpen: End-99")
}

// OnConnClose implements gortsplib.ServerHandlerOnConnClose.
func (s *Server) OnConnClose(ctx *gortsplib.ServerHandlerOnConnCloseCtx) {
	s.Log(logger.Debug, "server.go > OnConnClose: Begin")
	s.mutex.Lock()
	c := s.conns[ctx.Conn]
	delete(s.conns, ctx.Conn)
	s.mutex.Unlock()
	c.onClose(ctx.Error)
	s.Log(logger.Debug, "server.go > OnConnClose: End-99")
}

// OnRequest implements gortsplib.ServerHandlerOnRequest.
func (s *Server) OnRequest(sc *gortsplib.ServerConn, req *base.Request) {
	s.Log(logger.Debug, "server.go > OnRequest: Begin")
	c := sc.UserData().(*conn)
	c.onRequest(req)
	s.Log(logger.Debug, "server.go > OnRequest: End-99")
}

// OnResponse implements gortsplib.ServerHandlerOnResponse.
func (s *Server) OnResponse(sc *gortsplib.ServerConn, res *base.Response) {
	s.Log(logger.Debug, "server.go > OnResponse: Begin")
	c := sc.UserData().(*conn)
	c.OnResponse(res)
	s.Log(logger.Debug, "server.go > OnResponse: End-99")
}

// OnSessionOpen implements gortsplib.ServerHandlerOnSessionOpen.
func (s *Server) OnSessionOpen(ctx *gortsplib.ServerHandlerOnSessionOpenCtx) {
	s.Log(logger.Debug, "server.go > OnSessionOpen: Begin")
	se := &session{
		isTLS:           s.IsTLS,
		protocols:       s.Protocols,
		rsession:        ctx.Session,
		rconn:           ctx.Conn,
		rserver:         s.srv,
		externalCmdPool: s.ExternalCmdPool,
		pathManager:     s.PathManager,
		parent:          s,
	}
	se.initialize()
	s.mutex.Lock()
	s.sessions[ctx.Session] = se
	s.mutex.Unlock()
	ctx.Session.SetUserData(se)
	s.Log(logger.Debug, "server.go > OnSessionOpen: End-99")
}

// OnSessionClose implements gortsplib.ServerHandlerOnSessionClose.
func (s *Server) OnSessionClose(ctx *gortsplib.ServerHandlerOnSessionCloseCtx) {
	s.Log(logger.Debug, "server.go > OnSessionClose: Begin")
	s.mutex.Lock()
	se := s.sessions[ctx.Session]
	delete(s.sessions, ctx.Session)
	s.mutex.Unlock()

	if se != nil {
		se.onClose(ctx.Error)
	}
	s.Log(logger.Debug, "server.go > OnSessionClose: End-99")
}

// OnDescribe implements gortsplib.ServerHandlerOnDescribe.
func (s *Server) OnDescribe(ctx *gortsplib.ServerHandlerOnDescribeCtx,
) (*base.Response, *gortsplib.ServerStream, error) {
	s.Log(logger.Debug, "server.go > OnDescribe: Begin")
	c := ctx.Conn.UserData().(*conn)
	s.Log(logger.Debug, "server.go > OnDescribe: End-99")
	return c.onDescribe(ctx)
}

// OnAnnounce implements gortsplib.ServerHandlerOnAnnounce.
func (s *Server) OnAnnounce(ctx *gortsplib.ServerHandlerOnAnnounceCtx) (*base.Response, error) {
	s.Log(logger.Debug, "server.go > OnAnnounce: Begin")
	c := ctx.Conn.UserData().(*conn)
	se := ctx.Session.UserData().(*session)
	s.Log(logger.Debug, "server.go > OnAnnounce: End-99")
	return se.onAnnounce(c, ctx)
}

// OnSetup implements gortsplib.ServerHandlerOnSetup.
func (s *Server) OnSetup(ctx *gortsplib.ServerHandlerOnSetupCtx) (*base.Response, *gortsplib.ServerStream, error) {
	s.Log(logger.Debug, "server.go > OnSetup: Begin")
	c := ctx.Conn.UserData().(*conn)
	se := ctx.Session.UserData().(*session)
	s.Log(logger.Debug, "server.go > OnSetup: End-99")

	return se.onSetup(c, ctx)
}

// OnPlay implements gortsplib.ServerHandlerOnPlay.
func (s *Server) OnPlay(ctx *gortsplib.ServerHandlerOnPlayCtx) (*base.Response, error) {
	s.Log(logger.Debug, "server.go > OnPlay: Begin")
	se := ctx.Session.UserData().(*session)
	s.Log(logger.Debug, "server.go > OnPlay: End-99")
	return se.onPlay(ctx)
}

// OnRecord implements gortsplib.ServerHandlerOnRecord.
func (s *Server) OnRecord(ctx *gortsplib.ServerHandlerOnRecordCtx) (*base.Response, error) {
	s.Log(logger.Debug, "server.go > OnRecord: Begin")
	se := ctx.Session.UserData().(*session)
	s.Log(logger.Debug, "server.go > OnRecord: End-99")
	return se.onRecord(ctx)
}

// OnPause implements gortsplib.ServerHandlerOnPause.
func (s *Server) OnPause(ctx *gortsplib.ServerHandlerOnPauseCtx) (*base.Response, error) {
	s.Log(logger.Debug, "server.go > OnPause: Begin")
	se := ctx.Session.UserData().(*session)
	s.Log(logger.Debug, "server.go > OnPause: End-99")
	return se.onPause(ctx)
}

// OnPacketLost implements gortsplib.ServerHandlerOnDecodeError.
func (s *Server) OnPacketLost(ctx *gortsplib.ServerHandlerOnPacketLostCtx) {
	s.Log(logger.Debug, "server.go > OnPacketLost: Begin")
	se := ctx.Session.UserData().(*session)
	se.onPacketLost(ctx)
	s.Log(logger.Debug, "server.go > OnPacketLost: End-99")
}

// OnDecodeError implements gortsplib.ServerHandlerOnDecodeError.
func (s *Server) OnDecodeError(ctx *gortsplib.ServerHandlerOnDecodeErrorCtx) {
	s.Log(logger.Debug, "server.go > OnDecodeError: Begin")
	se := ctx.Session.UserData().(*session)
	se.onDecodeError(ctx)
	s.Log(logger.Debug, "server.go > OnDecodeError: End-99")
}

// OnStreamWriteError implements gortsplib.ServerHandlerOnStreamWriteError.
func (s *Server) OnStreamWriteError(ctx *gortsplib.ServerHandlerOnStreamWriteErrorCtx) {
	s.Log(logger.Debug, "server.go > OnStreamWriteErrorr: Begin")
	se := ctx.Session.UserData().(*session)
	se.onStreamWriteError(ctx)
	s.Log(logger.Debug, "server.go > OnStreamWriteErrorr: End-99")
}

func (s *Server) findConnByUUID(uuid uuid.UUID) *conn {
	s.Log(logger.Debug, "server.go > findConnByUUID: Begin")
	for _, c := range s.conns {
		if c.uuid == uuid {
			return c
		}
	}

	s.Log(logger.Debug, "server.go > findConnByUUID: End-99")
	return nil
}

func (s *Server) findSessionByUUID(uuid uuid.UUID) (*gortsplib.ServerSession, *session) {

	s.Log(logger.Debug, "server.go > findSessionByUUID: Begin")
	for key, sx := range s.sessions {
		if sx.uuid == uuid {
			return key, sx
		}
	}
	s.Log(logger.Debug, "server.go > findSessionByUUID: End-99")
	return nil, nil
}

// APIConnsList is called by api and metrics.
func (s *Server) APIConnsList() (*defs.APIRTSPConnsList, error) {
	s.Log(logger.Debug, "server.go > APIConnsList: Begin")
	select {
	case <-s.ctx.Done():
		return nil, fmt.Errorf("terminated")
	default:
	}

	s.mutex.RLock()
	defer s.mutex.RUnlock()

	data := &defs.APIRTSPConnsList{
		Items: []*defs.APIRTSPConn{},
	}

	for _, c := range s.conns {
		data.Items = append(data.Items, c.apiItem())
	}

	sort.Slice(data.Items, func(i, j int) bool {
		return data.Items[i].Created.Before(data.Items[j].Created)
	})

	s.Log(logger.Debug, "server.go > APIConnsList: End-99")

	return data, nil
}

// APIConnsGet is called by api.
func (s *Server) APIConnsGet(uuid uuid.UUID) (*defs.APIRTSPConn, error) {
	select {
	case <-s.ctx.Done():
		return nil, fmt.Errorf("terminated")
	default:
	}

	s.mutex.RLock()
	defer s.mutex.RUnlock()

	conn := s.findConnByUUID(uuid)
	if conn == nil {
		return nil, ErrConnNotFound
	}

	return conn.apiItem(), nil
}

// APISessionsList is called by api and metrics.
func (s *Server) APISessionsList() (*defs.APIRTSPSessionList, error) {
	select {
	case <-s.ctx.Done():
		return nil, fmt.Errorf("terminated")
	default:
	}

	s.mutex.RLock()
	defer s.mutex.RUnlock()

	data := &defs.APIRTSPSessionList{
		Items: []*defs.APIRTSPSession{},
	}

	for _, s := range s.sessions {
		data.Items = append(data.Items, s.apiItem())
	}

	sort.Slice(data.Items, func(i, j int) bool {
		return data.Items[i].Created.Before(data.Items[j].Created)
	})

	return data, nil
}

// APISessionsGet is called by api.
func (s *Server) APISessionsGet(uuid uuid.UUID) (*defs.APIRTSPSession, error) {
	select {
	case <-s.ctx.Done():
		return nil, fmt.Errorf("terminated")
	default:
	}

	s.mutex.RLock()
	defer s.mutex.RUnlock()

	_, sx := s.findSessionByUUID(uuid)
	if sx == nil {
		return nil, ErrSessionNotFound
	}

	return sx.apiItem(), nil
}

// APISessionsKick is called by api.
func (s *Server) APISessionsKick(uuid uuid.UUID) error {
	select {
	case <-s.ctx.Done():
		return fmt.Errorf("terminated")
	default:
	}

	s.mutex.RLock()
	defer s.mutex.RUnlock()

	key, sx := s.findSessionByUUID(uuid)
	if sx == nil {
		return ErrSessionNotFound
	}

	sx.Close()
	delete(s.sessions, key)
	sx.onClose(liberrors.ErrServerTerminated{})
	return nil
}

var (
	dynamoDBServerTableName string
	rtsp_server_id          string
	server_operating_system = runtime.GOOS
	server_environment      string
	server_public_ip        string
	server_private_ip       string
	server_region           string
	completeMetadata        map[string]types.AttributeValue
)

// init is called automatically when the package is loaded
func init() {
	dynamoDBServerTableName = os.Getenv("DYNAMODB_SERVER_TABLE_NAME")
	if dynamoDBServerTableName == "" {
		log.Printf("DYNAMODB_TABLE_NAME environment variable is not set")
		dynamoDBServerTableName = "rtsp-servers"
	}

	// Determine if running on Fargate or EC2
	go func() {
		// Check if Fargate metadata URI is set to decide the environment
		if os.Getenv("ECS_CONTAINER_METADATA_URI_V4") != "" {
			var err error
			completeMetadata, err = getFargateMetadata()
			if nil != err {
				log.Printf("Failed to get Fargate metadata: %v", err)
				return
			}
			// Log instance details and start the background update to DynamoDB
			log.Println("Instance details : ", rtsp_server_id)
			log.Println("Server : ", server_environment)

		} else {
			// Assume running on EC2
			var err error
			completeMetadata, err = getInstanceMetadata()
			if nil != err {
				log.Printf("Failed to get Fargate metadata: %v", err)
				return
			}
			// Log instance details and start the background update to DynamoDB
			log.Println("Instance details : ", rtsp_server_id)
			log.Println("Server : ", server_environment)

		}
		populateServerDynamoDB()

	}()
}

const (
	InstanceIdentityDocumentURL = "http://169.254.169.254/latest/dynamic/instance-identity/document"
	RequestTimeoutSeconds       = 2
)

// Function to fetch EC2 metadata
func getInstanceMetadata() (map[string]types.AttributeValue, error) {
	// Use a context with a timeout for metadata request
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*RequestTimeoutSeconds)
	defer cancel()

	// Make the HTTP request to fetch instance identity document
	req, err := http.NewRequestWithContext(ctx, "GET", InstanceIdentityDocumentURL, nil)
	if err != nil {
		return nil, fmt.Errorf("Error creating request for EC2 metadata: %v", err)

	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Error retrieving EC2 metadata: %v", err)

	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Failed to fetch metadata: HTTP %v", resp.Status)

	}

	// Parse the JSON response into a map
	var metadata map[string]interface{}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("Error reading EC2 metadata response: %v", err)

	}

	if err := json.Unmarshal(body, &metadata); err != nil {
		return nil, fmt.Errorf("Error decoding EC2 metadata JSON: %v", err)

	}

	// Assign values to the global variables
	if instanceID, ok := metadata["instanceId"].(string); ok {
		rtsp_server_id = instanceID
	} else {
		fmt.Println("Error: instanceId not found in metadata")
	}

	if region, ok := metadata["region"].(string); ok {
		server_region = region
	} else {
		fmt.Println("Error: region not found in metadata")
	}

	// Assign environment and operating system
	server_environment = "EC2"

	// Fetch private and public IP addresses separately
	server_public_ip = getPublicIP()

	if privateIP, ok := metadata["privateIp"].(string); ok {
		server_private_ip = privateIP
	} else {
		fmt.Println("Error: privateIp not found in metadata")
	}
	// Assign complete metadata
	ec2_metadata := convertToDynamoDBMap(metadata)

	return ec2_metadata, nil
}

func getFargateMetadata() (map[string]types.AttributeValue, error) {

	// Get the metadata URI from the environment variable
	metadataUri := os.Getenv("ECS_CONTAINER_METADATA_URI_V4")
	if metadataUri == "" {
		metadataUri = "http://169.254.170.2/v4"
	}

	// Append /task to get full task metadata
	taskEndpoint := metadataUri + "/task"

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", taskEndpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request for Fargate metadata: %v", err)

	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error retrieving Fargate metadata: %v", err)

	}
	defer resp.Body.Close()

	var full_metadata map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&full_metadata); err != nil {
		return nil, fmt.Errorf("Error decoding Fargate metadata JSON: %v", err)
	}

	taskARN, ok := full_metadata["TaskARN"].(string)
	if !ok {
		return nil, fmt.Errorf("TaskARN not found or invalid in metadata")
	}

	// Extract Task ID from TaskARN
	taskIDParts := strings.Split(taskARN, "/")
	if len(taskIDParts) > 1 {
		rtsp_server_id = taskIDParts[len(taskIDParts)-1]
	} else {
		return nil, fmt.Errorf("failed to parse task ID from TaskARN")
	}

	// Extract Region from TaskARN
	arnParts := strings.Split(taskARN, ":")
	if len(arnParts) > 3 {
		server_region = arnParts[3]
	} else {
		return nil, fmt.Errorf("failed to parse region from TaskARN")
	}

	// Fetch Private IP from Containers > Networks > IPv4Addresses
	containers, ok := full_metadata["Containers"].([]interface{})
	if !ok || len(containers) == 0 {
		return nil, fmt.Errorf("no containers found in metadata")
	}

	firstContainer, ok := containers[0].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid container format in metadata")
	}

	networks, ok := firstContainer["Networks"].([]interface{})
	if !ok || len(networks) == 0 {
		return nil, fmt.Errorf("no networks found in container metadata")
	}

	firstNetwork, ok := networks[0].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid network format in metadata")
	}

	ipv4Addresses, ok := firstNetwork["IPv4Addresses"].([]interface{})
	if !ok || len(ipv4Addresses) == 0 {
		return nil, fmt.Errorf("no IPv4 addresses found in network metadata")
	}

	server_private_ip, ok = ipv4Addresses[0].(string)
	if !ok {
		return nil, fmt.Errorf("invalid IPv4 address format")
	}

	// Set HostType and OS for DynamoDB (these may be known/static values)
	server_environment = "Fargate"
	server_public_ip = getPublicIP()
	dynamoMap := convertToDynamoDBMap(full_metadata)
	return dynamoMap, nil
}

// Helper function to recursively convert JSON map to DynamoDB map
func convertToDynamoDBMap(data map[string]interface{}) map[string]types.AttributeValue {
	dynamoMap := make(map[string]types.AttributeValue)
	for key, value := range data {
		switch v := value.(type) {
		case string:
			dynamoMap[key] = &types.AttributeValueMemberS{Value: v}
		case bool:
			dynamoMap[key] = &types.AttributeValueMemberBOOL{Value: v}
		case float64: // AWS DynamoDB uses string or integer, float handling may vary
			dynamoMap[key] = &types.AttributeValueMemberN{Value: fmt.Sprintf("%v", v)}
		case map[string]interface{}:
			dynamoMap[key] = &types.AttributeValueMemberM{Value: convertToDynamoDBMap(v)}
		case []interface{}:
			dynamoMap[key] = &types.AttributeValueMemberL{Value: convertToDynamoDBList(v)}
		}
	}
	return dynamoMap
}

// Helper function to convert a list to DynamoDB list format
func convertToDynamoDBList(data []interface{}) []types.AttributeValue {
	var dynamoList []types.AttributeValue
	for _, item := range data {
		switch v := item.(type) {
		case string:
			dynamoList = append(dynamoList, &types.AttributeValueMemberS{Value: v})
		case bool:
			dynamoList = append(dynamoList, &types.AttributeValueMemberBOOL{Value: v})
		case float64:
			dynamoList = append(dynamoList, &types.AttributeValueMemberN{Value: fmt.Sprintf("%v", v)})
		case map[string]interface{}:
			dynamoList = append(dynamoList, &types.AttributeValueMemberM{Value: convertToDynamoDBMap(v)})
		}
	}
	return dynamoList
}

// Function to update DynamoDB asynchronously
func populateServerDynamoDB() {
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithRegion("us-east-1"), // Replace with your desired region
	)
	if err != nil {
		panic("unable to load SDK config, " + err.Error())
	}

	// Initialize DynamoDB client with the configuration
	dbSvc = dynamodb.NewFromConfig(cfg)
	timestamp := time.Now().UTC().Format(time.RFC3339)
	formattedSessionCount := fmt.Sprintf("%06d", activeSessionCount)

	input := &dynamodb.PutItemInput{
		TableName: aws.String(dynamoDBServerTableName),
		Item: map[string]types.AttributeValue{
			"rtsp_server_id": &types.AttributeValueMemberS{Value: rtsp_server_id},
			"host_type":      &types.AttributeValueMemberS{Value: server_environment},
			"os":             &types.AttributeValueMemberS{Value: server_operating_system},
			"private_ip":     &types.AttributeValueMemberS{Value: server_private_ip},
			"public_ip":      &types.AttributeValueMemberS{Value: server_public_ip},
			"region":         &types.AttributeValueMemberS{Value: server_region},
			"time_started":   &types.AttributeValueMemberS{Value: timestamp},
			"server_info":    &types.AttributeValueMemberM{Value: completeMetadata},
			"session_count":  &types.AttributeValueMemberS{Value: formattedSessionCount},
		},
	}

	go func() {
		_, err := dbSvc.PutItem(context.TODO(), input) // Passing context as required
		if err != nil {
			log.Printf("failed to log stream start to DynamoDB: %v", err)
		}
	}()

}

// Function to update the time_stopped attribute in DynamoDB when the server stops
func updateDynamoDBStopTime(rtsp_server_id string) {

	// Get the current time
	timestamp := time.Now().UTC().Format(time.RFC3339)

	// Prepare the update input
	input := &dynamodb.UpdateItemInput{
		TableName: aws.String(dynamoDBServerTableName),
		Key: map[string]types.AttributeValue{
			"rtsp_server_id": &types.AttributeValueMemberS{Value: rtsp_server_id},
		},
		UpdateExpression: aws.String("SET time_stopped = :time_stopped"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":time_stopped": &types.AttributeValueMemberS{Value: timestamp},
		},
	}

	// Perform the update operation
	_, err := dbSvc.UpdateItem(context.TODO(), input)
	if err != nil {
		log.Printf("Failed to update time_stopped in DynamoDB: %v", err)
	}
}

func getPublicIP() string {
	resp, err := http.Get("https://api.ipify.org?format=json")
	if err != nil {
		log.Printf("error fetching public IP: %v", err)
		return ""
	}
	defer resp.Body.Close()

	var result map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		log.Printf("error fetching public IP: %v", err)
		return ""
	}

	return result["ip"]
}
