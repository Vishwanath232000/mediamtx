package rtsp

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/bluenviron/gortsplib/v4"
	rtspauth "github.com/bluenviron/gortsplib/v4/pkg/auth"
	"github.com/bluenviron/gortsplib/v4/pkg/base"
	"github.com/google/uuid"
	"github.com/pion/rtp"

	"github.com/bluenviron/mediamtx/internal/auth"
	"github.com/bluenviron/mediamtx/internal/conf"
	"github.com/bluenviron/mediamtx/internal/defs"
	"github.com/bluenviron/mediamtx/internal/externalcmd"
	"github.com/bluenviron/mediamtx/internal/hooks"
	"github.com/bluenviron/mediamtx/internal/logger"
	"github.com/bluenviron/mediamtx/internal/stream"

	// AWS SDK v2 imports
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
)

var (
	dbSvc                   *dynamodb.Client
	activeSessionCount      int
	countMutex              sync.Mutex
	dynamoDBStreamTableName string
	sqsSvc                  *sqs.Client
	queueURL                *string
)

func init() {
	log.Printf("session.go > init: Begin")

	// Load the AWS configuration from the environment, credentials file, or IAM role
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithRegion("us-east-1"), // Replace with your desired region
	)
	if err != nil {
		log.Printf("unable to load SDK config, " + err.Error())
	}

	// Initialize DynamoDB client with the configuration
	dbSvc = dynamodb.NewFromConfig(cfg)

	dynamoDBStreamTableName = os.Getenv("DYNAMODB_STREAM_TABLE_NAME")
	if dynamoDBStreamTableName == "" {
		log.Printf("DYNAMODB_TABLE_NAME environment variable is not set")
		dynamoDBStreamTableName = "rtsp-streams"

	}
	queueName := os.Getenv("SQS_NAME")
	if queueName == "" {
		queueName = "vish-stream-sqs"
	}
	sqsSvc = sqs.NewFromConfig(cfg)
	getQueueURLInput := &sqs.GetQueueUrlInput{
		QueueName: aws.String(queueName),
	}
	getQueueURLOutput, err := sqsSvc.GetQueueUrl(context.TODO(), getQueueURLInput)
	if err != nil {
		log.Printf("Failed to get queue URL: %v", err)
	}
	queueURL = getQueueURLOutput.QueueUrl
	log.Printf("session.go > init: End-99")
}

type session struct {
	isTLS           bool
	protocols       map[conf.Protocol]struct{}
	rsession        *gortsplib.ServerSession
	rconn           *gortsplib.ServerConn
	rserver         *gortsplib.Server
	externalCmdPool *externalcmd.Pool
	pathManager     serverPathManager
	parent          *Server

	uuid            uuid.UUID
	created         time.Time
	path            defs.Path
	stream          *stream.Stream
	onUnreadHook    func()
	mutex           sync.Mutex
	state           gortsplib.ServerSessionState
	transport       *gortsplib.Transport
	pathName        string
	query           string
	decodeErrLogger logger.Writer
	writeErrLogger  logger.Writer
}

func (s *session) initialize() {
	s.Log(logger.Debug, "session.go > initialize: Begin")
	s.uuid = uuid.New()
	s.created = time.Now()

	s.decodeErrLogger = logger.NewLimitedLogger(s)
	s.writeErrLogger = logger.NewLimitedLogger(s)

	s.Log(logger.Info, "created by %v", s.rconn.NetConn().RemoteAddr())
	s.Log(logger.Debug, "session.go > initialize: End-99")
}

// Close closes a Session.
func (s *session) Close() {
	s.rsession.Close()
}

func (s *session) remoteAddr() net.Addr {
	return s.rconn.NetConn().RemoteAddr()
}

// Log implements logger.Writer.
func (s *session) Log(level logger.Level, format string, args ...interface{}) {
	id := hex.EncodeToString(s.uuid[:4])
	s.parent.Log(level, "[session %s] "+format, append([]interface{}{id}, args...)...)
}

// onClose is called by rtspServer.
func (s *session) onClose(err error) {
	s.Log(logger.Debug, "session.go > onClose: Begin")
	if s.rsession.State() == gortsplib.ServerSessionStatePlay {
		s.onUnreadHook()
	}

	switch s.rsession.State() {
	case gortsplib.ServerSessionStatePrePlay, gortsplib.ServerSessionStatePlay:
		s.path.RemoveReader(defs.PathRemoveReaderReq{Author: s})

	case gortsplib.ServerSessionStatePreRecord, gortsplib.ServerSessionStateRecord:
		s.path.RemovePublisher(defs.PathRemovePublisherReq{Author: s})
		countMutex.Lock()
		activeSessionCount--
		formattedSessionCount := fmt.Sprintf("%06d", activeSessionCount) // Pads to 6 digits with leading zeros
		countMutex.Unlock()
		timestamp := time.Now().UTC().Format(time.RFC3339)

		// fmt.Printf(timestamp, " | %s | STOPPED | %s | %s\n", formattedSessionCount, s.uuid, s.path.Name())
		s.Log(logger.Info, "| %s | STOPPED | %s", formattedSessionCount, s.path.Name())

		// Only log to DynamoDB and print stop message for publishers
		updateStreamDynamoDBStopTime(s.path.Name(), timestamp)

		updateServerDynamoDB(formattedSessionCount, timestamp)

	}

	s.path = nil
	s.stream = nil
	s.Log(logger.Info, "destroyed: %v", err)
	s.Log(logger.Debug, "session.go > onClose: End-99")
}

// onAnnounce is called by rtspServer.
func (s *session) onAnnounce(c *conn, ctx *gortsplib.ServerHandlerOnAnnounceCtx) (*base.Response, error) {
	s.Log(logger.Debug, "session.go > onAnnounce: Begin")
	if len(ctx.Path) == 0 || ctx.Path[0] != '/' {
		s.Log(logger.Debug, "session.go > onAnnounce: End-1")
		return &base.Response{
			StatusCode: base.StatusBadRequest,
		}, fmt.Errorf("invalid path")
	}
	ctx.Path = ctx.Path[1:]

	if c.authNonce == "" {
		var err error
		c.authNonce, err = rtspauth.GenerateNonce()
		if err != nil {
			s.Log(logger.Debug, "session.go > onAnnounce: End-2")
			return &base.Response{
				StatusCode: base.StatusInternalServerError,
			}, err
		}
	}

	path, err := s.pathManager.AddPublisher(defs.PathAddPublisherReq{
		Author: s,
		AccessRequest: defs.PathAccessRequest{
			Name:        ctx.Path,
			Query:       ctx.Query,
			Publish:     true,
			IP:          c.ip(),
			Proto:       auth.ProtocolRTSP,
			ID:          &c.uuid,
			RTSPRequest: ctx.Request,
			RTSPNonce:   c.authNonce,
		},
	})
	if err != nil {
		var terr *auth.Error
		if errors.As(err, &terr) {
			s.Log(logger.Debug, "session.go > onAnnounce: End-3")
			return c.handleAuthError(terr)
		}

		s.Log(logger.Debug, "session.go > onAnnounce: End-4")

		return &base.Response{
			StatusCode: base.StatusBadRequest,
		}, err
	}

	s.path = path

	s.mutex.Lock()
	s.state = gortsplib.ServerSessionStatePreRecord
	s.pathName = ctx.Path
	s.query = ctx.Query
	s.mutex.Unlock()

	countMutex.Lock()
	activeSessionCount++
	formattedSessionCount := fmt.Sprintf("%06d", activeSessionCount) // Pads to 6 digits with leading zeros
	countMutex.Unlock()
	s.Log(logger.Info, "| %s | STARTED READING | %s", formattedSessionCount, s.path.Name())
	timestamp := time.Now().UTC().Format(time.RFC3339)
	populateStreamDynamoDB(s.path.Name(), s.uuid.String(), s.rconn.NetConn().RemoteAddr().String(), timestamp)
	updateServerDynamoDB(formattedSessionCount, timestamp)

	s.Log(logger.Debug, "session.go > onAnnounce: End-99")

	return &base.Response{
		StatusCode: base.StatusOK,
	}, nil
}

// onSetup is called by rtspServer.
func (s *session) onSetup(c *conn, ctx *gortsplib.ServerHandlerOnSetupCtx) (*base.Response, *gortsplib.ServerStream, error) {
	s.Log(logger.Debug, "session.go > onSetup: Begin")
	if len(ctx.Path) == 0 || ctx.Path[0] != '/' {

		s.Log(logger.Debug, "session.go > onSetup: End-1")

		return &base.Response{
			StatusCode: base.StatusBadRequest,
		}, nil, fmt.Errorf("invalid path")
	}
	ctx.Path = ctx.Path[1:]

	// in case the client is setupping a stream with UDP or UDP-multicast, and these
	// transport protocols are disabled, gortsplib already blocks the request.
	// we have only to handle the case in which the transport protocol is TCP
	// and it is disabled.
	if ctx.Transport == gortsplib.TransportTCP {
		if _, ok := s.protocols[conf.Protocol(gortsplib.TransportTCP)]; !ok {
			s.Log(logger.Debug, "session.go > onSetup: End-2")
			return &base.Response{
				StatusCode: base.StatusUnsupportedTransport,
			}, nil, nil
		}
	}

	switch s.rsession.State() {
	case gortsplib.ServerSessionStateInitial, gortsplib.ServerSessionStatePrePlay: // play
		if c.authNonce == "" {
			var err error
			c.authNonce, err = rtspauth.GenerateNonce()
			if err != nil {
				s.Log(logger.Debug, "session.go > onSetup: End-3")
				return &base.Response{
					StatusCode: base.StatusInternalServerError,
				}, nil, err
			}
		}

		path, stream, err := s.pathManager.AddReader(defs.PathAddReaderReq{
			Author: s,
			AccessRequest: defs.PathAccessRequest{
				Name:        ctx.Path,
				Query:       ctx.Query,
				IP:          c.ip(),
				Proto:       auth.ProtocolRTSP,
				ID:          &c.uuid,
				RTSPRequest: ctx.Request,
				RTSPNonce:   c.authNonce,
			},
		})
		if err != nil {
			var terr *auth.Error
			if errors.As(err, &terr) {
				res, err2 := c.handleAuthError(terr)
				s.Log(logger.Debug, "session.go > onSetup: End-4")
				return res, nil, err2
			}

			var terr2 defs.PathNoOnePublishingError
			if errors.As(err, &terr2) {
				s.Log(logger.Debug, "session.go > onSetup: End-5")
				return &base.Response{
					StatusCode: base.StatusNotFound,
				}, nil, err
			}
			s.Log(logger.Debug, "session.go > onSetup: End-6")

			return &base.Response{
				StatusCode: base.StatusBadRequest,
			}, nil, err
		}

		s.path = path
		s.stream = stream

		s.mutex.Lock()
		s.state = gortsplib.ServerSessionStatePrePlay
		s.pathName = ctx.Path
		s.query = ctx.Query
		s.mutex.Unlock()

		var rstream *gortsplib.ServerStream
		if !s.isTLS {
			rstream = stream.RTSPStream(s.rserver)
		} else {
			rstream = stream.RTSPSStream(s.rserver)
		}

		s.Log(logger.Debug, "session.go > onSetup: End-7")
		return &base.Response{
			StatusCode: base.StatusOK,
		}, rstream, nil

	default: // record
		s.Log(logger.Debug, "session.go > onSetup: End-99")
		return &base.Response{
			StatusCode: base.StatusOK,
		}, nil, nil
	}
}

// onPlay is called by rtspServer.
func (s *session) onPlay(_ *gortsplib.ServerHandlerOnPlayCtx) (*base.Response, error) {
	s.Log(logger.Debug, "session.go >  onPlay: Begin")
	h := make(base.Header)

	if s.rsession.State() == gortsplib.ServerSessionStatePrePlay {
		s.Log(logger.Info, "is reading from path '%s', with %s, %s",
			s.path.Name(),
			s.rsession.SetuppedTransport(),
			defs.MediasInfo(s.rsession.SetuppedMedias()))

		s.onUnreadHook = hooks.OnRead(hooks.OnReadParams{
			Logger:          s,
			ExternalCmdPool: s.externalCmdPool,
			Conf:            s.path.SafeConf(),
			ExternalCmdEnv:  s.path.ExternalCmdEnv(),
			Reader:          s.APIReaderDescribe(),
			Query:           s.rsession.SetuppedQuery(),
		})

		s.mutex.Lock()
		s.state = gortsplib.ServerSessionStatePlay
		s.transport = s.rsession.SetuppedTransport()
		s.mutex.Unlock()
	}
	s.Log(logger.Debug, "session.go >  onPlay: End-99")

	return &base.Response{
		StatusCode: base.StatusOK,
		Header:     h,
	}, nil
}

// onRecord is called by rtspServer.
func (s *session) onRecord(_ *gortsplib.ServerHandlerOnRecordCtx) (*base.Response, error) {
	s.Log(logger.Debug, "session.go >  onRecord: Begin")
	stream, err := s.path.StartPublisher(defs.PathStartPublisherReq{
		Author:             s,
		Desc:               s.rsession.AnnouncedDescription(),
		GenerateRTPPackets: false,
	})
	if err != nil {
		s.Log(logger.Debug, "session.go >  onRecord: End-1")
		return &base.Response{
			StatusCode: base.StatusBadRequest,
		}, err
	}

	s.stream = stream

	for _, medi := range s.rsession.AnnouncedDescription().Medias {
		for _, forma := range medi.Formats {
			cmedi := medi
			cforma := forma

			s.rsession.OnPacketRTP(cmedi, cforma, func(pkt *rtp.Packet) {
				pts, ok := s.rsession.PacketPTS2(cmedi, pkt)
				if !ok {
					s.Log(logger.Debug, "session.go >  onRecord: End-2")
					return
				}

				stream.WriteRTPPacket(cmedi, cforma, pkt, time.Now(), pts)
			})
		}
	}

	s.mutex.Lock()
	s.state = gortsplib.ServerSessionStateRecord
	s.transport = s.rsession.SetuppedTransport()
	s.mutex.Unlock()
	formattedSessionCount := fmt.Sprintf("%06d", activeSessionCount) // Pads to 6 digits with leading zeros
	// countMutex.Unlock()

	s.Log(logger.Info, "| %s | STARTED STREAMING | %s", formattedSessionCount, s.path.Name())

	// Log to DynamoDB for publishers
	messagePayload := map[string]string{
		"adapter_wifimac":   s.path.Name(),
		"server_public_ip":  server_public_ip,
		"server_private_ip": server_private_ip,
	}

	messageBody, err := json.Marshal(messagePayload)
	if err != nil {
		log.Printf("Failed to marshal message body: %v", err)

	}

	// Create the SendMessageInput
	sqsInput := &sqs.SendMessageInput{
		MessageBody: aws.String(string(messageBody)),
		QueueUrl:    aws.String(*queueURL), // Replace with your SQS queue URL
	}
	sqsResp, err := sqsSvc.SendMessage(context.Background(), sqsInput)
	if err != nil {
		log.Printf("Failed to send message to SQS: %v", err)
	}

	// Check and log the Message ID
	if sqsResp.MessageId != nil {
		log.Printf("Message sent to SQS successfully, MessageId: %s", *sqsResp.MessageId)
	} else {
		log.Println("MessageId is nil in SQS response")
	}

	s.Log(logger.Debug, "session.go >  onRecord: End-99")
	return &base.Response{
		StatusCode: base.StatusOK,
	}, nil
}

// onPause is called by rtspServer.
func (s *session) onPause(_ *gortsplib.ServerHandlerOnPauseCtx) (*base.Response, error) {
	s.Log(logger.Debug, "session.go > onPause: Begin")
	switch s.rsession.State() {
	case gortsplib.ServerSessionStatePlay:
		s.onUnreadHook()

		s.mutex.Lock()
		s.state = gortsplib.ServerSessionStatePrePlay
		s.mutex.Unlock()

	case gortsplib.ServerSessionStateRecord:
		s.path.StopPublisher(defs.PathStopPublisherReq{Author: s})

		s.mutex.Lock()
		s.state = gortsplib.ServerSessionStatePreRecord
		s.mutex.Unlock()
	}
	s.Log(logger.Debug, "session.go > onPause: End-99")

	return &base.Response{
		StatusCode: base.StatusOK,
	}, nil
}

// APIReaderDescribe implements reader.
func (s *session) APIReaderDescribe() defs.APIPathSourceOrReader {

	return defs.APIPathSourceOrReader{
		Type: func() string {
			if s.isTLS {
				return "rtspsSession"
			}
			return "rtspSession"
		}(),
		ID: s.uuid.String(),
	}
}

// APISourceDescribe implements source.
func (s *session) APISourceDescribe() defs.APIPathSourceOrReader {
	return s.APIReaderDescribe()
}

// onPacketLost is called by rtspServer.
func (s *session) onPacketLost(ctx *gortsplib.ServerHandlerOnPacketLostCtx) {
	s.Log(logger.Debug, "session.go > onPacketLost: Begin")
	s.decodeErrLogger.Log(logger.Warn, ctx.Error.Error())
	s.Log(logger.Debug, "session.go > onPacketLost: End-99")
}

// onDecodeError is called by rtspServer.
func (s *session) onDecodeError(ctx *gortsplib.ServerHandlerOnDecodeErrorCtx) {
	s.Log(logger.Debug, "session.go > onDecodeError: Begin")
	s.decodeErrLogger.Log(logger.Warn, ctx.Error.Error())
	s.Log(logger.Debug, "session.go > onDecodeError: End-99")
}

// onStreamWriteError is called by rtspServer.
func (s *session) onStreamWriteError(ctx *gortsplib.ServerHandlerOnStreamWriteErrorCtx) {
	s.Log(logger.Debug, "session.go > onStreamWriteError: Begin")
	s.writeErrLogger.Log(logger.Warn, ctx.Error.Error())
	s.Log(logger.Debug, "session.go > onStreamWriteError: End-99")
}

func (s *session) apiItem() *defs.APIRTSPSession {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return &defs.APIRTSPSession{
		ID:         s.uuid,
		Created:    s.created,
		RemoteAddr: s.remoteAddr().String(),
		State: func() defs.APIRTSPSessionState {
			switch s.state {
			case gortsplib.ServerSessionStatePrePlay,
				gortsplib.ServerSessionStatePlay:
				return defs.APIRTSPSessionStateRead

			case gortsplib.ServerSessionStatePreRecord,
				gortsplib.ServerSessionStateRecord:
				return defs.APIRTSPSessionStatePublish
			}
			return defs.APIRTSPSessionStateIdle
		}(),
		Path:  s.pathName,
		Query: s.query,
		Transport: func() *string {
			if s.transport == nil {
				return nil
			}
			v := s.transport.String()
			return &v
		}(),
		BytesReceived: s.rsession.BytesReceived(),
		BytesSent:     s.rsession.BytesSent(),
	}
}

func populateStreamDynamoDB(stream_id string, session_id string, streamer_ip_address string, timestamp string) {

	input := &dynamodb.PutItemInput{
		TableName: aws.String(dynamoDBStreamTableName),
		Item: map[string]types.AttributeValue{
			"stream_id": &types.AttributeValueMemberS{
				Value: stream_id,
			},
			"is_active": &types.AttributeValueMemberBOOL{
				Value: true,
			},
			"rtsp_server_id": &types.AttributeValueMemberS{
				Value: rtsp_server_id,
			},
			"session_id": &types.AttributeValueMemberS{
				Value: session_id,
			},
			"streamer_ip_address": &types.AttributeValueMemberS{
				Value: streamer_ip_address,
			},
			"time_connected": &types.AttributeValueMemberS{
				Value: timestamp,
			},
		},
	}

	go func() {
		_, err := dbSvc.PutItem(context.TODO(), input) // Passing context as required
		if err != nil {
			log.Printf("failed to log stream start to DynamoDB: %v", err)
		}
	}()

}

func updateServerDynamoDB(formattedSessionCount string, time_updated string) {
	input := &dynamodb.UpdateItemInput{
		TableName: aws.String(dynamoDBServerTableName),
		Key: map[string]types.AttributeValue{
			"rtsp_server_id": &types.AttributeValueMemberS{
				Value: rtsp_server_id,
			},
		},
		UpdateExpression: aws.String("SET time_updated = :time_updated , session_count=:session_count"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":time_updated": &types.AttributeValueMemberS{
				Value: time_updated,
			},
			":session_count": &types.AttributeValueMemberS{
				Value: formattedSessionCount,
			},
		},
	}
	go func() {
		_, err := dbSvc.UpdateItem(context.TODO(), input) // Passing context as required
		if err != nil {
			log.Printf("failed to update the server table after connection starts: %v", err)
		}
	}()

}

func updateStreamDynamoDBStopTime(stream_id string, timestamp string) {
	input := &dynamodb.UpdateItemInput{
		TableName: aws.String(dynamoDBStreamTableName),
		Key: map[string]types.AttributeValue{
			"stream_id": &types.AttributeValueMemberS{
				Value: stream_id,
			},
		},
		UpdateExpression:    aws.String("SET time_disconnected = :time_disconnected, is_active = :is_active"),
		ConditionExpression: aws.String("is_active = :is_active_condition"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":time_disconnected": &types.AttributeValueMemberS{
				Value: timestamp,
			},
			":is_active": &types.AttributeValueMemberBOOL{
				Value: false,
			},
			":is_active_condition": &types.AttributeValueMemberBOOL{
				Value: true,
			},
		},
	}
	go func() {
		_, err := dbSvc.UpdateItem(context.TODO(), input) // Passing context as required
		if err != nil {
			log.Printf("failed to log stream stop to DynamoDB: %v", err)
		}
	}()

}
