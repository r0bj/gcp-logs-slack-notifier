package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"gopkg.in/alecthomas/kingpin.v2"
)

const (
	ver           string = "0.6"
	logDateLayout string = "2006-01-02 15:04:05"
)

var (
	verbose         = kingpin.Flag("verbose", "Verbose mode.").Short('v').Bool()
	port            = kingpin.Flag("port", "Port to listen on.").Envar("PORT").String()
	slackWebhookUrl = kingpin.Flag("slack-webhook-url", "Slack webhook URL.").Envar("SLACK_WEBHOOK_URL").Required().String()
)

// PubSubMessage : containts PubSub message content
type PubSubMessage struct {
	Message struct {
		Data       []byte `json:"data"`
		Attributes struct {
			Timestamp string `json:"logging.googleapis.com/timestamp"`
		} `json:"attributes"`
	} `json:"message"`
	Subscription string `json:"subscription"`
}

// PubSubMessageData : containts PubSub message data content
type PubSubMessageData struct {
	ProtoPayload struct {
		MethodName         string `json:"methodName"`
		ResourceName       string `json:"resourceName"`
		ServiceName        string `json:"serviceName"`
		AuthenticationInfo struct {
			PrincipalEmail string `json:"principalEmail"`
		} `json:"authenticationInfo"`
	} `json:"protoPayload"`
	LogName  string `json:"logName"`
	Severity string `json:"severity"`
	Resource struct {
		Type   string `json:"type"`
		Labels struct {
			ProjectId string `json:"project_id"`
			Location  string `json:"location"`
			Zone      string `json:"zone"`
		} `json:"labels"`
	} `json:"resource"`
}

// SlackRequestBody : containts slack request body
type SlackRequestBody struct {
	Text        string                   `json:"text,omitempty"`
	Attachments []SlackMessageAttachment `json:"attachments"`
}

// SlackMessageAttachment : containts slack message attachment data
type SlackMessageAttachment struct {
	Text     string                 `json:"text,omitempty"`
	Color    string                 `json:"color,omitempty"`
	MrkdwnIn []string               `json:"mrkdwn_in,omitempty"`
	Fields   []SlackAttachmentField `json:"fields"`
}

// SlackAttachmentField : containts slack attachment field data
type SlackAttachmentField struct {
	Short bool   `json:"short"`
	Title string `json:"title"`
	Value string `json:"value"`
}

func internalHealth(w http.ResponseWriter, req *http.Request) {
	fmt.Fprintf(w, "OK\n")
}

func handlePubSub(w http.ResponseWriter, r *http.Request) {
	var m PubSubMessage
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Infof("ioutil.ReadAll: %v", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	if err := json.Unmarshal(body, &m); err != nil {
		log.Infof("json.Unmarshal: %v", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	log.Debugf("Request data: %+v", strings.ReplaceAll(string(body), " ", ""))

	if len(m.Message.Data) > 0 {
		var pubSubMessageData PubSubMessageData
		if err := json.Unmarshal(m.Message.Data, &pubSubMessageData); err != nil {
			log.Infof("json.Unmarshal: %v", err)
			return
		}

		slackRequestBody := SlackRequestBody{
			Attachments: []SlackMessageAttachment{
				SlackMessageAttachment{
					Color:  getSlackAttachmentColor(pubSubMessageData),
					Fields: fillMessageFields(pubSubMessageData),
				},
			},
		}

		log.Info("Sending slack notification")
		if err := sendSlackNotification(*slackWebhookUrl, slackRequestBody); err != nil {
			log.Errorf("Sending slack message fail: %v", err)
		}
	}
}

func getSlackAttachmentColor(pubSubMessageData PubSubMessageData) string {
	var result string
	// https://cloud.google.com/logging/docs/reference/v2/rest/v2/LogEntry#LogSeverity
	if pubSubMessageData.Severity == "INFO" ||
		pubSubMessageData.Severity == "NOTICE" {
		result = "good"
	} else if pubSubMessageData.Severity == "WARNING" {
		result = "warning"
	} else if pubSubMessageData.Severity == "ERROR" ||
		pubSubMessageData.Severity == "CRITICAL" ||
		pubSubMessageData.Severity == "ALERT" ||
		pubSubMessageData.Severity == "EMERGENCY" {
		result = "danger"
	}

	return result
}

func fillMessageFields(pubSubMessageData PubSubMessageData) []SlackAttachmentField {
	result := []SlackAttachmentField{
		SlackAttachmentField{
			Title: "project",
			Value: pubSubMessageData.Resource.Labels.ProjectId,
			Short: true,
		},
		SlackAttachmentField{
			Title: "category",
			Value: strings.Split(pubSubMessageData.ProtoPayload.ServiceName, ".")[0],
			Short: true,
		},
	}

	if pubSubMessageData.ProtoPayload.AuthenticationInfo.PrincipalEmail != "" {
		result = append(result, SlackAttachmentField{
			Title: "user",
			Value: pubSubMessageData.ProtoPayload.AuthenticationInfo.PrincipalEmail,
			Short: true,
		})
	}

	if pubSubMessageData.Resource.Labels.Location != "" {
		result = append(result, SlackAttachmentField{
			Title: "location",
			Value: pubSubMessageData.Resource.Labels.Location,
			Short: true,
		})
	} else if pubSubMessageData.Resource.Labels.Zone != "" {
		result = append(result, SlackAttachmentField{
			Title: "zone",
			Value: pubSubMessageData.Resource.Labels.Zone,
			Short: true,
		})
	}

	if pubSubMessageData.Resource.Type != "" {
		result = append(result, SlackAttachmentField{
			Title: "resource type",
			Value: pubSubMessageData.Resource.Type,
			Short: true,
		})
	}

	result = append(result,
		SlackAttachmentField{
			Title: "resource",
			Value: pubSubMessageData.ProtoPayload.ResourceName,
			Short: false,
		},
		SlackAttachmentField{
			Title: "operation",
			Value: pubSubMessageData.ProtoPayload.MethodName,
			Short: false,
		},
	)

	return result
}

func sendSlackNotification(webhookUrl string, slackRequestBody SlackRequestBody) error {
	slackBody, err := json.Marshal(slackRequestBody)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, webhookUrl, bytes.NewBuffer(slackBody))
	if err != nil {
		return err
	}

	req.Header.Add("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	if buf.String() != "ok" {
		return fmt.Errorf("Non-ok response returned from Slack: %s", buf.String())
	}

	return nil
}

func main() {
	customFormatter := new(log.TextFormatter)
	customFormatter.TimestampFormat = logDateLayout
	customFormatter.FullTimestamp = true
	log.SetFormatter(customFormatter)

	kingpin.Version(ver)
	kingpin.Parse()

	if *verbose {
		log.SetLevel(log.DebugLevel)
	}

	http.HandleFunc("/", handlePubSub)
	http.HandleFunc("/health", internalHealth)

	port := *port
	if port == "" {
		port = "8080"
		log.Infof("Defaulting to port %s", port)
	}

	log.Infof("Listening on port %s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
