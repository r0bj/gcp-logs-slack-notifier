package main

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"bytes"
	"time"
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"
	"gopkg.in/alecthomas/kingpin.v2"
)

const (
	ver string = "0.3"
	logDateLayout string = "2006-01-02 15:04:05"
)

var (
	verbose = kingpin.Flag("verbose", "Verbose mode.").Short('v').Bool()
	port = kingpin.Flag("port", "Port to listen on.").Envar("PORT").String()
	slackWebhookUrl = kingpin.Flag("slack-webhook-url", "Slack webhook URL.").Envar("SLACK_WEBHOOK_URL").Required().String()
)

// PubSubMessage : containts PubSub message content
type PubSubMessage struct {
	Message struct {
		Data []byte `json:"data"`
		Attributes struct {
			Timestamp string `json:"logging.googleapis.com/timestamp"`
		} `json:"attributes"`
	} `json:"message"`
	Subscription string `json:"subscription"`
}

// PubSubMessageData : containts PubSub message data content
type PubSubMessageData struct {
	ProtoPayload struct {
		MethodName string `json:"methodName"`
		ResourceName string `json:"resourceName"`
		ServiceName string `json:"serviceName"`
		AuthenticationInfo struct {
			PrincipalEmail string `json:"principalEmail"`
		} `json:"authenticationInfo"`
	} `json:"protoPayload"`
	LogName string `json:"logName"`
	Resource struct {
		Labels struct {
			ProjectId string `json:"project_id"`
			Location string `json:"location"`
			Zone string `json:"zone"`
		} `json:"labels"`
	} `json:"resource"`
}

// SlackRequestBody : containts slack request body
type SlackRequestBody struct {
	Text string `json:"text,omitempty"`
	Attachments []SlackMessageAttachment `json:"attachments"`
}

// SlackMessageAttachment : containts slack message attachment data
type SlackMessageAttachment struct {
	Text string `json:"text,omitempty"`
	Color string `json:"color,omitempty"`
	MrkdwnIn []string `json:"mrkdwn_in,omitempty"`
	Fields []SlackAttachmentField `json:"fields"`
}

// SlackAttachmentField : containts slack attachment field data
type SlackAttachmentField struct {
	Short bool `json:"short"`
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
					Text: formatMessageAttributes(pubSubMessageData),
				},
			},
		}

		log.Info("Sending slack notification")
		if err := sendSlackNotification(*slackWebhookUrl, slackRequestBody); err != nil {
			log.Errorf("Sending slack message fail: %v", err)
		}
	}
}

func formatMessageAttributes (pubSubMessageData PubSubMessageData) string {
	result := []string{
		"*project:* " + pubSubMessageData.Resource.Labels.ProjectId,
		"*category:* " + strings.Split(pubSubMessageData.ProtoPayload.ServiceName, ".")[0],
		"*resource:* " + pubSubMessageData.ProtoPayload.ResourceName,
		"*operation:* " + pubSubMessageData.ProtoPayload.MethodName,
		"*user:* " + pubSubMessageData.ProtoPayload.AuthenticationInfo.PrincipalEmail,
	}

	var location string
	if pubSubMessageData.Resource.Labels.Location != "" {
		location = "*location:* " + pubSubMessageData.Resource.Labels.Location
	} else if pubSubMessageData.Resource.Labels.Zone != "" {
		location = "*zone:* " + pubSubMessageData.Resource.Labels.Zone
	}

	if location != "" {
		// Insert location at second position in slice
		result = append(result, "")
		copy(result[2:], result[1:])
		result[1] = location
	}

	return strings.Join(result[:],"\n")
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
	log.Fatal(http.ListenAndServe(":" + port, nil))
}
