package rag

// TODO: Wire up with github.com/aws/aws-sdk-go-v2/service/bedrockagentruntime for full functionality.
// AWS Bedrock Knowledge Bases requires AWS Signature V4 signing, which is complex to implement
// without the SDK. This stub stores configuration and defines all request/response types so the
// implementation is ready to be wired up once the SDK dependency is added.

import (
	"context"
	"errors"
	"fmt"

	json "github.com/goccy/go-json"
)

const (
	bedrockProviderName   = "bedrock"
	bedrockDefaultRegion  = "us-east-1"
	bedrockDefaultModelARN = "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-sonnet-4-20250514"
)

// ErrNotConfigured indicates a provider requires SDK integration to function.
var ErrNotConfigured = errors.New("provider requires SDK integration - see implementation comments")

// BedrockProvider implements the Provider interface for AWS Bedrock Knowledge Bases.
// This is a stub that stores configuration and defines types. Full functionality
// requires the AWS SDK for SigV4 signing.
type BedrockProvider struct {
	region         string
	kbID           string
	modelARN       string
	accessKeyID    string
	secretAccessKey string
	sessionToken   string
}

// NewBedrockProvider creates a new AWS Bedrock Knowledge Bases provider.
func NewBedrockProvider(config map[string]string) (Provider, error) {
	kbID := config["kb_id"]
	if kbID == "" {
		return nil, fmt.Errorf("bedrock: kb_id is required")
	}

	region := config["region"]
	if region == "" {
		region = bedrockDefaultRegion
	}

	modelARN := config["model_arn"]
	if modelARN == "" {
		modelARN = bedrockDefaultModelARN
	}

	return &BedrockProvider{
		region:          region,
		kbID:            kbID,
		modelARN:        modelARN,
		accessKeyID:     config["access_key_id"],
		secretAccessKey: config["secret_access_key"],
		sessionToken:    config["session_token"],
	}, nil
}

func (p *BedrockProvider) Name() string {
	return bedrockProviderName
}

func (p *BedrockProvider) Ingest(_ context.Context, _ []Document) error {
	return fmt.Errorf("bedrock: ingest: %w (install github.com/aws/aws-sdk-go-v2/service/bedrockagentruntime)", ErrNotConfigured)
}

func (p *BedrockProvider) Query(_ context.Context, _ string, _ ...QueryOption) (*QueryResult, error) {
	return nil, fmt.Errorf("bedrock: query: %w (install github.com/aws/aws-sdk-go-v2/service/bedrockagentruntime)", ErrNotConfigured)
}

func (p *BedrockProvider) Retrieve(_ context.Context, _ string, _ int) ([]Citation, error) {
	return nil, fmt.Errorf("bedrock: retrieve: %w (install github.com/aws/aws-sdk-go-v2/service/bedrockagentruntime)", ErrNotConfigured)
}

func (p *BedrockProvider) Health(_ context.Context) error {
	return fmt.Errorf("bedrock: health: %w (AWS SDK is required for SigV4 authentication)", ErrNotConfigured)
}

func (p *BedrockProvider) Close() error {
	return nil
}

// Bedrock RetrieveAndGenerate request/response types.
// These match the AWS Bedrock Agent Runtime API.

type bedrockRetrieveAndGenerateInput struct {
	KnowledgeBaseID        string                          `json:"knowledgeBaseId"`
	ModelARN               string                          `json:"modelArn"`
	Input                  bedrockTextInput                `json:"input"`
	RetrievalConfiguration bedrockRetrievalConfiguration   `json:"retrievalConfiguration"`
}

type bedrockTextInput struct {
	Text string `json:"text"`
}

type bedrockRetrievalConfiguration struct {
	VectorSearchConfiguration bedrockVectorSearchConfiguration `json:"vectorSearchConfiguration"`
}

type bedrockVectorSearchConfiguration struct {
	NumberOfResults int `json:"numberOfResults"`
}

type bedrockRetrieveAndGenerateOutput struct {
	Output    bedrockTextOutput        `json:"output"`
	Citations []bedrockCitationGroup   `json:"citations"`
}

type bedrockTextOutput struct {
	Text string `json:"text"`
}

type bedrockCitationGroup struct {
	RetrievedReferences []bedrockRetrievedReference `json:"retrievedReferences"`
}

type bedrockRetrievedReference struct {
	Content  bedrockReferenceContent  `json:"content"`
	Location bedrockReferenceLocation `json:"location"`
}

type bedrockReferenceContent struct {
	Text string `json:"text"`
}

type bedrockReferenceLocation struct {
	S3Location bedrockS3Location `json:"s3Location"`
}

type bedrockS3Location struct {
	URI string `json:"uri"`
}

// Bedrock Retrieve-only request/response types.

type bedrockRetrieveInput struct {
	KnowledgeBaseID        string                        `json:"knowledgeBaseId"`
	RetrievalQuery         bedrockRetrievalQuery         `json:"retrievalQuery"`
	RetrievalConfiguration bedrockRetrievalConfiguration `json:"retrievalConfiguration"`
}

type bedrockRetrievalQuery struct {
	Text string `json:"text"`
}

type bedrockRetrieveOutput struct {
	RetrievalResults []bedrockRetrievalResult `json:"retrievalResults"`
}

type bedrockRetrievalResult struct {
	Content  bedrockReferenceContent  `json:"content"`
	Score    float64                  `json:"score"`
	Location bedrockReferenceLocation `json:"location"`
}

// bedrockRetrieveAndGenerateInputJSON serializes a RetrieveAndGenerate request for testing.
func bedrockRetrieveAndGenerateInputJSON(kbID, modelARN, question string, numResults int) []byte {
	input := bedrockRetrieveAndGenerateInput{
		KnowledgeBaseID: kbID,
		ModelARN:        modelARN,
		Input:           bedrockTextInput{Text: question},
		RetrievalConfiguration: bedrockRetrievalConfiguration{
			VectorSearchConfiguration: bedrockVectorSearchConfiguration{
				NumberOfResults: numResults,
			},
		},
	}
	data, _ := json.Marshal(input)
	return data
}

// bedrockRetrieveInputJSON serializes a Retrieve request for testing.
func bedrockRetrieveInputJSON(kbID, question string, numResults int) []byte {
	input := bedrockRetrieveInput{
		KnowledgeBaseID: kbID,
		RetrievalQuery:  bedrockRetrievalQuery{Text: question},
		RetrievalConfiguration: bedrockRetrievalConfiguration{
			VectorSearchConfiguration: bedrockVectorSearchConfiguration{
				NumberOfResults: numResults,
			},
		},
	}
	data, _ := json.Marshal(input)
	return data
}

// Compile-time interface check.
var _ Provider = (*BedrockProvider)(nil)
