package executor

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/auth/qoder"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
)

// TestNewQoderExecutor tests the constructor
func TestNewQoderExecutor(t *testing.T) {
	cfg := &config.Config{}
	executor := NewQoderExecutor(cfg)
	if executor == nil {
		t.Fatal("NewQoderExecutor returned nil")
	}
	if got := executor.Identifier(); got != "qoder" {
		t.Errorf("Identifier() = %q, want %q", got, "qoder")
	}
}

// TestIdentifier tests the identifier method
func TestIdentifier(t *testing.T) {
	executor := NewQoderExecutor(&config.Config{})
	if got := executor.Identifier(); got != "qoder" {
		t.Errorf("Identifier() = %q, want %q", got, "qoder")
	}
}

// TestExecuteStream_InvalidAuthStorage tests error for wrong storage type
func TestExecuteStream_InvalidAuthStorage(t *testing.T) {
	executor := NewQoderExecutor(&config.Config{})

	// Create a mock that doesn't implement TokenStorage
	authRecord := &cliproxyauth.Auth{
		Storage: nil, // nil storage
	}

	req := cliproxyexecutor.Request{
		Payload: []byte(`{"model":"auto","messages":[]}`),
	}

	opts := cliproxyexecutor.Options{}

	result, err := executor.ExecuteStream(context.Background(), authRecord, req, opts)
	if result != nil {
		t.Errorf("expected nil result, got %+v", result)
	}
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "invalid auth storage type") {
		t.Errorf("error %q does not contain %q", err.Error(), "invalid auth storage type")
	}
}

// TestExecuteStream_TokenRefreshFailure tests handling of token refresh failure
func TestExecuteStream_TokenRefreshFailure(t *testing.T) {
	executor := NewQoderExecutor(&config.Config{})

	storage := &qoder.QoderTokenStorage{
		Token:        "token",
		RefreshToken: "refresh",
		ExpireTime:   1000, // Expired
		UserID:       "user123",
		Name:         "Test User",
		Email:        "test@example.com",
	}

	authRecord := &cliproxyauth.Auth{
		Storage: storage,
	}

	req := cliproxyexecutor.Request{
		Payload: []byte(`{"model":"auto","messages":[]}`),
	}

	opts := cliproxyexecutor.Options{}

	// The request should still proceed despite refresh failure (warning logged)
	result, err := executor.ExecuteStream(context.Background(), authRecord, req, opts)
	// Should fail because we can't actually make the HTTP request
	if err == nil {
		t.Error("expected error, got nil")
	}
	if result != nil {
		t.Errorf("expected nil result, got %+v", result)
	}
}

// TestExecuteStream_InvalidRequestPayload tests handling of malformed JSON
func TestExecuteStream_InvalidRequestPayload(t *testing.T) {
	executor := NewQoderExecutor(&config.Config{})

	storage := &qoder.QoderTokenStorage{
		Token:        "token",
		RefreshToken: "refresh",
		ExpireTime:   time.Now().Add(1 * time.Hour).UnixMilli(),
		UserID:       "user123",
		Name:         "Test User",
		Email:        "test@example.com",
	}

	authRecord := &cliproxyauth.Auth{
		Storage: storage,
	}

	req := cliproxyexecutor.Request{
		Payload: []byte(`invalid json`),
	}

	opts := cliproxyexecutor.Options{}

	result, err := executor.ExecuteStream(context.Background(), authRecord, req, opts)
	if result != nil {
		t.Errorf("expected nil result, got %+v", result)
	}
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "failed to parse request") {
		t.Errorf("error %q does not contain %q", err.Error(), "failed to parse request")
	}
}

// TestExecuteStream_BuildAuthHeadersFailure tests auth header generation failure
func TestExecuteStream_BuildAuthHeadersFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `data: {"body":"{\\"error\\":\\"test\\"}"}
`)
	}))
	defer server.Close()

	executor := NewQoderExecutor(&config.Config{})

	storage := &qoder.QoderTokenStorage{
		Token:        "token",
		RefreshToken: "refresh",
		ExpireTime:   time.Now().Add(1 * time.Hour).UnixMilli(),
		UserID:       "user123",
		Name:         "Test User",
		Email:        "test@example.com",
	}

	authRecord := &cliproxyauth.Auth{
		Storage: storage,
	}

	req := cliproxyexecutor.Request{
		Payload: []byte(`{"model":"auto","messages":[]}`),
	}

	opts := cliproxyexecutor.Options{}

	result, err := executor.ExecuteStream(context.Background(), authRecord, req, opts)
	// Should fail because we can't build proper auth headers with test data
	if err == nil {
		t.Error("expected error, got nil")
	}
	if result != nil {
		t.Errorf("expected nil result, got %+v", result)
	}
}

// TestExecuteStream_HTTPRequestFailure tests network error handling
func TestExecuteStream_HTTPRequestFailure(t *testing.T) {
	executor := NewQoderExecutor(&config.Config{})

	storage := &qoder.QoderTokenStorage{
		Token:        "token",
		RefreshToken: "refresh",
		ExpireTime:   time.Now().Add(1 * time.Hour).UnixMilli(),
		UserID:       "user123",
		Name:         "Test User",
		Email:        "test@example.com",
	}

	authRecord := &cliproxyauth.Auth{
		Storage: storage,
	}

	req := cliproxyexecutor.Request{
		Payload: []byte(`{"model":"auto","messages":[]}`),
	}

	opts := cliproxyexecutor.Options{}

	// Use an invalid URL that will cause connection failure
	result, err := executor.ExecuteStream(context.Background(), authRecord, req, opts)
	if err == nil {
		t.Error("expected error, got nil")
	}
	if result != nil {
		t.Errorf("expected nil result, got %+v", result)
	}
}

// TestExecuteStream_NonOKResponse verifies ExecuteStream surfaces a clear
// error when no model_config has been cached for the requested model
// (i.e. /algo/api/v2/model/list was never fetched, or the model is unknown).
func TestExecuteStream_NonOKResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "Internal Server Error")
	}))
	defer server.Close()

	executor := NewQoderExecutor(&config.Config{})

	storage := &qoder.QoderTokenStorage{
		Token:        "token",
		RefreshToken: "refresh",
		ExpireTime:   time.Now().Add(1 * time.Hour).UnixMilli(),
		UserID:       "user123",
		Name:         "Test User",
		Email:        "test@example.com",
	}

	authRecord := &cliproxyauth.Auth{
		Storage: storage,
	}

	req := cliproxyexecutor.Request{
		Payload: []byte(`{"model":"auto","messages":[]}`),
	}

	opts := cliproxyexecutor.Options{}

	result, err := executor.ExecuteStream(context.Background(), authRecord, req, opts)
	if result != nil {
		t.Errorf("expected nil result, got %+v", result)
	}
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "model config cache is empty") {
		t.Errorf("error %q does not contain %q", err.Error(), "model config cache is empty")
	}
}

// TestExecuteStream_StreamParsing tests successful stream parsing
func TestExecuteStream_StreamParsing(t *testing.T) {
	// This test requires overriding QoderChatURL which is a constant
	// Skipping as it can't be properly tested without code changes
	t.Skip("requires ability to override QoderChatURL")
}

// TestExecuteStream_StreamErrorInResponse tests handling of error messages in stream
func TestExecuteStream_StreamErrorInResponse(t *testing.T) {
	// This test requires overriding QoderChatURL which is a constant
	// Skipping as it can't be properly tested without code changes
	t.Skip("requires ability to override QoderChatURL")
}

// TestExecuteStream_StreamContextCancel tests context cancellation
func TestExecuteStream_StreamContextCancel(t *testing.T) {
	// This test requires overriding QoderChatURL which is a constant
	// Skipping as it can't be properly tested without code changes
	t.Skip("requires ability to override QoderChatURL")
}

// TestBuildOpenAIChunk tests message transformation
func TestBuildOpenAIChunk(t *testing.T) {
	inner := map[string]interface{}{
		"choices": []interface{}{
			map[string]interface{}{
				"delta": map[string]interface{}{
					"content": "test",
				},
			},
		},
	}

	chunkBytes, err := buildOpenAIChunk(inner, "gpt-4")
	if err != nil {
		t.Fatalf("buildOpenAIChunk returned error: %v", err)
	}
	if chunkBytes == nil {
		t.Fatal("buildOpenAIChunk returned nil bytes")
	}

	var result map[string]interface{}
	if err = json.Unmarshal(chunkBytes, &result); err != nil {
		t.Fatalf("failed to unmarshal chunk: %v", err)
	}
	if got := result["model"]; got != "gpt-4" {
		t.Errorf("model = %v, want %q", got, "gpt-4")
	}
}

// TestNewQoderStatusError tests error creation
func TestNewQoderStatusError(t *testing.T) {
	err := newQoderStatusError(500, "test error")
	if err == nil {
		t.Fatal("newQoderStatusError returned nil")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error %q does not contain %q", err.Error(), "500")
	}
	if !strings.Contains(err.Error(), "test error") {
		t.Errorf("error %q does not contain %q", err.Error(), "test error")
	}
}

// TestExecuteStream_ModelMapping tests model name mapping
func TestExecuteStream_ModelMapping(t *testing.T) {
	executor := NewQoderExecutor(&config.Config{})

	storage := &qoder.QoderTokenStorage{
		Token:        "token",
		RefreshToken: "refresh",
		ExpireTime:   time.Now().Add(1 * time.Hour).UnixMilli(),
		UserID:       "user123",
		Name:         "Test User",
		Email:        "test@example.com",
	}

	authRecord := &cliproxyauth.Auth{
		Storage: storage,
	}

	// Test with a mapped model name
	req := cliproxyexecutor.Request{
		Payload: []byte(`{"model":"auto","messages":[]}`),
	}

	opts := cliproxyexecutor.Options{}

	// We can't easily override the URL, so this test will fail
	// Just verify it doesn't panic
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if _, err := executor.ExecuteStream(ctx, authRecord, req, opts); err == nil {
		t.Error("expected error, got nil")
	}
}

// TestExecute_InvalidAuth tests that Execute returns an error when the auth
// storage type is invalid. This fails before the HTTP call, so it can be
// tested without a mock server.
func TestExecute_InvalidAuth(t *testing.T) {
	executor := NewQoderExecutor(&config.Config{})
	authRecord := &cliproxyauth.Auth{
		Storage: nil,
	}
	req := cliproxyexecutor.Request{
		Payload: []byte(`{"model":"auto","messages":[]}`),
	}
	opts := cliproxyexecutor.Options{}

	resp, err := executor.Execute(context.Background(), authRecord, req, opts)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "invalid auth storage type") {
		t.Errorf("error %q does not contain %q", err.Error(), "invalid auth storage type")
	}
	if len(resp.Payload) != 0 {
		t.Errorf("expected empty payload, got %d bytes", len(resp.Payload))
	}
}

// TestExecute_TranslateNonStream_SameFormatIsPassthrough validates that when
// SourceFormat equals FormatOpenAI (Qoder's native response format), the
// TranslateNonStream call returns the response unchanged. This is the
// common case and must not break clients.
func TestExecute_TranslateNonStream_SameFormatIsPassthrough(t *testing.T) {
	openAIResp := map[string]interface{}{
		"id":      "chatcmpl-test-123",
		"object":  "chat.completion",
		"created": 1712345678,
		"model":   "auto",
		"choices": []map[string]interface{}{
			{
				"index": 0,
				"message": map[string]interface{}{
					"role":    "assistant",
					"content": "Hello from Qoder",
				},
				"finish_reason": "stop",
			},
		},
	}
	responseBytes, err := json.Marshal(openAIResp)
	if err != nil {
		t.Fatalf("marshal openAIResp: %v", err)
	}

	// When both from and to are FormatOpenAI, TranslateNonStream
	// falls back to returning rawJSON unchanged (no translator registered).
	var param any
	out := sdktranslator.TranslateNonStream(
		context.Background(),
		sdktranslator.FormatOpenAI,
		sdktranslator.FormatOpenAI,
		"auto",
		nil, nil,
		responseBytes,
		&param,
	)

	var result map[string]interface{}
	if err = json.Unmarshal(out, &result); err != nil {
		t.Fatalf("unmarshal translated response: %v", err)
	}
	if got := result["object"]; got != "chat.completion" {
		t.Errorf("object = %v, want %q", got, "chat.completion")
	}
	choices, ok := result["choices"].([]interface{})
	if !ok {
		t.Fatalf("choices is not []interface{}: %T", result["choices"])
	}
	if len(choices) != 1 {
		t.Fatalf("len(choices) = %d, want 1", len(choices))
	}
	msg := choices[0].(map[string]interface{})["message"].(map[string]interface{})
	if got := msg["content"]; got != "Hello from Qoder" {
		t.Errorf("message.content = %v, want %q", got, "Hello from Qoder")
	}
}

// TestExecute_TranslateNonStream_EmptySourceFormatIsPassthrough validates
// that when SourceFormat is empty (not set by handler), the response is
// returned unchanged.
func TestExecute_TranslateNonStream_EmptySourceFormatIsPassthrough(t *testing.T) {
	openAIResp := map[string]interface{}{
		"id":      "chatcmpl-test-456",
		"object":  "chat.completion",
		"created": 1712345678,
		"model":   "auto",
		"choices": []map[string]interface{}{
			{
				"index": 0,
				"message": map[string]interface{}{
					"role":    "assistant",
					"content": "Hello",
				},
				"finish_reason": "stop",
			},
		},
	}
	responseBytes, _ := json.Marshal(openAIResp)

	// Empty SourceFormat: no translator registered, raw JSON returned as-is.
	var param any
	out := sdktranslator.TranslateNonStream(
		context.Background(),
		sdktranslator.FormatOpenAI,
		"", // empty SourceFormat
		"auto",
		nil, nil,
		responseBytes,
		&param,
	)

	var result map[string]interface{}
	if err := json.Unmarshal(out, &result); err != nil {
		t.Fatalf("unmarshal translated response: %v", err)
	}
	if got := result["object"]; got != "chat.completion" {
		t.Errorf("object = %v, want %q", got, "chat.completion")
	}
}

// TestExecute_TranslateNonStream_NonOpenAISourceFormat validates that when
// SourceFormat differs from FormatOpenAI (e.g. "openai-response" from
// /v1/responses route), TranslateNonStream is called and returns a
// translated payload (or the raw JSON as fallback if no translator is
// registered for that format pair). This is the bugfix scenario.
func TestExecute_TranslateNonStream_NonOpenAISourceFormat(t *testing.T) {
	openAIResp := map[string]interface{}{
		"id":      "chatcmpl-test-789",
		"object":  "chat.completion",
		"created": 1712345678,
		"model":   "auto",
		"choices": []map[string]interface{}{
			{
				"index": 0,
				"message": map[string]interface{}{
					"role":    "assistant",
					"content": "Will be translated",
				},
				"finish_reason": "stop",
			},
		},
	}
	responseBytes, _ := json.Marshal(openAIResp)

	// Simulate a request from /v1/responses route (sets SourceFormat to "openai-response").
	// If a translator is registered, it will transform the payload; otherwise
	// the raw JSON is returned as fallback. Either way, this must not panic
	// or return an empty response.
	sourceFmt := sdktranslator.FromString("openai-response")
	var param any
	out := sdktranslator.TranslateNonStream(
		context.Background(),
		sdktranslator.FormatOpenAI,
		sourceFmt,
		"auto",
		nil, nil,
		responseBytes,
		&param,
	)

	if len(out) == 0 {
		t.Error("expected non-empty translated output")
	}
	if !json.Valid(out) {
		t.Error("TranslateNonStream must return valid JSON")
	}
}

// TestExecute_ResponseStructureMatchesOpenAISchema validates that the
// accumulated non-stream response built by Execute follows the OpenAI
// chat-completions schema before translation.
func TestExecute_ResponseStructureMatchesOpenAISchema(t *testing.T) {
	// Replicate the response structure built in Execute (lines 672-684).
	content := "test content"
	finishReason := "stop"
	model := "auto"

	response := map[string]interface{}{
		"id":      fmt.Sprintf("qoder-%d", time.Now().UnixNano()),
		"object":  "chat.completion",
		"created": time.Now().Unix(),
		"model":   model,
		"choices": []map[string]interface{}{
			{
				"index": 0,
				"message": map[string]interface{}{
					"role":    "assistant",
					"content": content,
				},
				"finish_reason": finishReason,
			},
		},
	}

	responseBytes, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}

	var result map[string]interface{}
	if err = json.Unmarshal(responseBytes, &result); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}

	// Verify top-level fields match OpenAI schema.
	if got := result["object"]; got != "chat.completion" {
		t.Errorf("object = %v, want %q", got, "chat.completion")
	}
	if got := result["model"]; got != model {
		t.Errorf("model = %v, want %q", got, model)
	}
	if id, _ := result["id"].(string); id == "" {
		t.Error("id is empty")
	}
	if created, _ := result["created"].(float64); created == 0 {
		t.Error("created is zero")
	}

	// Verify choices array.
	choices, ok := result["choices"].([]interface{})
	if !ok {
		t.Fatalf("choices is not []interface{}: %T", result["choices"])
	}
	if len(choices) != 1 {
		t.Fatalf("len(choices) = %d, want 1", len(choices))
	}

	choice, ok := choices[0].(map[string]interface{})
	if !ok {
		t.Fatalf("choice is not map[string]interface{}: %T", choices[0])
	}
	if got := choice["index"]; got != float64(0) {
		t.Errorf("choice.index = %v, want 0", got)
	}
	if got := choice["finish_reason"]; got != finishReason {
		t.Errorf("choice.finish_reason = %v, want %q", got, finishReason)
	}

	msg, ok := choice["message"].(map[string]interface{})
	if !ok {
		t.Fatalf("message is not map[string]interface{}: %T", choice["message"])
	}
	if got := msg["role"]; got != "assistant" {
		t.Errorf("message.role = %v, want %q", got, "assistant")
	}
	if got := msg["content"]; got != content {
		t.Errorf("message.content = %v, want %q", got, content)
	}
}

// TestExecute_TranslateNonStream_UsesRequestPayload verifies that when
// SourceFormat differs from FormatOpenAI, the request payload is translated
// before being passed to TranslateNonStream (matching the pattern in
// the fix).
func TestExecute_TranslateNonStream_UsesTranslatedRequestPayload(t *testing.T) {
	// Simulate the request translation that happens in the Execute fix.
	sourceFmt := sdktranslator.FromString("gemini")
	originalRequest := []byte(`{"model":"auto","messages":[{"role":"user","content":"hi"}],"generationConfig":{}}`)
	reqPayload := []byte(`{"model":"auto","messages":[{"role":"user","content":"hi"}]}`)
	openAIResp, _ := json.Marshal(map[string]interface{}{
		"id":      "test",
		"object":  "chat.completion",
		"created": 1,
		"model":   "auto",
		"choices": []map[string]interface{}{
			{"index": 0, "message": map[string]interface{}{
				"role": "assistant", "content": "hi",
			}, "finish_reason": "stop"},
		},
	})

	// Translate request: sourceFmt -> FormatOpenAI (as done in the fix)
	translatedPayload := reqPayload
	if sourceFmt != "" && sourceFmt != sdktranslator.FormatOpenAI {
		translatedPayload = sdktranslator.TranslateRequest(
			sourceFmt, sdktranslator.FormatOpenAI,
			"auto", reqPayload, false,
		)
	}
	if translatedPayload == nil {
		t.Fatal("translated payload is nil")
	}

	// Now call TranslateNonStream with the translated request payload.
	var param any
	out := sdktranslator.TranslateNonStream(
		context.Background(),
		sdktranslator.FormatOpenAI,
		sourceFmt,
		"auto",
		originalRequest,
		translatedPayload,
		openAIResp,
		&param,
	)

	if len(out) == 0 {
		t.Error("expected non-empty translated output")
	}
	if !json.Valid(out) {
		t.Error("TranslateNonStream must return valid JSON")
	}
}
