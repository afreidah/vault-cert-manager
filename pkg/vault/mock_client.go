package vault

import (
	"cert-manager/pkg/config"
	"reflect"
	"time"

	"go.uber.org/mock/gomock"
)

//go:generate mockgen -source=client.go -destination=mock_client.go -package=vault

type MockClient struct {
	ctrl     *gomock.Controller
	recorder *MockClientMockRecorder
}

type MockClientMockRecorder struct {
	mock *MockClient
}

func NewMockClient(ctrl *gomock.Controller) *MockClient {
	mock := &MockClient{ctrl: ctrl}
	mock.recorder = &MockClientMockRecorder{mock}
	return mock
}

func (m *MockClient) EXPECT() *MockClientMockRecorder {
	return m.recorder
}

func (m *MockClient) IssueCertificate(certConfig *config.CertificateConfig) (*CertificateData, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IssueCertificate", certConfig)
	ret0, _ := ret[0].(*CertificateData)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

func (mr *MockClientMockRecorder) IssueCertificate(certConfig interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IssueCertificate", reflect.TypeOf((*MockClient)(nil).IssueCertificate), certConfig)
}

func CreateTestCertificateData() *CertificateData {
	return &CertificateData{
		Certificate: `-----BEGIN CERTIFICATE-----
MIICODCCAcGgAwIBAgIUO1/zKTcqFJI2xJ2CQ0T4Np8WDxcwCgYIKoZIzj0EAwIw
FjEUMBIGA1UEAwwLZXhhbXBsZS5jb20wHhcNMjQwOTA0MTIwMDAwWhcNMjUwOTA0
MTIwMDAwWjAWMRQwEgYDVQQDDAtleGFtcGxlLmNvbTBZMBMGByqGSM49AgEGCCqG
SM49AwEHA0IABJLjGNcx7rMZxF+n6hFfWUl7VDkrR9e2qQ9o8GhL1JXF4NkU+V2D
g7K+HQo8b6QGsC6gQ+X4WO2hR/pJ4hQ9KK2jUzBRMB0GA1UdDgQWBBTKOEGRJrQw
F4fgKnR7Qa+5QhH/qjAfBgNVHSMEGDAWgBTKOEGRJrQwF4fgKnR7Qa+5QhH/qjAP
BgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0cAMEQCIC8NX5tV6bKZBR8B5eAy
Gp8OV5hLJV+r0FTKFzJqPpYOAiBmRv2L6yQIGFjNNkl9C2dOIJgEQGRJBs3vIQQF
VZVhzw==
-----END CERTIFICATE-----`,
		PrivateKey: `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgPfGGJ8k6k8J9WqJq
I4dGzJ8fzFdF8rW6zGCyNRzF2Y+hRANCAASS4xjXMe6zGcRfp+oRX1lJe1Q5K0fX
tqkPaPBoS9SVxeDZFPlRg4OyvRsKPG+kBrAuoEPl+FjtoUf6SeIUPSit
-----END PRIVATE KEY-----`,
		SerialNumber: "12345",
		Expiration:   time.Now().Add(24 * time.Hour),
	}
}