// Code generated by MockGen. DO NOT EDIT.
// Source: pkg/services/networkverifier/networkverifier.go

// Package mock_networkverifier is a generated GoMock package.
package mock_networkverifier

import (
	reflect "reflect"

	credentials "github.com/aws/aws-sdk-go/aws/credentials"
	gomock "github.com/golang/mock/gomock"
	v1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	v10 "github.com/openshift/hive/apis/hive/v1"
)

// MockService is a mock of Service interface.
type MockService struct {
	ctrl     *gomock.Controller
	recorder *MockServiceMockRecorder
}

// MockServiceMockRecorder is the mock recorder for MockService.
type MockServiceMockRecorder struct {
	mock *MockService
}

// NewMockService creates a new mock instance.
func NewMockService(ctrl *gomock.Controller) *MockService {
	mock := &MockService{ctrl: ctrl}
	mock.recorder = &MockServiceMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockService) EXPECT() *MockServiceMockRecorder {
	return m.recorder
}

// GetAWSCredentials mocks base method.
func (m *MockService) GetAWSCredentials() (credentials.Value, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetAWSCredentials")
	ret0, _ := ret[0].(credentials.Value)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetAWSCredentials indicates an expected call of GetAWSCredentials.
func (mr *MockServiceMockRecorder) GetAWSCredentials() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetAWSCredentials", reflect.TypeOf((*MockService)(nil).GetAWSCredentials))
}

// GetClusterDeployment mocks base method.
func (m *MockService) GetClusterDeployment(clusterID string) (*v10.ClusterDeployment, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetClusterDeployment", clusterID)
	ret0, _ := ret[0].(*v10.ClusterDeployment)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetClusterDeployment indicates an expected call of GetClusterDeployment.
func (mr *MockServiceMockRecorder) GetClusterDeployment(clusterID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetClusterDeployment", reflect.TypeOf((*MockService)(nil).GetClusterDeployment), clusterID)
}

// GetClusterInfo mocks base method.
func (m *MockService) GetClusterInfo(identifier string) (*v1.Cluster, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetClusterInfo", identifier)
	ret0, _ := ret[0].(*v1.Cluster)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetClusterInfo indicates an expected call of GetClusterInfo.
func (mr *MockServiceMockRecorder) GetClusterInfo(identifier interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetClusterInfo", reflect.TypeOf((*MockService)(nil).GetClusterInfo), identifier)
}

// GetSecurityGroupId mocks base method.
func (m *MockService) GetSecurityGroupId(infraID string) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetSecurityGroupId", infraID)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetSecurityGroupId indicates an expected call of GetSecurityGroupId.
func (mr *MockServiceMockRecorder) GetSecurityGroupId(infraID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetSecurityGroupId", reflect.TypeOf((*MockService)(nil).GetSecurityGroupId), infraID)
}

// GetSubnetId mocks base method.
func (m *MockService) GetSubnetId(infraID string) ([]string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetSubnetId", infraID)
	ret0, _ := ret[0].([]string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetSubnetId indicates an expected call of GetSubnetId.
func (mr *MockServiceMockRecorder) GetSubnetId(infraID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetSubnetId", reflect.TypeOf((*MockService)(nil).GetSubnetId), infraID)
}

// IsSubnetPrivate mocks base method.
func (m *MockService) IsSubnetPrivate(subnet string) bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IsSubnetPrivate", subnet)
	ret0, _ := ret[0].(bool)
	return ret0
}

// IsSubnetPrivate indicates an expected call of IsSubnetPrivate.
func (mr *MockServiceMockRecorder) IsSubnetPrivate(subnet interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IsSubnetPrivate", reflect.TypeOf((*MockService)(nil).IsSubnetPrivate), subnet)
}
