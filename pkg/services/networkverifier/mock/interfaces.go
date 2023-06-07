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
func (m *MockService) GetAWSCredentials() credentials.Value {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetAWSCredentials")
	ret0, _ := ret[0].(credentials.Value)
	return ret0
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

// GetSecurityGroupID mocks base method.
func (m *MockService) GetSecurityGroupID(infraID string) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetSecurityGroupID", infraID)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetSecurityGroupID indicates an expected call of GetSecurityGroupID.
func (mr *MockServiceMockRecorder) GetSecurityGroupID(infraID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetSecurityGroupID", reflect.TypeOf((*MockService)(nil).GetSecurityGroupID), infraID)
}

// GetSubnetID mocks base method.
func (m *MockService) GetSubnetID(infraID string) ([]string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetSubnetID", infraID)
	ret0, _ := ret[0].([]string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetSubnetID indicates an expected call of GetSubnetID.
func (mr *MockServiceMockRecorder) GetSubnetID(infraID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetSubnetID", reflect.TypeOf((*MockService)(nil).GetSubnetID), infraID)
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
