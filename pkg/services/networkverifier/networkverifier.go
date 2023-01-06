package networkverifier

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go/aws/credentials"
	v1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	hivev1 "github.com/openshift/hive/apis/hive/v1"

	"github.com/openshift/configuration-anomaly-detection/pkg/aws"
	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"
	"github.com/openshift/configuration-anomaly-detection/pkg/pagerduty"

	"github.com/openshift/osd-network-verifier/pkg/proxy"
	"github.com/openshift/osd-network-verifier/pkg/verifier"
	awsverifier "github.com/openshift/osd-network-verifier/pkg/verifier/aws"
)

// AwsClient is a wrapper around the aws client, and is used to import the received functions into the Provider
type AwsClient = aws.Client

// OcmClient is a wrapper around the ocm client, and is used to import the received functions into the Provider
type OcmClient = ocm.Client

// PdClient is a wrapper around the pagerduty client, and is used to import the received functions into the Provider
type PdClient = pagerduty.Client

// Provider should have all the functions that ChgmService is implementing
type Provider struct {
	// having awsClient and ocmClient this way
	// allows for all the method receivers defined on them to be passed into the parent struct,
	// thus making it more composable than just having each func redefined here
	//
	// a different solution is to have the structs have unique names to begin with, which makes the code
	// aws.AwsClient feel a bit redundant\
	AwsClient
	OcmClient
	PdClient
}

// Service will wrap all the required commands the client needs to run its operations
type Service interface {
	// OCM
	GetClusterInfo(identifier string) (*v1.Cluster, error)
	GetClusterDeployment(clusterID string) (*hivev1.ClusterDeployment, error)
	//TODO add network verifier limited support exists
	//TODO add network verifier limited support reason
	// PD
	AddNote(incidentID string, noteContent string) error
	MoveToEscalationPolicy(incidentID string, escalationPolicyID string) error
	GetEscalationPolicy() string
	GetSilentPolicy() string
	// AWS
	GetAWSCredentials() (credentials.Value, error)
}

// Client refers to the networkverifier client
type Client struct {
	Service
	cluster *v1.Cluster
}

func (c *Client) populateStructWith(externalID string) error {
	if c.cluster == nil {
		cluster, err := c.GetClusterInfo(externalID)
		if err != nil {
			return fmt.Errorf("could not retrieve cluster info for %s: %w", externalID, err)
		}
		// fmt.Printf("cluster ::: %v\n", cluster)
		c.cluster = cluster
	}
	return nil
}

type egressConfig struct {
	vpcSubnetID     string
	cloudImageID    string
	instanceType    string
	securityGroupId string
	cloudTags       map[string]string
	debug           bool
	region          string
	timeout         time.Duration
	kmsKeyID        string
	httpProxy       string
	httpsProxy      string
	CaCert          string
	noTls           bool
	awsProfile      string
}

var (
	awsDefaultTags = map[string]string{"osd-network-verifier": "owned", "red-hat-managed": "true", "Name": "osd-network-verifier"}
	// gcpDefaultTags     = map[string]string{"osd-network-verifier": "owned", "red-hat-managed": "true", "name": "osd-network-verifier"}
	// awsRegionEnvVarStr = "AWS_REGION"
	// awsRegionDefault   = "us-east-2"
	// gcpRegionEnvVarStr = "GCP_REGION"
	// gcpRegionDefault   = "us-east1"
)

//runNetworkVerifier runs the network verifier tool to check for network misconfigurations
func (c Client) RunNetworkVerifier(externalClusterID string) error {
	fmt.Printf("Running Network Verifier...")
	err := c.populateStructWith(externalClusterID)
	if err != nil {
		return fmt.Errorf("failed to populate struct in runNetworkVerifier in networkverifier step: %w", err)
	}

	credentials, err := c.GetAWSCredentials()
	config := egressConfig{}

	//make thingy to print which sg and subnet is being used
	if err != nil {
		return fmt.Errorf("failed to get SecurityGroupID: %w", err)
	}

	p := proxy.ProxyConfig{
		HttpProxy:  config.httpProxy,
		HttpsProxy: config.httpsProxy,
		Cacert:     config.CaCert,
		NoTls:      config.noTls,
	}

	subnets := c.GetSubnetId()
	for subnet := range subnets{

		// setup non cloud config options
		vei := verifier.ValidateEgressInput{
			Ctx:          context.TODO(),
			SubnetID:     subnet,
			CloudImageID: config.cloudImageID,
			Timeout:      config.timeout,
			Tags:         config.cloudTags,
			InstanceType: config.instanceType,
			Proxy:        p,
		}

		if len(vei.Tags) == 0 {
			vei.Tags = awsDefaultTags
		}

		//Setup AWS Specific Configs
		vei.AWS = verifier.AwsEgressConfig{
			KmsKeyID:        config.kmsKeyID,
			SecurityGroupId: config.securityGroupId,
		}

		//use newawsverifier directly instead of getawsverifier pass creds from customeraws
		awsVerifier, err := awsverifier.NewAwsVerifier(credentials.AccessKeyID, credentials.SecretAccessKey, credentials.SessionToken, c.cluster.Region().ID(), "", true)
		if err != nil {
			return fmt.Errorf("could not build awsVerifier %v", err)
		}

		awsVerifier.Logger.Warn(context.TODO(), "Using region: %s", c.cluster.Region().ID())

		out := verifier.ValidateEgress(awsVerifier, vei)
		out.Summary(config.debug)

		if !out.IsSuccessful() {
			awsVerifier.Logger.Error(context.TODO(), "Failure!")
			return fmt.Errorf("unknown failure")
		}
		awsVerifier.Logger.Info(context.TODO(), "Success")
		return nil
}




// GetSecurityGroupId will return the security group id needed for the network verifier
func (c Client) GetSecurityGroupId(infraID string) (*string, error) {
	in := &ec2.DescribeSecurityGroupsInput{
		Filters: []*ec2.Filter{
			{
				Name:   aws.String("tag:Name"),
				Values: []*string{aws.String(fmt.Sprintf("%s-worker-sg", infraID))},
			},
		},
	}
	out, err := c.Ec2Client.DescribeSecurityGroups(in)
	if err != nil {
		return nil, fmt.Errorf("failed to list security group: %w", err)
	}
	if out.SecurityGroups != nil && len(out.SecurityGroups) == 1 {
		return nil, fmt.Errorf("expected securitygroups to have len == 1")
	}
	if out.SecurityGroups == nil {
		return nil, fmt.Errorf("security groups are empty")
	}
	return out.SecurityGroups[0].GroupId, nil
}

// GetSubnetId will return the private subnets needed for the network verifier
func (c Client) GetSubnetId(infraID string) ([]string, error) {
	// For non-BYOVPC clusters, retrieve private subnets by tag
	if len(c.cluster.AWS().SubnetIDs()) == 0 {
		in := &ec2.DescribeSubnetsInput{
			Filters: []*ec2.Filter{
				{
					Name:   aws.String(fmt.Sprintf("tag:kubernetes.io/cluster/%s", infraID)),
					Values: []*string{aws.String("owned")},
				},
				{
					Name:   aws.String("tag-key"),
					Values: []*string{aws.String("kubernetes.io/role/internal-elb")},
				},
			},
		}	
		out, err := c.Ec2Client.DescribeSubnets(in)
		if err != nil {
			return nil, fmt.Errorf("failed to find private subnets for %s: %w", infraID, err)
		}
		if len(out.Subnets) == 0 {
			return nil, fmt.Errorf("found 0 subnets with kubernetes.io/cluster/%s=owned and kubernetes.io/role/internal-elb", infraID)
		}
		return []string {out.Subnets[0].SubnetId}, nil
	}
	// For PrivateLink clusters, any provided subnet is considered a private subnet
	if c.cluster.AWS().PrivateLink() {
		if len(c.cluster.AWS().SubnetIDs()) == 0 {
			return "", fmt.Errorf("unexpected error: %s is a PrivateLink cluster, but no subnets in OCM", infraID)
		}
		return c.cluster.AWS().SubnetIDs(), nil
	}
}
	// For non-PrivateLink BYOVPC clusters...
	
	// in := &ec2.DescribeRouteTablesInput{
	// 	Filters: []*ec2.Filter{
	// 		{
	// 			Name:   aws.String("association.subnet-id"),
	// 			Values: []*string{aws.String("subnet")},
	// 		},
	// 	},
	//}
