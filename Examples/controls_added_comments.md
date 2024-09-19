```
Category	Control	priority	Importance of the check [COMMENT]	Mod	Required	not REquired
Account	AWS account should be part of AWS Organizations	p3		Compliance		
Account	Security contact information should be provided for an AWS account	p1		Compliance	YES	
ACM	ACM certificates should have transparency logging enabled	p1		Compliance	YES	
ACM	Ensure That All the Expired ACM Certificates Are Removed	p1		Compliance	YES	
ACM	ACM certificates should not expire within 30 days	p1		Compliance	YES	
ACM	ACM certificates should not use wildcard certificates	p1		Compliance	YES	
ACM	Ensure that ACM certificates are not in failed state	p1		Compliance	YES	
ACM	Ensure that ACM certificates are not in pending validation state	p1		Compliance	YES	
				Compliance		
API Gateway	Access logging should be configured for API Gateway V2 Stages			Compliance		
API Gateway	API Gateway methods authorizer should be configured	p1		Compliance		
API Gateway	API Gateway methods request parameter should be validated			Compliance		
API Gateway	API Gateway REST API endpoint type should be configured to private	p1		Compliance		
API Gateway	API Gateway REST API public endpoints should be configured with authorizer	p1		Compliance		
API Gateway	API Gateway REST API stages should have AWS X-Ray tracing enabled			Compliance		
API Gateway	API Gateway routes should specify an authorization type	p1		Compliance		
API Gateway	API Gateway stage cache encryption at rest should be enabled	p1		Compliance		
API Gateway	API Gateway stage logging should be enabled	p1		Compliance		
API Gateway	API Gateway stage should be associated with waf			Compliance		
API Gateway	API Gateway stage should uses SSL certificate	p1		Compliance		
API Gateway	API Gateway stages should have authorizers configured			Compliance		
API Gateway	API Gateway V2 authorizer should be configured			Compliance		
AppStream	AppStream fleet default internet access should be disabled	p1	"Disabling internet access for the AppStream fleet is crucial for security, 
as it helps prevent unauthorized external access and reduces the potential attack surface."	Compliance		
AppStream	AppStream fleet idle disconnect timeout should be set to less than or equal to 10 mins			Compliance		
AppStream	AppStream fleet max user duration should be set to less than 10 hours			Compliance		
AppStream	AppStream fleet session disconnect timeout should be set to less than or equal to 5 mins			Compliance		
AppSync	AppSync graphql API logging should be enabled	p1	"Enabling AppSync GraphQL API logging is crucial for security as it helps monitor, audit, 
and detect unauthorized access or suspicious activities."	Compliance		
Athena	Athena workgroups should be encrypted at rest			Compliance		
Athena	Athena workgroups should enforce configuration			Compliance		
Auto Scaling	Auto Scaling group should configure EC2 instances to require Instance Metadata Service Version 2 (IMDSv2)	p1	IMDSv2 prevents unauthorized access to sensitive instance metadata.	Compliance		
Auto Scaling	Auto Scaling groups should not have any suspended processes			Compliance		
Auto Scaling	Auto Scaling groups with a load balancer should use health checks			Compliance		
Auto Scaling	Auto Scaling launch config public IP should be disabled			Compliance		
Auto Scaling	EC2 auto scaling group launch configurations should not have metadata response hop limit greater than 1			Compliance		
Auto Scaling	EC2 auto scaling group launch configurations user data should not have any sensitive data			Compliance		
Auto Scaling	EC2 auto scaling groups should cover multiple availability zones			Compliance		
Auto Scaling	EC2 Auto Scaling groups should use EC2 launch templates			Compliance		
Auto Scaling	EC2 auto scaling groups should use multiple instance types in multiple availability zones			Compliance		
Auto Scaling	Ensure EC2 Auto Scaling Groups Propagate Tags to EC2 Instances that it launches			Compliance		
Backup	Backup plan min frequency and min retention check			Compliance		
Backup	Backup plan should exist in a region			Compliance		
Backup	Backup recovery points manual deletion should be disabled			Compliance		
Backup	Backup recovery points should be encrypted	p1	Encryption protects backup data from unauthorized access and breaches.	Compliance		
Backup	Backup recovery points should not expire before retention period			Compliance		
Backup	Backup report plan should exist in a region where backup plan is enabled	p2		Compliance		
Backup	Backup vaults should exist in a region			Compliance		
CloudFormation	CloudFormation stacks differ from the expected configuration			Compliance		
CloudFormation	CloudFormation stacks outputs should not have any secrets	p1	Avoids exposing sensitive information that could lead to security breaches.	Compliance		
CloudFormation	CloudFormation stacks should have notifications enabled	p2		Compliance		
CloudFormation	CloudFormation stacks should have rollback enabled	p2		Compliance		
CloudFormation	Cloudformation stacks termination protection should be enabled	p2		Compliance		
CloudFront	CloudFront distributions access logs should be enabled	p2		Compliance		
CloudFront	CloudFront distributions should encrypt traffic to custom origins	p1	 Protects data in transit from interception.	Compliance		
CloudFront	CloudFront distributions should encrypt traffic to non S3 origins			Compliance		
CloudFront	CloudFront distributions should have a default root object configured			Compliance		
CloudFront	CloudFront distributions should have AWS WAF enabled	p2		Compliance		
CloudFront	CloudFront distributions should have field level encryption enabled	p2		Compliance		
CloudFront	CloudFront distributions should have geo restriction enabled	p2		Compliance		
CloudFront	CloudFront distributions should have latest TLS version	p1	Ensures up-to-date encryption standards.	Compliance		
CloudFront	CloudFront distributions should have origin access identity enabled	p2		Compliance		
CloudFront	CloudFront distributions should have origin failover configured			Compliance		
CloudFront	CloudFront distributions should not point to non-existent S3 origins			Compliance		
CloudFront	CloudFront distributions should not use deprecated SSL protocols between edge locations and custom origins			Compliance		
CloudFront	CloudFront distributions should require encryption in transit			Compliance		
CloudFront	CloudFront distributions should use custom SSL/TLS certificates	p2		Compliance		
CloudFront	CloudFront distributions should use secure SSL cipher	p1	 Safeguards connections from vulnerabilities.	Compliance		
CloudFront	CloudFront distributions should use SNI to serve HTTPS requests	p2		Compliance		
CloudTrail	All S3 buckets should log S3 data events in CloudTrail			Compliance		
CloudTrail	At least one CloudTrail trail should be enabled in the AWS account	p2		Compliance		
CloudTrail	At least one enabled trail should be present in a region	p2		Compliance		
CloudTrail	At least one multi-region AWS CloudTrail should be present in an account			Compliance		
CloudTrail	At least one trail should be enabled with security best practices	p2		Compliance		
CloudTrail	CloudTrail multi region trails should be integrated with CloudWatch logs			Compliance		
CloudTrail	CloudTrail trail log file validation should be enabled	p2		Compliance		
CloudTrail	CloudTrail trail logs should be encrypted with KMS CMK	p1	Protects sensitive audit data from unauthorized access.	Compliance		
CloudTrail	CloudTrail trail S3 buckets MFA delete should be enabled	p2		Compliance		
CloudTrail	CloudTrail trails should be enabled in all regions	p2		Compliance		
CloudTrail	CloudTrail trails should be integrated with CloudWatch logs			Compliance		
CloudTrail	CloudTrail trails should have insight selectors and logging enabled	p2		Compliance		
CloudTrail	Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket		Monitors access to the CloudTrail bucket to detect suspicious activities.	Compliance		
CloudTrail	Ensure that Object-level logging for read events is enabled for S3 bucket		Provides detailed access records for detecting unauthorized activities.	Compliance		
CloudTrail	Ensure that Object-level logging for write events is enabled for S3 bucket		Provides detailed access records for detecting unauthorized activities.	Compliance		
CloudTrail	Ensure the S3 bucket CloudTrail logs to is not publicly accessible			Compliance		
CloudWatch	CloudWatch alarm action should be enabled			Compliance		
CloudWatch	CloudWatch alarm should have an action configured			Compliance		
CloudWatch	CloudWatch should not allow cross-account sharing			Compliance		
CloudWatch	Ensure a log metric filter and alarm exist for AWS Config configuration changes			Compliance		
CloudWatch	Ensure a log metric filter and alarm exist for AWS Management Console authentication failures			Compliance		
CloudWatch	Ensure a log metric filter and alarm exist for AWS Management Console sign-in without MFA		Alerts on potentially compromised accounts.	Compliance		
CloudWatch	Ensure a log metric filter and alarm exist for changes to Network Access Control Lists (NACL)			Compliance		
CloudWatch	Ensure a log metric filter and alarm exist for changes to network gateways			Compliance		
CloudWatch	Ensure a log metric filter and alarm exist for CloudTrail configuration changes			Compliance		
CloudWatch	Ensure a log metric filter and alarm exist for disabling or scheduled deletion of customer managed keys			Compliance		
CloudWatch	Ensure a log metric filter and alarm exist for IAM policy changes			Compliance		
CloudWatch	Ensure a log metric filter and alarm exist for route table changes			Compliance		
CloudWatch	Ensure a log metric filter and alarm exist for S3 bucket policy changes			Compliance		
CloudWatch	Ensure a log metric filter and alarm exist for security group changes			Compliance		
CloudWatch	Ensure a log metric filter and alarm exist for unauthorized API calls		Detects and alerts on suspicious API activity.	Compliance		
CloudWatch	Ensure a log metric filter and alarm exist for usage of 'root' account			Compliance		
CloudWatch	Ensure a log metric filter and alarm exist for VPC changes			Compliance		
CloudWatch	Ensure AWS Organizations changes are monitored			Compliance		
CloudWatch	Log group encryption at rest should be enabled		Protects log data from unauthorized access.	Compliance		
CloudWatch	Log group retention period should be at least 365 days			Compliance		
CodeBuild	CodeBuild GitHub or Bitbucket source repository URLs should use OAuth			Compliance		
CodeBuild	CodeBuild project artifact encryption should be enabled		Protects build artifacts from unauthorized access.	Compliance		
CodeBuild	CodeBuild project environments should not have privileged mode enabled			Compliance		
CodeBuild	CodeBuild project plaintext environment variables should not contain sensitive AWS values		Prevents exposure of sensitive information in environment variables.	Compliance		
CodeBuild	CodeBuild project S3 logs should be encrypted		Ensures build logs are secure and protected from unauthorized access.	Compliance		
CodeBuild	CodeBuild projects should have logging enabled		Provides visibility into build activities and aids in security monitoring.	Compliance		
CodeBuild	CodeBuild projects should not be unused for 90 days or greater			Compliance		
CodeBuild	CodeBuild projects should not use an user controlled buildspec			Compliance		
CodeDeploy	Codedeploy deployment groups lambda allatonce traffic shift should be disabled			Compliance		
Config	AWS Config should be enabled		Tracks resource configurations for compliance	Compliance		
Config	Config configuration recorder should not fail to deliver logs			Compliance		
DAX	Directory Service			Compliance		
DAX	Directory Service certificates should not expire within 90 days		Prevents disruptions and potential security risks from expired certificates.	Compliance		
DAX	Directory Service directories manual snapshots limit should not be less than 2			Compliance		
DAX	Directory Service directories should have SNS notification enabled			Compliance		
DAX	DynamoDB Accelerator (DAX) clusters should be encrypted at rest		Protects data stored in DAX from unauthorized access.	Compliance		
DLM	DLM EBS snapshot lifecycle policy should be enabled			Compliance		
DMS	DMS endpoints should use SSL		Encrypts data in transit between endpoints to protect it from interception.	Compliance		
DMS	DMS replication instances should have automatic minor version upgrade enabled			Compliance		
DMS	DMS replication instances should not be publicly accessible		Prevents unauthorized access to replication instances from the internet.	Compliance		
DMS	DMS replication tasks for the source database should have logging enabled		Enables audit trails for data migration, aiding in security and troubleshooting.	Compliance		
DMS	DMS replication tasks for the target database should have logging enabled		Enables audit trails for data migration, aiding in security and troubleshooting.	Compliance		
DMS	Ensure that all the expired DMS certificates are removed			Compliance		
DocumentDB	Amazon DocumentDB manual cluster snapshots should not be public			Compliance		
DocumentDB	AWS DocumentDB clusters should be encrypted at rest		Protects stored data from unauthorized access.	Compliance		
DocumentDB	Amazon DocumentDB manual cluster snapshots should not be public		Prevents unauthorized access to snapshot data.	Compliance		
DocumentDB	DocumentDB clusters should have deletion protection enabled			Compliance		
DocumentDB	DocumentDB instance logging should be enabled		Provides audit trails for monitoring and troubleshooting.	Compliance		
DocumentDB	DocumentDB instance should be encrypted at rest			Compliance		
DRS	DRS jobs should be enabled			Compliance		
DynamoDB	DynamoDB table auto scaling should be enabled			Compliance		
DynamoDB	DynamoDB table point-in-time recovery should be enabled		Allows recovery of data to any point in time, ensuring data resilience.	Compliance		
DynamoDB	DynamoDB table should be encrypted with AWS KMS		Protects data at rest from unauthorized access.	Compliance		
DynamoDB	DynamoDB table should be protected by backup plan		Ensures regular backups and recovery options for data protection.	Compliance		
DynamoDB	DynamoDB table should have deletion protection enabled			Compliance		
DynamoDB	DynamoDB table should have encryption enabled			Compliance		
DynamoDB	DynamoDB tables should be in a backup plan			Compliance		
EBS	Attached EBS volumes should have delete on termination enabled			Compliance		
EBS	Attached EBS volumes should have encryption enabled		Protects data at rest from unauthorized access.	Compliance		
EBS	EBS snapshots should be encrypted		Secures backup data from unauthorized access.	Compliance		
EBS	EBS snapshots should not be publicly restorable		Prevents unauthorized access to snapshot data.	Compliance		
EBS	EBS volume encryption at rest should be enabled			Compliance		
EBS	EBS volume snapshots should exist			Compliance		
EBS	EBS volumes should be attached to EC2 instances			Compliance		
EBS	EBS volumes should be in a backup plan			Compliance		
EBS	EBS volumes should be protected by a backup plan			Compliance		
EC2	AWS EC2 instances should have termination protection enabled		Prevents accidental or malicious termination of instances.	Compliance		
EC2	AWS EC2 launch templates should not assign public IPs to network interfaces			Compliance		
EC2	EBS default encryption should be enabled			Compliance		
EC2	EC2 AMIs should restrict public access			Compliance		
EC2	EC2 Client VPN endpoints should have client connection logging enabled			Compliance		
EC2	EC2 instance detailed monitoring should be enabled			Compliance		
EC2	EC2 instance IAM role should not allow cloud log tampering access			Compliance		
EC2	EC2 instance IAM role should not allow database management write access			Compliance		
EC2	EC2 instance IAM role should not allow data destruction access		Restricts permissions to prevent unauthorized data deletion.	Compliance		
EC2	EC2 instance IAM role should not allow defense evasion impact of AWS security services access			Compliance		
EC2	EC2 instance IAM role should not allow destruction KMS access			Compliance		
EC2	EC2 instance IAM role should not allow destruction RDS access			Compliance		
EC2	EC2 instance IAM role should not allow elastic IP hijacking access.			Compliance		
EC2	EC2 instance IAM role should not allow management level access			Compliance		
EC2	EC2 instance IAM role should not allow new group creation with attached policy access			Compliance		
EC2	EC2 instance IAM role should not allow new role creation with attached policy access			Compliance		
EC2	EC2 instance IAM role should not allow new user creation with attached policy access			Compliance		
EC2	EC2 instance IAM role should not allow oraganization write access			Compliance		
EC2	EC2 instance IAM role should not allow privilege escalation risk access			Compliance		
EC2	EC2 instance IAM role should not allow security group write access			Compliance		
EC2	EC2 instance IAM role should not allow to alter critical s3 permissions configuration			Compliance		
EC2	EC2 instance IAM role should not allow write access to resource based policies			Compliance		
EC2	EC2 instance IAM role should not allow write level access			Compliance		
EC2	EC2 instance IAM role should not allow write permission on critical s3 configuration			Compliance		
EC2	EC2 instance IAM role should not be attached with credentials exposure access			Compliance		
EC2	EC2 instance IAM should not allow pass role and lambda invoke function access.			Compliance		
EC2	EC2 instances high level findings should not be there in inspector scans			Compliance		
EC2	EC2 instance should have EBS optimization enabled			Compliance		
EC2	EC2 instances should be in a VPC			Compliance		
EC2	EC2 instances should be protected by backup plan			Compliance		
EC2	EC2 instances should have IAM profile attached			Compliance		
EC2	EC2 instances should not be attached to 'launch wizard' security groups			Compliance		
EC2	EC2 instances should not have a public IP address		Reduces exposure to potential internet-based attacks.	Compliance		
EC2	EC2 instances should not use key pairs in running state			Compliance		
EC2	EC2 instances should not use multiple ENIs			Compliance		
EC2	EC2 instances should use IMDSv2		Enhances security by preventing unauthorized access to instance metadata.	Compliance		
EC2	EC2 instances user data should not have secrets			Compliance		
EC2	EC2 stopped instances should be removed in 30 days			Compliance		
EC2	EC2 transit gateways should have auto accept shared attachments disabled			Compliance		
EC2	Ensure EBS volumes attached to an EC2 instance is marked for deletion upon instance termination		Automatically cleans up EBS volumes when instances are terminated, avoiding orphaned resources.	Compliance		
EC2	Ensure Images (AMI) are not older than 90 days			Compliance		
EC2	Ensure Images (AMI's) are encrypted			Compliance		
EC2	Ensure instances stopped for over 90 days are removed			Compliance		
EC2	Ensure no AWS EC2 Instances are older than 180 days			Compliance		
EC2	Ensure unused ENIs are removed			Compliance		
EC2	Paravirtual EC2 instance types should not be used			Compliance		
EC2	Public EC2 instances should have IAM profile attached			Compliance		
ECR	ECR private repositories should have tag immutability configured		Prevents modification of image tags, ensuring consistency and security.	Compliance		
ECR	ECR repositories should have image scan on push enabled		Detects vulnerabilities in images as they are uploaded, enhancing security.	Compliance		
ECR	ECR repositories should have lifecycle policies configured		Manages image retention, reducing risks from outdated or unused images.	Compliance		
ECR	ECR repositories should prohibit public access		Ensures that sensitive container images are not exposed to unauthorized access.	Compliance		
ECS	At least one instance should be registered with ECS cluster			Compliance		
ECS	AWS ECS services should not have public IP addresses assigned to them automatically			Compliance		
ECS	ECS cluster container instances should have connected agent			Compliance		
ECS	ECS cluster instances should be in a VPC			Compliance		
ECS	ECS clusters encryption at rest should be enabled			Compliance		
ECS	ECS cluster should be configured with active services			Compliance		
ECS	ECS clusters should have container insights enabled			Compliance		
ECS	ECS containers should be limited to read-only access to root filesystems		Prevents unauthorized changes to the container's filesystem.	Compliance		
ECS	ECS containers should run as non-privileged		Minimizes risk of container escapes and unauthorized access.	Compliance		
ECS	ECS fargate services should run on the latest fargate platform version		Ensures security and access to the latest features.	Compliance		
ECS	ECS services should be attached to a load balancer			Compliance		
ECS	ECS task definition container definitions should be checked for host mode			Compliance		
ECS	ECS task definition containers should not have secrets passed as environment variables			Compliance		
ECS	ECS task definitions should have logging enabled		Enhances visibility into container activity for security monitoring.	Compliance		
ECS	ECS task definitions should not share the host's process namespace			Compliance		
ECS	ECS task definitions should not use root user.		Reduces the risk of privilege escalation.	Compliance		
EFS	EFS access points should enforce a root directory			Compliance		
EFS	EFS access points should enforce a user identity			Compliance		
EFS	EFS file system encryption at rest should be enabled		Protects data from unauthorized access if the physical storage is compromised.	Compliance		
EFS	EFS file systems should be encrypted with CMK		Provides additional control and security over encryption keys.	Compliance		
EFS	EFS file systems should be in a backup plan		Ensures data is recoverable in case of accidental loss or corruption.	Compliance		
EFS	EFS file systems should be protected by backup plan			Compliance		
EFS	EFS file systems should enforce SSL		Secures data in transit from interception or tampering.	Compliance		
EFS	EFS file systems should restrict public access		Prevents unauthorized external access to sensitive data.	Compliance		
EKS	EKS clusters endpoint public access should be restricted		Prevents unauthorized access to the cluster from the internet, enhancing security.	Compliance		
EKS	EKS clusters endpoint should restrict public access			Compliance		
EKS	EKS clusters should be configured to have kubernetes secrets encrypted using KMS		Protects sensitive information stored in secrets from unauthorized access.	Compliance		
EKS	EKS clusters should have control plane audit logging enabled		Provides visibility into cluster activities for security monitoring and troubleshooting.	Compliance		
EKS	EKS clusters should not be configured within a default VPC		Reduces the risk of misconfigurations and improves isolation by using a custom VPC.	Compliance		
EKS	EKS clusters should not use multiple security groups			Compliance		
EKS	EKS clusters should run on a supported Kubernetes version		Ensures compatibility with security patches and updates for stable and secure operations.	Compliance		
ElastiCache	ElastiCache clusters should not use public_subnet		Prevents exposure of the cache to the public internet, enhancing security.	Compliance		
ElastiCache	ElastiCache clusters should not use the default subnet group			Compliance		
ElastiCache	ElastiCache for Redis replication groups before version 6.0 should use Redis Auth			Compliance		
ElastiCache	ElastiCache for Redis replication groups should be encrypted at rest		Protects data stored in Redis from unauthorized access.	Compliance		
ElastiCache	ElastiCache for Redis replication groups should be encrypted in transit		Ensures data transmitted between Redis nodes is secure from interception.	Compliance		
ElastiCache	ElastiCache for Redis replication groups should be encrypted with CMK			Compliance		
ElastiCache	ElastiCache for Redis replication groups should have automatic failover enabled		Ensures high availability by automatically recovering from node failures.	Compliance		
ElastiCache	ElastiCache Redis cluster automatic backup should be enabled with retention period of 15 days or greater		Provides data recovery options and ensures historical backups are available.	Compliance		
ElastiCache	Elastic Beanstalk			Compliance		
ElastiCache	Elastic Beanstalk enhanced health reporting should be enabled		Provides detailed insights into the environment’s health for better monitoring and troubleshooting.	Compliance		
ElastiCache	Elastic Beanstalk environment should have managed updates enabled		Keeps the environment updated with the latest patches and features automatically.	Compliance		
ElastiCache	Elastic Beanstalk should stream logs to CloudWatch		Centralizes log management and enables effective monitoring and alerting.	Compliance		
ElastiCache	Minor version upgrades should be automatically applied to ElastiCache for Redis cache clusters			Compliance		
Elasticsearch	Connections to Elasticsearch domains should be encrypted using TLS 1.2		Ensures secure communication by enforcing strong encryption standards.	Compliance		
Elasticsearch	Elasticsearch domain error logging to CloudWatch Logs should be enabled		Provides visibility into domain errors, aiding in monitoring and troubleshooting.	Compliance		
Elasticsearch	Elasticsearch domain node-to-node encryption should be enabled		Protects data transferred between Elasticsearch nodes from interception or tampering.	Compliance		
Elasticsearch	Elasticsearch domain should send logs to CloudWatch			Compliance		
Elasticsearch	Elasticsearch domains should be configured with at least three dedicated master nodes			Compliance		
Elasticsearch	Elasticsearch domains should have at least three data nodes			Compliance		
Elasticsearch	Elasticsearch domains should have audit logging enabled		Captures detailed logs of user activities, improving security and compliance.	Compliance		
Elasticsearch	Elasticsearch domains should have cognito authentication enabled			Compliance		
Elasticsearch	Elasticsearch domains should have internal user database enabled			Compliance		
Elasticsearch	ES domain encryption at rest should be enabled		Protects stored data from unauthorized access by encrypting it at rest.	Compliance		
Elasticsearch	ES domains should be in a VPC		Isolates the domain within a secure network, limiting public access.	Compliance		
ELB	Classic Load Balancers should have connection draining enabled			Compliance		
ELB	ELB application and classic load balancer logging should be enabled		Enabling logging provides visibility into traffic patterns, helps with troubleshooting, and supports auditing efforts	Compliance		
ELB	ELB application and network load balancers should only use SSL or HTTPS listeners			Compliance		
ELB	ELB application and network load balancers should use listeners			Compliance		
ELB	ELB application load balancer deletion protection should be enabled		Provides visibility and audit trails for security monitoring and troubleshooting.	Compliance		
ELB	ELB application load balancers secured listener certificate should not expire within next 30 days			Compliance		
ELB	ELB application load balancers secured listener certificate should not expire within next 7 days			Compliance		
ELB	ELB application load balancers should be configured with defensive or strictest desync mitigation mode			Compliance		
ELB	ELB application load balancers should be drop HTTP headers			Compliance		
ELB	ELB application load balancers should have at least one outbound rule			Compliance		
ELB	ELB application load balancers should have Web Application Firewall (WAF) enabled		Enabling WAF provides additional security by filtering and monitoring HTTP requests to protect against common web exploits	Compliance		
ELB	ELB application load balancers should redirect HTTP requests to HTTPS		Prevents unencrypted traffic, enforcing secure connections for all users.	Compliance		
ELB	ELB classic load balancers should be configured with defensive or strictest desync mitigation mode			Compliance		
ELB	ELB classic load balancers should have at least one inbound rule			Compliance		
ELB	ELB classic load balancers should have at least one outbound rule			Compliance		
ELB	ELB classic load balancers should have at least one registered instance			Compliance		
ELB	ELB classic load balancers should have cross-zone load balancing enabled			Compliance		
ELB	ELB classic load balancers should only use SSL or HTTPS listeners		Forces encrypted communication, ensuring data is secure during transmission.	Compliance		
ELB	ELB classic load balancers should span multiple availability zones			Compliance		
ELB	ELB classic load balancers should use SSL certificates			Compliance		
ELB	ELB listeners should use secure SSL cipher		Ensures encrypted connections use strong cryptographic protocols to prevent vulnerabilities.	Compliance		
ELB	ELB listeners SSL/TLS protocol version should be checked			Compliance		
ELB	ELB load balancers should prohibit public access		Restricts unauthorized access to internal resources, enhancing security.			
ELB	ELB network load balancers should have TLS listener security policy configured				Restricts unauthorized access to internal resources, enhancing security.	
EMR	EMR cluster Kerberos should be enabled			Compliance		
EMR	EMR cluster local disks should be encrypted with CMK		Encrypting local disks with Customer Master Keys (CMK) ensures that data stored on local disks is secure	Compliance		
EMR	EMR cluster master nodes should not have public IP addresses		Preventing master nodes from having public IP addresses reduces exposure to the internet and minimizes attack vectors	Compliance		
EMR	EMR clusters client side encryption (CSE CMK) enabled with CMK			Compliance		
EMR	EMR clusters encryption at rest should be enabled		Protects stored data from unauthorized access.	Compliance		
EMR	EMR clusters encryption in transit should be enabled			Compliance		
EMR	EMR clusters local disk encryption should be enabled			Compliance		
EMR	EMR clusters server side encryption (SSE KMS) enabled with KMS			Compliance		
EMR	EMR clusters should have security configuration enabled		Security configurations provide a comprehensive set of security controls, including encryption and access controls, for EMR clusters	Compliance		
EMR	EMR public access should be blocked at account level		Blocking public access at the account level prevents EMR clusters from being exposed to the internet	Compliance		
EventBridge	EventBridge custom event buses should have a resource-based policy attached			Compliance		
FSx	FSx file system should be protected by backup plan			Compliance		
FSx	FSx for OpenZFS file systems should be configured to copy tags to backups and volumes			Compliance		
Glacier	Glacier vault should restrict public access			Compliance		
Glue	Glue connection SSL should be enabled			Compliance		
Glue	Glue data catalog connection password encryption should be enabled			Compliance		
Glue	Glue data catalog metadata encryption should be enabled			Compliance		
Glue	Glue dev endpoints CloudWatch logs encryption should be enabled			Compliance		
Glue	Glue dev endpoints job bookmark encryption should be enabled			Compliance		
Glue	Glue dev endpoints S3 encryption should be enabled			Compliance		
Glue	Glue jobs bookmarks encryption should be enabled			Compliance		
Glue	Glue jobs CloudWatch logs encryption should be enabled			Compliance		
Glue	Glue jobs S3 encryption should be enabled			Compliance		
GuardDuty	GuardDuty Detector should be centrally configured		configuration of GuardDuty detectors ensures consistent security monitoring and management across your AWS environment	Compliance		
GuardDuty	GuardDuty Detector should not have high severity findings		Addressing high severity findings promptly helps to mitigate critical security threats and maintain a secure environment	Compliance		
GuardDuty	GuardDuty findings should be archived		Archiving GuardDuty findings provides a record of security alerts for compliance and future reference.	Compliance		
GuardDuty	GuardDuty should be enabled			Compliance		
IAM	Eliminate use of the 'root' user for administrative and daily tasks		Reduces risk by avoiding the use of highly privileged accounts for routine operations.	Compliance		
IAM	Ensure access to AWSCloudShellFullAccess is restricted			Compliance		
IAM	Ensure a support role has been created to manage incidents with AWS Support			Compliance		
IAM	Ensure credentials unused for 45 days or greater are disabled		 Reduces the risk of unused accounts being exploited.	Compliance		
IAM	Ensure IAM password policy expires passwords within 90 days or less			Compliance		
IAM	Ensure IAM password policy prevents password reuse			Compliance		
IAM	Ensure IAM password policy requires a minimum length of 14 or greater			Compliance		
IAM	Ensure IAM password policy requires at least one lowercase letter			Compliance		
IAM	Ensure IAM password policy requires at least one number			Compliance		
IAM	Ensure IAM password policy requires at least one symbol			Compliance		
IAM	Ensure IAM password policy requires at least one uppercase letter			Compliance		
IAM	Ensure IAM policies are attached only to groups or roles			Compliance		
IAM	Ensure IAM policies that allow full "*:*" administrative privileges are not attached			Compliance		
IAM	Ensure IAM policy should not grant full access to service			Compliance		
IAM	Ensure IAM role not attached with Administratoraccess policy			Compliance		
IAM	Ensure IAM users are assigned access keys and passwords at setup			Compliance		
IAM	Ensure IAM users with access keys unused for 45 days or greater are disabled		 Reduces the risk of unused accounts being exploited.	Compliance		
IAM	Ensure IAM users with console access unused for 45 days or greater are disabled		 Reduces the risk of unused accounts being exploited.	Compliance		
IAM	Ensure managed IAM policies should not allow blocked actions on KMS keys			Compliance		
IAM	Ensure that all the expired SSL/TLS certificates stored in AWS IAM are removed			Compliance		
IAM	Ensure that IAM Access analyzer is enabled for all regions			Compliance		
IAM	Ensure there is only one active access key available for any single IAM user			Compliance		
IAM	IAM Access analyzer should be enabled without findings			Compliance		
IAM	IAM administrator users should have MFA enabled			Compliance		
IAM	IAM AWS managed policies should be attached to IAM role			Compliance		
IAM	IAM custom policy should not have overly permissive STS role assumption			Compliance		
IAM	IAM groups should have at least one user			Compliance		
IAM	IAM inline policy should not have administrative privileges			Compliance		
IAM	IAM password policies for users should have strong configurations			Compliance		
IAM	IAM policies should not allow full '*' administrative privileges			Compliance		
IAM	IAM policy should be in use			Compliance		
IAM	IAM policy should not grant full access to cloudtrail service			Compliance		
IAM	IAM policy should not grant full access to KMS service			Compliance		
IAM	IAM policy should not have statements with admin access			Compliance		
IAM	IAM roles should not have any assume role policies attached			Compliance		
IAM	IAM roles should not have read only access for external AWS accounts			Compliance		
IAM	IAM roles that have not been used in 60 days should be removed			Compliance		
IAM	IAM root user hardware MFA should be enabled			Compliance		
IAM	IAM root user MFA should be enabled			Compliance		
IAM	IAM root user should not have access keys			Compliance		
IAM	IAM Security Audit role should be created to conduct security audits			Compliance		
IAM	IAM unattached custom policy should not have statements with admin access			Compliance		
IAM	IAM user access keys should be rotated at least every 90 days			Compliance		
IAM	IAM user credentials that have not been used in 90 days should be disabled			Compliance		
IAM	IAM user MFA should be enabled			Compliance		
IAM	IAM user should not have any inline or attached policies			Compliance		
IAM	IAM users should be in at least one group			Compliance		
IAM	IAM users should have hardware MFA enabled			Compliance		
IAM	IAM users with console access should have MFA enabled			Compliance		
IAM	Password policies for IAM users should have strong configurations with minimum length of 8 or greater			Compliance		
Kinesis	Kinesis firehose delivery streams should have server side encryption enabled			Compliance		
Kinesis	Kinesis streams should be encrypted with CMK			Compliance		
Kinesis	Kinesis streams should have server side encryption enabled			Compliance		
KMS	KMS CMK policies should prohibit public access			Compliance		
KMS	KMS CMK rotation should be enabled			Compliance		
KMS	KMS key decryption should be restricted in IAM customer managed policy			Compliance		
KMS	KMS key decryption should be restricted in IAM inline policy			Compliance		
KMS	KMS key should be in use			Compliance		
KMS	KMS keys should not be pending deletion			Compliance		
Lambda	Ensure Cloudwatch Lambda insights is enabled			Compliance		
Lambda	Ensure encryption in transit is enabled for Lambda environment variables			Compliance		
Lambda	Lambda functions CloudTrail logging should be enabled			Compliance		
Lambda	Lambda functions concurrent execution limit configured			Compliance		
Lambda	Lambda functions CORS configuration should not allow all origins			Compliance		
Lambda	Lambda functions should be configured with a dead-letter queue			Compliance		
Lambda	Lambda functions should be in a VPC			Compliance		
Lambda	Lambda functions should operate in more than one availability zone			Compliance		
Lambda	Lambda functions should restrict public access			Compliance		
Lambda	Lambda functions should restrict public URL			Compliance		
Lambda	Lambda functions should use latest runtimes			Compliance		
Lambda	Lambda functions tracing should be enabled			Compliance		
Lambda	Lambda functions variable should not have any sensitive data			Compliance		
Lightsail	Disable IPv6 Networking if not in use within your organization			Compliance		
Lightsail	Disable SSH and RDP ports for Lightsail instances when not needed			Compliance		
Lightsail	Ensure RDP is restricted to only IP address that should have this access			Compliance		
Lightsail	Ensure SSH is restricted to only IP address that should have this access			Compliance		
MQ	MQ brokers should restrict public access			Compliance		
MSK	MSK clusters should be encrypted in transit among broker nodes			Compliance		
Neptune	Neptune DB cluster snapshots should be encrypted at rest			Compliance		
Neptune	Neptune DB cluster snapshots should not be public			Compliance		
Neptune	Neptune DB clusters should be configured to copy tags to snapshots			Compliance		
Neptune	Neptune DB clusters should be encrypted at rest			Compliance		
Neptune	Neptune DB clusters should have automated backups enabled			Compliance		
Neptune	Neptune DB clusters should have deletion protection enabled			Compliance		
Neptune	Neptune DB clusters should have IAM database authentication enabled			Compliance		
Neptune	Neptune DB clusters should not use public_subnet			Compliance		
Neptune	Neptune DB clusters should publish audit logs to CloudWatch Logs			Compliance		
Network Firewall	Networkfirewall firewall should be in a VPC			Compliance		
Network Firewall	Network Firewall firewalls should have deletion protection enabled			Compliance		
Network Firewall	Network Firewall logging should be enabled			Compliance		
Network Firewall	Network Firewall policies should have at least one rule group associated			Compliance		
Network Firewall	Stateless network firewall rule group should not be empty			Compliance		
Network Firewall	The default stateless action for Network Firewall policies should be drop or forward for fragmented packets			Compliance		
Network Firewall	The default stateless action for Network Firewall policies should be drop or forward for full packets			Compliance		
OpenSearch	OpenSearch domains cognito authentication should be enabled for kibana		Ensures that access to Kibana is secured using AWS Cognito for authentication.	Compliance		
OpenSearch	OpenSearch domains internal user database should be disabled			Compliance		
OpenSearch	OpenSearch domains logs to AWS CloudWatch Logs			Compliance		
OpenSearch	OpenSearch domains node-to-node encryption should be enabled			Compliance		
OpenSearch	OpenSearch domains should be in a VPC			Compliance		
OpenSearch	OpenSearch domains should be updated to the latest service software version			Compliance		
OpenSearch	OpenSearch domains should have at least three data nodes			Compliance		
OpenSearch	OpenSearch domains should have audit logging enabled.			Compliance		
OpenSearch	OpenSearch domains should have encryption at rest enabled		Protects data stored in OpenSearch domains.	Compliance		
OpenSearch	OpenSearch domains should have fine-grained access control enabled			Compliance		
OpenSearch	OpenSearch domains should use HTTPS			Compliance		
Operational Excellence	API Gateway stage logging should be enabled			AWS Well-Architected Framework		
Operational Excellence	At least one enabled trail should be present in a region			AWS Well-Architected Framework		
Operational Excellence	Auto Scaling groups with a load balancer should use health checks			AWS Well-Architected Framework		
Operational Excellence	AWS Config should be enabled		Monitors and records AWS resource configurations for auditing and compliance.	AWS Well-Architected Framework		
Operational Excellence	CloudFront distributions access logs should be enabled			AWS Well-Architected Framework		
Operational Excellence	CloudTrail trails should be integrated with CloudWatch logs			AWS Well-Architected Framework		
Operational Excellence	CloudWatch alarm should have an action configured			AWS Well-Architected Framework		
Operational Excellence	CodeBuild projects should have logging enabled			AWS Well-Architected Framework		
Operational Excellence	EC2 instance detailed monitoring should be enabled		Provides enhanced monitoring for EC2 instances, improving visibility into instance performance.	AWS Well-Architected Framework		
Operational Excellence	ECS task definitions should have logging enabled			AWS Well-Architected Framework		
Operational Excellence	Elastic Beanstalk enhanced health reporting should be enabled			AWS Well-Architected Framework		
Operational Excellence	ELB application and classic load balancer logging should be enabled		Captures logs for load balancers to monitor and troubleshoot traffic issues.	AWS Well-Architected Framework		
Operational Excellence	RDS DB instances should be integrated with CloudWatch logs			AWS Well-Architected Framework		
Operational Excellence	SSM managed instance patching should be compliant			AWS Well-Architected Framework		
Operational Excellence	VPC flow logs should be enabled		Captures information about network traffic for security analysis and troubleshooting.	AWS Well-Architected Framework		
Organization	AWS Private CA root certificate authority should be disabled			Compliance		
Organization	Ensure Tag Policies are enabled			Compliance		
Organization	Private Certificate Authority			Compliance		
RDS	An RDS event notifications subscription should be configured for critical cluster events			Compliance		
RDS	An RDS event notifications subscription should be configured for critical database instance events			Compliance		
RDS	An RDS event notifications subscription should be configured for critical database parameter group events			Compliance		
RDS	An RDS event notifications subscription should be configured for critical database security group events			Compliance		
RDS	Aurora MySQL DB clusters should publish audit logs to CloudWatch Logs			Compliance		
RDS	Database logging should be enabled			Compliance		
RDS	IAM authentication should be configured for RDS clusters			Compliance		
RDS	RDS Aurora clusters should be protected by backup plan			Compliance		
RDS	RDS Aurora clusters should have backtracking enabled			Compliance		
RDS	RDS Aurora PostgreSQL clusters should not be exposed to local file read vulnerability			Compliance		
RDS	RDS clusters should have deletion protection enabled			Compliance		
RDS	RDS database clusters should use a custom administrator username			Compliance		
RDS	RDS database instances should use a custom administrator username			Compliance		
RDS	RDS databases and clusters should not use a database engine default port			Compliance		
RDS	RDS DB clusters should be configured for multiple Availability Zones			Compliance		
RDS	RDS DB clusters should be configured to copy tags to snapshots			Compliance		
RDS	RDS DB clusters should be encrypted at rest			Compliance		
RDS	RDS DB clusters should be encrypted with CMK			Compliance		
RDS	RDS DB clusters should have automatic minor version upgrade enabled			Compliance		
RDS	RDS DB instance and cluster enhanced monitoring should be enabled			Compliance		
RDS	RDS DB instance automatic minor version upgrade should be enabled			Compliance		
RDS	RDS DB instance backup should be enabled			Compliance		
RDS	RDS DB instance encryption at rest should be enabled			Compliance		
RDS	RDS DB instance multiple az should be enabled			Compliance		
RDS	RDS DB instances backup retention period should be greater than or equal to 7			Compliance		
RDS	RDS DB instances CA certificates should not expire within next 7 days			Compliance		
RDS	RDS DB instances connections should be encrypted			Compliance		
RDS	RDS DB instance should be protected by backup plan			Compliance		
RDS	RDS DB instances should be configured to copy tags to snapshots			Compliance		
RDS	RDS DB instances should be in a backup plan			Compliance		
RDS	RDS DB instances should be integrated with CloudWatch logs			Compliance		
RDS	RDS DB instances should have deletion protection enabled			Compliance		
RDS	RDS DB instances should have iam authentication enabled			Compliance		
RDS	RDS DB instances should not use public subnet			Compliance		
RDS	RDS DB instances should prohibit public access			Compliance		
RDS	RDS DB snapshots should be encrypted at rest			Compliance		
RDS	RDS instances should be deployed in a VPC			Compliance		
RDS	RDS PostgreSQL DB instances should not be exposed to local file read vulnerability			Compliance		
RDS	RDS snapshots should prohibit public access			Compliance		
Redshift	AWS Redshift audit logging should be enabled		Tracks and monitors access to Redshift clusters.	Compliance		
Redshift	AWS Redshift clusters should be encrypted with KMS		Protects data at rest using KMS keys.	Compliance		
Redshift	AWS Redshift clusters should have automatic snapshots enabled			Compliance		
Redshift	AWS Redshift clusters should not use the default Admin username			Compliance		
Redshift	AWS Redshift enhanced VPC routing should be enabled			Compliance		
Redshift	AWS Redshift should have automatic upgrades to major versions enabled			Compliance		
Redshift	AWS Redshift should have required maintenance settings			Compliance		
Redshift	Redshift cluster audit logging and encryption should be enabled			Compliance		
Redshift	Redshift cluster encryption in transit should be enabled		Protects data as it travels between the cluster and other services.	Compliance		
Redshift	Redshift clusters should be encrypted with CMK		Uses customer-managed keys for encryption.	Compliance		
Redshift	Redshift clusters should not use the default database name			Compliance		
Redshift	Redshift clusters should prohibit public access			Compliance		
Reliability	ACM certificates should have transparency logging enabled			AWS Well-Architected Framework		
Reliability	API Gateway stage logging should be enabled			AWS Well-Architected Framework		
Reliability	AWS Redshift enhanced VPC routing should be enabled			AWS Well-Architected Framework		
Reliability	Backup recovery points manual deletion should be disabled			AWS Well-Architected Framework		
Reliability	Backup recovery points should be encrypted			AWS Well-Architected Framework		
Reliability	Backup recovery points should not expire before retention period			AWS Well-Architected Framework		
Reliability	Both VPN tunnels provided by AWS Site-to-Site VPN should be in UP status			AWS Well-Architected Framework		
Reliability	CloudFront distributions should have AWS WAF enabled			AWS Well-Architected Framework		
Reliability	CloudFront distributions should have origin failover configured			AWS Well-Architected Framework		
Reliability	CodeBuild projects should have logging enabled			AWS Well-Architected Framework		
Reliability	Database logging should be enabled			AWS Well-Architected Framework		
Reliability	DynamoDB table auto scaling should be enabled			AWS Well-Architected Framework		
Reliability	DynamoDB table point-in-time recovery should be enabled			AWS Well-Architected Framework		
Reliability	DynamoDB table should be protected by backup plan			AWS Well-Architected Framework		
Reliability	DynamoDB table should have encryption enabled			AWS Well-Architected Framework		
Reliability	DynamoDB tables should be in a backup plan			AWS Well-Architected Framework		
Reliability	EBS default encryption should be enabled			AWS Well-Architected Framework		
Reliability	EBS volume encryption at rest should be enabled			AWS Well-Architected Framework		
Reliability	EC2 auto scaling groups should cover multiple availability zones			AWS Well-Architected Framework		
Reliability	EC2 instance detailed monitoring should be enabled			AWS Well-Architected Framework		
Reliability	EC2 instances should be in a VPC			AWS Well-Architected Framework		
Reliability	EC2 instances should be protected by backup plan			AWS Well-Architected Framework		
Reliability	ECS cluster instances should be in a VPC			AWS Well-Architected Framework		
Reliability	ECS clusters should have container insights enabled			AWS Well-Architected Framework		
Reliability	ECS task definitions should have logging enabled			AWS Well-Architected Framework		
Reliability	ElastiCache Redis cluster automatic backup should be enabled with retention period of 15 days or greater			AWS Well-Architected Framework		
Reliability	Elastic Beanstalk enhanced health reporting should be enabled			AWS Well-Architected Framework		
Reliability	ELB application and classic load balancer logging should be enabled			AWS Well-Architected Framework		
Reliability	ELB classic load balancers should have cross-zone load balancing enabled			AWS Well-Architected Framework		
Reliability	ELB classic load balancers should span multiple availability zones			AWS Well-Architected Framework		
Reliability	ES domains should be in a VPC			AWS Well-Architected Framework		
Reliability	FSx file system should be protected by backup plan			AWS Well-Architected Framework		
Reliability	Lambda functions CloudTrail logging should be enabled			AWS Well-Architected Framework		
Reliability	Lambda functions concurrent execution limit configured			AWS Well-Architected Framework		
Reliability	Lambda functions should be in a VPC			AWS Well-Architected Framework		
Reliability	Lambda functions should operate in more than one availability zone			AWS Well-Architected Framework		
Reliability	OpenSearch domains should have audit logging enabled.			AWS Well-Architected Framework		
Reliability	RDS Aurora clusters should be protected by backup plan			AWS Well-Architected Framework		
Reliability	RDS Aurora clusters should have backtracking enabled			AWS Well-Architected Framework		
Reliability	RDS DB clusters should be configured for multiple Availability Zones			AWS Well-Architected Framework		
Reliability	RDS DB instance automatic minor version upgrade should be enabled			AWS Well-Architected Framework		
Reliability	RDS DB instance backup should be enabled			AWS Well-Architected Framework		
Reliability	RDS DB instance encryption at rest should be enabled			AWS Well-Architected Framework		
Reliability	RDS DB instance multiple az should be enabled			AWS Well-Architected Framework		
Reliability	RDS DB snapshots should be encrypted at rest			AWS Well-Architected Framework		
Reliability	Route 53 zones should have query logging enabled			AWS Well-Architected Framework		
Reliability	S3 bucket cross-region replication should be enabled			AWS Well-Architected Framework		
Reliability	S3 bucket default encryption should be enabled			AWS Well-Architected Framework		
Reliability	S3 bucket logging should be enabled			AWS Well-Architected Framework		
Reliability	S3 buckets object logging should be enabled			AWS Well-Architected Framework		
Reliability	WAF web ACL logging should be enabled			AWS Well-Architected Framework		
Route 53	Route 53 domains auto renew should be enabled			Compliance		
Route 53	Route53 domains privacy protection should be enabled		Protects sensitive domain registration details (e.g., personal information) from being publicly accessible in WHOIS records.	Compliance		
Route 53	Route 53 domains should have transfer lock enabled		Prevents unauthorized domain transfers, ensuring that your domain cannot be moved to another registrar without your consent.	Compliance		
Route 53	Route 53 domains should not be expired			Compliance		
Route 53	Route 53 domains should not expire within next 30 days			Compliance		
Route 53	Route 53 domains should not expire within next 7 days			Compliance		
Route 53	Route 53 zones should have query logging enabled		Allows tracking and auditing of DNS queries, which is essential for identifying unusual activity or potential security threats.	Compliance		
S3	AWS S3 permissions granted to other AWS accounts in bucket policies should be restricted			Compliance		
S3	Ensure MFA Delete is enabled on S3 buckets			Compliance		
S3	S3 access points should have block public access settings enabled			Compliance		
S3	S3 bucket ACLs should not be accessible to all authenticated user		Prevents bucket contents from being exposed to users outside of your organization.	Compliance		
S3	S3 bucket cross-region replication should be enabled			Compliance		
S3	S3 bucket default encryption should be enabled			Compliance		
S3	S3 bucket default encryption should be enabled with KMS		Ensures that data in the bucket is encrypted with customer-managed keys (KMS), giving more control and security over the data.	Compliance		
S3	S3 bucket logging should be enabled		Enables tracking of access requests to the S3 bucket for security audits and analysis.	Compliance		
S3	S3 bucket object lock should be enabled			Compliance		
S3	S3 bucket policy should prohibit public access		Prevents public access to your S3 buckets, ensuring sensitive data isn’t exposed.	Compliance		
S3	S3 buckets access control lists (ACLs) should not be used to manage user access to buckets			Compliance		
S3	S3 buckets object logging should be enabled			Compliance		
S3	S3 buckets should enforce SSL		Ensures secure transport (HTTPS) when accessing S3 buckets.	Compliance		
S3	S3 buckets should have event notifications enabled			Compliance		
S3	S3 buckets should have lifecycle policies configured			Compliance		
S3	S3 buckets should prohibit public read access			Compliance		
S3	S3 buckets should prohibit public write access		Prevents unauthorized users from writing to your bucket.	Compliance		
S3	S3 buckets static website hosting should be disabled			Compliance		
S3	S3 buckets with versioning enabled should have lifecycle policies configured			Compliance		
S3	S3 bucket versioning should be enabled			Compliance		
S3	S3 public access should be blocked at account and bucket levels		Blocking public access globally ensures there are no misconfigurations that allow public access.	Compliance		
S3	S3 public access should be blocked at account level			Compliance		
S3	S3 public access should be blocked at bucket levels			Compliance		
SageMaker	SageMaker endpoint configuration encryption should be enabled			Compliance		
SageMaker	SageMaker models should be in a VPC			Compliance		
SageMaker	SageMaker models should have network isolation enabled			Compliance		
SageMaker	SageMaker notebook instance encryption should be enabled			Compliance		
SageMaker	SageMaker notebook instances root access should be disabled			Compliance		
SageMaker	SageMaker notebook instances should be encrypted using CMK			Compliance		
SageMaker	SageMaker notebook instances should be in a VPC			Compliance		
SageMaker	SageMaker notebook instances should not have direct internet access			Compliance		
SageMaker	SageMaker training jobs should be enabled with inter-container traffic encryption			Compliance		
SageMaker	SageMaker training jobs should be in VPC			Compliance		
SageMaker	SageMaker training jobs should have network isolation enabled			Compliance		
SageMaker	SageMaker training jobs volumes and outputs should have KMS encryption enabled			Compliance		
Secrets Manager	Remove unused Secrets Manager secrets			Compliance		
Secrets Manager	Secrets Manager secrets should be encrypted using CMK		Ensures that sensitive information is encrypted with customer-managed keys for better control.	Compliance		
Secrets Manager	Secrets Manager secrets should be rotated as per the rotation schedule			Compliance		
Secrets Manager	Secrets Manager secrets should be rotated within a specified number of days			Compliance		
Secrets Manager	Secrets Manager secrets should be rotated within specific number of days			Compliance		
Secrets Manager	Secrets Manager secrets should have automatic rotation enabled		Automatic rotation helps to regularly update and secure sensitive credentials.	Compliance		
Secrets Manager	Secrets Manager secrets that have not been used in 90 days should be removed		Removes old, unused secrets that might become a security risk.	Compliance		
Security	3.10 Ensure that Object-level logging for write events is enabled for S3 bucket		All of the listed security checks are important for ensuring the security, compliance, and governance of your AWS environment. These checks cover a wide range of services and areas such as encryption, access control, logging, and network configurations, which are critical to maintaining a secure cloud infrastructure.	AWS Well-Architected Framework		
Security	3.11 Ensure that Object-level logging for read events is enabled for S3 bucket		None of the lines seem unnecessary or unimportant in the context of maintaining a robust and secure system.	AWS Well-Architected Framework		
Security	5.2 Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports			AWS Well-Architected Framework		
Security	ACM certificates should have transparency logging enabled			AWS Well-Architected Framework		
Security	ACM certificates should not expire within 30 days			AWS Well-Architected Framework		
Security	All S3 buckets should log S3 data events in CloudTrail			AWS Well-Architected Framework		
Security	API Gateway stage cache encryption at rest should be enabled			AWS Well-Architected Framework		
Security	API Gateway stage logging should be enabled			AWS Well-Architected Framework		
Security	API Gateway stage should be associated with waf			AWS Well-Architected Framework		
Security	API Gateway stage should uses SSL certificate			AWS Well-Architected Framework		
Security	API Gateway stages should have authorizers configured			AWS Well-Architected Framework		
Security	At least one multi-region AWS CloudTrail should be present in an account			AWS Well-Architected Framework		
Security	At least one trail should be enabled with security best practices			AWS Well-Architected Framework		
Security	Auto Scaling launch config public IP should be disabled			AWS Well-Architected Framework		
Security	AWS account should be part of AWS Organizations			AWS Well-Architected Framework		
Security	AWS Config should be enabled			AWS Well-Architected Framework		
Security	AWS Redshift audit logging should be enabled			AWS Well-Architected Framework		
Security	AWS Redshift clusters should be encrypted with KMS			AWS Well-Architected Framework		
Security	AWS Redshift enhanced VPC routing should be enabled			AWS Well-Architected Framework		
Security	AWS Redshift should have required maintenance settings			AWS Well-Architected Framework		
Security	Backup recovery points should be encrypted			AWS Well-Architected Framework		
Security	BP02 Enforce encryption at rest			AWS Well-Architected Framework		
Security	BP02 Secure account root user and properties			AWS Well-Architected Framework		
Security	BP03 Automate response to events			AWS Well-Architected Framework		
Security	CloudFront distributions access logs should be enabled			AWS Well-Architected Framework		
Security	CloudFront distributions should encrypt traffic to custom origins			AWS Well-Architected Framework		
Security	CloudFront distributions should have AWS WAF enabled			AWS Well-Architected Framework		
Security	CloudFront distributions should not use deprecated SSL protocols between edge locations and custom origins			AWS Well-Architected Framework		
Security	CloudTrail trail log file validation should be enabled			AWS Well-Architected Framework		
Security	CloudTrail trail logs should be encrypted with KMS CMK			AWS Well-Architected Framework		
Security	CloudTrail trails should be integrated with CloudWatch logs			AWS Well-Architected Framework		
Security	CloudWatch should not allow cross-account sharing			AWS Well-Architected Framework		
Security	CodeBuild project artifact encryption should be enabled			AWS Well-Architected Framework		
Security	CodeBuild project plaintext environment variables should not contain sensitive AWS values			AWS Well-Architected Framework		
Security	CodeBuild project S3 logs should be encrypted			AWS Well-Architected Framework		
Security	CodeBuild projects should not be unused for 90 days or greater			AWS Well-Architected Framework		
Security	CodeBuild projects should not use an user controlled buildspec			AWS Well-Architected Framework		
Security	Database logging should be enabled			AWS Well-Architected Framework		
Security	DMS replication instances should not be publicly accessible			AWS Well-Architected Framework		
Security	DynamoDB table should have encryption enabled			AWS Well-Architected Framework		
Security	EBS default encryption should be enabled			AWS Well-Architected Framework		
Security	EBS snapshots should not be publicly restorable			AWS Well-Architected Framework		
Security	EBS volumes should be attached to EC2 instances			AWS Well-Architected Framework		
Security	EC2 instances should be in a VPC			AWS Well-Architected Framework		
Security	EC2 instances should be managed by AWS Systems Manager			AWS Well-Architected Framework		
Security	EC2 instances should have IAM profile attached			AWS Well-Architected Framework		
Security	EC2 instances should not be attached to 'launch wizard' security groups			AWS Well-Architected Framework		
Security	EC2 instances should not have a public IP address			AWS Well-Architected Framework		
Security	EC2 instances should not use multiple ENIs			AWS Well-Architected Framework		
Security	EC2 instances should use IMDSv2			AWS Well-Architected Framework		
Security	EC2 stopped instances should be removed in 30 days			AWS Well-Architected Framework		
Security	ECR repositories should have image scan o			AWS Well-Architected Framework		
Security	ECR repositories should have image scan on push enabled			AWS Well-Architected Framework		
Security	ECR repositories should have lifecycle policies configured			AWS Well-Architected Framework		
Security	ECR repositories should prohibit public access			AWS Well-Architected Framework		
Security	ECS clusters should have container insights enabled			AWS Well-Architected Framework		
Security	ECS containers should be limited to read-only access to root filesystems			AWS Well-Architected Framework		
Security	ECS fargate services should run on the latest fargate platform version			AWS Well-Architected Framework		
Security	ECS task definition container definitions should be checked for host mode			AWS Well-Architected Framework		
Security	EFS file system encryption at rest should be enabled			AWS Well-Architected Framework		
Security	EKS clusters endpoint should restrict public access			AWS Well-Architected Framework		
Security	EKS clusters should be configured to have kubernetes secrets encrypted using KMS			AWS Well-Architected Framework		
Security	EKS clusters should have control plane audit logging enabled			AWS Well-Architected Framework		
Security	Elasticsearch domain node-to-node encryption should be enabled			AWS Well-Architected Framework		
Security	Elasticsearch domain should send logs to CloudWatch			AWS Well-Architected Framework		
Security	ELB application and classic load balancer logging should be enabled			AWS Well-Architected Framework		
Security	ELB application and network load balancers should only use SSL or HTTPS listeners			AWS Well-Architected Framework		
Security	ELB application load balancers should be drop HTTP headers			AWS Well-Architected Framework		
Security	ELB application load balancers should have Web Application Firewall (WAF) enabled			AWS Well-Architected Framework		
Security	ELB application load balancers should redirect HTTP requests to HTTPS			AWS Well-Architected Framework		
Security	ELB classic load balancers should only use SSL or HTTPS listeners			AWS Well-Architected Framework		
Security	ELB classic load balancers should use SSL certificates			AWS Well-Architected Framework		
Security	ELB listeners should use secure SSL cipher			AWS Well-Architected Framework		
Security	ELB load balancers should prohibit public access			AWS Well-Architected Framework		
Security	EMR cluster Kerberos should be enabled			AWS Well-Architected Framework		
Security	EMR cluster master nodes should not have public IP addresses			AWS Well-Architected Framework		
Security	EMR public access should be blocked at account level			AWS Well-Architected Framework		
Security	Ensure a support role has been created to manage incidents with AWS Support			AWS Well-Architected Framework		
Security	Ensure IAM password policy expires passwords within 90 days or less			AWS Well-Architected Framework		
Security	Ensure managed IAM policies should not allow blocked actions on KMS keys			AWS Well-Architected Framework		
Security	Ensure the S3 bucket CloudTrail logs to is not publicly accessible			AWS Well-Architected Framework		
Security	ES domain encryption at rest should be enabled			AWS Well-Architected Framework		
Security	ES domains should be in a VPC			AWS Well-Architected Framework		
Security	Glue dev endpoints CloudWatch logs encryption should be enabled			AWS Well-Architected Framework		
Security	Glue dev endpoints job bookmark encryption should be enabled			AWS Well-Architected Framework		
Security	Glue dev endpoints S3 encryption should be enabled			AWS Well-Architected Framework		
Security	Glue jobs bookmarks encryption should be enabled			AWS Well-Architected Framework		
Security	Glue jobs CloudWatch logs encryption should be enabled			AWS Well-Architected Framework		
Security	Glue jobs S3 encryption should be enabled			AWS Well-Architected Framework		
Security	GuardDuty should be enabled			AWS Well-Architected Framework		
Security	IAM groups should have at least one user			AWS Well-Architected Framework		
Security	IAM policy should not have statements with admin access			AWS Well-Architected Framework		
Security	IAM root user hardware MFA should be enabled			AWS Well-Architected Framework		
Security	IAM root user MFA should be enabled			AWS Well-Architected Framework		
Security	IAM root user should not have access keys			AWS Well-Architected Framework		
Security	IAM user credentials that have not been used in 90 days should be disabled			AWS Well-Architected Framework		
Security	KMS CMK policies should prohibit public access			AWS Well-Architected Framework		
Security	KMS keys should not be pending deletion			AWS Well-Architected Framework		
Security	Lambda functions CloudTrail logging should be enabled			AWS Well-Architected Framework		
Security	Lambda functions should be in a VPC			AWS Well-Architected Framework		
Security	Lambda functions should restrict public access			AWS Well-Architected Framework		
Security	Logging should be enabled on AWS WAFv2 regional and global web access control list (ACLs)			AWS Well-Architected Framework		
Security	Log group retention period should be at least 365 days			AWS Well-Architected Framework		
Security	Network ACLs should not allow ingress from 0.0.0.0/0 to port 22 or port 3389			AWS Well-Architected Framework		
Security	OpenSearch domains node-to-node encryption should be enabled			AWS Well-Architected Framework		
Security	OpenSearch domains should be in a VPC			AWS Well-Architected Framework		
Security	OpenSearch domains should have audit logging enabled.			AWS Well-Architected Framework		
Security	OpenSearch domains should have encryption at rest enabled			AWS Well-Architected Framework		
Security	OpenSearch domains should use HTTPS			AWS Well-Architected Framework		
Security	Public EC2 instances should have IAM profile attached			AWS Well-Architected Framework		
Security	RDS DB instance automatic minor version upgrade should be enabled			AWS Well-Architected Framework		
Security	RDS DB instance encryption at rest should be enabled			AWS Well-Architected Framework		
Security	RDS DB instances should be integrated with CloudWatch logs			AWS Well-Architected Framework		
Security	RDS DB instances should prohibit public access			AWS Well-Architected Framework		
Security	RDS DB snapshots should be encrypted at rest			AWS Well-Architected Framework		
Security	RDS snapshots should prohibit public access			AWS Well-Architected Framework		
Security	Redshift cluster encryption in transit should be enabled			AWS Well-Architected Framework		
Security	Redshift clusters should prohibit public access			AWS Well-Architected Framework		
Security	Route53 domains privacy protection should be enabled			AWS Well-Architected Framework		
Security	Route 53 domains should have transfer lock enabled			AWS Well-Architected Framework		
Security	Route 53 zones should have query logging enabled			AWS Well-Architected Framework		
Security	S3 bucket default encryption should be enabled			AWS Well-Architected Framework		
Security	S3 bucket policy should prohibit public access			AWS Well-Architected Framework		
Security	S3 buckets access control lists (ACLs) should not be used to manage user access to buckets			AWS Well-Architected Framework		
Security	S3 buckets object logging should be enabled			AWS Well-Architected Framework		
Security	S3 buckets should enforce SSL			AWS Well-Architected Framework		
Security	S3 buckets should prohibit public write access			AWS Well-Architected Framework		
Security	S3 bucket versioning should be enabled			AWS Well-Architected Framework		
Security	S3 public access should be blocked at account level			AWS Well-Architected Framework		
Security	SageMaker endpoint configuration encryption should be enabled			AWS Well-Architected Framework		
Security	SageMaker models should be in a VPC			AWS Well-Architected Framework		
Security	SageMaker models should have network isolation enabled			AWS Well-Architected Framework		
Security	SageMaker notebook instance encryption should be enabled			AWS Well-Architected Framework		
Security	SageMaker notebook instances should be encrypted using CMK			AWS Well-Architected Framework		
Security	SageMaker notebook instances should be in a VPC			AWS Well-Architected Framework		
Security	SageMaker notebook instances should not have direct internet access			AWS Well-Architected Framework		
Security	SageMaker training jobs should be enabled with inter-container traffic encryption			AWS Well-Architected Framework		
Security	SageMaker training jobs should be in VPC			AWS Well-Architected Framework		
Security	SageMaker training jobs should have network isolation enabled			AWS Well-Architected Framework		
Security	SageMaker training jobs volumes and outputs should have KMS encryption enabled			AWS Well-Architected Framework		
Security	Secrets Manager secrets that have not been used in 90 days should be removed			AWS Well-Architected Framework		
Security	Security groups should not allow unrestricted access to ports with high risk			AWS Well-Architected Framework		
Security	SNS topic policies should prohibit public access			AWS Well-Architected Framework		
Security	SNS topics should be encrypted at rest			AWS Well-Architected Framework		
Security	SQS queue policies should prohibit public access			AWS Well-Architected Framework		
Security	SSM documents should not be public			AWS Well-Architected Framework		
Security	SSM managed instance associations should be compliant			AWS Well-Architected Framework		
Security	SSM managed instance patching should be compliant			AWS Well-Architected Framework		
Security	VPC default security group should not allow inbound and outbound traffic			AWS Well-Architected Framework		
Security	VPC EIPs should be associated with an EC2 instance or ENI			AWS Well-Architected Framework		
Security	VPC flow logs should be enabled			AWS Well-Architected Framework		
Security	VPC network access control lists (network ACLs) should be associated with a subnet.			AWS Well-Architected Framework		
Security	VPC Security groups should only allow unrestricted incoming traffic for authorized ports			AWS Well-Architected Framework		
Security	VPC security groups should restrict ingress Kafka port access from 0.0.0.0/0			AWS Well-Architected Framework		
Security	VPC security groups should restrict ingress redis access from 0.0.0.0/0			AWS Well-Architected Framework		
Security	VPC security groups should restrict ingress TCP and UDP access from 0.0.0.0/0			AWS Well-Architected Framework		
Security	VPC subnet auto assign public IP should be disabled			AWS Well-Architected Framework		
Security	WAF global rule group should have at least one rule			AWS Well-Architected Framework		
Security	WAF global web ACL should have at least one rule or rule group			AWS Well-Architected Framework		
Security Hub	AWS Security Hub should be enabled for an AWS Account			Compliance		
SNS	Logging of delivery status should be enabled for notification messages sent to a topic			Compliance		
SNS	SNS topic policies should prohibit cross account access		Ensures that SNS topics are not accessed by untrusted accounts.	Compliance		
SNS	SNS topic policies should prohibit public access		Prevents unauthorized users from accessing sensitive SNS topics.	Compliance		
SNS	SNS topic policies should prohibit publishing access			Compliance		
SNS	SNS topic policies should prohibit subscription public access		Limits the exposure of SNS subscriptions to authorized users or services.	Compliance		
SNS	SNS topics should be encrypted at rest		Protects sensitive message data stored in SNS topics from unauthorized access.	Compliance		
SQS	AWS SQS queues should be encrypted at rest			Compliance		
SQS	SQS queue policies should prohibit public access			Compliance		
SQS	SQS queues should be configured with a dead-letter queue.			Compliance		
SQS	SQS queues should be encrypted with KMS CMK			Compliance		
SSM	EC2 instances should be managed by AWS Systems Manager		Centralized management of EC2 instances enhances security, compliance, and monitoring.	Compliance		
SSM	SSM documents should not be public		Ensures that sensitive parameter data is encrypted to prevent unauthorized access.	Compliance		
SSM	SSM managed instance associations should be compliant			Compliance		
SSM	SSM managed instance patching should be compliant		Ensures that instances are kept up-to-date with security patches.	Compliance		
SSM	SSM parameters encryption should be enabled			Compliance		
Step Functions	Step Functions state machines should have logging turned on		Enables visibility and tracking of execution events, which is crucial for identifying security issues.	Compliance		
VPC	Both VPN tunnels provided by AWS Site-to-Site			Compliance		
VPC	Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389			Compliance		
VPC	Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports		This is critical to prevent unauthorized remote desktop access.	Compliance		
VPC	Ensure no security groups allow ingress from ::/0 to remote server administration ports		Prevents unrestricted access to sensitive administrative ports.	Compliance		
VPC	Network ACLs should not allow ingress from 0.0.0.0/0 to port 22 or port 3389		Protects SSH and RDP access.	Compliance		
VPC	Security groups should not allow unrestricted access to ports with high risk		Ensures key services are protected from potential external attacks.	Compliance		
VPC	Unused EC2 security groups should be removed			Compliance		
VPC	VPC default security group should not allow inbound and outbound traffic		Limits traffic to the default security group, which is often overlooked.	Compliance		
VPC	VPC EIPs should be associated with an EC2 instance or ENI			Compliance		
VPC	VPC endpoint services should have acceptance required enabled			Compliance		
VPC	VPC flow logs should be enabled			Compliance		
VPC	VPC gateway endpoints should restrict public access			Compliance		
VPC	VPC internet gateways should be attached to authorized vpc			Compliance		
VPC	VPC network access control lists (network ACLs) should be associated with a subnet.			Compliance		
VPC	VPC route table should restrict public access to IGW			Compliance		
VPC	VPC security groups should be associated with at least one ENI			Compliance		
VPC	VPC Security groups should only allow unrestricted incoming traffic for authorized ports			Compliance		
VPC	VPC security groups should restrict ingress from 0.0.0.0/0 or ::/0 to cassandra ports 7199 or 9160 or 8888			Compliance		
VPC	VPC security groups should restrict ingress from 0.0.0.0/0 or ::/0 to memcached port 11211			Compliance		
VPC	VPC security groups should restrict ingress from 0.0.0.0/0 or ::/0 to mongoDB ports 27017 and 27018			Compliance		
VPC	VPC security groups should restrict ingress from 0.0.0.0/0 or ::/0 to oracle ports 1521 or 2483		Prevents unrestricted access to popular database ports.	Compliance		
VPC	VPC security groups should restrict ingress Kafka port access from 0.0.0.0/0		Secures Kafka services from being exposed publicly.	Compliance		
VPC	VPC security groups should restrict ingress kibana port access from 0.0.0.0/0			Compliance		
VPC	VPC security groups should restrict ingress redis access from 0.0.0.0/0			Compliance		
VPC	VPC security groups should restrict ingress SSH access from 0.0.0.0/0		Prevents open SSH access, a major security vulnerability.	Compliance		
VPC	VPC security groups should restrict ingress TCP and UDP access from 0.0.0.0/0		Protects against open access to general TCP and UDP ports.	Compliance		
VPC	VPC security groups should restrict uses of 'launch-wizard' security groups.			Compliance		
VPC	VPC should be configured to use VPC endpoints			Compliance		
VPC	VPCs peering connection route tables should have least privilege			Compliance		
VPC	VPCs peering connection should not be allowed in cross account			Compliance		
VPC	VPCs should be in use			Compliance		
VPC	VPCs should exist in multiple regions			Compliance		
VPC	VPCs should have both public and private subnets configured		Ensures separation of sensitive resources.	Compliance		
VPC	VPCs subnets should exist in multiple availability zones			Compliance		
VPC	VPC subnet auto assign public IP should be disabled		Prevents accidental exposure of instances to the internet.	Compliance		
WAF	WAF global rule group should have at least one rule			Compliance		
WAF	WAF global rule should have at least one condition			Compliance		
WAF	WAF global web ACL should have at least one rule or rule group		Ensures that a web access control list is actively protecting your applications.	Compliance		
WAF	WAF regional rule group should have at least one rule attached			Compliance		
WAF	WAF regional rule should have at least one condition			Compliance		
WAF	WAF regional web ACL should have at least one rule or rule group attached			Compliance		
WAF	WAF web ACL logging should be enabled		Provides critical logging for identifying and tracking attack patterns.	Compliance		
WAFv2	A WAFV2 web ACL should have at least one rule or rule group			Compliance		
WAFv2	AWS WAF rules should have CloudWatch metrics enabled			Compliance		
WAFv2	Logging should be enabled on AWS WAFv2 regional and global web access control list (ACLs)		Ensures visibility into access patterns for regional and global web ACLs.	Compliance		
WorkSpaces	WorkSpaces root and user volume encryption should be enabled			Compliance		
```
