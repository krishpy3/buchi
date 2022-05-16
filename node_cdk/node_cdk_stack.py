from email.policy import Policy
from aws_cdk import (
    Aws,
    CfnOutput,
    Duration,
    SecretValue,
    Stack,
    aws_autoscaling as autoscaling,
    aws_codebuild as cb,
    aws_codepipeline as codepipeline,
    aws_codepipeline_actions as codepipeline_actions,
    aws_ecr as ecr,
    aws_ecs as ecs,
    aws_ec2 as ec2,
    aws_elasticloadbalancingv2 as elbv2,
    aws_iam as iam,
    aws_s3 as s3,
)
from constructs import Construct


class NodeCdkStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        vpc = ec2.Vpc(
            self, "MyVpc",
            max_azs=2,
            nat_gateways=0
        )

        sg_elb = ec2.SecurityGroup(
            self,
            id="sg_elb",
            vpc=vpc,
            allow_all_outbound=True,
            security_group_name="sg_elb"
        )

        sg_elb.add_ingress_rule(
            peer=ec2.Peer.any_ipv4(),
            connection=ec2.Port.tcp(80),
            description="Allow HTTP"
        )

        sg_ecs = ec2.SecurityGroup(
            self,
            id="sg_ecs",
            vpc=vpc,
            allow_all_outbound=True,
            security_group_name="sg_ecs"
        )

        sg_ecs.add_ingress_rule(
            peer=ec2.Peer.any_ipv4(),
            connection=ec2.Port.tcp(80),
            description="Allow HTTP"
        )

        sg_ecs.add_ingress_rule(
            peer=ec2.Peer.any_ipv4(),
            connection=ec2.Port.tcp(22),
            description="Allow SSH"
        )

        sg_ecs.add_ingress_rule(
            peer=ec2.Peer.security_group_id(sg_elb.security_group_id),
            connection=ec2.Port.tcp_range(31000, 61000),
            description="Allow SSH"
        )

        cluster = ecs.Cluster(self, "EcsCluster", vpc=vpc)

        role = iam.Role(
            self, "Ec2EcrRole",
            description="Allow EC2 instances to Pull ECR Images",
            assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AmazonEC2ContainerServiceforEC2Role"),
                # iam.ManagedPolicy.from_aws_managed_policy_name(
                #     "service-role/AmazonECSContainerServiceRole"),
            ],
            role_name="EC2_ECR_Role")

        asg = autoscaling.AutoScalingGroup(
            self, "myASG",
            instance_type=ec2.InstanceType(
                "t2.micro"),
            machine_image=ecs.EcsOptimizedImage.amazon_linux2(),
            role=role,
            desired_capacity=1,
            key_name='buchi',
            vpc=vpc,
            security_group=sg_ecs,
            vpc_subnets={'subnet_type': ec2.SubnetType.PUBLIC},
        )

        capacity_provider = ecs.AsgCapacityProvider(self, "AsgCapacityProvider",
                                                    auto_scaling_group=asg,
                                                    )
        cluster.add_asg_capacity_provider(capacity_provider)

        task_definition = ecs.Ec2TaskDefinition(self, "TaskDef")

        container = task_definition.add_container(
            "TheContainer",
            image=ecs.ContainerImage.from_registry(
                f'{Aws.ACCOUNT_ID}.dkr.ecr.us-east-1.amazonaws.com/node_app:latest'
            ),
            cpu=256,
            memory_limit_mib=256,
            port_mappings=[ecs.PortMapping(
                container_port=3000, host_port=0)],
            environment={"MYSQL_HOST": "host"}
        )

        service = ecs.Ec2Service(self, "Service",
                                 cluster=cluster,
                                 task_definition=task_definition,
                                 desired_count=1
                                 )

        # Create ALB
        lb = elbv2.ApplicationLoadBalancer(
            self, "LB",
            vpc=vpc,
            internet_facing=True,
            security_group=sg_elb,
        )
        listener = lb.add_listener(
            "PublicListener",
            port=80,
            open=True
        )

        health_check = elbv2.HealthCheck(
            interval=Duration.seconds(60),
            path="/",
            timeout=Duration.seconds(5)
        )

        # Attach ALB to ECS Service
        listener.add_targets(
            "ECS",
            port=80,
            targets=[service],
            health_check=health_check,
        )

        CfnOutput(
            self, "LoadBalancerDNS",
            value=lb.load_balancer_dns_name
        )

        # pipeline requires versioned bucket
        bucket = s3.Bucket(
            self, "SourceBucket",
            bucket_name=f"artifact-{Aws.ACCOUNT_ID}",
            # versioned=True,
        )

        repository = ecr.Repository.from_repository_name(
            self, "NodeRepo", "node_app")

        pipeline = codepipeline.Pipeline(
            self, "MyPipeline", artifact_bucket=bucket)

        source_output = codepipeline.Artifact()
        build_output = codepipeline.Artifact()

        source_action = codepipeline_actions.GitHubSourceAction(
            action_name="Source",
            owner="krishpy3",
            repo="sample-nodeApp-ECS",
            oauth_token=SecretValue.secrets_manager('token'),
            output=source_output,
            branch="main"
        )

        # codebuild project meant to run in pipeline
        cb_docker_build = cb.PipelineProject(
            self, "DockerBuild",
            project_name='Docker-Build-Project',
            # build_spec=cb.BuildSpec.from_source_filename(
            #     filename='docker_build_buildspec.yml'),
            build_spec=cb.BuildSpec.from_object({
                "version": 0.2,
                "run-as": "root",
                "phases": {
                    "pre_build": {
                        "commands": [
                            "echo Logging in to Amazon ECR...",
                            "aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin $AWS_ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com",
                            "REPOSITORY_URI=$AWS_ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com/$IMAGE_REPO_NAME"
                        ]
                    },
                    "build": {
                        "commands": [
                            "echo Build started on `date`",
                            "echo Building the Docker image...",
                            "docker build -t $IMAGE_REPO_NAME:latest .",
                            "docker tag $IMAGE_REPO_NAME:latest $AWS_ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com/$IMAGE_REPO_NAME:latest"
                        ]
                    },
                    "post_build": {
                        "commands": [
                            "echo Build completed on `date`",
                            "echo Pushing the Docker image...",
                            "docker push $AWS_ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com/$IMAGE_REPO_NAME:latest",
                            "echo Writing image definitions file...",
                            "printf '[{\"name\":\"%s\",\"imageUri\":\"%s\"}]' $CONTAINER_NAME $REPOSITORY_URI:latest > imagedefinitions.json"
                        ]
                    }
                },
                "artifacts": {
                    "files": "imagedefinitions.json"
                }
            }),
            environment=cb.BuildEnvironment(
                privileged=True,
            ),
            # pass the ecr repo uri into the codebuild project so codebuild knows where to push
            environment_variables={
                'AWS_ACCOUNT_ID': cb.BuildEnvironmentVariable(
                    value=Aws.ACCOUNT_ID),
                'IMAGE_REPO_NAME': cb.BuildEnvironmentVariable(
                    value='node_app'),
                'CONTAINER_NAME': cb.BuildEnvironmentVariable(
                    value='TheContainer'),
            },
            description='Pipeline for CodeBuild',
            timeout=Duration.minutes(60),
        )
        # codebuild iam permissions to read write s3
        bucket.grant_read_write(cb_docker_build)

        repository.grant_pull_push(cb_docker_build)

        build_action = codepipeline_actions.CodeBuildAction(
            action_name="CodeBuild",
            project=cb_docker_build,
            input=source_output,
            outputs=[build_output]
            # execute_batch_build=True,  # optional, defaults to false
            # combine_batch_build_artifacts=True
        )

        pipeline.add_stage(
            stage_name="Source",
            actions=[source_action]
        )

        pipeline.add_stage(
            stage_name="Build",
            actions=[build_action]
        )

        deploy_action = codepipeline_actions.EcsDeployAction(
            action_name="DeployAction",
            service=service,
            input=build_output,
            # if your file name is _not_ imagedefinitions.json,
            # use the `imageFile` property,
            # and leave out the `input` property
            # image_file=build_output.at_path("imageDef.json"),
            deployment_timeout=Duration.minutes(60)
        )

        pipeline.add_stage(
            stage_name="Deploy",
            actions=[deploy_action]
        )
