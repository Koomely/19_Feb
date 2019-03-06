


resource "aws_instance" "Master-2" {
    ami                         = "ami-0ac019f4fcb7cb7e6"
    availability_zone           = "us-east-1b"
    ebs_optimized               = false
    instance_type               = "t2.micro"
    monitoring                  = false
    key_name                    = "19_Feb"
    subnet_id                   = "subnet-0130c3afdf7911ed0"
    vpc_security_group_ids      = ["sg-0f074abc8dcd2fda9"]
    associate_public_ip_address = true
    private_ip                  = "10.0.3.43"
    source_dest_check           = true
 
    root_block_device {
        volume_type           = "gp2"
        volume_size           = 8
        delete_on_termination = true
    }

    tags {
        "Name" = "Master 2"
    }
}

resource "aws_instance" "Slave-2" {
    ami                         = "ami-0ac019f4fcb7cb7e6"
    availability_zone           = "us-east-1b"
    ebs_optimized               = false
    instance_type               = "t2.micro"
    monitoring                  = false
    key_name                    = "19_Feb"
    subnet_id                   = "subnet-0b192051c64fc65f0"
    vpc_security_group_ids      = ["sg-0f074abc8dcd2fda9"]
    associate_public_ip_address = false
    private_ip                  = "10.0.4.106"
    source_dest_check           = true

    root_block_device {
        volume_type           = "gp2"
        volume_size           = 8
        delete_on_termination = true
    }

    tags {
        "Name" = "Slave 2"
    }
}

resource "aws_instance" "Slave-1" {
    ami                         = "ami-0ac019f4fcb7cb7e6"
    availability_zone           = "us-east-1a"
    ebs_optimized               = false
    instance_type               = "t2.micro"
    monitoring                  = false
    key_name                    = "19_Feb"
    subnet_id                   = "subnet-09790059508ba5477"
    vpc_security_group_ids      = ["sg-0f074abc8dcd2fda9"]
    associate_public_ip_address = false
    private_ip                  = "10.0.2.7"
    source_dest_check           = true

    root_block_device {
        volume_type           = "gp2"
        volume_size           = 8
        delete_on_termination = true
    }

    tags {
        "Name" = "Slave 1"
    }
}

resource "aws_instance" "Master-1" {
    ami                         = "ami-0ac019f4fcb7cb7e6"
    availability_zone           = "us-east-1a"
    ebs_optimized               = false
    instance_type               = "t2.micro"
    monitoring                  = false
    key_name                    = "19_Feb"
    subnet_id                   = "subnet-09fcc830f99d57edb"
    vpc_security_group_ids      = ["sg-0f074abc8dcd2fda9"]
    associate_public_ip_address = true
    private_ip                  = "10.0.1.134"
    source_dest_check           = true

    root_block_device {
        volume_type           = "gp2"
        volume_size           = 8
        delete_on_termination = true
    }

    tags {
        "Name" = "Master 1"
    }
}






resource "aws_iam_instance_profile" "EC2_Role" {
    name = "EC2_Role"
    path = "/"
    role = "EC2_Role"
}

resource "aws_iam_policy" "EC2-Role" {
    name        = "EC2-Role"
    path        = "/"
    description = "19.2 opsSkool"
    policy      = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "VisualEditor0",
      "Effect": "Allow",
      "Action": [
        "sts:AssumeRole",
        "ec2:*"
      ],
      "Resource": "*"
    }
  ]
}
POLICY
}

resource "aws_iam_policy" "ForeScout" {
    name        = "ForeScout"
    path        = "/"
    description = "Policy per AWS Plugin requirements"
    policy      = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "ec2:*",
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
POLICY
}

resource "aws_iam_policy_attachment" "EC2-Role-policy-attachment" {
    name       = "EC2-Role-policy-attachment"
    policy_arn = "arn:aws:iam::821910448117:policy/EC2-Role"
    groups     = []
    users      = []
    roles      = ["EC2_Role"]
}

resource "aws_iam_policy_attachment" "ForeScout-policy-attachment" {
    name       = "ForeScout-policy-attachment"
    policy_arn = "arn:aws:iam::821910448117:policy/ForeScout"
    groups     = []
    users      = ["Sustaining_TLV"]
    roles      = []
}

resource "aws_iam_policy_attachment" "AmazonEC2FullAccess-policy-attachment" {
    name       = "AmazonEC2FullAccess-policy-attachment"
    policy_arn = "arn:aws:iam::aws:policy/AmazonEC2FullAccess"
    groups     = []
    users      = ["Sustaining_TLV"]
    roles      = ["EC2_Role"]
}

resource "aws_iam_policy_attachment" "IAMFullAccess-policy-attachment" {
    name       = "IAMFullAccess-policy-attachment"
    policy_arn = "arn:aws:iam::aws:policy/IAMFullAccess"
    groups     = []
    users      = ["Sustaining_TLV"]
    roles      = []
}

resource "aws_iam_policy_attachment" "Billing-policy-attachment" {
    name       = "Billing-policy-attachment"
    policy_arn = "arn:aws:iam::aws:policy/job-function/Billing"
    groups     = []
    users      = ["Amit_T"]
    roles      = []
}

resource "aws_iam_policy_attachment" "AWSOrganizationsServiceTrustPolicy-policy-attachment" {
    name       = "AWSOrganizationsServiceTrustPolicy-policy-attachment"
    policy_arn = "arn:aws:iam::aws:policy/aws-service-role/AWSOrganizationsServiceTrustPolicy"
    groups     = []
    users      = []
    roles      = ["AWSServiceRoleForOrganizations"]
}

resource "aws_iam_policy_attachment" "AdministratorAccess-policy-attachment" {
    name       = "AdministratorAccess-policy-attachment"
    policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
    groups     = []
    users      = ["Amit_T"]
    roles      = []
}

resource "aws_iam_policy_attachment" "IAMUserChangePassword-policy-attachment" {
    name       = "IAMUserChangePassword-policy-attachment"
    policy_arn = "arn:aws:iam::aws:policy/IAMUserChangePassword"
    groups     = []
    users      = ["Amit_T"]
    roles      = []
}

resource "aws_iam_policy_attachment" "AWSSupportServiceRolePolicy-policy-attachment" {
    name       = "AWSSupportServiceRolePolicy-policy-attachment"
    policy_arn = "arn:aws:iam::aws:policy/aws-service-role/AWSSupportServiceRolePolicy"
    groups     = []
    users      = []
    roles      = ["AWSServiceRoleForSupport"]
}

resource "aws_iam_policy_attachment" "AmazonVPCFullAccess-policy-attachment" {
    name       = "AmazonVPCFullAccess-policy-attachment"
    policy_arn = "arn:aws:iam::aws:policy/AmazonVPCFullAccess"
    groups     = []
    users      = ["Sustaining_TLV"]
    roles      = ["EC2_Role"]
}

resource "aws_iam_policy_attachment" "AWSTrustedAdvisorServiceRolePolicy-policy-attachment" {
    name       = "AWSTrustedAdvisorServiceRolePolicy-policy-attachment"
    policy_arn = "arn:aws:iam::aws:policy/aws-service-role/AWSTrustedAdvisorServiceRolePolicy"
    groups     = []
    users      = []
    roles      = ["AWSServiceRoleForTrustedAdvisor"]
}

resource "aws_iam_role" "AWSServiceRoleForOrganizations" {
    name               = "AWSServiceRoleForOrganizations"
    path               = "/aws-service-role/organizations.amazonaws.com/"
    assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "organizations.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
POLICY
}

resource "aws_iam_role" "AWSServiceRoleForSupport" {
    name               = "AWSServiceRoleForSupport"
    path               = "/aws-service-role/support.amazonaws.com/"
    assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "support.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
POLICY
}

resource "aws_iam_role" "AWSServiceRoleForTrustedAdvisor" {
    name               = "AWSServiceRoleForTrustedAdvisor"
    path               = "/aws-service-role/trustedadvisor.amazonaws.com/"
    assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "trustedadvisor.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
POLICY
}

resource "aws_iam_role" "EC2_Role" {
    name               = "EC2_Role"
    path               = "/"
    assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
POLICY
}

resource "aws_iam_role" "SustainingTLVAdmin" {
    name               = "SustainingTLVAdmin"
    path               = "/"
    assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::993810264719:root"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
POLICY
}

resource "aws_iam_role_policy" "SustainingTLVAdmin_AdministratorAccess" {
    name   = "AdministratorAccess"
    role   = "SustainingTLVAdmin"
    policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    }
  ]
}
POLICY
}

resource "aws_iam_user" "Amit_T" {
    name = "Amit_T"
    path = "/"
}

resource "aws_iam_user" "Sustaining_TLV" {
    name = "Sustaining_TLV"
    path = "/"
}


resource "aws_internet_gateway" "igw-0744e51507a0f5e50" {
    vpc_id = "vpc-0baac485e31dbf1f5"

    tags {
    }
}

resource "aws_internet_gateway" "igw-db6617a3" {
    vpc_id = "vpc-0befc070"

    tags {
    }
}


resource "aws_network_acl" "acl-61a02d1b" {
    vpc_id     = "vpc-0befc070"
    subnet_ids = ["subnet-361c0d09", "subnet-5d21af52", "subnet-0a8f0e40", "subnet-fe9a65d0", "subnet-990af8c5", "subnet-05894862"]

    ingress {
        from_port  = 0
        to_port    = 0
        rule_no    = 100
        action     = "allow"
        protocol   = "-1"
        cidr_block = "0.0.0.0/0"
    }

    egress {
        from_port  = 0
        to_port    = 0
        rule_no    = 100
        action     = "allow"
        protocol   = "-1"
        cidr_block = "0.0.0.0/0"
    }

    tags {
    }
}

resource "aws_network_acl" "acl-0fa704895e90d1c3b" {
    vpc_id     = "vpc-0baac485e31dbf1f5"
    subnet_ids = ["subnet-0b192051c64fc65f0", "subnet-09fcc830f99d57edb", "subnet-09790059508ba5477", "subnet-0130c3afdf7911ed0"]

    ingress {
        from_port  = 0
        to_port    = 0
        rule_no    = 100
        action     = "allow"
        protocol   = "-1"
        cidr_block = "0.0.0.0/0"
    }

    egress {
        from_port  = 0
        to_port    = 0
        rule_no    = 100
        action     = "allow"
        protocol   = "-1"
        cidr_block = "0.0.0.0/0"
    }

    tags {
    }
}


resource "aws_network_interface" "eni-071954e00812993c6" {
    subnet_id         = "subnet-09790059508ba5477"
    private_ips       = ["10.0.2.7"]
    security_groups   = ["sg-0f074abc8dcd2fda9"]
    source_dest_check = true
    attachment {
        instance     = "i-0700fc91025dacb94"
        device_index = 0
    }
}

resource "aws_network_interface" "eni-069865dce1e48ff7b" {
    subnet_id         = "subnet-0130c3afdf7911ed0"
    private_ips       = ["10.0.3.43"]
    security_groups   = ["sg-0f074abc8dcd2fda9"]
    source_dest_check = true
    attachment {
        instance     = "i-04f142df3417f1f5b"
        device_index = 0
    }
}

resource "aws_network_interface" "eni-0773bafe249ed344e" {
    subnet_id         = "subnet-0b192051c64fc65f0"
    private_ips       = ["10.0.4.106"]
    security_groups   = ["sg-0f074abc8dcd2fda9"]
    source_dest_check = true
    attachment {
        instance     = "i-05ff2af20910ba5bf"
        device_index = 0
    }
}

resource "aws_network_interface" "eni-0c401c3b56a8fc429" {
    subnet_id         = "subnet-09fcc830f99d57edb"
    private_ips       = ["10.0.1.134"]
    security_groups   = ["sg-0f074abc8dcd2fda9"]
    source_dest_check = true
    attachment {
        instance     = "i-0036439ebf7bfd997"
        device_index = 0
    }
}

resource "aws_route_table" "rtb-02746185cae776b23" {
    vpc_id     = "vpc-0baac485e31dbf1f5"

    tags {
    }
}

resource "aws_route_table" "rtb-06fd34f35e2635506" {
    vpc_id     = "vpc-0baac485e31dbf1f5"

    route {
        cidr_block = "0.0.0.0/0"
        gateway_id = "igw-0744e51507a0f5e50"
    }

    tags {
    }
}

resource "aws_route_table" "rtb-7eecfc02" {
    vpc_id     = "vpc-0befc070"

    route {
        cidr_block = "0.0.0.0/0"
        gateway_id = "igw-db6617a3"
    }

    tags {
    }
}

resource "aws_route_table" "rtb-0642579661efc5e83" {
    vpc_id     = "vpc-0baac485e31dbf1f5"

    tags {
    }
}

resource "aws_route_table_association" "rtb-02746185cae776b23-rtbassoc-0efd7e3673ce39777" {
    route_table_id = "rtb-02746185cae776b23"
    subnet_id = "subnet-0b192051c64fc65f0"
}

resource "aws_route_table_association" "rtb-02746185cae776b23-rtbassoc-08c4650ba96843671" {
    route_table_id = "rtb-02746185cae776b23"
    subnet_id = "subnet-09790059508ba5477"
}

resource "aws_route_table_association" "rtb-06fd34f35e2635506-rtbassoc-08e806167b1e6e97f" {
    route_table_id = "rtb-06fd34f35e2635506"
    subnet_id = "subnet-09fcc830f99d57edb"
}

resource "aws_route_table_association" "rtb-06fd34f35e2635506-rtbassoc-0e6b395460db39ea8" {
    route_table_id = "rtb-06fd34f35e2635506"
    subnet_id = "subnet-0130c3afdf7911ed0"
}

resource "aws_security_group" "vpc-0baac485e31dbf1f5-default" {
    name        = "default"
    description = "default VPC security group"
    vpc_id      = "vpc-0baac485e31dbf1f5"

    ingress {
        from_port       = 0
        to_port         = 0
        protocol        = "-1"
        security_groups = []
        self            = true
    }


    egress {
        from_port       = 0
        to_port         = 0
        protocol        = "-1"
        cidr_blocks     = ["0.0.0.0/0"]
    }

}

resource "aws_security_group" "vpc-0baac485e31dbf1f5-19_Feb_SG" {
    name        = "19_Feb_SG"
    description = "Managed by Terraform"
    vpc_id      = "vpc-0baac485e31dbf1f5"

    ingress {
        from_port       = 22
        to_port         = 22
        protocol        = "tcp"
        cidr_blocks     = ["0.0.0.0/0"]
    }


    egress {
        from_port       = 0
        to_port         = 0
        protocol        = "-1"
        cidr_blocks     = ["0.0.0.0/0"]
    }

}

resource "aws_security_group" "vpc-0befc070-default" {
    name        = "default"
    description = "default VPC security group"
    vpc_id      = "vpc-0befc070"

    ingress {
        from_port       = 0
        to_port         = 0
        protocol        = "-1"
        security_groups = []
        self            = true
    }


    egress {
        from_port       = 0
        to_port         = 0
        protocol        = "-1"
        cidr_blocks     = ["0.0.0.0/0"]
    }

}

resource "aws_subnet" "subnet-0b192051c64fc65f0-subnet-0b192051c64fc65f0" {
    vpc_id                  = "vpc-0baac485e31dbf1f5"
    cidr_block              = "10.0.4.0/24"
    availability_zone       = "us-east-1b"
    map_public_ip_on_launch = false

    tags {
    }
}

resource "aws_subnet" "subnet-05894862-subnet-05894862" {
    vpc_id                  = "vpc-0befc070"
    cidr_block              = "172.31.0.0/20"
    availability_zone       = "us-east-1b"
    map_public_ip_on_launch = true

    tags {
    }
}

resource "aws_subnet" "subnet-fe9a65d0-subnet-fe9a65d0" {
    vpc_id                  = "vpc-0befc070"
    cidr_block              = "172.31.80.0/20"
    availability_zone       = "us-east-1c"
    map_public_ip_on_launch = true

    tags {
    }
}

resource "aws_subnet" "subnet-5d21af52-subnet-5d21af52" {
    vpc_id                  = "vpc-0befc070"
    cidr_block              = "172.31.64.0/20"
    availability_zone       = "us-east-1f"
    map_public_ip_on_launch = true

    tags {
    }
}

resource "aws_subnet" "subnet-0130c3afdf7911ed0-subnet-0130c3afdf7911ed0" {
    vpc_id                  = "vpc-0baac485e31dbf1f5"
    cidr_block              = "10.0.3.0/24"
    availability_zone       = "us-east-1b"
    map_public_ip_on_launch = true

    tags {
    }
}

resource "aws_subnet" "subnet-09790059508ba5477-subnet-09790059508ba5477" {
    vpc_id                  = "vpc-0baac485e31dbf1f5"
    cidr_block              = "10.0.2.0/24"
    availability_zone       = "us-east-1a"
    map_public_ip_on_launch = false

    tags {
    }
}

resource "aws_subnet" "subnet-09fcc830f99d57edb-subnet-09fcc830f99d57edb" {
    vpc_id                  = "vpc-0baac485e31dbf1f5"
    cidr_block              = "10.0.1.0/24"
    availability_zone       = "us-east-1a"
    map_public_ip_on_launch = true

    tags {
    }
}

resource "aws_subnet" "subnet-361c0d09-subnet-361c0d09" {
    vpc_id                  = "vpc-0befc070"
    cidr_block              = "172.31.48.0/20"
    availability_zone       = "us-east-1e"
    map_public_ip_on_launch = true

    tags {
    }
}

resource "aws_subnet" "subnet-990af8c5-subnet-990af8c5" {
    vpc_id                  = "vpc-0befc070"
    cidr_block              = "172.31.32.0/20"
    availability_zone       = "us-east-1a"
    map_public_ip_on_launch = true

    tags {
    }
}

resource "aws_subnet" "subnet-0a8f0e40-subnet-0a8f0e40" {
    vpc_id                  = "vpc-0befc070"
    cidr_block              = "172.31.16.0/20"
    availability_zone       = "us-east-1d"
    map_public_ip_on_launch = true

    tags {
    }
}


resource "aws_vpc" "vpc-0baac485e31dbf1f5" {
    cidr_block           = "10.0.0.0/16"
    enable_dns_hostnames = false
    enable_dns_support   = true
    instance_tenancy     = "default"

    tags {
    }
}

resource "aws_vpc" "vpc-0befc070" {
    cidr_block           = "172.31.0.0/16"
    enable_dns_hostnames = true
    enable_dns_support   = true
    instance_tenancy     = "default"

    tags {
    }
}

