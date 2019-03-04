#################
#VARIABLES
#################

variable "aws_access_key" {}
variable "aws_secret_key" {}
variable "private_key_path" {
    default = "/home/ubuntu/.ssh/key.pem"
}
variable "key_name" {
    default = "19_Feb"
}

variable "IAM_Role" {
    default = "EC2_Role"
}


variable "network_address_space" {
	default = "10.0.0.0/16"
}

variable "subnet1_address_space" {
	default = "10.0.1.0/24"
}

variable "subnet2_address_space" {
	default = "10.0.2.0/24"
}


variable "subnet3_address_space" {
	default = "10.0.3.0/24"
}


variable "subnet4_address_space" {
	default = "10.0.4.0/24"
}


#################
#PROVIDERS
#################

# Configure the AWS Provider
provider "aws" {
  access_key = "${var.aws_access_key}"
  secret_key = "${var.aws_secret_key}"
  region     = "us-east-1"
}

##################
#DATA
##################

data "aws_availability_zones" "available" {}


##################
#RESOURCES
##################

# NETWORKING #

resource "aws_vpc" "vpc" {
	cidr_block = "${var.network_address_space}"
}

resource "aws_internet_gateway" "igw" {
	vpc_id = "${aws_vpc.vpc.id}"
}

resource "aws_subnet" "ext_subnet1" {
	cidr_block = "${var.subnet1_address_space}"
	vpc_id = "${aws_vpc.vpc.id}"
	map_public_ip_on_launch = "true"
	availability_zone = "${data.aws_availability_zones.available.names[0]}"
}

resource "aws_subnet" "int_subnet2" {
	cidr_block = "${var.subnet2_address_space}"
	vpc_id = "${aws_vpc.vpc.id}"
	availability_zone = "${data.aws_availability_zones.available.names[0]}"
}

resource "aws_subnet" "ext_subnet3" {
	cidr_block = "${var.subnet3_address_space}"
	vpc_id = "${aws_vpc.vpc.id}"
	map_public_ip_on_launch = "true"
	availability_zone = "${data.aws_availability_zones.available.names[1]}"
}

resource "aws_subnet" "int_subnet4" {
	cidr_block = "${var.subnet4_address_space}"
	vpc_id = "${aws_vpc.vpc.id}"
	availability_zone = "${data.aws_availability_zones.available.names[1]}"
}

# ROUTING #

resource "aws_route_table" "ext_rtb" {
	vpc_id = "${aws_vpc.vpc.id}"
	route {
		cidr_block = "0.0.0.0/0"
		gateway_id = "${aws_internet_gateway.igw.id}"
	}
}

resource "aws_route_table" "int_rtb" {
	vpc_id = "${aws_vpc.vpc.id}"
}

resource "aws_route_table_association" "subnet1" {
	subnet_id = "${aws_subnet.ext_subnet1.id}"
	route_table_id = "${aws_route_table.ext_rtb.id}"
}

resource "aws_route_table_association" "subnet3" {
	subnet_id = "${aws_subnet.ext_subnet3.id}"
	route_table_id = "${aws_route_table.ext_rtb.id}"
}

resource "aws_route_table_association" "subnet2" {
	subnet_id = "${aws_subnet.int_subnet2.id}"
	route_table_id = "${aws_route_table.int_rtb.id}"
}
resource "aws_route_table_association" "subnet4" {
	subnet_id = "${aws_subnet.int_subnet4.id}"
	route_table_id = "${aws_route_table.int_rtb.id}"
}

# SECURITY GROUPS #

resource "aws_security_group" "19_Feb_SG" {
	name = "19_Feb_SG"
	vpc_id = "${aws_vpc.vpc.id}"
	
	# SSH Access from All IP
	ingress {
		from_port = 22
		to_port = 22
		protocol = "tcp"
		cidr_blocks = ["0.0.0.0/0"]
	}
	
	# Outbound access
	egress {
		from_port = 0
		to_port = 0
		protocol = "-1"
		cidr_blocks = ["0.0.0.0/0"]
	}
}



# INSTANCES #


resource "aws_instance" "master_1" {
	ami = "ami-0ac019f4fcb7cb7e6"
	instance_type = "t2.micro"
	subnet_id = "${aws_subnet.ext_subnet1.id}"
	vpc_security_group_ids = ["${aws_security_group.19_Feb_SG.id}"]
	key_name = "${var.key_name}"

# Copies the 19_Feb.pem file to Ubuntu home
  provisioner "file" {
    source      = "${var.private_key_path}"
    destination = "/home/ubuntu/.ssh/key.pem"
  }
  provisioner "file" {
    source      = "19_Feb.tf"
    destination = "/home/ubuntu/19_Feb.tf"
  }
  
  #provisioner "file" {
  #  source      = "terraform_0.11.11_linux_amd64.zip"
  #  destination = "/home/ubuntu/terraform_0.11.11_linux_amd64.zip"
  #}
  
   #  provisioner "remote-exec" {
   #     inline = [
   #     "sudo apt-get install unzip",
   #     "unzip terraform_0.11.11_linux_amd64.zip",
   #     ]
   # }

    connection {
      user = "ubuntu"
      private_key = "${file(var.private_key_path)}"
    }
    tags {
        Name = "Master 1"
    }
}

resource "aws_instance" "master_2" {
	ami = "ami-0ac019f4fcb7cb7e6"
	instance_type = "t2.micro"
	subnet_id = "${aws_subnet.ext_subnet3.id}"
	vpc_security_group_ids = ["${aws_security_group.19_Feb_SG.id}"]
	key_name = "${var.key_name}"


    connection {
      user = "ubuntu"
      private_key = "${file(var.private_key_path)}"
    }
    tags {
        Name = "Master 2"
    }
}

resource "aws_instance" "slave_1" {
	ami = "ami-0ac019f4fcb7cb7e6"
	instance_type = "t2.micro"
	subnet_id = "${aws_subnet.int_subnet2.id}"
	vpc_security_group_ids = ["${aws_security_group.19_Feb_SG.id}"]
	key_name = "${var.key_name}"
    
    connection {
      user = "ubuntu"
      private_key = "${file(var.private_key_path)}"
    }
    tags {
        Name = "Slave 1"
    }
}
resource "aws_instance" "slave_2" {
	ami = "ami-0ac019f4fcb7cb7e6"
	instance_type = "t2.micro"
	subnet_id = "${aws_subnet.int_subnet4.id}"
	vpc_security_group_ids = ["${aws_security_group.19_Feb_SG.id}"]
	key_name = "${var.key_name}"

    connection {
      user = "ubuntu"
      private_key = "${file(var.private_key_path)}"
    }
     tags {
        Name = "Slave 2"
    }
}



#########
# OUTPUT Public IP of master 1 and internal IP of the rest
#########

output "master1_node_public_ip" {
       value = "${aws_instance.master_1.public_ip}"
   }

output "master2_node_ip" {
       value = "${aws_instance.master_2.private_ip}"
   }


output "slave1_node_ip" {
       value = "${aws_instance.slave_1.private_ip}"
   }
output "slave2_node_ip" {
       value = "${aws_instance.slave_2.private_ip}"
   }









