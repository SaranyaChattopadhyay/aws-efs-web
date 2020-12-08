provider "aws" {
	region = "ap-south-1"
	profile = "Sara"
}


//Obtain default VPC and subnet
data "aws_vpc" "default_vpc" {
    default = true
}

data "aws_subnet_ids" "default_subnet" {
  vpc_id = data.aws_vpc.default_vpc.id
}


//Creating Key
resource "tls_private_key" "tls_key" {
  algorithm = "RSA"
}


//Generating Key-Value Pair
resource "aws_key_pair" "generated_key" {
  key_name   = "env-key"
  public_key = "${tls_private_key.tls_key.public_key_openssh}"

  depends_on = [
    tls_private_key.tls_key
  ]
}


//Saving Private Key PEM File
resource "local_file" "key-file" {
  content  = "${tls_private_key.tls_key.private_key_pem}"
  filename = "env-key.pem"

  depends_on = [
    tls_private_key.tls_key
  ]
}


//Create security group for instance
resource "aws_security_group" "webfirewall" {
	name = "webfirewall"
	description = "Allow ssh-22 and http-80 protocols"
	ingress {
	   description = "SSH"
	   from_port = 22
	   to_port = 22
	   protocol = "tcp"
	   cidr_blocks = ["0.0.0.0/0"]
	}
	ingress {
	   description = "HTTP"
	   from_port = 80
	   to_port = 80
	   protocol = "tcp"
	   cidr_blocks = ["0.0.0.0/0"]
	}
	egress {
	   from_port = 0
	   to_port = 0
	   protocol = "-1"
	   cidr_blocks = ["0.0.0.0/0"]
	}
	tags = {
	   Name = "webfirewall"
	}
}

// Creating Security group for EFS
resource "aws_security_group" "efs_sg" {
  depends_on = [
    aws_security_group.webfirewall,
  ]
  name        = "efs-sg"
  description = "Security group for efs storage"
  vpc_id      = data.aws_vpc.default_vpc.id
 

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port       = 0
    to_port         = 0
    protocol        = "-1"
    security_groups = [aws_security_group.webfirewall.id]
  }
}

// Creating EFS cluster
resource "aws_efs_file_system" "webStorage" {
  depends_on = [
    aws_security_group.efs_sg
  ]
  creation_token = "efs"
  tags = {
    Name = "webStorage"
  }
}

resource "aws_efs_mount_target" "efs_mount" {
  depends_on = [
    aws_efs_file_system.webStorage
  ]
  for_each        = data.aws_subnet_ids.default_subnet.ids
  file_system_id  = aws_efs_file_system.webStorage.id
  subnet_id       = each.value
  security_groups = ["${aws_security_group.efs_sg.id}"]
}

//Creating a S3 Bucket for Terraform Integration
resource "aws_s3_bucket" "saranya2405webBucket" {
  bucket = "saranya-static-data-bucket"
  acl    = "public-read"
}

//Putting Objects in S3 Bucket
resource "aws_s3_bucket_object" "web-object1" {
  bucket = "${aws_s3_bucket.saranya2405webBucket.bucket}"
  key    = "img.jpg"
  source = "C:\Users\saran\OneDrive\Desktop\AWS task-2/img.jpg"
  acl    = "public-read"
}

//Creating CloutFront with S3 Bucket Origin
resource "aws_cloudfront_distribution" "web-distribution" {
  origin {
    domain_name = "${aws_s3_bucket.saranya2405webBucket.bucket_regional_domain_name}"
    origin_id   = "${aws_s3_bucket.saranya2405webBucket.id}"
  }

  enabled             = true
  is_ipv6_enabled     = true
  comment             = "CloudFront Distribution"

  default_cache_behavior {
    allowed_methods  = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "${aws_s3_bucket.saranya2405webBucket.id}"

    forwarded_values {
      query_string = false

      cookies {
        forward = "none"
      }
    }

    viewer_protocol_policy = "allow-all"
    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
  }

  restrictions {
    geo_restriction {
      restriction_type = "whitelist"
      locations        = ["IN"]
    }
  }

  tags = {
    Name        = "web-distribution"
    Environment = "Production"
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }

  depends_on = [
    aws_s3_bucket.saranya2405webBucket
  ]
}


//Creating the EC2 Instance
resource "aws_instance" "webos" {

depends_on = [
    aws_efs_file_system.webStorage,
    aws_efs_mount_target.efs_mount,
    aws_cloudfront_distribution.web-distribution,
  ]

  ami           = "ami-0e306788ff2473ccb"
  instance_type = "t2.micro"
  key_name      = aws_key_pair.generated_key.key_name
  security_groups = [ "webfirewall" ]

  connection {
    type     = "ssh"
    user     = "ec2-user"
    private_key = tls_private_key.tls_key.private_key_pem
    host     = aws_instance.webos.public_ip
  }

  provisioner "remote-exec" {
    inline = [
      "sudo yum install httpd git -y",
      "sudo systemctl restart httpd",
      "sudo yum install -y amazon-efs-utils",
      "sudo mount -t efs -o tls ${aws_efs_file_system.webStorage.id}:/ /var/www/html",
      "sudo git clone https://github.com/SaranyaChattopadhyay/aws-efs-web.git /var/www/html",
      "echo '<img src='https://${aws_cloudfront_distribution.web-distribution.domain_name}/img.jpg' width='400' height='400'>' | sudo tee -a /var/www/html/index.html",
    ]
  }

  tags = {
    Name = "webos"
  }
}

//Open web-page
resource "null_resource" "ChromeOpen"  {
depends_on = [
    aws_instance.webos,
  ]

	provisioner "local-exec" {
	    command = "chrome  ${aws_instance.webos.public_ip}/index.html 
  	}
}