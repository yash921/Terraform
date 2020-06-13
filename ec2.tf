# configure the provider
provider "aws" {
    region = "ap-southeast-1"
    profile = "ydprofile"
}

/*-----------------------------------------------------*/

# creating a key pair
variable "key_name" {}

resource "tls_private_key" "example" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_key_pair" "generated_key" {
  key_name   = var.key_name
  public_key = tls_private_key.example.public_key_openssh
}

# saving key to local file
resource "local_file" "deploy-key" {
    content  = tls_private_key.example.private_key_pem
    filename = "/home/yash/tf_key.pem"
}

/*-----------------------------------------------------*/


# creating a Security-group
resource "aws_security_group" "triad" {
  name        = "MysecurityGroup"
  description = "Allow TLS inbound traffic"
#   vpc_id      = "${aws_vpc.main.id}"

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }


  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "allow_web_page"
  }
}


/*-----------------------------------------------------*/


# ec2 instance config
resource "aws_instance" "web" {
    ami = "ami-0615132a0f36d24f4"
    instance_type = "t2.micro"
    key_name = aws_key_pair.generated_key.key_name
    security_groups = ["MysecurityGroup"]
// using Ansible
  # provisioner "file" {
  #   source      = "parted.yml"
  #   destination = "/etc"

    connection {
      type = "ssh"
      host = self.public_ip
      private_key = tls_private_key.example.private_key_pem
      user        = "ec2-user"
      # timeout     = "2m"
    }
    
    provisioner "remote-exec" {
      inline = [
        "sudo yum install httpd php git -y",
        "sudo systemctl restart httpd",
        "sudo systemctl enable httpd"
     ]
   }
   tags = {
     Name = "web-server"
   }
}

# output "my-vol" {
#   value = aws_instance.web.availability_zone
# }

/*-----------------------------------------------------*/


# create an ebs volume
resource "aws_ebs_volume" "vol" {
  availability_zone = aws_instance.web.availability_zone
  size              = 1
  tags = {
    Name = "my-vol"
  }
}

# create an ebs snapshot
resource "aws_ebs_snapshot" "ebstest_snapshot" {
  volume_id = aws_ebs_volume.vol.id
  tags = {
    Name = "vol-snapshot"
  }
}

# attaching the volume
resource "aws_volume_attachment" "ebs_att" {
  device_name = "/dev/sdb"
  volume_id   = aws_ebs_volume.vol.id
  instance_id = aws_instance.web.id
  force_detach = true
}

output "info" {
  value = aws_instance.web.public_ip
}

# resource "null_resource" "nulllocal" {
#   provisioner "local-exec" {
#     command = "echo ${aws_instance.web.public_ip} > publicip.txt "
  
#   }
# }

resource "null_resource" "nullRemote" {
  depends_on = [
    aws_volume_attachment.ebs_att,
    aws_s3_bucket_object.image-upload

  ]

  connection {
    type = "ssh"
    user = "ec2-user"
    host = aws_instance.web.public_ip
    private_key = tls_private_key.example.private_key_pem
    # timeout = "4m"
  }
  provisioner "remote-exec" {
    inline = [
       "sudo mkfs.ext4 /dev/xvdb",
       "sudo mount /dev/xvdb /var/www/html",
       "sudo yum install git -y",
       "sudo rm -rf /var/www/html/*",
       "sudo git clone https://github.com/yash921/web.git  /temp_repo",
       "sudo cp -rf /temp_repo/* /var/www/html",
      #"sudo rm -rf /temp_repo"
      
    ]
  }
}
  
  # provisioner "remote-exec" {
  #       when    = destroy
  #       inline  = [
  #           "sudo umount /var/www/html"
  #       ]
  #   }


# resource "null_resource" "nullloacl1" {
# depends_on = [
#     null_resource.nullRemote,
# e]
#   provisioner "local-exec" {
#     command = "firefox ${aws_instance.web.public_ip}"
#   }
# }

/*-----------------------------------------------------*/

# S3 bucket
resource "aws_s3_bucket" "web_distribution" {
  bucket = "yash-921"
  acl    = "private"


  tags = {
    Name = "My bucket"
  }
}

locals {
  s3_origin_id = "myS3Origin"
}

resource "aws_s3_bucket_object" "image-upload" {
  depends_on = [
     aws_s3_bucket.web_distribution,
  ]

  bucket = aws_s3_bucket.web_distribution.bucket
  key    = "yash.png"
  source = "new/yash.png"
  acl    = "private"
}

/*-----------------------------------------------------*/

#Cloudfront permisions
resource "aws_cloudfront_origin_access_identity" "origin_access_identity" {
  comment = "For policies"
}

#s3 private bucket policies that will only give access to CloudFront 
data "aws_iam_policy_document" "s3_policy" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.web_distribution.arn}/*"]

    principals {
      type        = "AWS"
      identifiers = ["${aws_cloudfront_origin_access_identity.origin_access_identity.iam_arn}"]
    }
  }

  statement {
    actions   = ["s3:ListBucket"]
    resources = ["${aws_s3_bucket.web_distribution.arn}"]

    principals {
      type        = "AWS"
      identifiers = ["${aws_cloudfront_origin_access_identity.origin_access_identity.iam_arn}"]
    }
  }
}

resource "aws_s3_bucket_policy" "example" {
  bucket = "${aws_s3_bucket.web_distribution.id}"
  policy = "${data.aws_iam_policy_document.s3_policy.json}"
}


/*-----------------------------------------------------*/

#CloudFront creation
resource "aws_cloudfront_distribution" "web_distribution" {
  depends_on = [ 
    aws_cloudfront_origin_access_identity.origin_access_identity, 
    null_resource.nullRemote
  ]

  origin {
    domain_name = aws_s3_bucket.web_distribution.bucket_regional_domain_name
    origin_id   = local.s3_origin_id #"web_distribution_origin"
    s3_origin_config {
      origin_access_identity = aws_cloudfront_origin_access_identity.origin_access_identity.cloudfront_access_identity_path
    }
  }


  connection {
    type     = "ssh"
    user     = "ec2-user"
    private_key = tls_private_key.example.private_key_pem
    host     = aws_instance.web.public_ip
  }

  provisioner "remote-exec" {
    inline = [
      "sudo su << EOF",
      "echo \"<img src='http://${self.domain_name}/${aws_s3_bucket_object.image-upload.key}'>\" >> /var/www/html/index.html",
      "EOF"
    ]
  }

  enabled             = true
  is_ipv6_enabled     = true
  comment             = "Some comment"
  default_root_object = "index.html"

  # logging_config {
  #   include_cookies = false
  #   bucket          = "yash-1241242412.s3.amazonaws.com"
  #   prefix          = "myprefix"
  # }

  # aliases = ["mysite.example.com", "yoursite.example.com"]

  default_cache_behavior {
    allowed_methods  = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "${local.s3_origin_id}"

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

  # Cache behavior with precedence 0
  ordered_cache_behavior {
    path_pattern     = "/content/immutable/*"
    allowed_methods  = ["GET", "HEAD", "OPTIONS"]
    cached_methods   = ["GET", "HEAD", "OPTIONS"]
    target_origin_id = "${local.s3_origin_id}"

    forwarded_values {
      query_string = false
      headers      = ["Origin"]

      cookies {
        forward = "none"
      }
    }

    min_ttl                = 0
    default_ttl            = 86400
    max_ttl                = 31536000
    compress               = true
    viewer_protocol_policy = "redirect-to-https"
  }

  # Cache behavior with precedence 1
  ordered_cache_behavior {
    path_pattern     = "/content/*"
    allowed_methods  = ["GET", "HEAD", "OPTIONS"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "${local.s3_origin_id}"

    forwarded_values {
      query_string = false

      cookies {
        forward = "none"
      }
    }

    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
    compress               = true
    viewer_protocol_policy = "redirect-to-https"
  }

  price_class = "PriceClass_200"

  restrictions {
    geo_restriction {
      restriction_type = "none"
  }
}

  tags = {
    Environment = "dev"
  }


  viewer_certificate {
    cloudfront_default_certificate = true
  }
}

  