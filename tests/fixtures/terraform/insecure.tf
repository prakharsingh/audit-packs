resource "aws_s3_bucket" "b" {
  bucket = "example"
}
resource "aws_s3_bucket_acl" "b" {
  bucket = aws_s3_bucket.b.id
  acl    = "public-read"
}
