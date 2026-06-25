from audit_packs.diff import parse_unified_diff

DIFF = """diff --git a/main.tf b/main.tf
index 111..222 100644
--- a/main.tf
+++ b/main.tf
@@ -10,0 +11,2 @@ resource "aws_s3_bucket" "b" {
+  encrypted = false
+  acl       = "public-read"
@@ -20,1 +23,1 @@
+  versioning = false
+"""


def test_parse_extracts_added_lines_per_file():
    result = parse_unified_diff(DIFF)
    assert result == {"main.tf": {11, 12, 23}}


def test_parse_ignores_files_with_no_additions():
    diff = (
        "diff --git a/x.tf b/x.tf\n--- a/x.tf\n+++ b/x.tf\n@@ -1,1 +1,0 @@\n-removed\n"
    )
    assert parse_unified_diff(diff) == {}
