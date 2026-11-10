# =============================================================================
# IAM Access Analyzer — Organization level
# =============================================================================

resource "aws_accessanalyzer_analyzer" "this" {
  count = var.enable_access_analyzer ? 1 : 0

  analyzer_name = "tlz-org-access-analyzer"
  type          = "ORGANIZATION"

  depends_on = [aws_organizations_delegated_administrator.access_analyzer]
}
