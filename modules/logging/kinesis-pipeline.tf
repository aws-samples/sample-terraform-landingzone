# =============================================================================
# CloudWatch-to-S3 Kinesis Pipeline
# =============================================================================
# The pipeline is switched by the subscription inputs
# (local.kinesis_pipeline_enabled); var.kinesis_pipeline_config tunes its
# values. Every default of that variable is a production value, so a
# deployment without the input keeps its plan.

resource "aws_kinesis_stream" "cw_to_s3" {
  count = local.kinesis_pipeline_enabled ? 1 : 0

  name             = var.kinesis_stream_name
  retention_period = var.kinesis_pipeline_config.kinesis_retention_hours

  # A shard count is only valid on provisioned capacity; the variable rejects
  # it for on-demand streams. The provisioned default of 1 shard matches the
  # smallest stream the API accepts.
  shard_count = (
    var.kinesis_pipeline_config.kinesis_stream_mode == "PROVISIONED"
    ? coalesce(var.kinesis_pipeline_config.kinesis_shard_count, 1)
    : null
  )

  stream_mode_details {
    stream_mode = var.kinesis_pipeline_config.kinesis_stream_mode
  }

  encryption_type = "KMS"
  kms_key_id      = aws_kms_key.log_bucket.arn

  tags = {
    Name = var.kinesis_stream_name
  }
}

resource "aws_iam_role" "cw_to_kinesis" {
  count = local.kinesis_pipeline_enabled ? 1 : 0

  name = var.cw_to_kinesis_role_name

  assume_role_policy = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/logging/cw-to-kinesis-trust-policy.json", {
    region     = local.region
    dns_suffix = local.dns_suffix
    account_id = local.account_id
  })))
}

resource "aws_iam_role_policy" "cw_to_kinesis" {
  count = local.kinesis_pipeline_enabled ? 1 : 0

  name = var.cw_to_kinesis_policy_name
  role = aws_iam_role.cw_to_kinesis[0].id

  policy = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/logging/cw-to-kinesis-policy.json", {
    kinesis_stream_arn = aws_kinesis_stream.cw_to_s3[0].arn
    kms_key_arn        = aws_kms_key.log_bucket.arn
  })))
}

# --- IAM propagation delay (CloudWatch Logs delivery role) ---
# The consumers of this role — the subscription filters and the account-wide
# subscription policy in cloudtrail.tf — are validated SYNCHRONOUSLY by
# CloudWatch Logs, which assumes the role and puts a test record on the stream
# during the API call. depends_on gets the grant CREATED first, but PutRolePolicy
# returns before the grant is globally visible to the validating service, so the
# ordering edge alone can still lose the race. Same reason and same duration as
# the module-level barriers in control-tower, deployment-role and pipeline.
resource "time_sleep" "cw_to_kinesis_iam_propagation" {
  count = local.kinesis_pipeline_enabled ? 1 : 0

  create_duration = "30s"

  depends_on = [aws_iam_role_policy.cw_to_kinesis]
}

# --- Firehose Record-Processor Lambda (optional) ---
# CloudWatch Logs delivers subscription records as gzip-compressed envelopes.
# When enabled, this function replaces the delivery stream's native
# decompression processor: it decompresses each record and re-emits it as a
# JSON document carrying account_id, region and log_group, so the
# MetadataExtraction processor below can resolve the partition keys of the
# archive prefix. Built like the quarantine automation: archive_file over an
# inline template — no local-exec, no shell script, no external data source.

locals {
  firehose_processor_enabled = (
    local.kinesis_pipeline_enabled && var.kinesis_pipeline_config.lambda_processor.enabled
  )

  firehose_processor_lambda_code = <<-PYTHON
import base64
import gzip
import json
import os


def handler(event, context):
    """Reshape CloudWatch Logs subscription records for the archive pipeline.

    Each incoming record is a base64-encoded, gzip-compressed CloudWatch
    Logs envelope. The function decompresses it and re-emits a JSON document
    with the fields the delivery stream's MetadataExtraction query reads
    (account_id, region, log_group). Control messages are dropped; records
    without a log group cannot be partitioned and are marked failed, which
    routes them to the error prefix.
    """
    output = []
    for record in event["records"]:
        try:
            payload = json.loads(
                gzip.decompress(base64.b64decode(record["data"]))
            )
        except Exception:
            output.append(
                {
                    "recordId": record["recordId"],
                    "result": "ProcessingFailed",
                    "data": record["data"],
                }
            )
            continue
        if payload.get("messageType") == "CONTROL_MESSAGE":
            output.append(
                {
                    "recordId": record["recordId"],
                    "result": "Dropped",
                    "data": record["data"],
                }
            )
            continue
        if "logGroup" not in payload:
            output.append(
                {
                    "recordId": record["recordId"],
                    "result": "ProcessingFailed",
                    "data": record["data"],
                }
            )
            continue
        document = {
            "account_id": payload.get("owner", ""),
            "region": os.environ["PIPELINE_REGION"],
            "log_group": payload["logGroup"],
            "log_stream": payload.get("logStream", ""),
            "log_events": payload.get("logEvents", []),
        }
        output.append(
            {
                "recordId": record["recordId"],
                "result": "Ok",
                "data": base64.b64encode(
                    (json.dumps(document) + "\n").encode("utf-8")
                ).decode("ascii"),
            }
        )
    return {"records": output}
PYTHON
}

data "archive_file" "firehose_processor" {
  count = local.firehose_processor_enabled ? 1 : 0

  type        = "zip"
  output_path = "${path.module}/.archive/firehose_processor.zip"

  source {
    content  = local.firehose_processor_lambda_code
    filename = "index.py"
  }
}

resource "aws_iam_role" "firehose_processor" {
  count = local.firehose_processor_enabled ? 1 : 0

  name = var.firehose_processor_role_name

  assume_role_policy = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/logging/lambda-trust-policy.json", {
    dns_suffix = local.dns_suffix
  })))
}

resource "aws_iam_role_policy" "firehose_processor" {
  count = local.firehose_processor_enabled ? 1 : 0

  name = var.firehose_processor_policy_name
  role = aws_iam_role.firehose_processor[0].id

  # The logs grant is scoped to the function's own log group, which Lambda
  # derives from the function name — so the name must reach the template.
  policy = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/logging/firehose-processor-lambda-policy.json", {
    arn_prefix    = local.arn_prefix
    function_name = var.firehose_processor_function_name
  })))
}

# The grant that makes lambda_environment_kms_key_arn usable. Lambda decrypts a
# function's environment variables with the FUNCTION's role at cold start, so a
# customer-managed key without this statement produces a function that plans and
# applies cleanly and then fails every invocation. Its own resource rather than a
# statement in the policy document above, because the document is a static file
# and this statement exists only while a key is named.
resource "aws_iam_role_policy" "firehose_processor_env_kms" {
  count = local.firehose_processor_enabled && var.lambda_environment_kms_key_arn != "" ? 1 : 0

  name = "${var.firehose_processor_policy_name}-env-kms"
  role = aws_iam_role.firehose_processor[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "DecryptOwnEnvironment"
        Effect   = "Allow"
        Action   = "kms:Decrypt"
        Resource = var.lambda_environment_kms_key_arn
      },
    ]
  })
}

resource "aws_lambda_function" "firehose_processor" {
  count = local.firehose_processor_enabled ? 1 : 0

  function_name = var.firehose_processor_function_name
  description   = "Decompresses CloudWatch Logs records so the archive delivery stream can partition them"
  role          = aws_iam_role.firehose_processor[0].arn
  handler       = "index.handler"
  runtime       = "python3.12"

  # Firehose invokes the processor synchronously with up to 3 MB per batch
  # (the variable bounds buffer_size_mb); a minute is ample for decompressing
  # and re-encoding that much and stays far below the 5-minute ceiling the
  # service enforces on processor functions.
  timeout = 60

  # Cap on parallel executions: the function serves one delivery stream, so a
  # small reserved pool is ample and bounds a runaway invocation storm
  # instead of letting it drain the account's concurrency pool.
  reserved_concurrent_executions = 10

  filename         = data.archive_file.firehose_processor[0].output_path
  source_code_hash = data.archive_file.firehose_processor[0].output_base64sha256

  # Empty means the AWS-managed Lambda key keeps encrypting the variables
  # below. A key named here is also
  # granted to the execution role (aws_iam_role_policy.firehose_processor_env_kms),
  # without which the function cannot read its own variables at cold start.
  kms_key_arn = var.lambda_environment_kms_key_arn != "" ? var.lambda_environment_kms_key_arn : null

  environment {
    variables = {
      PIPELINE_REGION = local.region
    }
  }
}

# The processor's own execution log group. Lambda creates /aws/lambda/<function
# name> implicitly on the first invocation when nothing has declared it, and
# that group then sits outside the state: no retention, never destroyed with
# the stack — in every deployment, not only in a test. The monitoring module
# declares its two functions' groups for the same reason
# (modules/monitoring/README.md, "Lambda execution log groups"); no check
# covers this class, so this declaration is what closes the gap here.
#
# The name derives from the FUNCTION rather than from the variable the function
# reads, so the group cannot disagree with it: firehose_processor_function_name
# is operator-settable, and a group built independently from the same variable
# would only be equal by convention. The function's inline policy already
# scopes its logs grant to this exact group.
#
# CreateLogGroup is create-only — in an account where the processor has already
# run, the group exists outside the state and the apply fails with
# ResourceAlreadyExistsException until it is imported (README, "Lambda
# execution log groups").
resource "aws_cloudwatch_log_group" "firehose_processor" {
  count = local.firehose_processor_enabled ? 1 : 0

  name              = "/aws/lambda/${aws_lambda_function.firehose_processor[0].function_name}"
  retention_in_days = var.firehose_processor_log_retention_days
  kms_key_id        = var.firehose_processor_log_kms_key_arn != "" ? var.firehose_processor_log_kms_key_arn : null
}

# --- Kinesis Firehose Delivery Stream (CloudWatch → Kinesis → Firehose → S3) ---

resource "aws_iam_role" "firehose_delivery" {
  count = local.kinesis_pipeline_enabled ? 1 : 0

  name = var.firehose_delivery_role_name

  assume_role_policy = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/logging/firehose-delivery-trust-policy.json", {
    dns_suffix = local.dns_suffix
  })))
}

resource "aws_iam_role_policy" "firehose_delivery" {
  count = local.kinesis_pipeline_enabled ? 1 : 0

  name = var.firehose_delivery_policy_name
  role = aws_iam_role.firehose_delivery[0].id

  policy = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/logging/firehose-delivery-policy.json", {
    s3_bucket_arn        = aws_s3_bucket.central_logs.arn
    kinesis_stream_arn   = aws_kinesis_stream.cw_to_s3[0].arn
    kms_key_arn          = aws_kms_key.log_bucket.arn
    lambda_processor_arn = local.firehose_processor_enabled ? aws_lambda_function.firehose_processor[0].arn : ""
  })))
}

# --- IAM propagation delay (Firehose delivery role) ---
# Same class as the barrier above, and the same 30 seconds: CreateDeliveryStream
# is not a bare declaration — Firehose validates the role it is handed for both
# the Kinesis source and the S3 destination, and Terraform waits for the stream
# to reach ACTIVE, so a role that does not yet carry these grants fails the
# CREATE rather than merely degrading later.
resource "time_sleep" "firehose_delivery_iam_propagation" {
  count = local.kinesis_pipeline_enabled ? 1 : 0

  create_duration = "30s"

  depends_on = [aws_iam_role_policy.firehose_delivery]
}

resource "aws_kinesis_firehose_delivery_stream" "cw_to_s3" {
  count = local.kinesis_pipeline_enabled ? 1 : 0

  name        = var.firehose_delivery_stream_name
  destination = "extended_s3"

  kinesis_source_configuration {
    kinesis_stream_arn = aws_kinesis_stream.cw_to_s3[0].arn
    role_arn           = aws_iam_role.firehose_delivery[0].arn
  }

  extended_s3_configuration {
    role_arn   = aws_iam_role.firehose_delivery[0].arn
    bucket_arn = aws_s3_bucket.central_logs.arn

    buffering_size     = var.kinesis_pipeline_config.firehose_buffering_size_mb
    buffering_interval = var.kinesis_pipeline_config.firehose_buffering_interval_seconds

    compression_format = var.kinesis_pipeline_config.firehose_compression_format
    file_extension     = var.kinesis_pipeline_config.firehose_file_extension

    kms_key_arn = aws_kms_key.log_bucket.arn

    dynamic_partitioning_configuration {
      enabled = true
    }

    # The archive prefix partitions by account, region and log group. The
    # native path reads account and log group from the decompressed envelope;
    # the envelope carries no region field, so the deployment region is
    # pinned into the prefix at plan time (the Lambda path injects the same
    # value from its PIPELINE_REGION environment variable and keeps the
    # query-based prefix).
    prefix = (
      local.firehose_processor_enabled
      ? "cloudwatch-logs/!{partitionKeyFromQuery:account_id}/!{partitionKeyFromQuery:region}/!{partitionKeyFromQuery:log_group}/"
      : "cloudwatch-logs/!{partitionKeyFromQuery:account_id}/${local.region}/!{partitionKeyFromQuery:log_group}/"
    )
    error_output_prefix = var.kinesis_pipeline_config.firehose_error_output_prefix

    processing_configuration {
      enabled = true

      # The optional Lambda processor runs first and replaces the native
      # decompression below: it decompresses the CloudWatch Logs envelope
      # and re-emits a reshaped JSON document, which is what its variant of
      # the MetadataExtraction query expects.
      dynamic "processors" {
        for_each = local.firehose_processor_enabled ? [var.kinesis_pipeline_config.lambda_processor] : []
        content {
          type = "Lambda"

          parameters {
            parameter_name  = "LambdaArn"
            parameter_value = "${aws_lambda_function.firehose_processor[0].arn}:$LATEST"
          }

          parameters {
            parameter_name  = "RoleArn"
            parameter_value = aws_iam_role.firehose_delivery[0].arn
          }

          parameters {
            parameter_name  = "BufferSizeInMBs"
            parameter_value = tostring(processors.value.buffer_size_mb)
          }

          parameters {
            parameter_name  = "BufferIntervalInSeconds"
            parameter_value = tostring(processors.value.buffer_interval_seconds)
          }

          parameters {
            parameter_name  = "NumberOfRetries"
            parameter_value = tostring(processors.value.retries)
          }
        }
      }

      # Native decompression (the default path): CloudWatch Logs delivers
      # subscription records as gzip-compressed envelopes; without a
      # decompressor the MetadataExtraction query below reads binary gzip,
      # every record fails partitioning and lands under the error prefix.
      # Firehose decompresses each record into the plain-JSON envelope whose
      # owner/logGroup fields the query reads. Message extraction
      # (CloudWatchLogProcessing) is deliberately not chained here: it strips
      # the very envelope metadata the partition keys are extracted from.
      dynamic "processors" {
        for_each = local.firehose_processor_enabled ? [] : ["GZIP"]
        content {
          type = "Decompression"

          parameters {
            parameter_name  = "CompressionFormat"
            parameter_value = processors.value
          }
        }
      }

      processors {
        type = "MetadataExtraction"

        # The Lambda processor re-emits documents carrying account_id,
        # region and log_group; the native path keeps the CloudWatch Logs
        # envelope, whose fields are owner and logGroup (region comes from
        # the prefix above).
        parameters {
          parameter_name = "MetadataExtractionQuery"
          parameter_value = (
            local.firehose_processor_enabled
            ? "{account_id:.account_id,region:.region,log_group:.log_group}"
            : "{account_id:.owner,log_group:.logGroup}"
          )
        }

        parameters {
          parameter_name  = "JsonParsingEngine"
          parameter_value = "JQ-1.6"
        }
      }
    }
  }

  # kinesis_source_configuration.role_arn and extended_s3_configuration.role_arn
  # order this after the ROLE only; the grants Firehose is validated against are
  # the role's inline POLICY, aws_iam_role_policy.firehose_delivery above, which
  # nothing in the data flow links to this stream — so a fresh apply was free to
  # call CreateDeliveryStream first. This is NOT a redundant edge; do not tidy it
  # away. Same class as the two subscription consumers in cloudtrail.tf, and the
  # barrier is here for the same reason it is there: the ordering edge alone does
  # not wait for the grant to become visible to the validating service.
  depends_on = [
    aws_iam_role_policy.firehose_delivery,
    time_sleep.firehose_delivery_iam_propagation,
    # The stream is what invokes the processor; its log group must exist before
    # the first invocation can create it implicitly.
    aws_cloudwatch_log_group.firehose_processor,
  ]
}

# Safety net: the pipeline must never plan without a decompression path.
# CloudWatch Logs delivers gzip; a processing chain without a decompressor
# sends every record to the error prefix — the archive stays empty while the
# feature looks healthy.
check "kinesis_pipeline_carries_a_decompression_path" {
  assert {
    condition = alltrue([
      for stream in aws_kinesis_firehose_delivery_stream.cw_to_s3 :
      anytrue([
        for processor in stream.extended_s3_configuration[0].processing_configuration[0].processors :
        contains(["Lambda", "Decompression"], processor.type)
      ])
    ])
    error_message = "The CloudWatch-to-S3 delivery stream carries neither the native Decompression processor nor the Lambda processor — gzip subscription records cannot be partitioned and every record lands under the error prefix."
  }
}
