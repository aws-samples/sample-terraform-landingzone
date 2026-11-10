import json
import os
import boto3

sns_client = boto3.client('sns')
CENTRAL_TOPIC_ARN = os.environ['CENTRAL_TOPIC_ARN']


def handler(event, context):
    for record in event.get('Records', []):
        sns_message = record.get('Sns', {})
        message = sns_message.get('Message', '')
        # SNS delivers "Subject": null when the publisher set no subject, so a
        # dict default alone does not protect the slice below -- `or` also
        # covers the null (None) and empty-string cases.
        subject = sns_message.get('Subject') or 'Forwarded SNS Message'

        sns_client.publish(
            TopicArn=CENTRAL_TOPIC_ARN,
            Message=message,
            Subject=subject[:100]  # SNS subject max 100 chars
        )

    return {'statusCode': 200, 'body': json.dumps('Messages forwarded')}
