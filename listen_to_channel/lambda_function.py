import os
import json
import base64
import random
import time

import boto3
from botocore.exceptions import ClientError

from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError


# This function is triggered when a new message is sent to the channel
# The bot will reply to the user with an ephemeral message
DYNAMODB_TABLE_NAME = os.environ['DYNAMODB_TABLE_NAME']

def lambda_handler(event, context):   
    print(json.dumps(event))
    print('Retrieving bot token...')
    os.environ['SLACK_BOT_TOKEN'] = get_secret('slack_service_bot_token')['bot_token']

    # Create a Slack client and send an ephemeral message to the user on the same chanenel of the event
    print('Creating Slack client...')
    client = WebClient(token=os.environ["SLACK_BOT_TOKEN"])
    message_channel_event = json.loads(event['body'])['event']

    user_id = message_channel_event['user']
    channel_id = message_channel_event['channel']

    # Get the user record from DynamoDB
    print('Getting user record...')
    user_record = get_item(user_id)

    # If the user record doesn't exist, create it
    if user_record is None:
        print('User record not found. Creating...')
        user_record = {
            'user_id': user_id
        }
        response = create_item(user_record)
        print(json.dumps(response))
        print('User record created.')

    # If the last message was sent less than 10 minutes ago, don't send another one
    if user_record.get('last_message_sent_at') is not None:
        last_message_sent_at = float(user_record['last_message_sent_at'])
        if time.time() - last_message_sent_at < 600:
            print('Last message sent less than 10 minutes ago. Not sending another one.')
            return {
                'statusCode': 200,
                'body': json.dumps('Last message sent less than 10 minutes ago. Not sending another one.')
            }
    
    # Send the message
    print('Sending message...')
    response = send_slack_message(client, user_id, channel_id)
    user_record['last_message_sent_at'] = response['message_ts']

    # Update the user record in DynamoDB
    print('Updating user record...')
    response = create_item(user_record)
    print(json.dumps(response))
    print('User record updated.')

    return {
        'statusCode': 200,
        'body': json.dumps('Hello from Lambda!')
    }

# Function that gets a secret from AWS Secrets Manager
def get_secret(secret_name, region = "us-west-2"):
   # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region
    )

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'DecryptionFailureException':
            raise e
        elif e.response['Error']['Code'] == 'InternalServiceErrorException':
            raise e
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            raise e
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            raise e
        elif e.response['Error']['Code'] == 'LimitExceededException':
            raise e
        elif e.response['Error']['Code'] == 'ResourceNotFoundException':
            raise e
    else:
        # Decrypts secret using the associated KMS key.
        # Depending on whether the secret is a string or binary, one of these fields will be populated.
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
            return json.loads(secret)
        else:
            decoded_binary_secret = base64.b64decode(get_secret_value_response['SecretBinary'])

# Function that sends a slack ephemeral message utilizing exponential backoff
def send_ephemeral_message(client, channel, user, text):
    backoff_time = 1
    for i in range(0, 5):
        try:
            client.chat_postEphemeral(
                channel=channel,
                text=text,
                user=user
            )
            break
        except SlackApiError as e:
            if e.response['error']['code'] == 429:
                print("Rate limited. Backing off for {} seconds".format(backoff_time))
                time.sleep(backoff_time + random.random())
                backoff_time *= 2
            else:
                raise e
                break

# Function that gets the item from DynamoDB where the user_id is the key
def get_item(user_id):
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table(DYNAMODB_TABLE_NAME)
    response = table.get_item(
        Key={
            'user_id': user_id
        }
    )
    return response.get('Item')


# Function that creates a new item in DynamoDB
def create_item(item):
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table(DYNAMODB_TABLE_NAME)
    response = table.put_item(
        Item= item
    )
    print(json.dumps(response))
    return response

# Function that updates an item in DynamoDB
def update_item(item):
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table(DYNAMODB_TABLE_NAME)
    response = table.update_item(
        Key={
            'user_id': item['user_id']
        },
        UpdateExpression="set last_message_sent_at = :last_message_sent_at",
        ExpressionAttributeValues={
            ':last_message_sent_at': item['last_message_sent_at']
        }
    )
    print(json.dumps(response))
    return response

def send_slack_message(client, user_id, channel_id):
    message = f'Hello, <@{user_id}>!\n\nIf you are having an issue please submit a ticket to itsupport@covidclinc.org. Or simply type /servicebot to submit a ticket from Slack.'

    print('Sending ephemeral message...')
    response = client.chat_postEphemeral(
        channel=channel_id,
        text=message,
        user=user_id
    )
    print('Ephemeral message sent!')
    return response