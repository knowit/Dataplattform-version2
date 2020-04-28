from dataplattform.common.handler import Handler
from dataplattform.common.schema import Data
from dataplattform.common.aws import SSM
import datetime
import googleapiclient.discovery
import httplib2
from oauth2client.service_account import ServiceAccountCredentials
import boto3
import os
import json
import time

import pandas as pd
from typing import Dict

handler = Handler()


@handler.ingest()
def ingest(event) -> Data:
    return Data(metadata={}, data={})


@handler.process(partitions={})
def process(data) -> Dict[str, pd.DataFrame]:
    df = pd.DataFrame()
    return {
        'google_calender_event': df
    }


def handler(event, context):

    poll()

    return {
        'statusCode': 200,
        'body': 'Success'
    }


def poll():
    client = boto3.client('ssm')
    credentials = client.get_parameter(
        Name='/dev/poller/google/credentials',
        WithDecryption=False)
    credsentials_from_ssm = credentials['Parameter']['Value']

    calendar_ids = client.get_parameter(
        Name='/dev/poller/google/calendarIDs',
        WithDecryption=False)
    calendar_ids_from_ssm = calendar_ids['Parameter']['Value'].split(',')

    events = {
        "data": {},
        "timestamp": int(time.time())
    }

    for calendar_id in calendar_ids_from_ssm:
        events['data'].update(get_events(credsentials_from_ssm, calendar_id))

    if bool(events['data']):
        path = os.getenv("ACCESS_PATH")

        s3 = boto3.resource('s3')
        s3_object = s3.Object(os.getenv('DATALAKE'),
                              path + str(int(time.time())) + ".json")
        s3_object.put(Body=(bytes(json.dumps(events).encode('UTF-8'))))

    return True


def get_events(credsentials_from_env, calendar_id):
    """
    :param creds: credentials
    :param calendar_id:
    :return: A dictionary containing (max 10) of the events in the nearest future from this
    specific calendar_id.
    """

    credsentials_json = json.loads(credsentials_from_env)
    credentials = ServiceAccountCredentials.from_json_keyfile_dict(credsentials_json, [
        'https://www.googleapis.com/auth/calendar.readonly'])

    http = httplib2.Http()
    http = credentials.authorize(http)
    service = googleapiclient.discovery.build(
        serviceName='calendar', version='v3', http=http, cache_discovery=False)
    now = datetime.datetime.utcnow().isoformat() + '+02:00'
    tomorrow = datetime.datetime.utcfromtimestamp(datetime.datetime.now().timestamp() + (
        60 * 60 * 24)).isoformat() + '+02:00'
    events_result = service.events().list(
        calendarId=calendar_id,
        timeMin=now,
        timeMax=tomorrow,
        timeZone='UTC+0:00',
        singleEvents=True,
        orderBy='startTime') \
        .execute()
    events = events_result.get('items', [])
    info = {}
    for event in events:
        boxes = []
        if 'location' in event:
            temp = event['location'].split(',')
            for box in temp:
                if "Enheter" in box:
                    boxes.append(box.split('-')[-1])

        startTime = ""
        endTime = 0
        if "dateTime" in event['start']:
            startTime = get_timestamp(event['start']['dateTime'])
        else:
            timeObject = list(map(int, event['start']['date'].split("-")))
            startTime = datetime.datetime.timestamp(
                datetime.datetime(timeObject[0], timeObject[1], timeObject[2]))
        if "dateTime" in event['end']:
            endTime = get_timestamp(event['end']['dateTime'])
        else:
            timeObject = list(map(int, event['end']['date'].split("-")))
            endTime = datetime.datetime.timestamp(datetime.datetime(
                timeObject[0], timeObject[1], timeObject[2]))

        summary = ""
        if "summary" in event:
            summary = event["summary"]

        creator = ""
        if "creator" in event:
            creator = event['creator']['email']

        info[event['id']] = {
            'calendar_id': calendar_id,
            'timestamp_from': startTime,
            'timestamp_to': endTime,
            'event_summary': summary,
            'event_button_names': boxes,
            'creator': creator,
        }
    return info


def get_timestamp(date):
    return datetime.datetime.fromisoformat(date).timestamp()


if __name__ == "__main__":
    poll()
