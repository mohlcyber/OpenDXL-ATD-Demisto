#!/usr/bin/env python

import logging
import os
import sys
import time
import json
import threading
import requests

from dxlclient.callbacks import EventCallback
from dxlclient.client import DxlClient
from dxlclient.client_config import DxlClientConfig
from dxlclient.message import Event, Request

# Configure local logger
logging.getLogger().setLevel(logging.ERROR)
logger = logging.getLogger(__name__)

# Create DXL configuration from file
CONFIG_FILE = "path to config file"
config = DxlClientConfig.create_dxl_config_from_file(CONFIG_FILE)

# Create the client
with DxlClient(config) as client:

    # Connect to the fabric
    client.connect()

    class Demisto:

        def __init__(self, data):
            self.url = 'demisto url'
            self.headers = {'Authorization' : 'api key',
                            'Content-Type' : 'application/json'}
            self.verify = False
            self.data = data

        def incident(self):

            res = requests.post(self.url + '/incident', headers=self.headers, json=self.data, verify=self.verify)
            return res.json()

    # Create and add event listener
    class MyEventCallback(EventCallback):

        def on_event(self, event):

            try:
                query = event.payload.decode()
                query = query[:query.rfind('}')+1]
                query = json.loads(query)

                data = {
                    "type": "dxl",
                    "name": "DXL - ATD Analysis for %s" % query['Summary']['Subject']['Name'],
                    "owner": "admin",
                    "severity": 3,
                    "labels": [
                        {"type": "profile", "value": query['Summary']['OSversion']},
                        {"type": "atdip", "value": query['Summary']['ATD IP']},
                        {"type": "srcip", "value": query['Summary']['Src IP']},
                        {"type": "dstip", "value": query['Summary']['Dst IP']},
                        {"type": "taskid", "value": query['Summary']['TaskId']},
                        {"type": "jobid", "value": query['Summary']['JobId']},
                        {"type": "filename", "value": query['Summary']['Subject']['Name']},
                        {"type": "filetype", "value": query['Summary']['Subject']['Type']},
                        {"type": "filemd5", "value": query['Summary']['Subject']['md5']},
                        {"type": "filesha1", "value": query['Summary']['Subject']['sha-1']},
                        {"type": "filesha256", "value": query['Summary']['Subject']['sha-256']},
                        {"type": "filesize", "value": query['Summary']['Subject']['size']},
                        {"type": "date", "value": query['Summary']['Subject']['Timestamp']},
                        {"type": "severity", "value": query['Summary']['Verdict']['Severity']},
                        {"type": "description", "value": query['Summary']['Verdict']['Description']}
                    ],
                    "details": "DXL Message - ATD malicious conviction"
                }

                res = Demisto(data).incident()
                print res

            except Exception as e:
                print e

        @staticmethod
        def worker_thread(req):
            client.sync_request(req)

    # Register the callback with the client
    client.add_event_callback('#', MyEventCallback(), subscribe_to_topic=False)
    client.subscribe("/mcafee/event/atd/file/report")

    # Wait forever
    while True:
        time.sleep(60)
