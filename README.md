# OpenDXL-ATD-Demisto
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

This Python script is an OpenDXL subscriber to launch new Investigations within Demisto. The script will subscribe to DXL messages from McAfee Advanced Threat Defence (ATD) parse indicators and create new investigations in Demisto.

## Component Description

**McAfee Advanced Threat Defense (ATD)** is a malware analytics solution combining signatures and behavioral analysis techniques to rapidly identify malicious content and provides local threat intelligence. ATD exports IOC data in STIX format and DXL.
https://www.mcafee.com/in/products/advanced-threat-defense.aspx

**Demisto Enterprise** delivers a complete solution that helps Tier-1 through Tier-3 analysts and SOC managers to optimize the entire incident life cycle while auto documenting and journaling all the evidence. More than 150 integrations enable security orchestration workflows for incident management and other critical security operation tasks.
https://www.demisto.com/product-automated-incident-response/

## Prerequisites
McAfee ATD solution (tested with ATD 4.2.2)

Demisto (tested with 3.5 - Content Version 18.5.3 (7186783))

Requests ([Link](http://docs.python-requests.org/en/master/user/install/#install))

OpenDXL SDK ([Link](https://github.com/opendxl/opendxl-client-python))
```sh
git clone https://github.com/opendxl/opendxl-client-python.git
cd opendxl-client-python/
python setup.py install
```

McAfee ePolicy Orchestrator, DXL Broker

## Configuration
Enter the Demisto url and api key in the atd_to_demisto_sub.py file (line 33, 34).

<img width="638" alt="screen shot 2018-05-23 at 08 43 27" src="https://user-images.githubusercontent.com/25227268/40407648-6a183bee-5e65-11e8-9ea0-740f8e3c0c0a.png">

Create Certificates for OpenDXL ([Link](https://opendxl.github.io/opendxl-client-python/pydoc/epoexternalcertissuance.html)). 

Make sure that the FULL PATH to the config file is entered in line 21 (atd_to_demisto_sub.py).

## Process Description
McAfee ATD receives files from multiple sensors like Endpoints, Web Gateways, Network IPS or via Rest API. 
ATD will perform malware analytics and produce local threat intelligence. After an analysis every IOC will be published via the Data Exchange Layer (topic: /mcafee/event/atd/file/report). 

### atd_to_demisto_sub.py
The atd_to_demisto_sub.py receives DXL messages from ATD, parse indicators create a new incident in Demisto via the APIs.

<img width="1440" alt="screen shot 2018-05-23 at 08 47 25" src="https://user-images.githubusercontent.com/25227268/40407824-f51322a4-5e65-11e8-9186-623f67b8d5e2.png">

## Run the OpenDXL wrapper
> python atd_subscriber.py

or

> nohup python atd_subscriber.py &

## Summary
With this use case, ATD produces local intelligence that is immediatly launching new investigations and playbooks in Demisto Orchestration.
