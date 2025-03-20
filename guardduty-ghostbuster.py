import boto3
import json
import os
import logging
from botocore.exceptions import BotoCoreError, ClientError

# Set up logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Load the detector id from environment variables or set it to None
DETECTOR_ID = os.getenv("GUARDDUTY_DETECTOR_ID")

if not DETECTOR_ID:
    raise ValueError("Error: GUARDDUTY_DETECTOR_ID is not set. Please provide a valid GuardDuty Detector ID.")


def archive_findings(client, sample_findings):
    batch_size = 50

    if not sample_findings:
        logging.info("No sample findings to archive.")
        return

    # GuardDuty will only accept batches of 50 or less findings at a time.
    for i in range(0, len(sample_findings), batch_size):
        batch = sample_findings[i:i + batch_size]

        try:
            client.archive_findings(
                DetectorId=DETECTOR_ID,
                FindingIds=batch
            )
            logging.info(f"Successfully archived {len(batch)} findings")
        except (BotoCoreError, ClientError) as e:
            logging.error(f"Error archiving findings: {e}")


def get_guardduty_findings(client):
    findings = []
    try:
        paginator = client.get_paginator("list_findings")
        response_iterator = paginator.paginate(
            DetectorId=DETECTOR_ID,
            FindingCriteria={"Criterion": {"service.archived": {"Eq": ["false"]}}}
        )

        for response in response_iterator:
            for finding_id in response['FindingIds']:
                findings.append(finding_id)
    except (BotoCoreError, ClientError) as e:
        logging.error(f"Error retrieving GuardDuty findings: {e}")

    return findings


def process_guardduty_findings(client, findings):
    total_findings = 0
    sample_findings = 0
    non_sample_findings = 0
    sample_finding_ids = []

    for finding_id in findings:
        total_findings += 1
        try:
            finding_response = client.get_findings(
                DetectorId=DETECTOR_ID,
                FindingIds=[finding_id]
            )['Findings']
            additional_info = finding_response[0].get('Service', {}).get('AdditionalInfo', {}).get('Value', None)
            additional_info = json.loads(additional_info)

            if additional_info.get('sample') is True:
                sample_finding_ids.append(finding_id)
                sample_findings += 1
            else:
                non_sample_findings += 1
        except (BotoCoreError, ClientError) as e:
            logging.error(f"Error retrieving details for finding {finding_id}: {e}")

    return total_findings, sample_findings, non_sample_findings, sample_finding_ids


def main():
    total_findings = 0
    sample_findings = 0
    non_sample_findings = 0
    sample_finding_ids = []

    logging.info("Starting GuardDuty findings cleanup...")

    # Start a GuardDuty client
    gd_client = boto3.client('guardduty')

    # List the non-archived findings
    logging.info("Building a list of all non-archived GuardDuty findings...")
    findings = get_guardduty_findings(gd_client)

    # Process all the findings
    logging.info("Processing GuardDuty findings and identifying samples...")
    total_findings, sample_findings, non_sample_findings, sample_finding_ids = process_guardduty_findings(gd_client, findings)

    # Loop through the list and archive all the sample findings
    logging.info(f"Archiving {sample_findings} GuardDuty findings...")
    archive_findings(gd_client, sample_finding_ids)

    # Close the GuardDuty client
    gd_client.close()

    print(f"Total findings: {total_findings}")
    print(f"Sample findings: {sample_findings}")
    print(f"Non-sample findings: {non_sample_findings}")
    #print("Archiving of sample findings complete.")


if __name__ == "__main__":
    main()
