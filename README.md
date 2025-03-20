# GuardDuty Ghostbuster

A Python script that automatically identifies and archives sample findings in AWS GuardDuty, helping you maintain a clean security findings dashboard.

## What it does

`guard-duty-ghostbuster.py` helps you clean up your AWS GuardDuty console by:

1. Retrieving all non-archived GuardDuty findings
2. Identifying which findings are sample findings (test findings generated by AWS)
3. Archiving all sample findings in batches
4. Providing a summary of total findings, sample findings, and non-sample findings

## Why it's useful

AWS GuardDuty often includes sample findings to demonstrate how the service works. While these are helpful for understanding GuardDuty's capabilities, they can clutter your security dashboard and make it harder to focus on real security issues. This script helps you maintain a clean dashboard by automatically archiving these sample findings.

## Requirements

- Python 3.x
- boto3 library
- AWS credentials configured with appropriate GuardDuty permissions
- GuardDuty Detector ID

## Setup

1. Ensure you have the required Python packages:
   ```
   pip install boto3
   ```

2. Set your GuardDuty Detector ID as an environment variable:
   ```
   export GUARDDUTY_DETECTOR_ID="your-detector-id"
   ```

## Usage

Simply run the script:

```
python guard-duty-ghostbuster.py
```

The script will:
- Connect to your AWS GuardDuty service
- Retrieve all non-archived findings
- Identify and archive sample findings
- Display a summary of the findings processed

## Output

The script provides a summary of:
- Total number of findings processed
- Number of sample findings archived
- Number of non-sample findings (actual security findings)

## Permissions

The AWS IAM user or role running this script needs the following permissions:
- `guardduty:ListFindings`
- `guardduty:GetFindings`
- `guardduty:ArchiveFindings`
