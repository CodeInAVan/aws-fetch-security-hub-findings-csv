# Fetch AWS Security Hub Findings


## Multi-Account Version

- download an aws Organisations account list and remove the header row, this has a default name of Organization_accounts_information.csv, see example Organization_accounts_information_example.csv 
- open the file in excel and make the accountid number format '000000000000' as any account numbers less than 12 digits needa a leading 0 or 00!
- use "runme.sh" to run, please examine this first and check it's reading the correct org account list file.

##

Small script (copy of https://github.com/dominikjaeckle/aws-fetch-security-hub-findings ) to fetch aws security hub findings based on defined aws profiles and filters. The script reads a configuration file and fetches the security hub findings based on pre-defined aws profiles and filters, which are to be defined in the settings.yaml file. 

Modified to support a csv output.

## Prerequisites
If you have not done so, set up the local AWS profiles (config + crendentials file) following the instructions here: https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html 

Please note that you must be authenticated when running this script. 

Also install the requirements:
```bash
$ pip install -r requirements.txt
```

## Configuration
Find the configuration in the **settings.yaml** file.
```yaml
# Configure all environments according to your file at ~/.aws/config
# List all account profiles that shall be used below.
accounts:
  - $$profile1$$
  - $$profile2$$
  - ...

# definition of filters and sort criteria can be found here:
# https://docs.aws.amazon.com/cli/latest/reference/securityhub/get-findings.html

# filters to be used to filter for security findints
filters:
  - filter_name: WorkflowStatus
    value: NEW
    comparison: EQUALS

  - filter_name: SeverityLabel
    value: HIGH
    comparison: EQUALS

  - filter_name: RecordState
    value: ACTIVE
    comparison: EQUALS

# sorting of the return list
sort_criteria:
  field: LastObservedAt
  sort_order: desc
```

## Fetch the Security Hub Findings
Run the following command to fetch the security hub findings
```bash
$ python fetch_sec_findings.py
```

In the same directory, the script will generate a file called **security_findings_%Y%m%d.html** and a file **security_findings_%Y%m%d.csv**, which can be opened in any browser. 

## Extensions
The basic set of attributes that is extracted from the security hub findings can be extended as per your convinience. So far, the following definition exists using pydantic:

```python
class Finding(BaseModel):
    environment: str = ''
    account_id: str = ''
    created_at: str = ''
    updated_at: str = ''
    compliance_status: str = ''
    title: str = ''
    description: str = ''
    recommendation_text: str = ''
    recommendation_url: str = ''
    workflow_state: str = ''
    workflow_status: str = ''
    record_state: str = ''
    severity_label: str = ''
```