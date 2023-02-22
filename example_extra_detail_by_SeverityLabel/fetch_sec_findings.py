import os
import json
import yaml
from datetime import datetime
from pydantic import BaseModel
from typing import List

class Finding(BaseModel):
    environment: str = ''
    region: str = ''
    account_id: str = ''
    created_at: str = ''
    updated_at: str = ''
    compliance_status: str = ''
    title: str = ''
    productname: str = ''
    controlid: str = ''
    baseimage: str = ''
    description: str = ''
    recommendation_text: str = ''
    recommendation_url: str = ''
    workflow_state: str = ''
    workflow_status: str = ''
    record_state: str = ''
    severity_label: str = ''
    ecrrepositoryname: str = ''
    resource_type: str = ''
    resource_id: str = ''
    resource_details: str = ''


def fetch_findings(environment: str, filterstr: str, sortcriteria: str) -> List[Finding]:
    '''
        Fetches the findings from a given aws account following a certain filter and sorting criteria
    '''

    os.environ['AWS_PROFILE'] = environment
    region = os.environ['AWS_DEFAULT_REGION']

    #findings_raw = os.popen(f'aws securityhub get-findings --filters {filterstr} --sort-criteria {sortcriteria} --page-size 100 --max-items 100000')
    findings_raw = os.popen(f'aws securityhub get-findings --filters {filterstr} --page-size 100 --max-items 100000')
    findings_json = json.loads(findings_raw.read())['Findings']

    findings: List[Finding] = []
    for f in findings_json:
        finding = Finding()
        finding.environment = environment
        finding.region = region
        finding.account_id = f['AwsAccountId']
        finding.created_at = f['CreatedAt']
        finding.updated_at = f['UpdatedAt']
        finding.compliance_status = f["Compliance"]["Status"] if ("Compliance" in f.keys()) else ''
        finding.title = f["Title"]
        finding.description = f["Description"]
        finding.productname = f["ProductName"]
        finding.controlid = f["ProductFields"]["ControlId"] if ("ProductFields" in f.keys() and "ControlId" in f["ProductFields"].keys()) else ''
        finding.baseimage = f["ProductFields"]["aws/inspector/resources/1/resourceDetails/awsEcrContainerImageDetails/platform"] if ("ProductFields" in f.keys() and "aws/inspector/resources/1/resourceDetails/awsEcrContainerImageDetails/platform" in f["ProductFields"].keys()) else ''
        finding.recommendation_text = f["Remediation"]["Recommendation"]["Text"] if ("Remediation" in f.keys()) else ''
        finding.recommendation_url = f["Remediation"]["Recommendation"]["Url"] if ("Remediation" in f.keys() and "Url" in f["Remediation"]["Recommendation"].keys()) else ''
        finding.workflow_state = f["WorkflowState"]
        finding.workflow_status = f["Workflow"]["Status"]
        finding.record_state = f["RecordState"]
        finding.severity_label = f["FindingProviderFields"]["Severity"]["Label"]
        finding.resource_type = str(f["Resources"][0]["Type"])
        finding.resource_id = str(f["Resources"][0]["Id"])
        finding.resource_details = str(f["Resources"][0]["Details"] if ("Details" in f["Resources"][0].keys()) else '')
        finding.ecrrepositoryname = str(f["Resources"][0]["Details"]["AwsEcrContainerImage"]["RepositoryName"] if ("Details" in f["Resources"][0].keys() and "AwsEcrContainerImage" in f["Resources"][0]["Details"].keys()) else '')

        findings.append(finding)

    return findings

def create_valid_html(findings: List[Finding],findingtype: str):
    '''
        Creates a html report from the given findings
    '''

    file = open(f'security_findings_{datetime.now().strftime("%Y%m%d-%H%M%S")}_{findingtype}.html','w')
    file2 = open(f'security_findings_{datetime.now().strftime("%Y%m%d-%H%M%S")}_{findingtype}.csv','w')
    csv = ''
    html = '''
        <html>
        <head>
            <style>
                body, html {
                    font-family: Arial, sans-serif;
                    font-size: 0.9em;
                }
                table {
                    width: 100%;
                    font-size: 0.4em;
                }
                table tr th {
                    background-color: whitesmoke;
                }
                table, td, th {
                    border:1px solid black;
                    border-collapse: collapse;
                }
                td, th {
                    padding: 5px;
                }
            </style>
        </head>
        <body>
            <h1>Security Findings<h1>
            <table>
    '''

    if (len(findings) > 0):
        html += '<tr>'
        html += '<th>index</th>'
        csv += 'index,'
        for key, value in findings[0]:
            html += f'<th>{key}</th>'
            csv += f'{key},'
        html += '</tr>'
        csv += f'\n'

    index = 0
    for finding in findings:
        html += f'<tr style="background-color: {"#ffcfcc" if finding.severity_label == "HIGH" else "#F492B8" if finding.severity_label == "CRITICAL" else "none"}">'
        html += f'<td>{index}</td>'
        csv += f'{index},'
        for key, value in finding:
            html += f'<td>{value}</td>'

            newvalue = value.replace(","," ")
            newvalue = newvalue.replace('"',' ')
            newvalue = newvalue.replace('\n',' ')
            newvalue = newvalue.replace('\r',' ')
            csv += f'"{newvalue}",'
        html += '</tr>'
        csv += f'\n'
        index += 1

    html += '</table></body></html>'

    file.write(html)
    file.close()
    file2.write(csv)
    file2.close()

if __name__ == '__main__':
    '''
        Fetches all security findings that follow a certain filter criteria.
        The script is executed on the locally configered AWS environments and requires that awssso was run before.

        https://docs.aws.amazon.com/cli/latest/reference/securityhub/get-findings.html
    '''
    settings = None


    ## PROCESS CRITICAL

    with open('settings_critical.yaml', 'r') as stream:
        settings = yaml.safe_load(stream)

    # fetch environments and build filters and sorting criteria
    environments = settings['accounts']
    filterstr = '\'{' + ','.join(f'"{x["filter_name"]}": [{{"Value": "{x["value"]}", "Comparison": "{x["comparison"]}"}}]' for x in settings['filters'])+ '}\''
    sortcriteria = ''

    print(F' Settings : {filterstr}')
    # fetch all findings and create a html report
    findings = [finding for env in environments for finding in fetch_findings(environment=env, filterstr=filterstr, sortcriteria=sortcriteria)]
    create_valid_html(findings=findings,findingtype="critical")

    print(f'Finished, Found: {len(findings)} CRITICAL finding(s)')

    ## PROCESS HIGH

    with open('settings_high.yaml', 'r') as stream:
        settings = yaml.safe_load(stream)

    # fetch environments and build filters and sorting criteria
    environments = settings['accounts']
    filterstr = '\'{' + ','.join(f'"{x["filter_name"]}": [{{"Value": "{x["value"]}", "Comparison": "{x["comparison"]}"}}]' for x in settings['filters'])+ '}\''
    # sortcriteria = f'\'{{"Field": "{settings["sort_criteria"]["field"]}", "SortOrder": "{settings["sort_criteria"]["sort_order"]}"}}\''
    sortcriteria = ''

    print(F' Settings : {filterstr}')
    # fetch all findings and create a html report
    findings = [finding for env in environments for finding in fetch_findings(environment=env, filterstr=filterstr, sortcriteria=sortcriteria)]
    create_valid_html(findings=findings,findingtype="high")

    print(f'Finished, Found: {len(findings)} HIGH finding(s)')
    

 