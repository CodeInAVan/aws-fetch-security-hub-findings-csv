import os
import json
import yaml
from datetime import datetime
from pydantic import BaseModel
from typing import List

class Finding(BaseModel):

    FindingId: str = ''
    CreatedAt: str = ''
    UpdatedAt: str = ''
    FirstObservedAt: str = ''
    LastObservedAt: str = ''
    AccountId: str = ''
    AccountName: str = ''
    Region: str = ''
    Product: str = ''
    Resource: str = ''
    Control: str =''
    Controlid: str = ''
    Title: str = ''
    Description: str = ''
    Severity: str = ''
    Status: str = ''
    Workflow_Status: str = ''
    Record_State: str = ''
    Remediation: str = ''



def fetch_findings(environment: str, filterstr: str, sortcriteria: str, accountName: str) -> List[Finding]:
    '''
        Fetches the findings from a given aws account following a certain filter and sorting criteria
    '''
    region = os.environ.get('AWS_DEFAULT_REGION')
    if not region:
        region='eu-central-1'

    os.environ['AWS_PROFILE'] = environment

    #print(f'aws securityhub get-findings --filters {filterstr} --page-size 100 --max-items 9999999 --region {region}')

    findings_raw = os.popen(f'aws securityhub get-findings --filters {filterstr} --page-size 100 --max-items 9999999 --region {region}')
    findings_json = json.loads(findings_raw.read())['Findings']

    findings: List[Finding] = []
    for f in findings_json:
        finding = Finding()
     
        finding.FindingId = f['Id']
        finding.Region = f['Region']
        finding.AccountId = f['AwsAccountId']
        finding.AccountName = accountName
        finding.CreatedAt = f['CreatedAt'] 
        finding.UpdatedAt = f['UpdatedAt']
        finding.FirstObservedAt = f["FirstObservedAt"] if ("FirstObservedAt" in f.keys()) else ''
        finding.LastObservedAt = f["LastObservedAt"] if ("LastObservedAt" in f.keys()) else ''
        finding.Status = f["Compliance"]["Status"] if ("Compliance" in f.keys()) else ''
        finding.Title = f["Title"]
        finding.Description = f["Description"]
        finding.Product = f["ProductName"]
        finding.Control = f["ProductFields"]["aws/config/ConfigRuleName"] if ("ProductFields" in f.keys() and "aws/config/ConfigRuleName" in f["ProductFields"].keys()) else f["GeneratorId"]
        finding.Controlid = f["ProductFields"]["ControlId"] if ("ProductFields" in f.keys() and "ControlId" in f["ProductFields"].keys()) else ''
        finding.Remediation = f["Remediation"]["Recommendation"]["Url"] if ("Remediation" in f.keys() and "Url" in f["Remediation"]["Recommendation"].keys()) else ''
        finding.Workflow_Status = f["Workflow"]["Status"]
        finding.Record_State = f["RecordState"]
        finding.Severity = f["FindingProviderFields"]["Severity"]["Label"]
        finding.Resource = str(f["Resources"][0]["Id"])
        
        findings.append(finding)

    return findings

def create_valid_html(findings: List[Finding],findingtype: str):
    '''
        Creates a html report from the given findings
    '''

    #file = open(f'security_findings_{datetime.now().strftime("%Y%m%d-%H%M%S")}_{findingtype}.html','w')
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
        html += f'<tr style="background-color: {"#ffcfcc" if finding.Severity == "HIGH" else "#F492B8" if finding.Severity == "CRITICAL" else "none"}">'
        html += f'<td>{index}</td>'
        csv += f'{index},'
        for key, value in finding:
            html += f'<td>{value}</td>'

            newvalue = value.replace(","," ")
            newvalue = newvalue.replace('"',' ')
            newvalue = newvalue.replace('\n',' ')
            newvalue = newvalue.replace('\r',' ')
            csv += f'{newvalue},'
        html += '</tr>'
        csv += f'\n'
        index += 1

    html += '</table></body></html>'

    # file.write(html)
    # file.close()
    file2.write(csv)
    file2.close()

if __name__ == '__main__':
    '''
        Fetches all security findings that follow a certain filter criteria.
        The script is executed on the locally configered AWS environments and requires that awssso was run before.

        https://docs.aws.amazon.com/cli/latest/reference/securityhub/get-findings.html
    '''
    settings = None

    if len(os.sys.argv[1]) > 1:
        accountName=os.sys.argv[1]
    else:
        accountName=''


    ## PROCESS CRITICAL

    with open('settings_config.yaml', 'r') as stream:
        settings = yaml.safe_load(stream)

    # fetch environments and build filters and sorting criteria
    environments = settings['accounts']
    filterstr = '\'{' + ','.join(f'"{x["filter_name"]}": [{{"Value": "{x["value"]}", "Comparison": "{x["comparison"]}"}}]' for x in settings['filters'])+ '}\''
    sortcriteria = ''

    #print(F' Settings : {filterstr}')
    # fetch all findings and create a html report
    findings = [finding for env in environments for finding in fetch_findings(environment=env, filterstr=filterstr, sortcriteria=sortcriteria, accountName=accountName)]
    create_valid_html(findings=findings,findingtype="config")

    print(f'Finished, Found: {len(findings)} CONFIG finding(s)')

    ## PROCESS HIGH

    with open('settings_sechub.yaml', 'r') as stream:
        settings = yaml.safe_load(stream)

    # fetch environments and build filters and sorting criteria
    environments = settings['accounts']
    filterstr = '\'{' + ','.join(f'"{x["filter_name"]}": [{{"Value": "{x["value"]}", "Comparison": "{x["comparison"]}"}}]' for x in settings['filters'])+ '}\''
    # sortcriteria = f'\'{{"Field": "{settings["sort_criteria"]["field"]}", "SortOrder": "{settings["sort_criteria"]["sort_order"]}"}}\''
    sortcriteria = ''

    #print(F' Settings : {filterstr}')
    # fetch all findings and create a html report
    findings = [finding for env in environments for finding in fetch_findings(environment=env, filterstr=filterstr, sortcriteria=sortcriteria, accountName=accountName)]
    create_valid_html(findings=findings,findingtype="SecurityHub")

    print(f'Finished, Found: {len(findings)} SecurityHub finding(s)')
    

 