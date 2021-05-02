# Module 3 - Analytics Rule

#### 🎓 Level: 200 (Intermediate)
#### ⌛ Estimated time to complete this lab: 30 minutes

## Objectives

This exercise guides you through the Analytics Rule part in Azure Sentinel, and shows you How to create diffrent type of rules(Security Detections)

#### Prerequisites

To get started with Azure Sentinel, you must have a subscription to Microsoft Azure. If you do not have a subscription, you can sign up for a free account.

### Exercise 1: Understanding Azure Sentinel Analytics Rule


m3-securityEvent01.gif

c.	Create custom rule:
i.	This rule will use pre-ingested data to custom logs
ii.	Will go through all steps. Basics, KQL query, mapping entities, scheduling, attach playbook 
iii.	We will provide the query for the analytic rule, so it triggers immediately
The rule name can be “Malicious Inbox Rule”

The query:
let Keywords = dynamic(["helpdesk", " alert", " suspicious", "fake", "malicious", "phishing", "spam", "do not click", "do not open", "hijacked", "Fatal"]);
OfficeActivity_CL
| where Operation_s =~ "New-InboxRule"
| where Parameters_s has "Deleted Items" or Parameters_s has "Junk Email" 
| extend Events=todynamic(Parameters_s)
| parse Events  with * "SubjectContainsWords" SubjectContainsWords '}'*
| parse Events  with * "BodyContainsWords" BodyContainsWords '}'*
| parse Events  with * "SubjectOrBodyContainsWords" SubjectOrBodyContainsWords '}'*
| where SubjectContainsWords has_any (Keywords)
or BodyContainsWords has_any (Keywords)
or SubjectOrBodyContainsWords has_any (Keywords)
| extend ClientIPAddress = case( ClientIP_s has ".", tostring(split(ClientIP_s,":")[0]), ClientIP_s has "[", tostring(trim_start(@'[[]',tostring(split(ClientIP_s,"]")[0]))), ClientIP_s )
| extend Keyword = iff(isnotempty(SubjectContainsWords), SubjectContainsWords, (iff(isnotempty(BodyContainsWords),BodyContainsWords,SubjectOrBodyContainsWords )))
| extend RuleDetail = case(OfficeObjectId_s contains '/' , tostring(split(OfficeObjectId_s, '/')[-1]) , tostring(split(OfficeObjectId_s, '\\')[-1]))
| summarize count(), StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated) by  Operation_s, UserId__s, ClientIPAddress, ResultStatus_s, Keyword, OriginatingServer_s, OfficeObjectId_s, RuleDetail
| extend timestamp = StartTimeUtc,  IPCustomEntity = ClientIPAddress, AccountCustomEntity = UserId__s, HostCustomEntity =  OriginatingServer_s

Mapping 

 

We can add dynamic title (currently under feature flag ) Malicious Inbox Rule in  {{AccountCustomEntity}} mailbox
Malicious Inbox Rule in  {{AccountCustomEntity}} mailbox

 
Scheduling:
Run every 5 min
Lookback 24hr

Suppression:
Stop running after alert is generated: ON

Incident should look:
 




