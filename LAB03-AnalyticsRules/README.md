# Module 3 - Analytics Rule

#### 🎓 Level: 200 (Intermediate)
#### ⌛ Estimated time to complete this lab: 30 minutes

## Objectives

This exercise guides you through the Analytics Rule part in Azure Sentinel, and shows you How to create diffrent type of rules(Security Detections)

#### Prerequisites

To get started with Azure Sentinel, you must have a subscription to Microsoft Azure. If you do not have a subscription, you can sign up for a free account.

### Exercise 1: Overview of the Azure Sentinel Analytics Rule
1. Open your newly created Azure sentinel instance.
2. Navigate to analytics on the left menu and select **Rule template** section
3. Review the analytics rules templates that ship with the product.
4. On the analytics rule filterת select Data sources and check security Event, review all the analytics rule that apply on this data source
	
![Select Security Events](../Images/m3-securityEvent01.gif?raw=true)

5. in the Rule search bar search for **Rare RDP Connections** rule name.
6. To review the rule logic and possible configuration options, in the right lower corner press **create rule** 
7. Review the mapping tactics and severity, please notice that this open are configurable and you can align it to your organization requirement.
8. Press 88Nexr: Set rule logic** in the button of the page 
9. This is the rule logic screen, in this screen you are able to see and modify the rule KQL query, control of the entity mapping and define the scheduling and lookback time range.
10. Close this page and navigate back to the main azure sentinel Overview screen 

### Exercise 2: Enable Azure Sentinel Microsoft incident creation rule

Azure Sentinel is a cloud-native SIEM and part of the main use cases on SIEM besides event correlation is to act as the single pane of glass.
For this purpose, we have the Microsoft incident creation rule to be able to ingest Microsoft Security Product Alerts.
in this exercise, we will review this feature and create one example rule that will use the reach filtring option to help the analyst to deal with alert fatigue.

1. In Azure Sentinel main page press on the **Analytics** section.
2. In the top bar press on **+Create** and select **Microsoft incident creation rule**

![Select Microsoft incident creation rule](../Images/m3-microsoft-creation-rule.gif?raw=true)

3. in the rule name enter **Azure Defender only medium and high Alerts** 
4. in the **Microsoft security service** dropdown select **Azure Defender**
5. in the **Filter by severity** select **custom** and mark **High** and **Medium**

![Azure Defender Filter by severity](../Images/m3-microsoft-creation-rule02.gif?raw=true)

6. Press **Next: Automated response**
7. please notice that in the above Automated response page you can attached automation rule that will generate some automation tasks that can assist your SOC with repetitive tasks, or Security remediation. More in this topic in the SOAR module. 
8. Press **Next: Review** and **create** in the next page.

![review the azure defender rule](../Images/m3-microsoft-creation-rule03.gif?raw=true)

### Exercise 3: Review Azure Sentinel Fusion Rule (Advanced Multistage Attack Detection)

Fusion rule is a unique kind of detection rule, with fusion rule 
Azure Sentinel can automatically detect multistage attacks by identifying combinations of anomalous behaviors and suspicious activities That are observed at various stages of the kill-chain

In this exercise we will learn how to distinguish and enable fusion rule  in Azure Sentinel.

1. In the analytics page rule template tab, use the **Rule Type** filter and select **Fusion**

![Select fustion data source](../Images/m3-fusion01.gif?raw=true)

	2. In the template screen notice the tag **IN USE** as this rule is the only rule that enabled by default.
	3. Press the rule and review the rule data sources in the right pane 

![fusion description](../Images/m3-fusion02.gif?raw=true)


As fusion rules produce security incident with high fidelity and its hard to simulate it, we are adding here example for an fusion incident 

In the above example we are seeing 2 low severity alerts from **Azure Active Directory Identity Protection** and **Microsoft Cloud App Security** that together stich into high severity incidence 

![fustion alert story](../Images/m3-fusion03.gif?raw=true)

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
 




