# Module 3 - Analytics Rule

#### 🎓 Level: 200 (Intermediate)
#### ⌛ Estimated time to complete this lab: 30 minutes

## Objectives

This exercise guides you through the Analytics Rule part in Azure Sentinel, and shows you how to create diffrent type of rules (Security Detections)

#### Prerequisites

To get started with Azure Sentinel, you must have a subscription to Microsoft Azure. If you do not have a subscription, you can sign up for a free account.

### Exercise 1: Overview of the Azure Sentinel Analytics Rule
1. Open your newly created Azure sentinel instance.
2. On the left menu navigate to analytics and select **Rule template** section
3. Review the analytics rules templates that ship with the product.
4. On the analytics rule filter select **Data sources** and check **security Event**, review all the analytic rules on the above data source.
	
![Select Security Events](../Images/m3-securityEvent01.gif?raw=true)

5. In the rule search bar type  **Rare RDP Connections** for the rule name.
6. To review the rule logic and possible configuration options, in the right lower corner press **create rule** 
7. Review the rule defintion like tactics and severity.
8. Press **Next: Set rule logic** in the bottom of the page 
9. in the rule logic screen, you have the ability to create or modify the rule KQL query, control of the entity mapping and define the scheduling and lookback time range.
10. After you reviewwd the rule configuration options, close this page and navigate back to the main azure sentinel Overview screen 

### Exercise 2: Enable Azure Sentinel Microsoft incident creation rule

Azure Sentinel is a cloud-native SIEM and one of the main use cases is to act as  single pane of glass, for alerts and event correlation. 
For this purpose, and to be able to ingest and surafce Alewrts from Microsoft Security Product Alerts, we create t he we have the **Microsoft incident creation rule**
In this exercise, we will review this feature and create one example rule twith a filtring option to help the analyst deal with alert fatigue.

1. In Azure Sentinel main page press on the **Analytics** section.
2. In the top bar press on **+Create** and select **Microsoft incident creation rule**

![Select Microsoft incident creation rule](../Images/m3-microsoft-creation-rule.gif?raw=true)

3. in the rule name enter **"Azure Defender only medium and high Alerts"** 
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

### Exercise 3: Create Azure sentinel custom analytics rule

You Security Risk consult notify this online thread https://www.reddit.com/r/sysadmin/comments/7kyp0a/recent_phishing_attempts_my_experience_and_what/
Base on the attack vector and the organization risk he recommend you to create detection rule for this malicious activity.
In this exercise you will use Azure sentinel analytics rule wizard to create new detection.

1. Review the article in the above link and understand what is the data source that will be part of the detection.
2. Check if this operation are capture as part of your collection strategy:
- In the left menu press on the **Logs** and navigate to the search canvas

**important note: in this lab we are using custom logs that replace the Out-off-the-box tables** 

- Run the above search query to see the list of operation Azure sentinel cupture in the last 24hr 
	
    ```powershell
	OfficeActivity_CL
	| distinct Operation_s
    ```
- As you can see the **New-Mailbox** operation is indeed captures in your index.

3. In the analytics rule page,  in the top bar press on **+Create** and select  **scheduled query Rule**
4. In this screen we will add general information regarding this rule 
5. In the **Name** type **Malicious Inbox Rule - custom**
6. In the rule **Description** type **This rule is detecting on delete all traces of phishing email from user mailboxes**
7. In the **Tactics** select **Persistence** and **Defense Evasion**
8. In the rule **severity**  select **medium**
9. Press **Next: SET rule logic**
10. In the **Rule logic** page, review and copy the above query

 ```powershell
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
  ```

11. To view ahead your incident creation prediction, check the right side press the **Test with current data** and see the number of hits.
12. Under the **Alert enrichment (Preview)**, under entity mapping section we will need to map our filed to well-known buckets
	- In the **Entity type** open the supported list of entities and select **Account** in the identifier select **FullName** and map it to **UserId__s**
	- Press **+ Add new entity** and this time select **Host** entity in the identifier select **FullName** and map it to **OriginatingServer_s**
	- Select  **Address** and map it to **ClientIPAddress** value.

Your mapping should look like the above:
	
![entity mapping](../Images/m3-entity01.gif?raw=true)

To be to make you SOC more productive, save analyst time and affectively triage newly created incidents, your SOC analyst ask you to add the effected user in the alert title.

3. For applying this request, we will need to use the **Alert details** feature and create custom **alert Name Format**

- In the **Alert Name Format copy the above dynamic title **"Malicious Inbox Rule, affected user {{UserId__s}}"**

4. In the **Query scheduling** set the **run query every** to **5 minutes** and the **Lookup data to last 12 Hours** (This scheduling are not ideal for production environment and should be tune.
5. In the **Suppression** leave it on **Off**
6. Press the **Next:Incident settings(Preview)** 
7. As our SOC is under stuff and we will need to reduce the number of alerts and be sure that when analyst handle on specific incident He will see all related events or other incidents related to the same attack story, we  will **implement Alert grouping** feature: 
	
- In the **Incident settings (Preview)** under **Alert grouping** change it to **Enabled**
- Modify the **Limit the group to alerts created within the selected time frame** to **12 hours**
- Select the **Grouping alerts into a single incident if the selected entity types and details matches** and select the Account
8. Press the **Next: Automated response** and also press **Next:Review** and create this newly analytics rule


 




