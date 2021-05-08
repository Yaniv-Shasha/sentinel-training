# Module 5 - SOC Analyst track - Incident Managment 2 

#### 🎓 Level: 300 (Intermediate)
#### ⌛ Estimated time to complete this lab: 40 minutes

This exercise guides you through the SOC Analyst objects and Rule and train you how to use Azure sentinel tools and features in an incident response drill.

#### Prerequisites
This module relay on completing LAB01-Setup part, as the data and the artifacts that we will be using in this module need to be deployed on your sentinel instance.

### Exercise 1: Review Azure Sentinel incident tools and capabilities
As a SOC analyst the entry point to consume Security incidents(tickets) in Sentinel is the Incident page.
1.  in the left navigation menu press on the incident and open the incident page.
this page will show by default all the open incident in the last 24hr.
2. When we want to change the time window, present only incident from specific severity or to see also closed incident, we can use the filters bar


![Select Microsoft incident creation rule](../Images/m5-incident-filter.gif?raw=true)

3. On the incident page select the "Model Evasion in Critical ML model" incident.
in the right pane you can see the incident preview with the high level information on the incident. 

4.As you are the SME SOC analyst that deal and investigate fraud tickets, you need to take ownership on this incident.
on the right page change the unassigned to "Assign to me" and also change the status from New to active.
 
![Select Microsoft incident creation rule](../Images/m5-assigen_ticket.gif?raw=true)

5. Another way to consume incidents and also get high level view on the general SOC health is through the Security Operations Efficiency Workbook(we will have separated module on workbook)

we have 2 opetion to open the workbook:

- Through the top navigation, this will open the workbook general view, we overall statistics on the incidents.

![Select Microsoft incident creation rule](../Images/m5-SecurityOperationsEfficiency.gif?raw=true)

- Through the incident itself, that will open the same workbook on a different tab, and present the information and lifecycle for the given incident. 

![Select Microsoft incident creation rule](../Images/m5-SecurityOperationsEfficiency_incident.gif?raw=true)

6. Review the dashbaord.

### Exercise 2: handling Incident **"Sign-ins from IPs that attempt sign-ins to disabled accounts"**

1. Open Azure Aentiel incident page.
2. Locate the incident **"Sign-ins from IPs that attempt sign-ins to disabled accounts"**
3. Press on the incident and look on the right pane for the incident preview, please notcie that in this pane we are surfcing the incident eneities that belong this incident.
4. Take ownership on the incident and change its status to **Active**
5. Navigate to incidsrnt full details by pressing **View full details** and execute playbook to bring Geo IP data (user will notice tags being added). IP should be public IP.
6. navigate to the **Alerts** tab and press the number of **Events** this action will redirect you to Raw logs that will present the alert evidence to support the investigation 

![Select Microsoft incident creation rule](../Images/m5-select_events.gif?raw=true)

7. In raw log search, expend the received event and review the column and data we received, this properties will help us to decide if this incident is correlated to other events.

![Select Microsoft incident creation rule](../Images/m5-evidence.gif?raw=true)

8. To get more context for this IP, we want to add GEO IP enrichment.
in a real life SOC this operation will run automatically, but for this lab we want you to run it manually.
 - Navigate back to the incident full page to the alert tab and scroll to the right

![Select Microsoft incident creation rule](../Images/m5-NAV_incident.gif?raw=true)

- To view the relevant automation that will assist us with the enrichment opertion, Press **view playbook**

![Select Microsoft incident creation rule](../Images/m5-view_playbooks.gif?raw=true)

9. Locate the playbook **Get-GeoFromIpAndTagIncident** and press **Run**, If the playbook cofigiured curectlly its should finiesh in cupple of secands.

10. Navigate back to the main incident page and notice to new tags that added to the incident.

![Select Microsoft incident creation rule](../Images/m5-tags-incident?raw=true)

** **Bonus** : Open the resource group for Sentinel deployment, locate the playbook and look on the last playbook run to review the execution steps.

11. As this enrichment informaiton add your concern, you want to check what elase this IP doing in your network, for this investigation you want to use the investigation workbook.
12. In the left navigation press **Workbooks** and select **MY Workbooks** 

![Select Microsoft incident creation rule](../Images/m5-my-workbooks?raw=true)

13. To open the **Investigation Insights - sentinel-training-ws** saved Workbook, in the right page press **View saved workbook**
14. validate that in the properties selector, your worksapce is set on **sentinel-training-ws** and the subscription is the sub that hoest azure sentinel Lab.

![Select Microsoft incident creation rule](../Images/m5-workbook-validator?raw=true)




c.	Move to Workbooks and save the Investigation Insights workbook 
d.	Use entity investigation and add IP address from incident
e.	This should show many successful logins from this IP and a known user email, but also some failed logins to disabled account from last day/hours 
f.	Call/email user and confirm that this is part of red team exercise
g.	Go back to incident queue and create automation rule from incident view to automatically close similar incidents for the affected IP address during the timeframe the red team exercise is active

