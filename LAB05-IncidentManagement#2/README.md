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

a.	Open Azure Aentiel incident page.
b.	Locate the incident **"Sign-ins from IPs that attempt sign-ins to disabled accounts"**
c.  Press on the incident and look on the right pane for the incident preview, please notcie that in this pane we are surfcing the incident eneities that belong this incident.
d. Take ownership on the incident and change its status to **Active**
e. Navigate to incidsrnt full details by pressing **View full details** and execute playbook to bring Geo IP data (user will notice tags being added). IP should be public IP.
f. navigate to the **Alerts** tab and press the number of **Events** this action will redirect you to Raw logs that will present the alert evidence to support the investigation 

![Select Microsoft incident creation rule](../Images/m5-select_events.gif?raw=true)


c.	Move to Workbooks and save the Investigation Insights workbook 
d.	Use entity investigation and add IP address from incident
e.	This should show many successful logins from this IP and a known user email, but also some failed logins to disabled account from last day/hours 
f.	Call/email user and confirm that this is part of red team exercise
g.	Go back to incident queue and create automation rule from incident view to automatically close similar incidents for the affected IP address during the timeframe the red team exercise is active

