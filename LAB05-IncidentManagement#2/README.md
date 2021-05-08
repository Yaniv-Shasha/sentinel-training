# Module 5 - SOC Analyst track - Incident Managment 2 

#### 🎓 Level: 200 (Intermediate)
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

4. as we are the SOC analyst that expert on forud ticket, we need to take ownership on this incident.
on the right page change the unassigned to "Assign to me" and also change the status from New to active 
 
![Select Microsoft incident creation rule](../Images/m5-assigen_ticket.gif?raw=true)

5. Another way to consume incidents and also get high level view on the general SOC health is through the Security Operations Efficiency Workbook(we will have separated module on workbook)

b.	Navigate to full details and execute playbook to bring Geo IP data (user will notice tags being added). IP should be public IP.
c.	Move to Workbooks and save the Investigation Insights workbook 
d.	Use entity investigation and add IP address from incident
e.	This should show many successful logins from this IP and a known user email, but also some failed logins to disabled account from last day/hours 
f.	Call/email user and confirm that this is part of red team exercise
g.	Go back to incident queue and create automation rule from incident view to automatically close similar incidents for the affected IP address during the timeframe the red team exercise is active

