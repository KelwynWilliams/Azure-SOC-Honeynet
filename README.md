# Building a SOC + Honeynet in Azure (Live Traffic)
![Cloud Honeynet / SOC](https://i.imgur.com/ZWxe03e.jpg)

## Introduction

In this project, I build a mini honeynet in Azure and ingest log sources from various resources into a Log Analytics workspace, which is then used by Microsoft Sentinel to build attack maps, trigger alerts, and create incidents. I measured some security metrics in the insecure environment for 24 hours, apply some security controls to harden the environment, measure metrics for another 24 hours, then show the results below. The metrics we will show are:

- SecurityEvent (Windows Event Logs)
- Syslog (Linux Event Logs)
- SecurityAlert (Log Analytics Alerts Triggered)
- SecurityIncident (Incidents created by Sentinel)
- AzureNetworkAnalytics_CL (Malicious Flows allowed into our honeynet)



## Architecture Before Hardening / Security Controls
![Architecture Diagram](https://i.imgur.com/aBDwnKb.jpg)

## Architecture After Hardening / Security Controls
![Architecture Diagram](https://i.imgur.com/YQNa9Pp.jpg)

The architecture of the mini honeynet in Azure consists of the following components:

- Virtual Network (VNet)
- Network Security Group (NSG)
- Virtual Machines (2 windows, 1 linux)
- Log Analytics Workspace
- Azure Key Vault
- Azure Storage Account
- Microsoft Sentinel

For the "BEFORE" metrics, all resources were originally deployed, exposed to the internet. The Virtual Machines had both their Network Security Groups and built-in firewalls wide open, and all other resources are deployed with public endpoints visible to the Internet; aka, no use for Private Endpoints.

For the "AFTER" metrics, Network Security Groups were hardened by blocking ALL traffic with the exception of my admin workstation, and all other resources were protected by their built-in firewalls as well as Private Endpoint

Let's start by configuring the resources we will need for our Honeynet

## Configuring our Honeynet Resources
1. Create a Resource Group
```Bash
az group create --name Honeynet-RG --location eastus
```

2. Create a Virtual Network and Subnet
```Bash
az network vnet create \
  --resource-group Honeynet-RG \
  --name Honeynet-VNet \
  --address-prefix 10.0.0.0/16 \
  --subnet-name Honeynet-Subnet \
  --subnet-prefix 10.0.0.0/24
```

3. Create a Public IP Address
```Bash
az network public-ip create \
  --resource-group Honeynet-RG \
  --name Honeynet-PublicIP
```

4. Create a Network Security Group (NSG) to Allow all Inbound Traffic via the Internet

We are creating this NSG to allow all inbound traffic to our Virtual Machines, making our Honeynet environment enticing to attackers/hackers. not to worry will be replaced with a hardened NSG later on in our project.

4.1. Create NSG Instance
```Bash
az network nsg create \
  --resource-group Honeynet-RG \
  --name Honeynet-NSG
```
4.2. Create NSG Rule to Allow All Inbound Traffic
```Bash
az network nsg rule create \
  --resource-group Honeynet-RG \
  --nsg-name Honeynet-NSG \
  --name DANGER_AllowAnyInbound \
  --priority 100 \
  --direction Inbound \
  --access Allow \
  --protocol ‘*’ \
  --source-address-prefix ‘*’ \
  --source-port-range ‘*’ \
  --destination-address-prefix ‘*’ \
  --destination-port-range ‘*’
```

5. Configure the Windows VM 

5.1. Create Windows VM
Here, we use a Windows 10 image for the VM.
```Bash
az vm create \
  --resource-group Honeynet-RG \
  --name Windows-VM \
  --vnet-name Honeynet-VNet \
  --subnet Honeynet-Subnet \
  --image MicrosoftWindowsDesktop:Windows-10:win10-21h2-pro:latest \
  --admin-username <username> \
  --admin-password <password>
```

5.2. Identify the NIC Associated with the Windows VM

We will need to know the VM's Network Interface Card (NIC) in order to associate the Open Honeynet NSG to the VM
```Bash
az vm show \
  --resource-group Honeynet-RG \
  --name Windows-VM \
  --query “networkProfile.networkInterfaces[0].id” \
  --output tsv
```

5.3. Apply the NSG to the NIC

Use the az network nic update command to associate the NSG with the Windows NIC
```Bash
az network nic update \
  --resource-group Honeynet-RG \
  --name <WindowsVMNIC> \
  --network-security-group Honeynet-NSG
```
**Parameters:**
  --name: Replace <WindowsVMNIC> with the name of the VM's NIC you discovered earlier

  

## Attack Maps Before Hardening / Security Controls
![NSG Allowed Inbound Malicious Flows](https://i.imgur.com/1qvswSX.png)<br>
![Linux Syslog Auth Failures](https://i.imgur.com/G1YgZt6.png)<br>
![Windows RDP/SMB Auth Failures](https://i.imgur.com/ESr9Dlv.png)<br>

## Metrics Before Hardening / Security Controls

The following table shows the metrics we measured in our insecure environment for 24 hours:
Start Time 2023-03-15 17:04:29
Stop Time 2023-03-16 17:04:29

| Metric                   | Count
| ------------------------ | -----
| SecurityEvent            | 19470
| Syslog                   | 3028
| SecurityAlert            | 10
| SecurityIncident         | 348
| AzureNetworkAnalytics_CL | 843

## Attack Maps Before Hardening / Security Controls

```All map queries actually returned no results due to no instances of malicious activity for the 24 hour period after hardening.```

## Metrics After Hardening / Security Controls

The following table shows the metrics we measured in our environment for another 24 hours, but after we have applied security controls:
Start Time 2023-03-18 15:37
Stop Time	2023-03-19 15:37

| Metric                   | Count
| ------------------------ | -----
| SecurityEvent            | 8778
| Syslog                   | 25
| SecurityAlert            | 0
| SecurityIncident         | 0
| AzureNetworkAnalytics_CL | 0

## Conclusion

In this project, a mini honeynet was constructed in Microsoft Azure and log sources were integrated into a Log Analytics workspace. Microsoft Sentinel was employed to trigger alerts and create incidents based on the ingested logs. Additionally, metrics were measured in the insecure environment before security controls were applied, and then again after implementing security measures. It is noteworthy that the number of security events and incidents were drastically reduced after the security controls were applied, demonstrating their effectiveness.

It is worth noting that if the resources within the network were heavily utilized by regular users, it is likely that more security events and alerts may have been generated within the 24-hour period following the implementation of the security controls.
