# Building a SOC + Honeynet in Azure (Live Traffic)
![Cloud Honeynet / SOC](https://github.com/CyberJayByDay/Azure-Honeynet/assets/168309573/6bb62f4a-d431-4252-a145-88e2f99e72a4)

## Introduction

In this project, I build a mini honeynet in Azure and ingest log sources from various resources into a Log Analytics workspace, which is then used by Microsoft Sentinel to build attack maps, trigger alerts, and create incidents. I measured some security metrics in the insecure environment for 24 hours, apply some security controls to harden the environment, measure metrics for another 24 hours, then show the results below. The metrics we will show are:

- SecurityEvent (Windows Event Logs)
- Syslog (Linux Event Logs)
- SecurityAlert (Log Analytics Alerts Triggered)
- SecurityIncident (Incidents created by Sentinel)
- AzureNetworkAnalytics_CL (Malicious Flows allowed into our honeynet)

## Architecture Before Hardening / Security Controls
![SocBeforeHardening](https://github.com/CyberJayByDay/Azure-Honeynet/assets/168309573/8206d541-7cc5-4925-9631-2b7b05836f0a)

## Architecture After Hardening / Security Controls
![SOCAfterHardening](https://github.com/CyberJayByDay/Azure-Honeynet/assets/168309573/339f56f9-8743-44a7-8a9f-3e4e51c2b4d3)

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

## Attack Maps Before Hardening / Security Controls
![Before-NsgMaliciousAllowedIn](https://github.com/CyberJayByDay/Azure-Honeynet/assets/168309573/c4ff5857-d1f6-4691-ab32-3858d7d8e0ca)<br>
![Before-LinusSshAuthFail](https://github.com/CyberJayByDay/Azure-Honeynet/assets/168309573/a81e5021-afc4-4e66-873a-415f9dcc7025)<br>
![Before-WindowsRdpAuthFail](https://github.com/CyberJayByDay/Azure-Honeynet/assets/168309573/66942376-4f38-4511-a635-77bf29302275)<br>

## Metrics Before Hardening / Security Controls

The following table shows the metrics we measured in our insecure environment for 24 hours:
Start Time 2024-04-23 20:50:08
Stop Time 2024-04-24 20:50:08

| Metric                   | Count
| ------------------------ | -----
| SecurityEvent            | 12021
| Syslog                   | 2345
| SecurityAlert            | 279
| SecurityIncident         | 278
| AzureNetworkAnalytics_CL | 970

## Attack Maps Before Hardening / Security Controls

```All map queries actually returned no results due to no instances of malicious activity for the 24 hour period after hardening.```

## Metrics After Hardening / Security Controls

The following table shows the metrics we measured in our environment for another 24 hours, but after we have applied security controls:
Start Time 2024-04-27 20:15:09
Stop Time	2024-04-27 20:15:09

| Metric                   | Count
| ------------------------ | -----
| SecurityEvent            | 9560
| Syslog                   | 1
| SecurityAlert            | 0
| SecurityIncident         | 0
| AzureNetworkAnalytics_CL | 0

## Conclusion

In this project, a mini honeynet was constructed in Microsoft Azure and log sources were integrated into a Log Analytics workspace. Microsoft Sentinel was employed to trigger alerts and create incidents based on the ingested logs. Additionally, metrics were measured in the insecure environment before security controls were applied, and then again after implementing security measures. It is noteworthy that the number of security events and incidents were drastically reduced after the security controls were applied, demonstrating their effectiveness. Security events were reduced by 20.47%, Linux Syslog events were reduced by  99.96%, and Security Alerts, Incidents, and Azure Network Analytics were all reduced by 100%. 

It is worth noting that if the resources within the network were heavily utilized by regular users, it is likely that more security events and alerts may have been generated within the 24-hour period following the implementation of the security controls.
