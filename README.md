# CP-IDS
Source code for CP-IDS (IFAC World Congress 2026)
## Paper
CP-IDS: A Cross-Plane Cooperative Intrusion Detection System Using Programmable Switches
## Cite
Waiting for public search
## Abstract
The Internet integration of industrial control systems (ICSs), while enabling advanced industrial applications, exposes ICSs to severe threats (e.g., distributed denial-of-service (DDoS) and man-in-the-middle (MitM) attacks). Nevertheless, existing intrusion detection systems (IDSs) face limitations in detection comprehensiveness and inference timeliness. This paper presents CP-IDS, a cross-plane cooperative IDS framework leveraging programmable switches to overcome these limitations. Specifically, CP-IDS deploys a rule-based model in the switch data plane for line speed DDoS detection and a lightweight isolation forest model with payload signature matching in the switch control plane for timely MitM detection. The two models communicate via the switch's internal secure channel. Implemented on an Intel Tofino switch, CP-IDS demonstrates a 4.14% accuracy improvement and a 9X efficiency gain over state-of-the-art approaches, achieving comprehensive and timely intrusion detection for ICS networks.
## Source Code Usage
### Overview
We have provided four folders.
#### Control_Plane_Model/
It includes an isolated forest detection model deployed in the control plane in the Python format. The input is the payload information of the packets, and the output is whether the packets are judged as abnormal. In the program, to improve the detection effect of the payload part, a feature matching detection for common payload attacks in industrial control network scenarios has been added.
#### Data_Plane_Model/
It includes a threshold detection model deployed in the data plane in the P4 format. The input is the header protocol information of the packets, and the output is whether the packets are judged as abnormal. 
#### Dataset/
It contains two subfolders, which respectively provide the three types of DDoS attacks that are used for detection in the data plane, as well as the three types of payload attacks that are used for detection in the control plane.
#### Test_GRPC/
The core challenge of this paper lies in how to achieve cross-plane collaboration. Therefore, we provide a set of programs to illustrate how to implement cross-plane packet transmission in programmable switches. This folder contains two sets of programs. The P4 format program provides instructions on how to transfer packets from a specified port in the data plane to the control plane, while the Python format program offers guidance on how to listen for packets from the data plane in the control plane. Through coordinated deployment, the process of cross-plane collaboration can be replicated.
### Setup Instructions
As for the control plane Python program, we utilize Python 3.8.   
As for the data plane P4 program, we utilize bf-sde-9.10.0 with Intel Tofino switch.

