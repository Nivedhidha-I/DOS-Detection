# DDoS Detection and Network Forensics: A Two-Phase Capstone Project

## Project Summary

This repository contains the final undergraduate capstone project, which addressed network security by employing a two-pronged approach to Distributed Denial of Service (DDoS) detection. The first phase involved traditional network forensics using specialized tools, while the second phase focused on developing a machine learning model for automated, real-time threat identification. This work demonstrates proficiency in both investigative analysis and predictive security modeling.

## Core Objectives (The 'Why')

This project highlights critical skills in proactive threat identification and incident response planning:

* Threat Identification & Forensics: Gained practical experience in using specialized tools (e.g., Wireshark) to analyze packet capture (PCAP) files, manually identify attack signatures, and conduct deep network protocol inspection.

* Automated Defense Modeling: Developed a supervised machine learning classifier capable of distinguishing between normal network traffic and known DDoS attack vectors (e.g., volumetric or protocol-based attacks).

* Security Tool Integration: Demonstrated the ability to extract meaningful features from raw network data (PCAP) and prepare them for analysis by a predictive model.

## Technical Scope & Components (The 'How')

The project utilized a combined technical and analytical stack:

### Phase 1: Forensics
Manual analysis of PCAP files using Wireshark to establish indicators of compromise (IoCs) and identify attack traffic patterns.

### Phase 2: ML Development
Implementation of a classification algorithm (e.g., Decision Tree or Random Forest) in Python to predict attack presence.

* Language: Python (for ML modeling and feature extraction).

* Data Source: Simulated network traffic data (.pcap files) and extracted csv files from Kaggle.

## Repository Structure

The repository is structured to clearly separate the analysis and machine learning components:

* extract/: Python utility scripts dedicated to loading PCAP data, calculating network metrics (e.g., inter-arrival times, packet sizes), and preparing the final feature set for the ML model.

* model/: The core Python scripts for model training, validation, and evaluation metrics (e.g., accuracy, precision, recall) using the extracted features.

## Key Professional Learnings

* Dual-Threat Analysis: Demonstrated the ability to tackle security challenges using both manual investigative techniques and modern data science methodologies.

* Feature Engineering: Developed expertise in transforming raw network metadata (packet size, frequency, source/destination counts) into meaningful features for ML classification.

* Incident Response Simulation: Gained experience in the initial phases of incident response by rapidly identifying and characterizing a network attack.
