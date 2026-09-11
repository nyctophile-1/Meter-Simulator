# Meter-Simulator
Meter Simulation Service

## Deployment

For the Observability server, follow the [DRISHTI deployment SOP](deploy/drishti-deployment-sop.md), including access, build, deployment, verification, and rollback steps.

For the EQA server, follow the [EQA deployment SOP](deploy/eqa-deployment-sop.md), including its separate SSH key, meter prefix, and compressed data backup procedure.

This project is a DLMS/COSEM Meter Simulation Service built in .NET, designed to simulate smart energy meters for testing and development purposes. It enables end-to-end validation of HES, head-end systems, and DLMS clients without requiring physical meters.

## Key Features

  Simulates DLMS/COSEM compliant meters
  
  Supports Authentication & Encryption (Low / High / GMAC as applicable)
  
  Configurable Logical Names (OBIS codes) and meter data
  
  TCP/IP based communication
  
  Suitable for testing secure client connections, command execution, and data reads
  
  Lightweight, modular, and easy to extend

## Use Cases

  HES / AMI platform testing
  
  DLMS client development & debugging
  
  Secure communication validation
  
  Offline development without real meters
  

## Tech Stack

  .NET
  
  DLMS/COSEM (Gurux compatible)
  
  TCP Socket Communication
