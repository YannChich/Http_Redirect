# RUDP File Download Project

This project implements a Reliable User Datagram Protocol (RUDP) for file download, along with a custom DNS and DHCP server. The RUDP protocol enables the reliable transmission of data over an unreliable network, providing features such as congestion control, packet loss handling, and retransmission.

## Project Overview

The project consists of four main components:

1. **Client**: The client application sends RUDP signals to the RUDP server to request files and manage the connection.
2. **RUDP Server**: The RUDP server manages the connection with the client, redirecting file requests and handling packet loss and congestion.
3. **DNS Server**: The custom DNS server resolves domain names to IP addresses.
4. **DHCP Server**: The custom DHCP server dynamically assigns IP addresses to clients.

With these components, the project enables users to download files securely and reliably using the RUDP protocol, with support for handling various network conditions and scenarios.

## Getting Started

To set up and run the project, follow the instructions in the accompanying documentation. This will guide you through the process of configuring each component and running the client-server communication.

We hope you enjoy using our RUDP File Download Project!
