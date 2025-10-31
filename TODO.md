# TODO: Enhance Network Scanner Module

## Information Gathered
- Current `modules/network/scanner.py` is basic with simple discover_hosts, scan_ports functions
- Inspiration folder contains advanced modules:
  - `hostdiscovery.py`: ARP, ICMP, TCP discovery with threading
  - `tcpscanner.py`: Advanced TCP scanning with SYN scan, connect scan, service detection
  - `nmapintegration.py`: Nmap wrapper with OS detection, service enumeration, vulnerability scanning
  - `smbenumerator.py`: SMB/NetBIOS enumeration with share discovery, user enumeration
  - `integrated_scanner.py`: Comprehensive scanner combining all phases
- Framework has database persistence, reporting, and modular structure

## Plan
- Enhance `modules/network/scanner.py` with multi-phase scanning:
  - Phase 1: Host discovery (ARP, ICMP, TCP)
  - Phase 2: Port scanning (TCP connect, SYN, UDP)
  - Phase 3: Service enumeration (SMB, HTTP, SNMP, etc.)
  - Phase 4: Consolidation and reporting
- Adapt code from Inspiration to use framework components
- Ensure database persistence and report generation
- Add new 'integrated' subcommand in main.py

## Dependent Files to be Edited
- `modules/network/scanner.py`: Add comprehensive scanning functions
- `main.py`: Add 'integrated' subcommand

## Followup Steps
- Test the new integrated scanning functionality
- Verify database persistence works
- Check report generation
- Ensure compatibility with existing framework

## Current Status
- [x] Read and analyzed Inspiration files
- [x] Created plan
- [ ] Enhance modules/network/scanner.py
- [ ] Update main.py for new subcommand
- [ ] Test integration
