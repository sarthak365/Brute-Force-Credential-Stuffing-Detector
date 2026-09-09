# Brute-Force-Credential-Stuffing-Detector

A detector for brute force and credential stuffing attacks.

## Project Structure

- **data/** - Data files and datasets
- **src/** - Source code
- **reports/** - Generated reports and analysis
- **tests/** - Test files

## Getting Started

TODO: Add getting started instructions

## License

TODO: Add license information
## Detection Logic Notes

- **Brute Force** vs **Credential Stuffing** are distinguished by username 
  diversity: brute force targets 1-2 accounts repeatedly, while credential 
  stuffing spreads attempts across many usernames (typically from a breach 
  list). Without this distinction, high-volume credential stuffing could be 
  misclassified as brute force.
- **Brute Force + Compromise overlapping on the same IP is intentional**, 
  not a bug — it represents a real escalation: a brute-force attack that 
  succeeded. In a SOC, this would be reported as a single incident with 
  an escalating severity, not two unrelated alerts.
