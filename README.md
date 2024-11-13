# Yahoo Data Breach (2013-2014)
# Secure Cookie and HMAC Authentication Demo

## Overview
This repository demonstrates a simple implementation of secure cookie creation and validation using HMAC (Hash-based Message Authentication Code) and base64 encoding. It simulates a scenario where a secure cookie is created for a user with an associated nonce (unique identifier), and it showcases how tampering with the cookie results in failed authentication.

The purpose of this project is to highlight the importance of securing authentication mechanisms, and the potential vulnerabilities in systems that fail to verify the integrity of cookies or tokens properly.

## Features
- **Secure Cookie Creation**: Uses HMAC and base64 encoding to generate secure cookies.
- **Nonce Generation**: Generates unique nonces for each user session to prevent replay attacks.
- **Cookie Validation**: Verifies the integrity of cookies to ensure they have not been tampered with.
- **Tampering Simulation**: Demonstrates what happens when a secure cookie is tampered with by an attacker.

## Project Structure
/secure_demo.py
/insecure_demo.py

## Requirements
To run the demo, ensure you have the following installed:

- Python 3.6 or higher
- Required Python packages (hmac, base64, hashlib, datetime)

## Conclusion
This project demonstrates how secure cookie management can help prevent common security vulnerabilities, such as cookie tampering and replay attacks. 
The insecure demo highlights the risks of not verifying cookies, while the secure demo showcases how HMAC and base64 encoding can be used to enhance the security of cookie-based authentication.
