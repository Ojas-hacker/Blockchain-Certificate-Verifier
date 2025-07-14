# Blockchain Certificate Verifier

A secure and decentralized certificate verification system built with Python, Flask, and blockchain technology. This application allows institutions to issue tamper-proof digital certificates and enables anyone to verify their authenticity.

## Features

- **Role-Based Access Control (RBAC)**
  - Super Admin: Can manage institutional admins
  - Institutional Admin: Can issue and verify certificates (requires approval)
  - End User: Can verify certificates (no login required)

- **Blockchain Integration**
  - Tamper-proof certificate storage
  - Transparent verification process
  - Immutable record of all issued certificates

- **User-Friendly Interface**
  - Clean and intuitive dashboard
  - Easy certificate issuance
  - Quick verification with certificate ID

## Prerequisites

- Python 3.8 or higher
- pip (Python package manager)

## Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/Ojas-hacker/Blockchain-Certificate-Verifier.git
   cd blockchain-certificate-verifier
   ```

2. **Create a virtual environment (recommended)**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Initialize the database**
   ```bash
   python -c "from app import app, db; app.app_context().push(); db.create_all()"
   ```

## Running the Application

1. **Start the development server**
   ```bash
   python app.py
   ```

2. **Access the application**
   Open your web browser and go to: `http://127.0.0.1:5000`

## Default Accounts

- **Super Admin**
  - Username: admin
  - Password: admin123

## Usage

### For Super Admins
1. Log in with super admin credentials
2. Approve pending admin registrations
3. Monitor system statistics
4. Issue certificates

### For Institutional Admins
1. Register for an account (requires super admin approval)
2. Once approved, log in to your dashboard
3. Issue new certificates to recipients
4. Verify existing certificates

### For End Users
1. Visit the homepage
2. Click on "Verify a Certificate"
3. Enter the certificate ID
4. View the verification results

## Security Considerations

- Always run this in a secure environment in production
- Change the default secret key in `app.py`
- Use HTTPS in production
- Keep your admin credentials secure
- Regularly backup the database

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
