
# Phishing Shield

A powerful browser extension that provides real-time protection against phishing attacks using advanced machine learning and threat intelligence.

## Features

### Real-Time Protection
- **Active URL Monitoring**: Analyzes URLs in real-time as you browse
- **Instant Alerts**: Displays warning banners for potentially dangerous websites
- **Risk Score Assessment**: Provides detailed risk scoring for each analyzed website

### Security Analysis
- **SSL Certificate Verification**: Checks for valid SSL certificates and secure connections
- **Domain Age Detection**: Identifies newly registered domains that are often used in phishing
- **Threat Intelligence Integration**: Cross-references URLs with known threat databases
- **Visual Risk Indicators**: Color-coded risk levels and intuitive security indicators

### User Interface
- **Clean Dashboard**: Easy-to-read analysis results and security recommendations
- **Detailed Reports**: Comprehensive breakdown of security findings
- **Quick Actions**: One-click access to security information and controls

## Installation

### For Developers

#### Prerequisites
- Python 3.8+
- Docker and Docker Compose
- Chrome Browser

#### Local Development Setup

1. **Clone the repository**
```bash
git clone https://github.com/yourusername/phishing-shield.git
cd phishing-shield
```

2. **Set up the backend environment**
```bash
# Create and activate virtual environment
python -m venv venv

# Linux/Mac
source venv/bin/activate

# Windows
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

3. **Start the services**
```bash
# Start backend services
docker compose up --build
```

5. **Load the extension in Chrome**
- Open Chrome and navigate to `chrome://extensions/`
- Enable "Developer mode" in the top right
- Click "Load unpacked" and select the `extension` directory
- The extension icon should appear in your toolbar

6. **Run tests**
```bash
# Run backend tests
pytest

```
## Architecture

The extension consists of three main components:

1. **Background Script**: Handles URL monitoring and API communication
2. **Content Script**: Manages warning banner injection
3. **Popup Interface**: Provides detailed analysis and controls

The backend API provides:
- URL analysis endpoints
- Threat intelligence integration
- Machine learning classification
- Security feature verification

## Contributing

We welcome contributions! Here's how you can help:

1. **Fork** the repository
2. **Create** a feature branch:
```bash
git checkout -b feature/amazing-feature
```
3. **Make** your changes and commit them:
```bash
git commit -m 'Add amazing feature'
```
4. **Push** to your branch:
```bash
git push origin feature/amazing-feature
```
5. Submit a **Pull Request**


## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
