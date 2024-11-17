# Phishing Detection Extension

A browser extension that leverages machine learning and threat intelligence for real-time phishing detection.

## Features
- **URL Analysis & Classification**: Identifies and classifies suspicious URLs based on known phishing patterns.
- **ML-Based Content Analysis**: Analyzes web page content using machine learning models to detect malicious or phishing attempts.
- **Real-Time Threat Intelligence Integration**: Integrates with live threat intelligence feeds to stay up-to-date on the latest phishing threats.
- **Browser Extension Interface**: A lightweight browser extension that provides users with phishing alerts and classification results.

## Local Development Setup

### 1. Clone the repository
First, clone the repository and navigate to the project directory:
```bash
git clone https://github.com/yourusername/phishing-detection.git
cd phishing-detection
```

### 2. Set up the environment

- **Create and activate the virtual environment**:
  ```bash
  # Linux/Mac
  python -m venv venv
  source venv/bin/activate
  
  # Windows
  python -m venv venv
  venv\Scripts\activate
  ```

- **Install the required dependencies**:
  ```bash
  pip install -r requirements.txt
  ```

### 3. Start services

Use Docker to run the necessary services and components:
```bash
docker compose up --build
```

### 4. Run Tests

Run the tests to ensure everything is working as expected:
```bash
pytest
```

## Contributing

We welcome contributions to enhance the Phishing Detection Extension. To contribute:

1. **Fork** the repository.
2. **Create a feature branch**:
   ```bash
   git checkout -b feature/AmazingFeature
   ```
3. **Commit your changes**:
   ```bash
   git commit -m 'Add some AmazingFeature'
   ```
4. **Push** to the branch:
   ```bash
   git push origin feature/AmazingFeature
   ```
5. Open a **Pull Request** with a description of the feature or bug fix.
