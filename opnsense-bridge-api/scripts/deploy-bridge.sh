#!/bin/bash

# deploy-bridge.sh - Deploy OPNsense Monitoring Bridge (Docker or Kubernetes)
# Uses .env variables for configuration

# Load .env file
if [ -f .env ]; then
    export $(grep -v '^#' .env | xargs)
else
    echo "Error: .env file not found in $(pwd)"
    exit 1
fi

# Validate required environment variables
required_vars=(BRIDGE_IP BRIDGE_PORT JWT_SECRET_KEY OPNSENSE_HOST OPNSENSE_API_KEY OPNSENSE_API_SECRET SSL_CERT_PATH SSL_KEY_PATH)
for var in "${required_vars[@]}"; do
    if [ -z "${!var}" ]; then
        echo "Error: Required environment variable $var is not set in .env"
        exit 1
    fi
done

# Run setup script
echo "Running setup script..."
./scripts/setup-bridge.sh
if [ $? -ne 0 ]; then
    echo "Error: Setup failed"
    exit 1
fi

# Deploy with Docker Compose
if [ -f docker-compose.yml ]; then
    echo "Deploying with Docker Compose..."
    docker-compose up -d
    if [ $? -eq 0 ]; then
        echo "Docker Compose deployment successful"
    else
        echo "Error: Docker Compose deployment failed"
        exit 1
    fi
else
    echo "Warning: docker-compose.yml not found, skipping Docker deployment"
fi

# Deploy with Kubernetes
if [ -d k8s ]; then
    echo "Deploying with Kubernetes..."
    kubectl apply -f k8s/secret.yaml
    kubectl apply -f k8s/configmap.yaml
    kubectl apply -f k8s/deployment.yaml
    kubectl apply -f k8s/service.yaml
    kubectl apply -f k8s/ingress.yaml
    if [ $? -eq 0 ]; then
        echo "Kubernetes deployment successful"
        kubectl -n opnsense-bridge get pods
    else
        echo "Error: Kubernetes deployment failed"
        exit 1
    fi
else
    echo "Warning: k8s directory not found, skipping Kubernetes deployment"
fi

# Test API connectivity
echo "Testing API connectivity..."
./scripts/test-api.sh
if [ $? -eq 0 ]; then
    echo "Deployment and API tests completed successfully"
else
    echo "Error: API tests failed"
    exit 1
fi