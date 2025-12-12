#!/bin/bash

# Script to generate and display test sender credentials
# This includes the business private key needed for testing

set -e

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== Paycrest Test Sender Credentials ===${NC}\n"

# Database defaults
DB_HOST="localhost"
DB_PORT="5432"
DB_USER="postgres"
DB_NAME="paycrest"

# Test sender from dump.sql
SENDER_USER_ID="6f7209d3-8f70-499f-aec8-65644d55ad5e"
SENDER_PROFILE_ID="e93a1cba-832f-4a7c-aab5-929a53c84324"
SENDER_API_KEY="11f93de0-d304-4498-8b7b-6cecbc5b2dd8"

echo -e "${GREEN}Sender API Key (for API requests):${NC}"
echo "$SENDER_API_KEY"
echo ""

echo -e "${GREEN}Sender User Details:${NC}"
echo "User ID: $SENDER_USER_ID"
echo "Email: john.doe@paycrest.io"
echo "Scope: sender provider"
echo ""

echo -e "${GREEN}Sender Profile ID:${NC}"
echo "$SENDER_PROFILE_ID"
echo ""

# Generate a test business private key (32 bytes hex)
# In production, this would be securely generated and stored
BUSINESS_PRIVATE_KEY=$(openssl rand -hex 32)

echo -e "${YELLOW}Generated Test Business Private Key:${NC}"
echo "$BUSINESS_PRIVATE_KEY"
echo ""

echo -e "${BLUE}Note: The business private key is used to encrypt recipient data (salt).${NC}"
echo -e "${BLUE}In production, this is securely generated when creating a sender account.${NC}"
echo ""

# Check if we can connect to the database
if command -v docker &> /dev/null && docker ps | grep -q paycrest_db; then
    echo -e "${GREEN}Checking database for linked addresses...${NC}"
    
    LINKED_ADDRESSES=$(docker exec paycrest_db psql -U "$DB_USER" -d "$DB_NAME" -t -c \
        "SELECT COUNT(*) FROM linked_addresses WHERE sender_profile_linked_address = '$SENDER_PROFILE_ID';")
    
    if [ "$LINKED_ADDRESSES" -eq 0 ]; then
        echo -e "${YELLOW}No linked addresses found for this sender.${NC}"
        echo "You can create linked addresses using the Sender API endpoints."
    else
        echo -e "${GREEN}Found $LINKED_ADDRESSES linked address(es) for this sender.${NC}"
        
        # Get linked addresses
        docker exec paycrest_db psql -U "$DB_USER" -d "$DB_NAME" -c \
            "SELECT address, institution, account_identifier, account_name 
             FROM linked_addresses 
             WHERE sender_profile_linked_address = '$SENDER_PROFILE_ID';"
    fi
    echo ""
fi

echo -e "${BLUE}=== Testing Instructions ===${NC}"
echo "1. Use the Sender API Key for all API requests"
echo "2. The business private key is for encrypting recipient details when creating linked addresses"
echo "3. API Base URL: http://localhost:8000"
echo "4. Swagger Documentation: http://localhost:8000/swagger/index.html"
echo ""

echo -e "${GREEN}Example cURL request to test:${NC}"
cat << 'EOF'
curl -X GET "http://localhost:8000/api/v1/sender/orders" \
  -H "x-api-key: 11f93de0-d304-4498-8b7b-6cecbc5b2dd8" \
  -H "Content-Type: application/json"
EOF
echo ""

echo -e "${YELLOW}Save this business private key securely for your tests!${NC}"
