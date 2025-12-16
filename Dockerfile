# Start from golang base image
FROM golang:1.25.5-bookworm

# Install the air binary 
RUN curl -sSfL https://raw.githubusercontent.com/cosmtrek/air/master/install.sh | sh -s -- -b $(go env GOPATH)/bin

# Set up working directory
WORKDIR /app

# Copy go mod files first for better caching
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy the rest of the code
COPY . .

# Clear go cache and temporary files to save space
RUN go clean -cache -modcache -i -r

CMD ["air"]