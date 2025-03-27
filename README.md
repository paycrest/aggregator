## Paycrest Aggregator

The aggregator works to simplify and automate how liquidity flows between various provision nodes and user-created orders.


## Protocol Architecture

![image](https://github.com/user-attachments/assets/fdea36e5-9f54-4b17-bf0d-44d33d96fc62)

**Create Order**: The user creates an on/off ramp order (read Payment Intent) on the Gateway Smart Contract (escrow) through an onchain app built on the protocol like [Zap by Paycrest](https://github.com/paycrest/zap) or through our [Sender API](https://app.paycrest.io/).

**Aggregate**: The aggregator node indexes the order and assigns it to one or more provision nodes run by liquidity providers.

**Fulfill**: The provisioning node automatically disburses funds to their wallet or recipient's local bank account, mobile money wallet via connections to payment service providers (PSP).

## Development Setup

Pre-requisite: Install required dependencies:
- [Docker Compose](https://docs.docker.com/compose/install/)
- [Ent](https://entgo.io/docs/getting-started/) for database ORM
- [Atlas](https://atlasgo.io/guides/evaluation/install#install-atlas-locally) for database migrations

To set up your development environment, follow these steps:

1. Setup the aggregator repo on your local machine.

```bash

# clone the repo

git clone https://github.com/paycrest/aggregator.git

cd aggregator

# copy enviroment variables

cp .env.example .env
```

2. Start and seed the development environment:
```bash

# build the image
docker-compose build

# run containers
docker-compose up -d

# make script executable
chmod +x scripts/import_db.sh

# run the script to seed db with sample configured sender & provider profile
./scripts/import_db.sh -h localhost
```

3. Run our sandbox provision node and connect it to your local aggregator by following the [instructions here](https://paycrest.notion.site/run-sandbox-provision-node)

Here, we’d make use of a demo provision node and connect it to our local aggregator

That's it! The server will now be running at http://localhost:8000. You can use an API testing tool like Postman or cURL to interact with the API.


## Usage
- Try a decentralized offramp on [Zap by Paycrest](https://zap.paycrest.io)
- [Swagger REST API Specification](https://app.swaggerhub.com/apis/paycrest-dev/paycrest-api/0.1.0)
- Interact with the Sender API using the sandbox API Key `11f93de0-d304-4498-8b7b-6cecbc5b2dd8`
 - Payment orders that are initiated using the Sender API in sandbox should use the following testnet tokens from the public faucets of their respective networks:
	 - **DAI** on Base Sepolia
	 - **USDT** on Ethereum Sepolia and Arbitrum Sepolia


## Contributing

We welcome contributions to the Paycrest Protocol! To get started, follow these steps:

**Important:** Before you begin contributing, please ensure you've read and understood these important documents:

- [Contribution Guide](https://paycrest.notion.site/Contribution-Guide-1602482d45a2809a8930e6ad565c906a) - Critical information about development process, standards, and guidelines.

- [Code of Conduct](https://paycrest.notion.site/Contributor-Code-of-Conduct-1602482d45a2806bab75fd314b381f4c) - Our community standards and expectations.

Our team will review your pull request and work with you to get it merged into the main branch of the repository.

If you encounter any issues or have questions, feel free to open an issue on the repository or leave a message in our [developer community on Telegram](https://t.me/+Stx-wLOdj49iNDM0)


## Testing

We use a combination of unit tests and integration tests to ensure the reliability of the codebase.

To run the tests, run the following command:

```bash
# install and run ganache local blockchain
npm install ganache --global
HD_WALLET_MNEMONIC="media nerve fog identify typical physical aspect doll bar fossil frost because"; ganache -m "$HD_WALLET_MNEMONIC" --chain.chainId 1337 -l 21000000

# run all tests
go test ./...

# run a specific test
go test ./path/to/test/file
```
It is mandatory that you write tests for any new features or changes you make to the codebase. Only PRs that include passing tests will be accepted.

## License

[Affero General Public License v3.0](https://choosealicense.com/licenses/agpl-3.0/)
