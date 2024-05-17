package client

import ethcommon "github.com/ethereum/go-ethereum/common"

// APIs defines the interface for blockchain interactions.
type APIs interface {
	// NormalTransaction performs a normal transaction.
	NormalTransaction(to string, value int64, data string) (string, error)
	
	// Mint mints a new NFT with the specified royalty and metadata.
	Mint(royalty uint32, metaURL string, exchanger string) (string, error)
	
	// Transfer transfers an NFT to another address.
	Transfer(nftAddress, to string) (string, error)
	
	// Author assigns an author to an NFT.
	Author(nftAddress, to string) (string, error)
	
	// AuthorRevoke revokes an author's rights to an NFT.
	AuthorRevoke(nftAddress, to string) (string, error)
	
	// AccountAuthor assigns an author to an account.
	AccountAuthor(to string) (string, error)
	
	// AccountAuthorRevoke revokes an author's rights to an account.
	AccountAuthorRevoke(to string) (string, error)
	
	// SNFTToERB converts an SNFT to an ERB.
	SNFTToERB(nftAddress string) (string, error)
	
	// TokenPledge pledges a token.
	TokenPledge(toaddress ethcommon.Address, proxyAddress, name, url string, value int64, feerate int) (string, error)
	
	// TokenRevokesPledge revokes a token pledge.
	TokenRevokesPledge(toaddress ethcommon.Address, value int64) (string, error)
	
	// TransactionNFT initiates an NFT transaction.
	TransactionNFT(buyer []byte, to string) (string, error)
	
	// BuyerInitiatingTransaction starts a transaction from the buyer's side.
	BuyerInitiatingTransaction(seller1 []byte) (string, error)
	
	// FoundryTradeBuyer handles a foundry trade from the buyer's perspective.
	FoundryTradeBuyer(seller2 []byte) (string, error)
	
	// FoundryExchange handles an exchange between a buyer and a seller.
	FoundryExchange(buyer, seller2 []byte, to string) (string, error)
	
	// NftExchangeMatch matches an NFT exchange between a buyer and a seller.
	NftExchangeMatch(buyer, seller, exchangerAuth []byte, to string) (string, error)
	
	// FoundryExchangeInitiated initiates a foundry exchange.
	FoundryExchangeInitiated(buyer, seller2, exchangerAuthor []byte, to string) (string, error)
	
	// NFTDoesNotAuthorizeExchanges handles a case where an NFT does not authorize exchanges.
	NFTDoesNotAuthorizeExchanges(buyer, seller1 []byte, to string) (string, error)
	
	// AdditionalPledgeAmount adds to a pledge amount.
	AdditionalPledgeAmount(value int64) (string, error)
	
	// RevokesPledgeAmount revokes a pledge amount.
	RevokesPledgeAmount(value int64) (string, error)
	
	// VoteOfficialNFT votes on an official NFT.
	VoteOfficialNFT(dir, startIndex string, number uint64, royalty uint32, creator string) (string, error)
	
	// VoteOfficialNFTByApprovedExchanger votes on an official NFT with an approved exchanger.
	VoteOfficialNFTByApprovedExchanger(dir, startIndex string, number uint64, royalty uint32, creator string, exchangerAuth []byte) (string, error)
	
	// UnforzenAccount unfreezes an account.
	UnforzenAccount() (string, error)
	
	// WeightRedemption redeems weight.
	WeightRedemption() (string, error)
	
	// BatchSellTransfer handles batch sell transfers.
	BatchSellTransfer(buyer, seller, buyerAuth, sellerAuth, exchangerAuth []byte, to string) (string, error)
	
	// ForceBuyingTransfer handles a forced buying transfer.
	ForceBuyingTransfer(buyer, buyerAuth, exchangerAuth []byte, to string) (string, error)
	
	// ExtractERB extracts ERB.
	ExtractERB() (string, error)
	
	// AccountDelegate delegates an account.
	AccountDelegate(proxySign []byte, proxyAddress string) (string, error)
}
