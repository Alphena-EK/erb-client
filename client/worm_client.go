package client

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/ethereum/go-ethereum"
	"log"
	"math/big"

	"github.com/erbieio/erb-client/tools"
	types2 "github.com/erbieio/erb-client/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rpc"
)

// Wallet represents a wallet with a private key.
type Wallet struct {
	priKey string
}

// Erbie represents a client with a wallet and an RPC client.
type Erbie struct {
	Wallet
	c *rpc.Client
}

// NewClient creates a new Erbie client for the given URL and priKey.
// If rawurl is empty, it initializes the wallet, allowing signing of buyer, seller, and exchange information.
// If rawurl is not empty, it initializes the NFT, enabling NFT-related transactions.
func NewClient(priKey, rawurl string) *Erbie {
	if rawurl == "" {
		return &Erbie{
			Wallet{priKey: priKey},
			nil,
		}
	} else {
		client, err := rpc.Dial(rawurl)
		if err != nil {
			log.Fatalf("failed to connect to Ethereum node: %v", err)
			return &Erbie{}
		}
		return &Erbie{
			Wallet{
				priKey: priKey,
			},
			client,
		}
	}
}

// CloseConnect closes the RPC client connection.
func (erbie *Erbie) CloseConnect() {
	erbie.c.Close()
}

// UpdatePri updates the private key.
func (erbie *Erbie) UpdatePri(pri string) {
	erbie.priKey = pri
}

// ChainID retrieves the current chain ID for transaction replay protection.
func (erbie *Erbie) ChainID(ctx context.Context) (*big.Int, error) {
	var result hexutil.Big
	err := erbie.c.CallContext(ctx, &result, "eth_chainId")
	if err != nil {
		return nil, err
	}
	return (*big.Int)(&result), err
}

// BlockByNumber returns a block from the current canonical chain. If number is nil, the latest known block is returned.
func (erbie *Erbie) BlockByNumber(ctx context.Context, number *big.Int) (*types.Block, error) {
	return erbie.getBlock(ctx, "eth_getBlockByNumber", toBlockNumArg(number), true)
}

type rpcBlock struct {
	Hash         common.Hash      `json:"hash"`
	Transactions []rpcTransaction `json:"transactions"`
	UncleHashes  []common.Hash    `json:"uncles"`
}

func (erbie *Erbie) getBlock(ctx context.Context, method string, args ...interface{}) (*types.Block, error) {
	var raw json.RawMessage
	err := erbie.c.CallContext(ctx, &raw, method, args...)
	if err != nil {
		return nil, err
	} else if len(raw) == 0 {
		return nil, ethereum.NotFound
	}
	// Decode header and transactions.
	var head *types.Header
	var body rpcBlock
	if err := json.Unmarshal(raw, &head); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, err
	}
	// Quick-verify transaction and uncle lists. This mostly helps with debugging the server.
	if head.UncleHash == types.EmptyUncleHash && len(body.UncleHashes) > 0 {
		return nil, fmt.Errorf("server returned non-empty uncle list but block header indicates no uncles")
	}
	if head.UncleHash != types.EmptyUncleHash && len(body.UncleHashes) == 0 {
		return nil, fmt.Errorf("server returned empty uncle list but block header indicates uncles")
	}
	if head.TxHash == types.EmptyRootHash && len(body.Transactions) > 0 {
		return nil, fmt.Errorf("server returned non-empty transaction list but block header indicates no transactions")
	}
	if head.TxHash != types.EmptyRootHash && len(body.Transactions) == 0 {
		return nil, fmt.Errorf("server returned empty transaction list but block header indicates transactions")
	}
	// Load uncles because they are not included in the block response.
	var uncles []*types.Header
	if len(body.UncleHashes) > 0 {
		uncles = make([]*types.Header, len(body.UncleHashes))
		reqs := make([]rpc.BatchElem, len(body.UncleHashes))
		for i := range reqs {
			reqs[i] = rpc.BatchElem{
				Method: "eth_getUncleByBlockHashAndIndex",
				Args:   []interface{}{body.Hash, hexutil.EncodeUint64(uint64(i))},
				Result: &uncles[i],
			}
		}
		if err := erbie.c.BatchCallContext(ctx, reqs); err != nil {
			return nil, err
		}
		for i := range reqs {
			if reqs[i].Error != nil {
				return nil, reqs[i].Error
			}
			if uncles[i] == nil {
				return nil, fmt.Errorf("got null header for uncle %d of block %x", i, body.Hash[:])
			}
		}
	}
	// Fill the sender cache of transactions in the block.
	txs := make([]*types.Transaction, len(body.Transactions))
	for i, tx := range body.Transactions {
		if tx.From != nil {
			setSenderFromServer(tx.tx, *tx.From, body.Hash)
		}
		txs[i] = tx.tx
	}
	return types.NewBlockWithHeader(head).WithBody(txs, uncles), nil
}

// BlockNumber returns the most recent block number.
func (erbie *Erbie) BlockNumber(ctx context.Context) (uint64, error) {
	var result hexutil.Uint64
	err := erbie.c.CallContext(ctx, &result, "eth_blockNumber")
	return uint64(result), err
}

func (erbie *Erbie) GetBlockByNumber(ctx context.Context, number *big.Int) (map[string]interface{}, error) {
	var raw json.RawMessage
	block := make(map[string]interface{})
	erbie.c.CallContext(ctx, &raw, "eth_getBlockByNumber", toBlockNumArg(number), true)
	err := json.Unmarshal(raw, &block)
	if err != nil {
		return nil, err
	}
	return block, nil
}

func (erbie *Erbie) GetRandomDrop(ctx context.Context, number *big.Int) (common.Hash, error) {
	var randomDrop common.Hash
	err := erbie.c.CallContext(ctx, &randomDrop, "eth_getRandomDrop", toBlockNumArg(number))
	return randomDrop, err
}

func (erbie *Erbie) GetRevocationValidators(ctx context.Context, start *big.Int, end *big.Int) []common.Address {
	var revocationAddrs []common.Address
	err := erbie.c.CallContext(ctx, &revocationAddrs, "eth_getRevocationValidators", toBlockNumArg(start), toBlockNumArg(end))
	fmt.Println(err)
	return revocationAddrs
}

type rpcTransaction struct {
	tx *types.Transaction
	txExtraInfo
}

type txExtraInfo struct {
	BlockNumber *string         `json:"blockNumber,omitempty"`
	BlockHash   *common.Hash    `json:"blockHash,omitempty"`
	From        *common.Address `json:"from,omitempty"`
}

func (tx *rpcTransaction) UnmarshalJSON(msg []byte) error {
	if err := json.Unmarshal(msg, &tx.tx); err != nil {
		return err
	}
	return json.Unmarshal(msg, &tx.txExtraInfo)
}

// TransactionInBlock returns a single transaction at index in the given block.
func (erbie *Erbie) TransactionInBlock(ctx context.Context, blockHash common.Hash, index uint) (*types.Transaction, error) {
	var json *rpcTransaction
	err := erbie.c.CallContext(ctx, &json, "eth_getTransactionByBlockHashAndIndex", blockHash, hexutil.Uint64(index))
	if err != nil {
		return nil, err
	}
	if json == nil {
		return nil, ethereum.NotFound
	} else if _, r, _ := json.tx.RawSignatureValues(); r == nil {
		return nil, fmt.Errorf("server returned transaction without signature")
	}
	if json.From != nil && json.BlockHash != nil {
		setSenderFromServer(json.tx, *json.From, *json.BlockHash)
	}
	return json.tx, err
}

// PendingNonceAt returns the account nonce of the given account in the pending state.
// This is the nonce that should be used for the next transaction.
func (erbie *Erbie) PendingNonceAt(ctx context.Context, account common.Address) (uint64, error) {
	var result hexutil.Uint64
	err := erbie.c.CallContext(ctx, &result, "eth_getTransactionCount", account, "pending")
	return uint64(result), err
}

// SuggestGasPrice retrieves the currently suggested gas price to allow a timely execution of a transaction.
func (erbie *Erbie) SuggestGasPrice(ctx context.Context) (*big.Int, error) {
	var hex hexutil.Big
	if err := erbie.c.CallContext(ctx, &hex, "eth_gasPrice"); err != nil {
		return nil, err
	}
	return (*big.Int)(&hex
