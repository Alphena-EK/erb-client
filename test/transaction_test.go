package test

import (
	"context"
	"fmt"
	"github.com/erbieio/erb-client/tools"
	"github.com/erbieio/erb-client/types"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/erbieio/erb-client/client"
	"github.com/ethereum/go-ethereum/common"
)

const (
	//endpoint         = "http://192.168.4.223:8560"
	//endpoint         = "http://43.129.181.130:8561"
	//endpoint = "http://192.168.4.240:8561"
	//endpoint = "https://api.erbie.io/"
	endpoint = "http://localhost:8545"
	//priKey           = "7c6786275d6011adb6288587757653d3f9061275bafc2c35ae62efe0bc4973e9"
	priKey           = "434cfa1cc3db70bd6193f468358646c5cd61967f1ab3732b0c4d0cfdbb59f08c"
	buyerPriKey      = "f616c4d20311a2e73c67ef334630f834b7fb42304a1d4448fb2058e9940ecc0a"
	buyerAddress     = "0x44d952db5dfb4cbb54443554f4bb9cbebee2194c"
	sellerPriKey     = "e04d9e04569d1de38be6b0dbced9413ebf86d33d3670c6db965726b46de0572a"
	sellerAddress    = "0xFFF531a2DA46d051FdE4c47F042eE6322407DF3f"
	exchangerPriKey  = "74960499b76daa6c987fb3872619fe28d875d5c64fd96bbb2b9c0ae676eb2c45"
	exchangeAddress  = "0x83c43f6F7bB4d8E429b21FF303a16b4c99A59b05"
	exchangerPriKey1 = "8c9c4464a685583b1ddcb30bfd991444248eb492d10ceca647fdd41329499b49"
	exchangeAddress1 = "0xB685EB3226d5F0D549607D2cC18672b756fd090c"
)

func TestBlockNumber(t *testing.T) {
	worm := client.NewClient(priKey, endpoint)
	number, _ := worm.BlockNumber(context.Background())
	fmt.Println("blocknumber = ", number)
}

func TestNewClient(t *testing.T) {
	worm := client.NewClient(priKey, endpoint)
	_ = worm
}

// Recharge
func TestRecharge(t *testing.T) {
	worm := client.NewClient(priKey, endpoint)
	rs, _ := worm.NormalTransaction("0x53761Ef357d99EFfbbcE56Ff1aB707a7Be21a27F", 1000, "")
	fmt.Println(rs)
}

func TestGetBalance2(t *testing.T) {
	worm := client.NewClient(priKey, endpoint)
	balance, _ := worm.Balance(context.Background(), "0x53761Ef357d99EFfbbcE56Ff1aB707a7Be21a27F")
	fmt.Println(balance)
}

// Transfer
// NFT transfer 1
func TestTransfer(t *testing.T) {
	worm := client.NewClient(priKey, endpoint)
	rs, _ := worm.Transfer("0x0000000000000000000000000000000000000001", sellerAddress)
	fmt.Println(rs)
}

//0x5e8dd659b0ceb95ab53ce32d37daa8688accab601ce58c75e706f08bb47617f4

// TokenPledge
// ERB pledge 9
func TestTokenPledge(t *testing.T) {
	worm := client.NewClient(priKey, endpoint)
	account, _, err := tools.PriKeyToAddress(priKey)
	rs, _ := worm.TokenPledge(account.Hex(), "", 10)
	fmt.Println(rs, err)
}

//0x6ceb02802455ab959964866410f37a2f0fcd78e7e64e87d6c9d8102de7f9974b

// TokenRevokesPledge
// ERB revokes pledge 10
func TestTokenRevokesPledge(t *testing.T) {
	worm := client.NewClient(priKey, endpoint)
	account, _, err := tools.PriKeyToAddress(priKey)
	rs, _ := worm.TokenRevokesPledge(account.Hex(), 10)
	fmt.Println(rs, err)
}

func TestGetBalance(t *testing.T) {
	worm := client.NewClient(priKey, endpoint)
	balance, _ := worm.Balance(context.Background(), exchangeAddress)
	fmt.Println(balance)
}

// func TestCheckNFTPool(t *testing.T) {
// 	worm := client.NewClient("c1e74da8e26c5a60870089f59695a1b243887f9d23571d24c7f011b8eb068768", "http://192.168.4.240:8561")

// 	var flag bool
// 	num := int64(22)
// 	for {
// 		if flag {
// 			break
// 		} else {
// 			current, _ := worm.BlockNumber(context.Background())
// 			if uint64(num) > current {
// 				time.Sleep(time.Second * 5)
// 			} else {
// 				fmt.Println("num: ", num)
// 				//res1, _ := worm.NFT.GetBlockBeneficiaryAddressByNumber(context.Background(), num)
// 				//for _, miners := range *res1 {
// 				//	if miners.Address == common.HexToAddress("0xEE3168308949237d395202F134C4243630ebB4A8") {
// 				//		fmt.Println("miner", miners.Address)
// 				//		flag = true
// 				//		//break
// 				//	}
// 				//}

// 				//res1, _ := worm.NFT.GetValidators(context.Background(), num)
// 				//for _, validator := range res1.Validators {
// 				//	fmt.Println("validator", validator)
// 				//	if validator.Addr == common.HexToAddress("0xA7aa3f181aebE59ca697D803B2197cfA50A3913E") {
// 				//		fmt.Println("miner", validator) //0x0F7094Cf6391273AAC99b478b8Eca9D636BBbf0c
// 				//		flag = true
// 				//		break
// 				//	}
// 				//}

// 				res1, _ := worm.GetActiveLivePool(context.Background(), uint64(num))
// 				for _, miners := range res1.ActiveMiners {
// 					fmt.Println("miner", miners)
// 					if miners.Address == common.HexToAddress("0xA7aa3f181aebE59ca697D803B2197cfA50A3913E") {
// 						fmt.Println("miner", miners) //0x0F7094Cf6391273AAC99b478b8Eca9D636BBbf0c
// 						flag = true
// 						break
// 					}
// 				}

// 				//res1, _ := worm.NFT.QueryMinerProxy(context.Background(), num, "0xA7F60Adc80E09F71a7A56044003a2B606Ed1Cac2")
// 				//for _, miners := range res1 {
// 				//	if miners.Address == common.HexToAddress("0x279c59A0DC597276bac3D160Cb1596beFA46bad2") {
// 				//		fmt.Println("miner", miners)
// 				//		flag = true
// 				//		break
// 				//	}
// 				//}
// 				num++
// 			}
// 		}
// 	}
// }

func TestGetSNFT(t *testing.T) {
	exchanger := make(map[string]string)
	exchanger["0x68B14e0F18C3EE322d3e613fF63B87E56D86Df60"] = "d8cf127b1780c0a0e0d2e40519ae2c611d6d7f6b8b706c967ed8183170267d99"
	exchanger["0xeEF79493F62dA884389312d16669455A7E0045c1"] = "9bdbec1e6329a5484105c05aacbbce9ff78a287d20cbd8a8b59c414b5e1edbb6"
	exchanger["0xa5999Cc1DEC36a632dF735064Dc75eF6af0E7389"] = "b6290ad66f10eead80c1371be065af9493ff0cc611fa6d4c207f46e2516f2f38"
	exchanger["0x63d913dfDB75C7B09a1465Fe77B8Ec167793096b"] = "b1c0f70e418cdc851534c6a09c40a50b676466819c3cd65a7aeed9cb581d1643"
	exchanger["0xF50f73B83721c108E8868C5A2706c5b194A0FDB1"] = "f17a19d3d0c4620759e4e365ef79f2553b0639fd1a7bdfbafe570f7e3d59f7aa"
	exchanger["0xB000811Aff6e891f8c0F1aa07f43C1976D4c3076"] = "ec299549a07e9e6202999445dccfe6a1efdc3af75dd942461a403d4a3a03edb3"
	exchanger["0x257F3c6749a0690d39c6FBCd2DceB3fB464f0F94"] = "382b13e70a7e66f7f6d94007b977c1ad6acdc8f454ee77e3e5bb159d0e09f7cb"
	exchanger["0x43ee5cB067F29B920CC44d5d5367BCEb162B4d9E"] = "405321241ccffe1d2bddcac1202209460a5a0caded3a9b203bdbba5c40f45de0"
	exchanger["0x85D3FDA364564c365870233E5aD6B611F2227846"] = "efdb9f92fbae899e8069a41c3ed589f6fdaf9cc0be1da86bb5d0cf77ccf3b5d3"
	exchanger["0xDc807D83d864490C6EEDAC9C9C071E9AAeD8E7d7"] = "ef5664558107effaa7a20d01c328037a15e9a4989a06be79249f517dad7c7eea"
	exchanger["0xFA623BCC71BE5C3aBacfe875E64ef97F91B7b110"] = "f6842d3207b8b81a5ea1e3d08fcb013ec2ef8a320e325252cd2af18c390772fe"
	exchanger["0xb17fAe1710f80Eb9a39732862B0058077F338B21"] = "38f6551752c4c561fe68abe365eae069cc667ae31a92bf3d52df468d918454c6"
	exchanger["0x86FFd3e5a6D310Fcb4668582eA6d0cfC1c35da49"] = "d60c5a8a3fdc26b22533d1c5fffdb11c12b17771cd9f2380e71df30a8970a8b1"
	exchanger["0x6bB0599bC9c5406d405a8a797F8849dB463462D0"] = "04a5ddb33b11fff6923b5eee08f949fead766e9d92a42f4350c726a1b18ffc81"
	exchanger["0x765C83dbA2712582C5461b2145f054d4F85a3080"] = "a1a78a79fb1159a4c871a20a60f1a05ece8189115226fda182565d027b0015da"

	var collects = "0xC65F08C9Dfceb0988631B175E293Af5666535CF0"

	var Empty, _ = new(big.Int).SetString("0x0000000000000000000000000000000000000000", 16)

	worm := client.NewClient("38fc3f36f420ca662e0b423342b61243337a84f992eb60847a67cb8fe90af133", "http://192.168.4.240:8561")
	Nft, _ := new(big.Int).SetString("8000000000000000000000000000000000000000", 16)
	ctx := context.Background()
	for {
		latest, _ := worm.BlockNumber(ctx)
		address := common.BytesToAddress(Nft.Bytes())
		res1, _ := worm.GetAccountInfo(context.Background(), address.String(), int64(latest))

		if (*res1).Csbt.Owner.String() == common.BytesToAddress(Empty.Bytes()).String() {
			time.Sleep(time.Second * 5)
		}

		for ex, pri := range exchanger {
			fmt.Println((*res1).Csbt.Owner.String())
			fmt.Println(ex)
			if strings.ToLower(ex) == strings.ToLower(res1.Csbt.Owner.String()) {
				worms := client.NewClient(pri, "http://192.168.4.240:8561")
				worms.Transfer(common.BytesToAddress(Nft.Bytes()).String(), collects)
				break
			}
		}
		Nft = new(big.Int).Add(Nft, big.NewInt(1))
	}
}

//"number":           (*hexutil.Big)(head.Number),
//"hash":             head.Hash(),
//"parentHash":       head.ParentHash,
//"nonce":            head.Nonce,
//"mixHash":          head.MixDigest,
//"sha3Uncles":       head.UncleHash,
//"logsBloom":        head.Bloom,
//"stateRoot":        head.Root,
//"miner":            miner,
//"difficulty":       (*hexutil.Big)(head.Difficulty),
//"extraData":        hexutil.Bytes(head.Extra),
//"size":             hexutil.Uint64(head.Size()),
//"gasLimit":         hexutil.Uint64(head.GasLimit),
//"gasUsed":          hexutil.Uint64(head.GasUsed),
//"timestamp":        hexutil.Uint64(head.Time),
//"transactionsRoot": head.TxHash,
//"receiptsRoot":     head.ReceiptHash,

type BlockInfo struct {
	Hash    string
	PreHash string
	Number  uint64
	Miner   string
}

func TestAnalysisBlocks(t *testing.T) {
	worm := client.NewClient(priKey, endpoint)
	blockInfoMap := make(map[uint64]*BlockInfo, 0)
	for {
		time.Sleep(1 * time.Second)
		currentBlockNumber, _ := worm.BlockNumber(context.Background())
		currentBlock, err := worm.GetBlockByNumber(context.Background(), new(big.Int).SetUint64(currentBlockNumber))
		if err != nil {
			continue
		}
		t.Log(currentBlock["hash"])
		t.Log(currentBlock["parentHash"])
		t.Log(currentBlock["miner"])
		hash := currentBlock["hash"].(string)
		prehash := currentBlock["parentHash"].(string)
		miner := currentBlock["miner"].(string)
		t.Log(hash)
		t.Log(prehash)
		t.Log(miner)

		currentBlockInfo := &BlockInfo{
			Hash:    hash,
			PreHash: prehash,
			Number:  currentBlockNumber,
			Miner:   miner,
		}

		v, ok := blockInfoMap[currentBlockNumber]
		if ok {
			if v.Hash != hash {
				t.Error("fork, two blocks have same blocknumber, but not same hash \n",
					"blocknumber ", currentBlockNumber, "\nold hash ", v.Hash, "new hash", hash,
					"\nold miner ", v.Miner, "new miner ", miner)
			}
		} else {
			t.Log("current block number ", currentBlockNumber)
			blockInfoMap[currentBlockNumber] = currentBlockInfo
		}
		if preBlockInfo, ok := blockInfoMap[currentBlockNumber-1]; ok {
			if preBlockInfo.Hash != currentBlockInfo.PreHash {
				t.Error("fork, new block's prehash is not same with the parent block's hash\n",
					"new block number ", currentBlockInfo.Number,
					"\nnew block's prehash ", currentBlockInfo.PreHash,
					"parent block's hash ", preBlockInfo.Hash)
				break
			}
		}

		t.Log("map len ", len(blockInfoMap))
		var startDeleteIndex uint64
		var deleteIndexs []uint64
		if len(blockInfoMap) > 1000 {
			startDeleteIndex = currentBlockNumber - 1000

			for k, _ := range blockInfoMap {
				if k <= startDeleteIndex {
					deleteIndexs = append(deleteIndexs, k)
				}
			}

			for _, v := range deleteIndexs {
				delete(blockInfoMap, v)
			}
			deleteIndexs = deleteIndexs[:0]
		}
	}
}

func TestGetRandomDrop(t *testing.T) {
	worm := client.NewClient(priKey, endpoint)
	drop, err := worm.GetRandomDrop(context.Background(), big.NewInt(1))
	t.Log("drop=", drop, "err=", err)
}

func TestGetMint(t *testing.T) {
	MintDeepStorageAddress := common.HexToAddress("0x0000000000000000000000000000000000000001")
	mask, _ := new(big.Int).SetString("8000000000000000000000000000000000000000", 16)
	worm := client.NewClient(priKey, endpoint)
	res1, _ := worm.GetAccountInfo(context.Background(), MintDeepStorageAddress.String(), 35144)
	t.Log("OfficialMint1 = ", new(big.Int).Sub(res1.Staker.Mint.OfficialMint, mask))
	res2, _ := worm.GetAccountInfo(context.Background(), MintDeepStorageAddress.String(), 35145)
	t.Log("OfficialMint2 = ", new(big.Int).Sub(res2.Staker.Mint.OfficialMint, mask))
}

func AnalysisValidators(t *testing.T, ch chan common.Address, start int, end int) {
	ValidatorStorageAddress := common.HexToAddress("0x0000000000000000000000000000000000000002")
	worm := client.NewClient(priKey, endpoint)
	//currentBlockNumber, _ := worm.BlockNumber(context.Background())
	t.Log("start = ", start)
	var lastValidators []*types.Validator
	var revocationAddrs []common.Address
	var isExist bool
	for i := start; i <= end; i++ {
		t.Log("blocknumber = ", i)
		validatorsAcc, _ := worm.GetAccountInfo(context.Background(), ValidatorStorageAddress.String(), int64(i))
		if len(lastValidators) == 0 {
			lastValidators = append(lastValidators, validatorsAcc.Staker.Validators.Validators...)
			continue
		}

		for _, validator := range lastValidators {
			for _, v := range validatorsAcc.Staker.Validators.Validators {
				if validator.Addr == v.Addr {
					acc, _ := worm.GetAccountInfo(context.Background(), validator.Addr.Hex(), int64(i))
					if acc.Worm.PledgedBalance.Cmp(big.NewInt(1)) > 0 {
						isExist = true
					}
					break
				}
			}

			if !isExist {
				revocationAddrs = append(revocationAddrs, validator.Addr)
			}
		}
	}

	//t.Log("revocation  address number = ", len(revocationAddrs))
	//for _, v := range revocationAddrs {
	//	t.Log(v.Hex())
	//}
	for _, v := range revocationAddrs {
		ch <- v
	}
}

func TestAnalysisValidators(t *testing.T) {
	ValidatorStorageAddress := common.HexToAddress("0x0000000000000000000000000000000000000002")
	worm := client.NewClient(priKey, endpoint)
	currentBlockNumber, _ := worm.BlockNumber(context.Background())
	t.Log("currentBlockNumber = ", currentBlockNumber)
	var lastValidators []*types.Validator
	var revocationAddrs []common.Address
	var isExist bool
	for i := 360000; i < int(currentBlockNumber); i++ {
		t.Log("blocknumber = ", i)
		validatorsAcc, _ := worm.GetAccountInfo(context.Background(), ValidatorStorageAddress.String(), int64(i))
		if len(lastValidators) == 0 {
			lastValidators = append(lastValidators, validatorsAcc.Staker.Validators.Validators...)
			continue
		}

		for _, validator := range lastValidators {
			for _, v := range validatorsAcc.Staker.Validators.Validators {
				if validator.Addr == v.Addr {
					acc, _ := worm.GetAccountInfo(context.Background(), validator.Addr.Hex(), int64(i))
					if acc.Worm.PledgedBalance.Cmp(big.NewInt(1)) > 0 {
						isExist = true
					}
					break
				}
			}

			if !isExist {
				revocationAddrs = append(revocationAddrs, validator.Addr)
			}
		}
	}

	t.Log("revocation  address number = ", len(revocationAddrs))
	for _, v := range revocationAddrs {
		t.Log(v.Hex())
	}
}

func TestAnalysisValidators2(t *testing.T) {
	addressCh := make(chan common.Address, 2000)
	var wg sync.WaitGroup

	worm := client.NewClient(priKey, endpoint)
	currentBlockNumber, _ := worm.BlockNumber(context.Background())
	t.Log("currentBlockNumber = ", currentBlockNumber)
	startNumber := 360000
	all := false
	i := 1

loop:
	start := startNumber + (i-1)*2000
	end := startNumber + i*2000
	if uint64(end) > currentBlockNumber {
		end = int(currentBlockNumber)
		all = true
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		AnalysisValidators(t, addressCh, start, end)
	}()
	if !all {
		i++
		goto loop
	}

	wg.Wait()

	addr := common.HexToAddress("0x0000000000000000000000000000000000000000")
	addressCh <- addr
	var revocationAddrs []common.Address
	for {
		a := <-addressCh
		if a == addr {
			break
		}
		revocationAddrs = append(revocationAddrs, a)
	}

	t.Log("revocation  address number = ", len(revocationAddrs))
	for _, v := range revocationAddrs {
		t.Log(v.Hex())
	}
}

func TestGetRevocationValidators(t *testing.T) {
	worm := client.NewClient(priKey, endpoint)
	currentBlockNumber, _ := worm.BlockNumber(context.Background())
	revocationValidators := worm.GetRevocationValidators(context.Background(), big.NewInt(320000), big.NewInt(int64(currentBlockNumber)))

	t.Log("revocation  address number = ", len(revocationValidators))
	for _, v := range revocationValidators {
		t.Log(v.Hex())
	}
}

// 353069/353072/353143/354589
func TestAnalysisValidators3(t *testing.T) {
	ValidatorStorageAddress := common.HexToAddress("0x0000000000000000000000000000000000000002")
	worm := client.NewClient(priKey, endpoint)
	//currentBlockNumber, _ := worm.BlockNumber(context.Background())
	//t.Log("currentBlockNumber = ", currentBlockNumber)
	var lastValidators []*types.Validator
	var revocationAddrs []common.Address
	var isExist bool
	for i := 353068; i <= 353072; i++ {
		t.Log("blocknumber = ", i)
		validatorsAcc, _ := worm.GetAccountInfo(context.Background(), ValidatorStorageAddress.String(), int64(i))
		t.Log("validators len = ", len(validatorsAcc.Staker.Validators.Validators))
		if len(lastValidators) == 0 {
			lastValidators = append(lastValidators, validatorsAcc.Staker.Validators.Validators...)
			continue
		}
		var tempRevocaAddrs []common.Address
		for _, validator := range lastValidators {
			for _, v := range validatorsAcc.Staker.Validators.Validators {
				if validator.Addr == v.Addr {
					acc, _ := worm.GetAccountInfo(context.Background(), validator.Addr.Hex(), int64(i))
					if acc.Worm.PledgedBalance.Cmp(big.NewInt(1)) > 0 {
						isExist = true
					}
					break
				}
			}

			if !isExist {
				tempRevocaAddrs = append(tempRevocaAddrs, validator.Addr)
			}
			isExist = false
		}
		for _, v := range tempRevocaAddrs {
			info, _ := worm.GetAccountInfo(context.Background(), v.String(), int64(i-1))
			t.Log(v.Hex(), info.Worm.Coefficient, info.Balance)
		}
		revocationAddrs = append(revocationAddrs, tempRevocaAddrs...)
		lastValidators = lastValidators[:0]
		lastValidators = append(lastValidators, validatorsAcc.Staker.Validators.Validators...)
	}
	t.Log("\n-----------------------------------------------------\n")
	t.Log("revocation  address number = ", len(revocationAddrs))
	for _, v := range revocationAddrs {
		t.Log(v.Hex())
	}
}

func TestGetAccountInfo2(t *testing.T) {
	worm := client.NewClient(priKey, endpoint)
	base, _ := new(big.Int).SetString("1000000000000000000", 10)
	currentBlockNumber, _ := worm.BlockNumber(context.Background())
	t.Log("currentBlockNumber = ", currentBlockNumber)
	address := common.HexToAddress("0x9169f9f2D108158667088C6E1073058393392Ec3")
	acc, _ := worm.GetAccountInfo(context.Background(), address.Hex(), int64(currentBlockNumber))
	ValidatorStorageAddress := common.HexToAddress("0x0000000000000000000000000000000000000002")
	validators, _ := worm.GetAccountInfo(context.Background(), ValidatorStorageAddress.Hex(), int64(currentBlockNumber))
	validatorBalance := new(big.Int)
	for _, v := range validators.Staker.Validators.Validators {
		if v.Addr == address {
			validatorBalance.Set(v.Balance)
			break
		}
	}

	t.Log("address = ", address.Hex())
	t.Log("balance = ", new(big.Int).Div(acc.Balance, base), acc.Balance)
	t.Log("pledged balance = ", new(big.Int).Div(acc.Worm.PledgedBalance, base), acc.Worm.PledgedBalance)
	t.Log("validator balance = ", new(big.Int).Div(validatorBalance, base), validatorBalance)

	t.Log("\n\n------------------------------------------------\n")
	var num int
	for _, v := range validators.Staker.Validators.Validators {
		if new(big.Int).Div(v.Balance, base).Cmp(big.NewInt(100000)) > 0 {
			num++
		}
		info, _ := worm.GetAccountInfo(context.Background(), v.Addr.Hex(), int64(currentBlockNumber))
		t.Log("validator balance = ", new(big.Int).Div(v.Balance, base), v.Balance,
			"pledged balance = ", new(big.Int).Div(info.Worm.PledgedBalance, base), info.Worm.PledgedBalance)
	}

	t.Log("num = ", num)

	t.Log("\n\n------------------------------------------------\n")
	for _, v := range validators.Staker.Validators.Validators {
		info, _ := worm.GetAccountInfo(context.Background(), v.Addr.Hex(), int64(currentBlockNumber))
		if new(big.Int).Div(info.Worm.PledgedBalance, base).Cmp(big.NewInt(70000)) < 0 {
			t.Log(v.Addr.Hex(), "validator balance = ", new(big.Int).Div(v.Balance, base), v.Balance,
				"pledged balance = ", new(big.Int).Div(info.Worm.PledgedBalance, base), info.Worm.PledgedBalance)
		}
	}
}

func TestGetAllWeights(t *testing.T) {
	ValidatorStorageAddress := common.HexToAddress("0x0000000000000000000000000000000000000002")
	base, _ := new(big.Int).SetString("1000000000000000000", 10)
	worm := client.NewClient(priKey, endpoint)
	currentBlockNumber, _ := worm.BlockNumber(context.Background())
	t.Log("currentBlockNumber = ", currentBlockNumber)
	validatorsAcc, _ := worm.GetAccountInfo(context.Background(), ValidatorStorageAddress.String(), int64(currentBlockNumber))
	t.Log("validators len = ", len(validatorsAcc.Staker.Validators.Validators))
	var num int
	for _, v := range validatorsAcc.Staker.Validators.Validators {
		info, _ := worm.GetAccountInfo(context.Background(), v.Addr.Hex(), int64(currentBlockNumber))
		if info.Worm.PledgedBalance.Cmp(v.Balance) != 0 {
			t.Log("validator address = ", v.Addr.Hex(), new(big.Int).Div(v.Balance, base))
		}

		//if info.Worm.Coefficient != 70 {
		//	num++
		//	t.Log("validator address = ", v.Addr.Hex(),
		//		"Coefficient = ", info.Worm.Coefficient)
		//}
	}
	t.Log("num = ", num)
}

func TestGet16Weights(t *testing.T) {
	worm := client.NewClient(priKey, endpoint)
	base, _ := new(big.Int).SetString("1000000000000000000", 10)
	currentBlockNumber, _ := worm.BlockNumber(context.Background())
	addrs := []string{
		"0x091DBBa95B26793515cc9aCB9bEb5124c479f27F",
		"0x107837Ea83f8f06533DDd3fC39451Cd0AA8DA8BD",
		"0x612DFa56DcA1F581Ed34b9c60Da86f1268Ab6349",
		"0x84d84e6073A06B6e784241a9B13aA824AB455326",
		"0x9e4d5C72569465270232ed7Af71981Ee82d08dBF",
		"0xa270bBDFf450EbbC2d0413026De5545864a1b6d6",
		"0x4110E56ED25e21267FBeEf79244f47ada4e2E963",
		"0xdb33217fE3F74bD41c550B06B624E23ab7f55d05",
		"0xE2FA892CC5CC268a0cC1d924EC907C796351C645",
		"0x52EAE6D396E82358D703BEDeC2ab11E723127230",
		"0x31534d5C7b1eabb73425c2361661b878F4322f9D",
		"0xbbaE84E9879F908700c6ef5D15e928Abfb556a21",
		"0x20cb28AE861c322A9A86b4F9e36Ad6977930fA05",
		"0xFfAc4cd934f026dcAF0f9d9EEDDcD9af85D8943e",
		"0xc067825f4B7a53Bb9f2Daf72fF22C8EE39736afF",
		"0x7bf72621Dd7C4Fe4AF77632e3177c08F53fdAF09",
	}

	for _, addr := range addrs {
		info, _ := worm.GetAccountInfo(context.Background(), addr, int64(currentBlockNumber))
		//t.Log(addr, info.Worm.Coefficient)
		t.Log("validator address = ", new(big.Int).Div(info.Worm.PledgedBalance, base))
	}
}

func TestAnalysisPunish(t *testing.T) {
	ValidatorStorageAddress := common.HexToAddress("0x0000000000000000000000000000000000000002")
	base, _ := new(big.Int).SetString("1000000000000000000", 10)
	worm := client.NewClient(priKey, endpoint)
	currentBlockNumber, _ := worm.BlockNumber(context.Background())
	t.Log("currentBlockNumber = ", currentBlockNumber)
	validatorsAcc, _ := worm.GetAccountInfo(context.Background(), ValidatorStorageAddress.String(), 621111)
	t.Log("validators len = ", len(validatorsAcc.Staker.Validators.Validators))
	var num int

	//punishAddr := common.HexToAddress("0x8520dc57a2800e417696bdf93553e63bcf31e597")

	punishAddrs := []common.Address{
		common.HexToAddress("0xa270bbdff450ebbc2d0413026de5545864a1b6d6"),
		common.HexToAddress("0x52eae6d396e82358d703bedec2ab11e723127230"),
		common.HexToAddress("0xdb33217fe3f74bd41c550b06b624e23ab7f55d05"),
		common.HexToAddress("0x66f9e46b49eddc40f0da18d67c07ae755b3643ce"),
		common.HexToAddress("0x107837ea83f8f06533ddd3fc39451cd0aa8da8bd"),
		common.HexToAddress("0xbad3f0edd751b3b8def4aaddbcf5533ec93452c2"),
		common.HexToAddress("0x8520dc57a2800e417696bdf93553e63bcf31e597"),
	}

	var punishValidators []common.Address

	for _, v := range validatorsAcc.Staker.Validators.Validators {
		//info, _ := worm.GetAccountInfo(context.Background(), v.Addr.Hex(), int64(currentBlockNumber))
		//if info.Worm.PledgedBalance.Cmp(v.Balance) != 0 {
		//	t.Log("validator address = ", v.Addr.Hex(), new(big.Int).Div(v.Balance, base))
		//}

		for _, punishAddr := range punishAddrs {
			if v.Addr == punishAddr || v.Proxy == punishAddr {
				t.Log("validator address = ", v.Addr.Hex(), new(big.Int).Div(v.Balance, base),
					"proxy", v.Proxy.Hex())
				punishValidators = append(punishValidators, v.Addr)

			}

		}

		//if info.Worm.Coefficient != 70 {
		//	num++
		//	t.Log("validator address = ", v.Addr.Hex(),
		//		"Coefficient = ", info.Worm.Coefficient)
		//}
	}

	t.Log("------------------------------------------------------------------------")

	for _, v := range punishValidators {
		beforeInfo, _ := worm.GetAccountInfo(context.Background(), v.Hex(), 621110)
		afterInfo, _ := worm.GetAccountInfo(context.Background(), v.Hex(), 621111)
		t.Log("***************************************************************************************")
		t.Log("address = ", v.Hex(), "pledgebalance", new(big.Int).Div(beforeInfo.Worm.PledgedBalance, base), new(big.Int).Div(afterInfo.Worm.PledgedBalance, base))
		for _, staker := range beforeInfo.Worm.StakerExtension.StakerExtensions {
			t.Log("before address = ", staker.Addr.Hex(), new(big.Int).Div(staker.Balance, base))
		}
		for _, staker := range afterInfo.Worm.StakerExtension.StakerExtensions {
			t.Log("after address = ", staker.Addr.Hex(), new(big.Int).Div(staker.Balance, base))
		}
		t.Log("***************************************************************************************")
	}

	t.Log("num = ", num)
}

func TestGetValidators(t *testing.T) {
	ValidatorStorageAddress := common.HexToAddress("0x0000000000000000000000000000000000000002")
	base, _ := new(big.Int).SetString("1000000000000000000", 10)
	worm := client.NewClient(priKey, endpoint)
	currentBlockNumber, _ := worm.BlockNumber(context.Background())
	t.Log("currentBlockNumber = ", currentBlockNumber)

	validatorsAcc, _ := worm.GetAccountInfo(context.Background(), ValidatorStorageAddress.String(), int64(currentBlockNumber))
	//validatorsAcc, _ := worm.GetAccountInfo(context.Background(), ValidatorStorageAddress.String(), 649999)
	t.Log("validators len = ", len(validatorsAcc.Staker.Validators.Validators))
	for _, v := range validatorsAcc.Staker.Validators.Validators {
		//t.Log("validator address = ", v.Addr.Hex(), new(big.Int).Div(v.Balance, base),
		//	"proxy", v.Proxy.Hex())

		info, _ := worm.GetAccountInfo(context.Background(), v.Addr.Hex(), int64(currentBlockNumber))
		if info.Worm.PledgedBalance.Cmp(v.Balance) != 0 {
			t.Log("validator address = ", v.Addr.Hex(), new(big.Int).Div(v.Balance, base), new(big.Int).Div(info.Worm.PledgedBalance, base))
		}

		//info, _ := worm.GetAccountInfo(context.Background(), v.Addr.Hex(), int64(currentBlockNumber))
		//if info.Worm.PledgedBalance.Cmp(v.Balance) != 0 {
		//	t.Log("validator address = ", v.Addr.Hex(), new(big.Int).Div(v.Balance, base), new(big.Int).Div(info.Worm.PledgedBalance, base))
		//	if info.Worm.PledgedBalance.Cmp(big.NewInt(0)) != 0 {
		//		for _, staker := range info.Worm.StakerExtension.StakerExtensions {
		//			t.Log("after address = ", staker.Addr.Hex(), new(big.Int).Div(staker.Balance, base))
		//		}
		//	}
		//}
	}
}

func TestAnalysisPledgedBalance(t *testing.T) {
	ValidatorStorageAddress := common.HexToAddress("0x0000000000000000000000000000000000000002")
	StakerStorageAddress := common.HexToAddress("0x0000000000000000000000000000000000000003")
	base, _ := new(big.Int).SetString("1000000000000000000", 10)
	worm := client.NewClient(priKey, endpoint)
	currentBlockNumber, _ := worm.BlockNumber(context.Background())
	t.Log("currentBlockNumber = ", currentBlockNumber)

	validatorsAcc, _ := worm.GetAccountInfo(context.Background(), ValidatorStorageAddress.String(), int64(currentBlockNumber))
	stakersAcc, _ := worm.GetAccountInfo(context.Background(), StakerStorageAddress.String(), int64(currentBlockNumber))
	//validatorsAcc, _ := worm.GetAccountInfo(context.Background(), ValidatorStorageAddress.String(), 649999)
	for _, v := range validatorsAcc.Staker.Validators.Validators {
		//t.Log("validator address = ", v.Addr.Hex(), new(big.Int).Div(v.Balance, base),
		//	"proxy", v.Proxy.Hex())

		//info, _ := worm.GetAccountInfo(context.Background(), v.Addr.Hex(), int64(currentBlockNumber))
		//if info.Worm.PledgedBalance.Cmp(v.Balance) != 0 {
		//	t.Log("validator address = ", v.Addr.Hex(), new(big.Int).Div(v.Balance, base), new(big.Int).Div(info.Worm.PledgedBalance, base))
		//}

		info, _ := worm.GetAccountInfo(context.Background(), v.Addr.Hex(), int64(currentBlockNumber))
		if info.Worm.PledgedBalance.Cmp(v.Balance) != 0 {
			//t.Log("validator address = ", v.Addr.Hex(), new(big.Int).Div(v.Balance, base), new(big.Int).Div(info.Worm.PledgedBalance, base))
			if info.Worm.PledgedBalance.Cmp(big.NewInt(0)) != 0 {
				//for _, staker := range info.Worm.StakerExtension.StakerExtensions {
				//	t.Log("after address = ", staker.Addr.Hex(), new(big.Int).Div(staker.Balance, base))
				//}
				sum := big.NewInt(0)
				for _, s := range stakersAcc.Staker.CSBTCreators.Stakers {
					info, _ := worm.GetAccountInfo(context.Background(), s.Addr.Hex(), int64(currentBlockNumber))
					for _, staker := range info.Worm.StakerExtension.StakerExtensions {
						if staker.Addr == v.Addr {
							sum.Add(sum, staker.Balance)
						}
						t.Log("staker address = ", s.Addr.Hex(), new(big.Int).Div(staker.Balance, base))
					}
				}

				t.Log("validator address = ", v.Addr.Hex(), new(big.Int).Div(v.Balance, base),
					new(big.Int).Div(info.Worm.PledgedBalance, base),
					new(big.Int).Div(sum, base))

			}
		}
	}
}
