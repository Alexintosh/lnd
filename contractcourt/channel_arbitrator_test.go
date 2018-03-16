package contractcourt

import (
	"crypto/sha256"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/lightningnetwork/lnd/chainntnfs"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/roasbeef/btcd/btcec"
	"github.com/roasbeef/btcd/chaincfg/chainhash"
	"github.com/roasbeef/btcd/txscript"
	"github.com/roasbeef/btcd/wire"
)

type mockChainIO struct{}

func (*mockChainIO) GetBestBlock() (*chainhash.Hash, int32, error) {
	return nil, 0, nil
}

func (*mockChainIO) GetUtxo(op *wire.OutPoint,
	heightHint uint32) (*wire.TxOut, error) {
	return nil, nil
}

func (*mockChainIO) GetBlockHash(blockHeight int64) (*chainhash.Hash, error) {
	return nil, nil
}

func (*mockChainIO) GetBlock(blockHash *chainhash.Hash) (*wire.MsgBlock, error) {
	return nil, nil
}

type mockSigner struct {
	key *btcec.PrivateKey
}

func (m *mockSigner) SignOutputRaw(tx *wire.MsgTx, signDesc *lnwallet.SignDescriptor) ([]byte, error) {
	amt := signDesc.Output.Value
	witnessScript := signDesc.WitnessScript
	privKey := m.key

	if !privKey.PubKey().IsEqual(signDesc.KeyDesc.PubKey) {
		return nil, fmt.Errorf("incorrect key passed")
	}

	switch {
	case signDesc.SingleTweak != nil:
		privKey = lnwallet.TweakPrivKey(privKey,
			signDesc.SingleTweak)
	case signDesc.DoubleTweak != nil:
		privKey = lnwallet.DeriveRevocationPrivKey(privKey,
			signDesc.DoubleTweak)
	}

	sig, err := txscript.RawTxInWitnessSignature(tx, signDesc.SigHashes,
		signDesc.InputIndex, amt, witnessScript, signDesc.HashType,
		privKey)
	if err != nil {
		return nil, err
	}

	return sig[:len(sig)-1], nil
}
func (m *mockSigner) ComputeInputScript(tx *wire.MsgTx, signDesc *lnwallet.SignDescriptor) (*lnwallet.InputScript, error) {

	// TODO(roasbeef): expose tweaked signer from lnwallet so don't need to
	// duplicate this code?

	privKey := m.key

	switch {
	case signDesc.SingleTweak != nil:
		privKey = lnwallet.TweakPrivKey(privKey,
			signDesc.SingleTweak)
	case signDesc.DoubleTweak != nil:
		privKey = lnwallet.DeriveRevocationPrivKey(privKey,
			signDesc.DoubleTweak)
	}

	witnessScript, err := txscript.WitnessSignature(tx, signDesc.SigHashes,
		signDesc.InputIndex, signDesc.Output.Value, signDesc.Output.PkScript,
		signDesc.HashType, privKey, true)
	if err != nil {
		return nil, err
	}

	return &lnwallet.InputScript{
		Witness: witnessScript,
	}, nil
}

type mockPreimageCache struct {
	sync.Mutex
	preimageMap map[[32]byte][]byte
}

func (m *mockPreimageCache) LookupPreimage(hash []byte) ([]byte, bool) {
	m.Lock()
	defer m.Unlock()

	var h [32]byte
	copy(h[:], hash)

	p, ok := m.preimageMap[h]
	return p, ok
}

func (m *mockPreimageCache) AddPreimage(preimage []byte) error {
	m.Lock()
	defer m.Unlock()

	m.preimageMap[sha256.Sum256(preimage[:])] = preimage

	return nil
}

func (m *mockPreimageCache) SubscribeUpdates() *WitnessSubscription {
	return nil
}

func createTestChannel() (*channeldb.OpenChannel, error) {

	channel := &channeldb.OpenChannel{}
	return channel, nil
}

func createTestChannelArbitrator() (*ChannelArbitrator, chan struct{}, func(), error) {
	blockEpoch := &chainntnfs.BlockEpochEvent{
		Cancel: func() {},
	}

	chanPoint := wire.OutPoint{}
	shortChanID := lnwire.ShortChannelID{}
	chanEvents := &ChainEventSubscription{
		RemoteUnilateralClosure: make(chan *lnwallet.UnilateralCloseSummary, 1),
		CooperativeClosure:      make(chan struct{}, 1),
		LocalUnilateralClosure:  make(chan struct{}, 1),
		ContractBreach:          make(chan *lnwallet.BreachRetribution, 1),
	}

	chainIO := &mockChainIO{}
	chainArbCfg := ChainArbitratorConfig{
		//Notifier: notifier,
		ChainIO: chainIO,
		PublishTx: func(*wire.MsgTx) error {
			return nil
		},
	}

	resolvedChan := make(chan struct{}, 1)

	// Next we'll create the matching configuration struct that contains
	// all interfaces and methods the arbitrator needs to do its job.
	arbCfg := ChannelArbitratorConfig{
		ChanPoint:   chanPoint,
		ShortChanID: shortChanID,
		BlockEpochs: blockEpoch,
		//	ForceCloseChan: func() (*lnwallet.ForceCloseSummary, error) {
		//		return nil, nil
		//	},
		CloseChannel: func(summary *channeldb.ChannelCloseSummary) error {
			return nil
		},
		MarkChannelResolved: func() error {
			resolvedChan <- struct{}{}
			return nil
		},
		MarkLinkInactive: func() error {
			return nil
		},
		ForceCloseSummary: func() (*lnwallet.ForceCloseSummary, error) {
			summary := &lnwallet.ForceCloseSummary{
				CloseTx:         &wire.MsgTx{},
				HtlcResolutions: &lnwallet.HtlcResolutions{},
			}
			return summary, nil
		},

		ChainArbitratorConfig: chainArbCfg,
		ChainEvents:           chanEvents,
	}
	testLog, cleanUp, err := newTestBoltArbLog(
		testChainHash, testChanPoint1,
	)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("unable to create test log: %v", err)
	}

	//	arbCfg.MarkChannelResolved = func() error {
	//		return c.resolveContract(chanPoint, chanLog)
	//	}

	return NewChannelArbitrator(
		arbCfg, nil, testLog,
	), resolvedChan, cleanUp, nil

}

func assertState(t *testing.T, c *ChannelArbitrator, expected ArbitratorState) {
	if c.state != expected {
		t.Fatalf("expected state %v, was %v", expected, c.state)
	}
}

func TestChannelArbitratorCooperativeClose(t *testing.T) {
	chanArb, _, cleanUp, err := createTestChannelArbitrator()
	if err != nil {
		t.Fatalf("unable to create ChannelArbitrator: %v", err)
	}
	defer cleanUp()

	if err := chanArb.Start(); err != nil {
		t.Fatalf("unable to start ChannelArbitrator: %v", err)
	}
	defer chanArb.Stop()

	// It should start out in the default state.
	assertState(t, chanArb, StateDefault)

	// Cooperative close should do nothing.
	// TODO: this will change.
	chanArb.cfg.ChainEvents.CooperativeClosure <- struct{}{}
	assertState(t, chanArb, StateDefault)
}

func TestChannelArbitratorRemoteForceClose(t *testing.T) {
	chanArb, resolved, cleanUp, err := createTestChannelArbitrator()
	if err != nil {
		t.Fatalf("unable to create ChannelArbitrator: %v", err)
	}
	defer cleanUp()

	if err := chanArb.Start(); err != nil {
		t.Fatalf("unable to start ChannelArbitrator: %v", err)
	}
	defer chanArb.Stop()

	// It should start out in the default state.
	assertState(t, chanArb, StateDefault)

	//	channel, err := createTestChannel()
	//	if err != nil {
	//		t.Fatalf("error. %v", err)
	//	}
	//
	//signer := &mockSigner{}
	//pCache := &mockPreimageCache{}
	commitSpend := &chainntnfs.SpendDetail{
		SpenderTxHash: &chainhash.Hash{},
	}
	//remoteCommit := channeldb.ChannelCommitment{}
	//	uniClose, err := lnwallet.NewUnilateralCloseSummary(channel,
	//		signer, pCache, commitSpend, remoteCommit,
	//	)
	//	if err != nil {
	//		t.Fatalf("error: %v", err)
	//	}

	uniClose := &lnwallet.UnilateralCloseSummary{
		SpendDetail:     commitSpend,
		HtlcResolutions: &lnwallet.HtlcResolutions{},
	}
	chanArb.cfg.ChainEvents.RemoteUnilateralClosure <- uniClose

	select {
	case <-resolved:
		// Expected.
	case <-time.After(5 * time.Second):
		t.Fatalf("contract was not resolved")
	}

	time.Sleep(300 * time.Millisecond)
	assertState(t, chanArb, StateFullyResolved)
}

func TestChannelArbitratorLocalForceClose(t *testing.T) {
	chanArb, _, cleanUp, err := createTestChannelArbitrator()
	if err != nil {
		t.Fatalf("unable to create ChannelArbitrator: %v", err)
	}
	defer cleanUp()

	if err := chanArb.Start(); err != nil {
		t.Fatalf("unable to start ChannelArbitrator: %v", err)
	}
	defer chanArb.Stop()

	// It should start out in the default state.
	assertState(t, chanArb, StateDefault)

	stateChan := make(chan ArbitratorState)

	chanArb.cfg.PublishTx = func(*wire.MsgTx) error {
		// When the force close tx is being broadcasted, check that the
		// state is correct at that point.
		stateChan <- chanArb.state
		return nil
	}

	errChan := make(chan error, 1)
	respChan := make(chan *wire.MsgTx, 1)

	// With the channel found, and the request crafted, we'll send over a
	// force close request to the arbitrator that watches this channel.
	chanArb.forceCloseReqs <- &forceCloseReq{
		errResp: errChan,
		closeTx: respChan,
	}

	select {
	case state := <-stateChan:
		if state != StateBroadcastCommit {
			t.Fatalf("state during PublishTx was %v", state)
		}
	}

	select {
	case <-respChan:
	case err := <-errChan:
		t.Fatalf("error force closing channel: %v", err)
	}

	time.Sleep(300 * time.Millisecond)
	assertState(t, chanArb, StateCommitmentBroadcasted)

	fmt.Println("sending local unilaterla")
	chanArb.cfg.ChainEvents.LocalUnilateralClosure <- struct{}{}
	fmt.Println("done sending local unilaterla")
	time.Sleep(500 * time.Millisecond)

	// TODO: intermediate states as well.
	assertState(t, chanArb, StateFullyResolved)
}

func TestChannelArbitratorLocalForceCloseRemoteConfirmed(t *testing.T) {
	chanArb, resolved, cleanUp, err := createTestChannelArbitrator()
	if err != nil {
		t.Fatalf("unable to create ChannelArbitrator: %v", err)
	}
	defer cleanUp()

	if err := chanArb.Start(); err != nil {
		t.Fatalf("unable to start ChannelArbitrator: %v", err)
	}
	defer chanArb.Stop()

	// It should start out in the default state.
	assertState(t, chanArb, StateDefault)

	stateChan := make(chan ArbitratorState)

	chanArb.cfg.PublishTx = func(*wire.MsgTx) error {
		// When the force close tx is being broadcasted, check that the
		// state is correct at that point.
		stateChan <- chanArb.state
		return nil
	}

	errChan := make(chan error, 1)
	respChan := make(chan *wire.MsgTx, 1)

	// With the channel found, and the request crafted, we'll send over a
	// force close request to the arbitrator that watches this channel.
	chanArb.forceCloseReqs <- &forceCloseReq{
		errResp: errChan,
		closeTx: respChan,
	}

	select {
	case state := <-stateChan:
		if state != StateBroadcastCommit {
			t.Fatalf("state during PublishTx was %v", state)
		}
	}

	select {
	case <-respChan:
	case err := <-errChan:
		t.Fatalf("error force closing channel: %v", err)
	}

	time.Sleep(300 * time.Millisecond)
	assertState(t, chanArb, StateCommitmentBroadcasted)

	commitSpend := &chainntnfs.SpendDetail{
		SpenderTxHash: &chainhash.Hash{},
	}
	uniClose := &lnwallet.UnilateralCloseSummary{
		SpendDetail:     commitSpend,
		HtlcResolutions: &lnwallet.HtlcResolutions{},
	}
	chanArb.cfg.ChainEvents.RemoteUnilateralClosure <- uniClose

	select {
	case <-resolved:
		// Expected.
	case <-time.After(5 * time.Second):
		t.Fatalf("contract was not resolved")
	}
	time.Sleep(500 * time.Millisecond)

	// TODO: intermediate states as well.
	assertState(t, chanArb, StateFullyResolved)
}
