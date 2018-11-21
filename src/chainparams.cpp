// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "arith_uint256.h"
#include "chainparams.h"
#include "consensus/merkle.h"

#include "tinyformat.h"
#include "util.h"
#include "utilstrencodings.h"

#include <assert.h>

#include <boost/assign/list_of.hpp>

#include "chainparamsseeds.h"


static CBlock CreateGenesisBlock(const char* pszTimestamp, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.nTime    = nTime;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 0 << CScriptNum(42) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].SetEmpty();;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);

    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion)
{
    const char* pszTimestamp = "14/Apr/2014 No chowder for you, cause clams have feelings too";
    return CreateGenesisBlock(pszTimestamp, nTime, nNonce, nBits, nVersion);
}

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        //consensus.nSubsidyHalvingInterval = 985500; // qtum halving every 4 years
        consensus.BIP34Height = 0;
        consensus.BIP34Hash = uint256S("0x00000c3ce6b3d823a35224a39798eca9ad889966aeb5a9da7b960ffb9869db35");
        consensus.BIP65Height = 0; // 
        consensus.BIP66Height = 0; // 
        //consensus.powLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit = 0x1E0FFFFF;
        consensus.posLimit = 0x1E0FFFFF;
        consensus.fPowNoRetargeting = true;
        consensus.fPoSNoRetargeting = false;
        consensus.nCoinbaseMaturity = 500;

        consensus.fPowAllowMinDifficultyBlocks = false;


        consensus.nRuleChangeActivationThreshold = 1916; // 95% of 2016
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing

        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 999999999999ULL;

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 999999999999ULL;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000000000000010000"); 

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00000000000000000013176bf8d7dfeab4e1db31dc93bc311b436e82ab226b90"); //453354

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0x03;
        pchMessageStart[1] = 0x22;
        pchMessageStart[2] = 0x35;
        pchMessageStart[3] = 0x15;
        nDefaultPort = 31174; // mainnet
        nPruneAfterHeight = 100000;

        genesis = CreateGenesisBlock(1397512438, 2054231, 0x1E0FFFFF, 1);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x00000c3ce6b3d823a35224a39798eca9ad889966aeb5a9da7b960ffb9869db35"));
        assert(genesis.hashMerkleRoot == uint256S("0xef10b32afd53e4a6ebb8bdb0486c6acbe9b43afe3dfa538e913b89bb1319ff96"));

        // push peer seeders running this network crawler: https://github.com/dooglus/bitcoin-seeder/tree/clam
        vSeeds.push_back(CDNSSeedData("clam.just-dice.com"   , "clam.just-dice.com"   , false)); // mainnet
        vSeeds.push_back(CDNSSeedData("clam.freebitcoins.com", "clam.freebitcoins.com", false)); // mainnet


        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,137);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,13);
        //CLAM Secret key, from old base58.h (release 1.4.2.1)  == 5 + 128
        base58Prefixes[SECRET_KEY]     = std::vector<unsigned char>(1,133);
        //BTC, LTC and DOGE secret keys
        base58Prefixes[SECRET_KEY_BTC] = std::vector<unsigned char>(1,128);
        base58Prefixes[SECRET_KEY_LTC] = std::vector<unsigned char>(1,176);
        base58Prefixes[SECRET_KEY_DOGE] = std::vector<unsigned char>(1,158);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x88)(0xB2)(0x1E).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x88)(0xAD)(0xE4).convert_to_container<std::vector<unsigned char> >();

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;

        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            (    5000, uint256S("0x0000062a14145c32edd657a1576087c183312a62ccb59883cfab5eb5e8e2f984") )
            (   10000, uint256S("0x00000de398b1ec72c393c5c54574a1e1784eb178d683e1ad0856c12fac34f603") )
            (   20000, uint256S("0xe83f9c8d6f07222274e4a7105437ac2d297455f6b19f77766e8c528356283677") )
            (  100000, uint256S("0x41148b9796e65ddbefea175f6372b2448fc2f6b22b66da64fc3a15d29c8ed843") )
            (  200001, uint256S("0xc9228ec146f5a959c3e6d183419157a7c53d8a07e1dd810f8c478d66f71ac493") ) // block 199999's time is later than the following 2 blocks
            (  300000, uint256S("0x144de2a2169e1a98e0b121bfdd7cdee6192dba71c10cde65e785e39f00f05c2b") )
            (  400000, uint256S("0x6ec2869889333270e1eb549bfe5d19b6423ad8b36a05807a71d2301accfadf0b") )
            (  500000, uint256S("0xaf388da4175404ebac7be210e1ed092e4e283d167505db617f009d9bc56f42fc") )
            (  600000, uint256S("0x7b8e45a49a80036e6001d56332202d87354bcf6f29c52f2dd5616a92cdbcb587") )
            (  700000, uint256S("0x8bec13dbec630f40ed510698ec530610ab4941b6c98f7ccab89728b071c685a0") )
            (  800000, uint256S("0xfe190fa9449f261552325e4e771a4745373a062c4b4478e303b931787f16cfb3") )
            (  900000, uint256S("0x179c18fad48240b7ee5bea0b58ad4ba430ac73c585098d32d0704edf9e86e762") )
            ( 1000000, uint256S("0x4bb58b747f305b04d7f71946a9650b059a58f26b44ec05b1f8bd211424c5a586") )
            ( 1100000, uint256S("0x7ae10e91b28df2ffbc085c10304886b0494be3fad331c7eb90163298df79c3d0") )
            ( 1200000, uint256S("0xea14770cc6c3221bd846d47616dde32cf542714328beb17a1a0caace1c3f45a5") )
            ( 1300000, uint256S("0x75b89e41b2329c07d2f7bf20dd57c42be0b9c6bbe8f4efb1bdbfa94866ee9c1c") )
            ( 1400000, uint256S("0x0302c17f034ba74d1effa776bacb8d00e33d7943b24658d87e1284973462f5e4") )
            ( 1500000, uint256S("0x2aea9081720f4c04208967f190ddeb942cac4b712ccad2e4e34fbfba08369486") )
            ( 1600000, uint256S("0x4a2352b132204bc47681d6f1dd38762bda3fb65510b3e80ffd39b37502d80baa") )
            ( 1700000, uint256S("0xd7107cd318b223801951a7b8da481c64caaccf0ee973cb7c1e59987e6dccd2bc") )
            ( 1800000, uint256S("0x1a98f3ae87de517a53ba0de643f31f055a22cb2060238904285a5920371b9b8e") )
            ( 1900000, uint256S("0xcc31b05431c8bc4866ce0e3ba3e0cd9d8535c5028f1a7e08678201bcb580030b") )
            ( 2000000, uint256S("0xeec5059373725515e2423c15661978d55ff08b2a139f16ebcebf5c01fcdaf813") )
            ( 2100000, uint256S("0x2803ef082f2a5b1d95984949fd404c01f6848794ce51cbdb074b390c4a422a93") )
            ( 2200000, uint256S("0xfc3f25c1bd27e2a20a5fa0f3fd9f235249063a6eda726e7a7e7af741591e3e5c") )
            ( 2280000, uint256S("0x37558d2153a41e277bf9c9393cf9b41fe318e4c766b3e16c55b51c01e7423048") )
        };

        chainTxData = ChainTxData{
            // Data as of block 37558d2153a41e277bf9c9393cf9b41fe318e4c766b3e16c55b51c01e7423048 (height 2280000).
            1541345216, // * UNIX timestamp of last known number of transactions
            5642352,    // * total number of transactions between genesis and that timestamp
                        //   (the tx=... number in the SetBestChain debug.log lines)
            0.034       // * estimated number of transactions per second after that timestamp
        };


        consensus.nTargetSpacing = 1 * 5; // 5 Seconds, this was only used to the inital PoW and distrubution
        consensus.nTargetStakeSpacing = 1 * 60; // 60 seconds
        consensus.nStakeMinAge = 4 * 60 * 60; // 4 hours
        consensus.nStakeMaxAge = -1; // unlimited
        consensus.nModifierInterval = 10 * 60; // time to elapse before new modifier is computed
        consensus.nTargetTimespan = 16 * 60;  // 16 mins

        consensus.nProtocolV2Height = 203500;
        consensus.nProtocolV3Height = 9999999;

        consensus.DISTRIBUTION_END = 10000;
        consensus.LAST_POW_BLOCK = 10000;
        consensus.COIN_YEAR_REWARD = 1 * 1000000; // 1% per year
        consensus.LOTTERY_START = 34000;
        consensus.LOTTERY_END = 170000;

    }
};
static CMainParams mainParams;

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        consensus.BIP34Height = 0;
        consensus.BIP34Hash = uint256S("0x00001924120e93f445dd4adb9d90e0020350b8c6c2b08e1a4950372a37f8bcc8");
        consensus.BIP65Height = 0; // 00000000007f6655f22f98e72ed80d8b06dc761d5da09df0fa1dc4be4f861eb6
        consensus.BIP66Height = 0; // 000000002104c8c45e99a8853285a3b592602a3ccde2b832481da85e9e4ba182
        consensus.powLimit = 0x1f00ffff; //0x1E00FFFF
        consensus.posLimit = 0x1E0FFFFF;


        consensus.nTargetSpacing = 1 * 5; // 5 Seconds, this was only used to the inital PoW and distrubution
        consensus.nTargetStakeSpacing = 1 * 60; // 60 seconds
        consensus.nStakeMinAge = 1 * 30 * 60; // 30 minutes
        consensus.nStakeMaxAge = -1; // unlimited
        consensus.nModifierInterval = 10 * 60; // time to elapse before new modifier is computed
        consensus.nTargetTimespan = 16 * 60;  // 16 mins

        consensus.DISTRIBUTION_END = 300;
        consensus.LAST_POW_BLOCK = 300;
        consensus.nProtocolV2Height = -1;
        consensus.nProtocolV3Height = 3000000;

        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = true;
        consensus.fPoSNoRetargeting = false;
        consensus.nCoinbaseMaturity = 10;

        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        //consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
       // consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        //consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 999999999999ULL;

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 999999999999ULL;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000000000000010000");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00001924120e93f445dd4adb9d90e0020350b8c6c2b08e1a4950372a37f8bcc8");

        pchMessageStart[0] = 0xc4;
        pchMessageStart[1] = 0xf1;
        pchMessageStart[2] = 0xc0;
        pchMessageStart[3] = 0xdf;
        nDefaultPort = 35714; // testnet
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1397512438, 15165, 0x1f00ffff, 1);
        consensus.hashGenesisBlock = genesis.GetHash();

        assert(consensus.hashGenesisBlock == uint256S("0x00001924120e93f445dd4adb9d90e0020350b8c6c2b08e1a4950372a37f8bcc8"));
        assert(genesis.hashMerkleRoot == uint256S("0xef10b32afd53e4a6ebb8bdb0486c6acbe9b43afe3dfa538e913b89bb1319ff96"));

        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;


        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            ( 0, uint256S("0x00001924120e93f445dd4adb9d90e0020350b8c6c2b08e1a4950372a37f8bcc8")),
        };

        chainTxData = ChainTxData{
            // Data as of block 00000000c2872f8f8a8935c8e3c5862be9038c97d4de2cf37ed496991166928a (height 1063660)
            0,
            0,
            0
        };



    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        consensus.nSubsidyHalvingInterval = 150;
        consensus.BIP34Height = 0; // BIP34 has not activated on regtest (far in the future so block v1 are not rejected in tests) // 
        consensus.BIP34Hash = uint256S("0x00001924120e93f445dd4adb9d90e0020350b8c6c2b08e1a4950372a37f8bcc8");
        consensus.BIP65Height = 0; // BIP65 activated on regtest (Used in rpc activation tests)
        consensus.BIP66Height = 0; // BIP66 activated on regtest (Used in rpc activation tests)
        consensus.powLimit = 0x1E0FFFFF;
        consensus.posLimit = 0x1E0FFFFF;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.fPoSNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 999999999999ULL;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xbf;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0xda;
        nDefaultPort = 18444; // regtest
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1397512438, 15165, 0x1f00ffff, 1);
        consensus.hashGenesisBlock = genesis.GetHash();

        assert(consensus.hashGenesisBlock == uint256S("0x00001924120e93f445dd4adb9d90e0020350b8c6c2b08e1a4950372a37f8bcc8"));
        assert(genesis.hashMerkleRoot == uint256S("0xef10b32afd53e4a6ebb8bdb0486c6acbe9b43afe3dfa538e913b89bb1319ff96"));
        
        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;

        checkpointData = (CCheckpointData){
            boost::assign::map_list_of
            ( 0, uint256S("0x00001924120e93f445dd4adb9d90e0020350b8c6c2b08e1a4950372a37f8bcc8"))
        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,120);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,110);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();
    }

    void UpdateBIP9Parameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
    {
        consensus.vDeployments[d].nStartTime = nStartTime;
        consensus.vDeployments[d].nTimeout = nTimeout;
    }
};
static CRegTestParams regTestParams;

static CChainParams *pCurrentParams = 0;

const CChainParams &Params() {
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams& Params(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
            return mainParams;
    else if (chain == CBaseChainParams::TESTNET)
            return testNetParams;
    else if (chain == CBaseChainParams::REGTEST)
            return regTestParams;
    else
        throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    pCurrentParams = &Params(network);
}

void UpdateRegtestBIP9Parameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    regTestParams.UpdateBIP9Parameters(d, nStartTime, nTimeout);
}
 
