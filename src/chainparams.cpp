// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>

#include <chainparamsseeds.h>
#include <consensus/merkle.h>
#include <deploymentinfo.h>
#include <hash.h>
#include <script/interpreter.h>
#include <util/string.h>
#include <util/system.h>

#include <assert.h>

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

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

static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "BitSteal Genesis - Freedom Currency for All";
    const CScript genesisOutputScript = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

/**
 * BitSteal main network
 */
class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "bitsteal";
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.nSubsidyHalvingInterval = 210000;
        
        // 모든 소프트포크를 처음부터 활성화
        consensus.BIP34Height = 1;
        consensus.BIP34Hash = uint256{};
        consensus.BIP65Height = 1;
        consensus.BIP66Height = 1;
        consensus.CSVHeight = 1;
        consensus.SegwitHeight = 1;
        consensus.MinBIP9WarningHeight = 1;
        
        consensus.powLimit = uint256S("0000ffff00000000000000000000000000000000000000000000000000000000");
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // 2주
        consensus.nPowTargetSpacing = 10 * 60; // 10분
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1815;
        consensus.nMinerConfirmationWindow = 2016;
        
        // Taproot 활성화
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0;

        // 체인 워크와 검증 블록 초기화
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000000000000000001");
        consensus.defaultAssumeValid = uint256{};

        // BitSteal 네트워크 메시지 시작 바이트
        pchMessageStart[0] = 0xe2;
        pchMessageStart[1] = 0xc3;
        pchMessageStart[2] = 0xa9;
        pchMessageStart[3] = 0xfc;
        nDefaultPort = 8333;

        // DNS Seeds 제거 (자체 네트워크)
        vSeeds.clear();

        // BitSteal 제네시스 블록 생성
        genesis = CreateGenesisBlock(1753150989, 178391, 0x1f00ffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();

        // 제네시스 블록 해시 검증 (실제 마이닝 후 업데이트 필요)
        // assert(consensus.hashGenesisBlock == uint256S("0x00007d7ec8a58ec236b39852d8e744233a297dfde7c8b1e31a3d74d74dfe2ed9"));
        // assert(genesis.hashMerkleRoot == uint256S("0xc58250dd67353779e63f8071309ba61f3e0bcb875471630a481915b778430309"));

        // BitSteal 주소 프리픽스 (Bitcoin과 구별)
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,25);  // 'B'로 시작
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,85);  // 'b'로 시작  
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,153);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1F};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE5};

        bech32_hrp = "bs"; // BitSteal bech32 prefix

        vFixedSeeds = std::vector<uint8_t>();

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        m_is_test_chain = false;
        m_is_mockable_chain = false;

        // 체크포인트 (제네시스 블록만)
        checkpointData = {
            {
                {0, genesis.GetHash()},
            }
        };

        m_assumeutxo_data = MapAssumeutxo{};

        // 체인 트랜잭션 데이터
        chainTxData = ChainTxData{
            1753150989, // 제네시스 블록 시간
            1,          // 트랜잭션 수
            0.0         // 트랜잭션 비율
        };
    }
};

static std::unique_ptr<const CChainParams> globalChainParams;

const CChainParams &Params() {
    assert(globalChainParams);
    return *globalChainParams;
}

std::unique_ptr<const CChainParams> CreateChainParams(const ArgsManager& args, const std::string& chain)
{
    if (chain == "main" || chain == "bitsteal") {
        return std::unique_ptr<CChainParams>(new CMainParams());
    }
    throw std::runtime_error(strprintf("%s: Unknown chain %s. Only 'main' or 'bitsteal' supported.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    globalChainParams = CreateChainParams(gArgs, network);
}
