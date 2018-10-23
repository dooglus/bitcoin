// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "pow.h"

#include "arith_uint256.h"
#include "chain.h"

#include "chainparams.h"
#include "consensus/params.h"
#include "consensus/consensus.h"

#include "primitives/block.h"
#include "uint256.h"
#include "util.h"

// ppcoin: find last block index up to pindex
const CBlockIndex* GetLastBlockIndex(const CBlockIndex* pindex, bool fProofOfStake)
{
    //CBlockIndex will be updated with information about the proof type later
    while (pindex && pindex->pprev && (pindex->IsProofOfStake() != fProofOfStake))
        pindex = pindex->pprev;
    return pindex;
}

inline arith_uint256 GetLimit(const Consensus::Params& params, bool fProofOfStake)
{
    arith_uint256 bnTargetLimit;
    if(fProofOfStake) 
        return bnTargetLimit.SetCompact(params.posLimit);
    else 
        return bnTargetLimit.SetCompact(params.powLimit);
}

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const Consensus::Params& params, bool fProofOfStake)
{
    if (!pindexLast)
        return params.powLimit;
    
    if (pindexLast->nHeight < params.DISTRIBUTION_END && Params().NetworkIDString() == "main")
        return GetNextTargetRequiredV1(pindexLast, params, fProofOfStake);
    else if (pindexLast->nHeight <= params.nProtocolV2Height && Params().NetworkIDString() == "main")
        return GetNextTargetRequiredV2(pindexLast, params, fProofOfStake);
    else    
        return GetNextTargetRequiredV3(pindexLast, params, fProofOfStake);
}

unsigned int GetNextTargetRequiredV1(const CBlockIndex* pindexLast, const Consensus::Params& params, bool fProofOfStake)
{
    arith_uint256 bnTargetLimit;
    bnTargetLimit.SetCompact(params.powLimit);
    
    int64_t currentTargetSpacing = params.nTargetSpacing;
 
    if (pindexLast == NULL)
        return bnTargetLimit.GetCompact(); // genesis block
 
    const CBlockIndex* pindexPrev = GetLastBlockIndex(pindexLast, fProofOfStake);
    if (pindexPrev->pprev == NULL)
        return bnTargetLimit.GetCompact(); // first block
    const CBlockIndex* pindexPrevPrev = GetLastBlockIndex(pindexPrev->pprev, fProofOfStake);
    if (pindexPrevPrev->pprev == NULL)
        return bnTargetLimit.GetCompact(); // second block
 
    int64_t nActualSpacing = pindexPrev->GetBlockTime() - pindexPrevPrev->GetBlockTime();
    if (nActualSpacing < 0)
        nActualSpacing = currentTargetSpacing;
 
    // ppcoin: target change every block
    // ppcoin: retarget with exponential moving toward target spacing
    arith_uint256 bnNew;
    bnNew.SetCompact(pindexPrev->nBits);
    int64_t nInterval = params.nTargetTimespan / params.nTargetSpacing;
    bnNew *= ((nInterval - 1) * currentTargetSpacing + nActualSpacing + nActualSpacing);
    bnNew /= ((nInterval + 1) * currentTargetSpacing);
 
    if (bnNew <= 0 || bnNew > bnTargetLimit)
        bnNew = bnTargetLimit;

    return bnNew.GetCompact();
}
 
unsigned int GetNextTargetRequiredV2(const CBlockIndex* pindexLast, const Consensus::Params& params, bool fProofOfStake)
{
    arith_uint256 bnTargetLimit;
    if(fProofOfStake) {
        bnTargetLimit.SetCompact(params.posLimit);
    }
    else {
        bnTargetLimit.SetCompact(params.powLimit);
    }

    int64_t currentTargetSpacing = params.nTargetStakeSpacing;
 

    if (pindexLast == NULL)
        return bnTargetLimit.GetCompact(); // genesis block
 
    const CBlockIndex* pindexPrev = GetLastBlockIndex(pindexLast, fProofOfStake);
    if (pindexPrev->pprev == NULL)
        return bnTargetLimit.GetCompact(); // first block
    const CBlockIndex* pindexPrevPrev = GetLastBlockIndex(pindexPrev->pprev, fProofOfStake);
    if (pindexPrevPrev->pprev == NULL)
        return bnTargetLimit.GetCompact(); // second block
 
    int64_t nActualSpacing = pindexPrev->GetBlockTime() - pindexPrevPrev->GetBlockTime();
    if (nActualSpacing < 0)
        nActualSpacing = currentTargetSpacing;
 


    // ppcoin: target change every block
    // ppcoin: retarget with exponential moving toward target spacing
    arith_uint256 bnNew;
    bnNew.SetCompact(pindexPrev->nBits);
    int64_t nInterval = params.nTargetTimespan / currentTargetSpacing;
    bnNew *= ((nInterval - 1) * currentTargetSpacing + nActualSpacing + nActualSpacing);
    bnNew /= ((nInterval + 1) * currentTargetSpacing);
 
    if (bnNew <= 0 || bnNew > bnTargetLimit)
        bnNew = bnTargetLimit;
 
    return bnNew.GetCompact();
}

unsigned int GetNextTargetRequiredV3(const CBlockIndex* pindexLast, const Consensus::Params& params, bool fProofOfStake)
{
    arith_uint256 bnTargetLimit;
    if(fProofOfStake) {
        bnTargetLimit.SetCompact(params.posLimit);
    }
    else {
        bnTargetLimit.SetCompact(params.powLimit);
    }


    const CBlockIndex* pindex;
    const CBlockIndex* pindexPrevPrev = NULL;

    if (pindexLast == NULL)
        return bnTargetLimit.GetCompact(); // genesis block
 
    const CBlockIndex* pindexPrev = GetLastBlockIndex(pindexLast, fProofOfStake);


    int64_t nInterval = (params.nTargetTimespan / params.nTargetStakeSpacing) * 4;
    int64_t count = 0;

    for (pindex = pindexPrev; pindex && pindex->nHeight && count < nInterval; pindex = GetLastBlockIndex(pindex, fProofOfStake))
    {
        pindexPrevPrev = pindex;
        pindex = pindex->pprev;
        if (!pindex) break;
        count++;
        pindex = GetLastBlockIndex(pindex, fProofOfStake);
    }

    if (!pindex || !pindex->nHeight)
        count--;

    count--;

    if (count < 1)
        return bnTargetLimit.GetCompact(); // not enough blocks yet
 
    int64_t nActualSpacing = (pindexPrev->GetBlockTime() - pindexPrevPrev->GetBlockTime()) / count;

    /*
    if (0)
        LogPrintf("nctualSpacing = ((block %d) %"PRId64" - (block %d) %"PRId64") / %"PRId64" = %"PRId64" / %"PRId64" = %"PRId64"\n",
               pindexPrev    ->nHeight, pindexPrev    ->GetBlockTime(),
               pindexPrevPrev->nHeight, pindexPrevPrev->GetBlockTime(),
               count,
               (pindexPrev->GetBlockTime() - pindexPrevPrev->GetBlockTime()), count,
               nActualSpacing);
    */

    if (nActualSpacing < 0) nActualSpacing = params.nTargetStakeSpacing;

    arith_uint256 bnNew;
    bnNew.SetCompact(pindexPrev->nBits);
    bnNew *= ((nInterval - 1) * params.nTargetStakeSpacing + 2 * nActualSpacing);
    bnNew /= ((nInterval + 1) * params.nTargetStakeSpacing);
 
    if (bnNew <= 0 || bnNew > bnTargetLimit)
        bnNew = bnTargetLimit;
 

    //LogPrintf("xploited GetNextTargetRequired V3: %d %d %d %d\n", bnNew.GetCompact(), nActualSpacing, nInterval, params.nTargetStakeSpacing);
    return bnNew.GetCompact();
}

bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params, bool fProofOfStake)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    arith_uint256 limit;
    limit.SetCompact(params.powLimit);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > limit)
        return false;

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return false;

    return true;
}




