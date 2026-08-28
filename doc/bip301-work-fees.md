# Work-priced BIP301 bids

The Elements candidate producer prices deterministic TapSimplicity validation
work before it submits an M8/BMM bid:

    maximum bid = candidate policy-asset fees
                - ceil(simplicity milliweight * work rate / 1,000,000)
                - producer reserve

The divisor converts milliweight to thousands of validation-weight units.
Candidate fees and work are derived from the block template; they are not
estimated from transaction byte size. A candidate is not submitted when it
cannot fund a positive bid after its verification charge and reserve.

Relevant options:

    drivechainbmmworksatsperkwu=1000
    drivechainbmmproducerreserve=0
    drivechainbmmwalletaddr=127.0.0.1:30301
    drivechainbmmconnectauthcookie=<BitWindow auth cookie path>

The getblocktemplate RPC reports producerfeerevenuesats,
simplicityworkmilliweight, and bmmworkfeequote. The funded parent-chain bid is
created by BitWindow's
cusf.mainchain.v1.WalletService/CreateBmmCriticalDataTransaction bridge. The
sidechain coinbase pays the candidate's policy-asset fees to its producer, so
the producer both funds the M8 bid and retains the verification charge and
configured reserve.

The validator endpoint and wallet endpoint are intentionally separate:
drivechainbmmgrpcaddr is used for public validation data, while
drivechainbmmwalletaddr is the authenticated local wallet bridge.
