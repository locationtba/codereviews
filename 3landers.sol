// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/finance/PaymentSplitter.sol";
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/token/ERC721/extensions/ERC721Enumerable.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol";
import "@openzeppelin/contracts/utils/Address.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@chainlink/contracts/src/v0.8/VRFConsumerBase.sol";
import "./lib/BlockBasedSale.sol";
import "./lib/EIP712Whitelisting.sol";

contract OxStandard is
    Ownable,
    ERC721,
    ERC721Enumerable,
    EIP712Whitelisting,
    VRFConsumerBase,
    BlockBasedSale,
    ReentrancyGuard
{
    using Address for address;
    using SafeMath for uint256;

    event PermanentURI(string _value, uint256 indexed _id);
    event RandomseedRequested(uint256 timestamp);
    event RandomseedFulfilmentSuccess(
        uint256 timestamp,
        bytes32 requestId,
        uint256 seed
    );
    event RandomseedFulfilmentFail(uint256 timestamp, bytes32 requestId);
    event RandomseedFulfilmentManually(uint256 timestamp);

    enum SaleState {
        NotStarted,
        PrivateSaleBeforeWithoutBlock,
        PrivateSaleBeforeWithBlock,
        PrivateSaleDuring,
        PrivateSaleEnd,
        PrivateSaleEndSoldOut,
        PublicSaleBeforeWithoutBlock,
        PublicSaleBeforeWithBlock,
        PublicSaleDuring,
        PublicSaleEnd,
        PublicSaleEndSoldOut,
        PauseSale,
        AllSalesEnd
    }

    PaymentSplitter private _splitter;

    struct chainlinkParams {
        address coordinator;
        address linkToken;
        bytes32 keyHash;
    }

    struct revenueShareParams {
        address[] payees;
        uint256[] shares;
    }

    bool public randomseedRequested = false;
    bool public beneficiaryAssigned = false;

    bytes32 public keyHash;    

    
    uint256 public revealBlock = 0;
    uint256 public seed = 0;

    mapping(address => bool) private _airdropAllowed;
    mapping(address => uint256) private _privateSaleClaimed;

    string public _defaultURI;
    string public _tokenBaseURI;

    constructor(
        uint256 _privateSalePrice,
        uint256 _publicSalePrice,
        string memory name,
        string memory symbol,
        uint256 _maxSupply,
        chainlinkParams memory chainlink,
        revenueShareParams memory revenueShare
    )
        ERC721(name, symbol)
        VRFConsumerBase(chainlink.coordinator, chainlink.linkToken)
    {
        _splitter = new PaymentSplitter(
            revenueShare.payees,
            revenueShare.shares
        );
        keyHash = chainlink.keyHash;
        maxSupply = _maxSupply;
        publicSalePrice = _publicSalePrice;
        privateSalePrice = _privateSalePrice;
    }

    address private beneficiaryAddress;

    modifier airdropRoleOnly() {
        require(_airdropAllowed[msg.sender], "Only airdrop role allowed.");
        _;
    }
    
    modifier beneficiaryOnly() {
        require(
            beneficiaryAssigned && msg.sender == beneficiaryAddress,
            "Only beneficiary allowed."
        );
        _;
    }

    function airdrop(address[] memory addresses, uint256 amount)
        external
        airdropRoleOnly
    {
        require(
            totalSupply().add(addresses.length.mul(amount)) <= maxSupply,
            "Exceed max supply limit."
        );

        require(
            totalReserveMinted.add(addresses.length.mul(amount)) <= maxReserve,
            "Insufficient reserve."
        );

        for (uint256 i = 0; i < addresses.length; i++) {
            _mintToken(addresses[i], amount);
        }

        totalReserveMinted = totalReserveMinted.add(
            addresses.length.mul(amount)
        );
    }

    function setAirdropRole(address addr) external onlyOwner {
        _airdropAllowed[addr] = true;
    }

    function getMarketState() external pure returns (SaleState) {
        return SaleState.NotStarted;
    }

    function setRevealBlock(uint256 blockNumber) external onlyOwner {
        revealBlock = blockNumber;
    }

    function freeze(uint256[] memory ids) external onlyOwner {
        for (uint256 i = 0; i < ids.length; i += 1) {
            emit PermanentURI(tokenURI(ids[i]), ids[i]);
        }
    }

    function mintToken(uint256 amount, bytes calldata signature)
        external
        payable
        nonReentrant
        returns (bool)
    {
        require(!msg.sender.isContract(), "Contract is not allowed.");
        require(
            getState() == SaleState.PrivateSaleDuring ||
                getState() == SaleState.PublicSaleDuring,
            "Sale not available."
        );

        if (getState() == SaleState.PublicSaleDuring) {
            require(
                amount <= maxPublicSalePerTx,
                "Mint exceed transaction limits."
            );
            require(
                msg.value >= amount.mul(getPriceByMode()),
                "Insufficient funds."
            );
            require(
                totalSupply().add(amount).add(availableReserve()) <= maxSupply,
                "Purchase exceed max supply."
            );
        }

        if (getState() == SaleState.PrivateSaleDuring) {
            require(isEIP712WhiteListed(signature), "Not whitelisted.");
            require(
                amount <= maxPrivateSalePerTx,
                "Mint exceed transaction limits"
            );
            require(
                _privateSaleClaimed[msg.sender] + amount <=
                    maxWhitelistClaimPerWallet,
                "Mint limit per wallet exceeded."
            );
            require(
                totalPrivateSaleMinted.add(amount) <= privateSaleCapped,
                "Purchase exceed private sale capped."
            );

            require(
                msg.value >= amount.mul(getPriceByMode()),
                "Insufficient funds."
            );
        }

        if (
            getState() == SaleState.PrivateSaleDuring ||
            getState() == SaleState.PublicSaleDuring
        ) {
            _mintToken(msg.sender, amount);
            if (getState() == SaleState.PublicSaleDuring) {
                totalPublicMinted = totalPublicMinted + amount;
            }
            if (getState() == SaleState.PrivateSaleDuring) {
                _privateSaleClaimed[msg.sender] =
                    _privateSaleClaimed[msg.sender] +
                    amount;
                totalPrivateSaleMinted = totalPrivateSaleMinted + amount;
            }
            payable(_splitter).transfer(msg.value);
        }

        return true;
    }

    function setSeed(uint256 randomNumber) external onlyOwner {
        randomseedRequested = true;
        seed = randomNumber;
        emit RandomseedFulfilmentManually(block.timestamp);
    }

    function setBaseURI(string memory baseURI) external onlyOwner {
        _tokenBaseURI = baseURI;
    }

    function setDefaultURI(string memory defaultURI) external onlyOwner {
        _defaultURI = defaultURI;
    }

    function requestChainlinkVRF() external onlyOwner {
        require(!randomseedRequested, "Chainlink VRF already requested");
        require(
            LINK.balanceOf(address(this)) >= 2000000000000000000,
            "Insufficient LINK"
        );
        requestRandomness(keyHash, 2000000000000000000);
        randomseedRequested = true;
        emit RandomseedRequested(block.timestamp);
    }

    function getState() public view returns (SaleState) {
        uint256 supplyWithoutReserve = maxSupply - maxReserve;
        uint256 mintedWithoutReserve = totalPublicMinted +
            totalPrivateSaleMinted;

        if (
            salePhase != SalePhase.None &&
            overridedSaleState == OverrideSaleState.Close
        ) {
            return SaleState.AllSalesEnd;
        }

        if (
            salePhase != SalePhase.None &&
            overridedSaleState == OverrideSaleState.Pause
        ) {
            return SaleState.PauseSale;
        }

        if (
            salePhase == SalePhase.Public &&
            mintedWithoutReserve == supplyWithoutReserve
        ) {
            return SaleState.PublicSaleEndSoldOut;
        }

        if (salePhase == SalePhase.None) {
            return SaleState.NotStarted;
        }

        if (
            salePhase == SalePhase.Public &&
            publicSale.endBlock > 0 &&
            block.number > publicSale.endBlock
        ) {
            return SaleState.PublicSaleEnd;
        }

        if (
            salePhase == SalePhase.Public &&
            publicSale.beginBlock > 0 &&
            block.number >= publicSale.beginBlock
        ) {
            return SaleState.PublicSaleDuring;
        }

        if (
            salePhase == SalePhase.Public &&
            publicSale.beginBlock > 0 &&
            block.number < publicSale.beginBlock &&
            block.number > privateSale.endBlock
        ) {
            return SaleState.PublicSaleBeforeWithBlock;
        }

        if (
            salePhase == SalePhase.Public &&
            publicSale.beginBlock == 0 &&
            block.number > privateSale.endBlock
        ) {
            return SaleState.PublicSaleBeforeWithoutBlock;
        }

        if (
            salePhase == SalePhase.Private &&
            totalPrivateSaleMinted == privateSaleCapped
        ) {
            return SaleState.PrivateSaleEndSoldOut;
        }

        if (
            salePhase == SalePhase.Private &&
            privateSale.endBlock > 0 &&
            block.number > privateSale.endBlock
        ) {
            return SaleState.PrivateSaleEnd;
        }

        if (
            salePhase == SalePhase.Private &&
            privateSale.beginBlock > 0 &&
            block.number >= privateSale.beginBlock
        ) {
            return SaleState.PrivateSaleDuring;
        }
        
        if (
            salePhase == SalePhase.Private &&
            privateSale.beginBlock > 0 &&
            block.number < privateSale.beginBlock
        ) {
            return SaleState.PrivateSaleBeforeWithBlock;
        }

        if (salePhase == SalePhase.Private && privateSale.beginBlock == 0) {
            return SaleState.PrivateSaleBeforeWithoutBlock;
        }

        return SaleState.NotStarted;
    }

    function getStartSaleBlock() external view returns (uint256) {
        if (
            SaleState.PrivateSaleBeforeWithBlock == getState() ||
            SaleState.PrivateSaleDuring == getState()
        ) {
            return privateSale.beginBlock;
        }

        if (
            SaleState.PublicSaleBeforeWithBlock == getState() ||
            SaleState.PublicSaleDuring == getState()
        ) {
            return publicSale.beginBlock;
        }

        return 0;
    }

    function getEndSaleBlock() external view returns (uint256) {
        if (
            SaleState.PrivateSaleBeforeWithBlock == getState() ||
            SaleState.PrivateSaleDuring == getState()
        ) {
            return privateSale.endBlock;
        }

        if (
            SaleState.PublicSaleBeforeWithBlock == getState() ||
            SaleState.PublicSaleDuring == getState()
        ) {
            return publicSale.endBlock;
        }

        return 0;
    }

    function tokenBaseURI() external view returns (string memory) {
        return _tokenBaseURI;
    }

    function isRevealed() public view returns (bool) {
        return seed > 0 && revealBlock > 0 && block.number > revealBlock;
    }

    function getMetadata(uint256 tokenId) public view returns (string memory) {
        if (_msgSender() != owner()) {
            require(tokenId < totalSupply(), "Token not exists.");
        }

        if (!isRevealed()) return "default";

        uint256[] memory metadata = new uint256[](maxSupply+1);

        for (uint256 i = 1; i <= maxSupply; i += 1) {
            metadata[i] = i;
        }

        for (uint256 i = 2; i <= maxSupply; i += 1) {
            uint256 j = (uint256(keccak256(abi.encode(seed, i))) % (maxSupply)) + 1;

            if(j>=2 && j<= maxSupply) {
                (metadata[i], metadata[j]) = (metadata[j], metadata[i]);
            }
        }

        return Strings.toString(metadata[tokenId]);
    }

    function tokenURI(uint256 tokenId)
        public
        view
        override(ERC721)
        returns (string memory)
    {
        require(tokenId < totalSupply()+1, "Token not exist.");

        return
            isRevealed()
                ? string(
                    abi.encodePacked(
                        _tokenBaseURI,
                        getMetadata(tokenId),
                        ".json"
                    )
                )
                : _defaultURI;
    }

    function availableReserve() public view returns (uint256) {
        return maxReserve - totalReserveMinted;
    }

    function getMaxSupplyByMode() public view returns (uint256) {
        if (getState() == SaleState.PrivateSaleDuring) return privateSaleCapped;
        if (getState() == SaleState.PublicSaleDuring)
            return maxSupply - totalPrivateSaleMinted - maxReserve;
        return 0;
    }

    function getMintedByMode() external view returns (uint256) {
        if (getState() == SaleState.PrivateSaleDuring)
            return totalPrivateSaleMinted;
        if (getState() == SaleState.PublicSaleDuring) return totalPublicMinted;
        return 0;
    }

    function getTransactionCappedByMode() external view returns (uint256) {
        return
            getState() == SaleState.PrivateSaleDuring
                ? maxPrivateSalePerTx
                : maxPublicSalePerTx;
    }

    function availableForSale() external view returns (uint256) {
        return maxSupply - totalSupply();
    }

    function getPriceByMode() public view returns (uint256) {
        if (getState() == SaleState.PrivateSaleDuring) return privateSalePrice;

        if (getState() == SaleState.PublicSaleDuring) {
            uint256 passedBlock = block.number - publicSale.beginBlock;
            uint256 discountPrice = passedBlock.div(discountBlockSize).mul(
                priceFactor
            );

            if (discountPrice >= publicSalePrice.sub(lowerBoundPrice)) {
                return lowerBoundPrice;
            } else {
                return publicSalePrice.sub(discountPrice);
            }
        }

        return publicSalePrice;
    }

    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override(ERC721, ERC721Enumerable)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }

    function startPublicSaleBlock() external view returns (uint256) {
        return publicSale.beginBlock;
    }

    function endPublicSaleBlock() external view returns (uint256) {
        return publicSale.endBlock;
    }

    function startPrivateSaleBlock() external view returns (uint256) {
        return privateSale.beginBlock;
    }

    function endPrivateSaleBlock() external view returns (uint256) {
        return privateSale.endBlock;
    }

    function release(address payable account) public virtual onlyOwner {
        _splitter.release(account);
    }

    function withdraw() external beneficiaryOnly {
        uint256 balance = address(this).balance;
        payable(msg.sender).transfer(balance);
    }

    function _mintToken(address addr, uint256 amount) internal returns (bool) {
        for (uint256 i = 0; i < amount; i++) {
            uint256 tokenIndex = totalSupply();
            if (tokenIndex < maxSupply) _safeMint(addr, tokenIndex +1);
        }
        return true;
    }

    function fulfillRandomness(bytes32 requestId, uint256 randomNumber)
        internal
        override
    {
        if (randomNumber > 0) {
            seed = randomNumber;
            emit RandomseedFulfilmentSuccess(block.timestamp, requestId, seed);
        } else {
            seed = 1;
            emit RandomseedFulfilmentFail(block.timestamp, requestId);
        }
    }

    function _beforeTokenTransfer(
        address from,
        address to,
        uint256 tokenId
    ) internal virtual override(ERC721, ERC721Enumerable) {
        super._beforeTokenTransfer(from, to, tokenId);
    }
}


// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol";

contract BlockBasedSale is Ownable {
    using SafeMath for uint256;

    enum OverrideSaleState {
        None,
        Pause,
        Close
    }

    enum SalePhase {
        None,
        Private,
        Public
    }

    OverrideSaleState public overridedSaleState = OverrideSaleState.None;
    SalePhase public salePhase = SalePhase.None;

    uint256 public maxPrivateSalePerTx = 10;
    uint256 public maxPublicSalePerTx = 20;
    uint256 public maxWhitelistClaimPerWallet = 10;

    uint256 public privateSaleCapped = 690;
    uint256 public totalPrivateSaleMinted = 0;
    uint256 public privateSalePrice;

    uint256 public totalPublicMinted = 0;
    uint256 public totalReserveMinted = 0;
    uint256 public maxSupply = 6969;
    uint256 public maxReserve = 169;

    uint256 public discountBlockSize = 180;
    uint256 public lowerBoundPrice = 0;
    uint256 public publicSalePrice;
    uint256 public priceFactor = 1337500000000000;

    struct SaleConfig {
        uint256 beginBlock;
        uint256 endBlock;
    }

    SaleConfig public privateSale;
    SaleConfig public publicSale;

    function setDiscountBlockSize(uint256 blockNumber) external onlyOwner {
        discountBlockSize = blockNumber;
    }

    function setPriceDecayParams(uint256 _lowerBoundPrice, uint256 _priceFactor) external onlyOwner{
        require(_lowerBoundPrice >= 0);
        require(_priceFactor <= publicSalePrice);
        lowerBoundPrice = _lowerBoundPrice;
        priceFactor = _priceFactor;
    }

    function setTransactionLimit(uint256 privateSaleLimit,uint256 publicSaleLimit, uint256 maxWhitelist) external onlyOwner {
        require(privateSaleLimit > 0);
        require(publicSaleLimit > 0);
        require(maxWhitelist <= privateSaleLimit);
        maxPrivateSalePerTx = privateSaleLimit;
        maxPublicSalePerTx = publicSaleLimit;
        maxWhitelistClaimPerWallet = maxWhitelist;
    }

    function setPrivateSaleConfig(SaleConfig memory _privateSale)
        external
        onlyOwner
    {
        privateSale = _privateSale;
    }

    function setPublicSaleConfig(SaleConfig memory _publicSale) external onlyOwner {
        publicSale = _publicSale;
    }

    function setPublicSalePrice(uint256 _price) external onlyOwner {
        publicSalePrice = _price;
    }

    function setPrivateSalePrice(uint256 _price) external onlyOwner {
        privateSalePrice = _price;
    }

    function setCloseSale() external onlyOwner {
        overridedSaleState = OverrideSaleState.Close;
    }

    function setPauseSale() external onlyOwner {
        overridedSaleState = OverrideSaleState.Pause;
    }

    function resetOverridedSaleState() external onlyOwner {
        overridedSaleState = OverrideSaleState.None;
    }

    function setReserve(uint256 reserve) external onlyOwner {
        maxReserve = reserve;
    }

    function setPrivateSaleCap(uint256 cap) external onlyOwner {
        privateSaleCapped = cap;
    }

    function isPrivateSaleSoldOut() external view returns (bool) {
        return totalPrivateSaleMinted == privateSaleCapped;
    }

    function isPublicSaleSoldOut() external view returns (bool) {
        uint256 supplyWithoutReserve = maxSupply - maxReserve;
        uint256 mintedWithoutReserve = totalPublicMinted +
            totalPrivateSaleMinted;
        return supplyWithoutReserve == mintedWithoutReserve;
    }

    function enablePublicSale() external onlyOwner {
        salePhase = SalePhase.Public;
    }

    function enablePrivateSale() external onlyOwner {
        salePhase = SalePhase.Private;
    }
}


// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract EIP712Whitelisting is Ownable {
    using ECDSA for bytes32;

    // The key used to sign whitelist signatures.
    // We will check to ensure that the key that signed the signature
    // is this one that we expect.
    address whitelistSigningKey = address(0);

    // Domain Separator is the EIP-712 defined structure that defines what contract
    // and chain these signatures can be used for.  This ensures people can't take
    // a signature used to mint on one contract and use it for another, or a signature
    // from testnet to replay on mainnet.
    // It has to be created in the constructor so we can dynamically grab the chainId.
    // https://github.com/ethereum/EIPs/blob/master/EIPS/eip-712.md#definition-of-domainseparator
    bytes32 public DOMAIN_SEPARATOR;

    // The typehash for the data type specified in the structured data
    // https://github.com/ethereum/EIPs/blob/master/EIPS/eip-712.md#rationale-for-typehash
    // This should match whats in the client side whitelist signing code
    bytes32 public constant MINTER_TYPEHASH =
        keccak256("Minter(address wallet)");

    constructor() {
        // This should match whats in the client side whitelist signing code
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256(
                    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                ),
                // This should match the domain you set in your client side signing.
                keccak256(bytes("WhitelistToken")),
                keccak256(bytes("1")),
                block.chainid,
                address(this)
            )
        );
    }

    function setWhitelistSigningAddress(address newSigningKey)
        public
        onlyOwner
    {
        whitelistSigningKey = newSigningKey;
    }

    modifier requiresWhitelist(bytes calldata signature) {
        require(whitelistSigningKey != address(0), "whitelist not enabled.");
        require(
            getEIP712RecoverAddress(signature) == whitelistSigningKey,
            "Not whitelisted."
        );
        _;
    }

    function isEIP712WhiteListed(bytes calldata signature)
        public
        view
        returns (bool)
    {
        require(whitelistSigningKey != address(0), "whitelist not enabled.");
        return getEIP712RecoverAddress(signature) == whitelistSigningKey;
    }

    function getEIP712RecoverAddress(bytes calldata signature)
        internal
        view
        returns (address)
    {
        // Verify EIP-712 signature by recreating the data structure
        // that we signed on the client side, and then using that to recover
        // the address that signed the signature for this data.
        // Signature begin with \x19\x01, see: https://eips.ethereum.org/EIPS/eip-712
        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                keccak256(abi.encode(MINTER_TYPEHASH, msg.sender))
            )
        );

        // Use the recover method to see what address was used to create
        // the signature on this data.
        // Note that if the digest doesn't exactly match what was signed we'll
        // get a random recovered address.
        return digest.recover(signature);
    }
}
