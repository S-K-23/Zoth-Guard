// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title Price Oracle Interface
 * @author ZeUSD Protocol Team
 * @notice Interface for price feed oracles used in the protocol
 * @dev Compatible with Chainlink and similar oracle implementations
 */
interface IPriceOracle {
    /**
     * @notice Gets the latest price data from the oracle
     * @dev Returns comprehensive round data including timestamps
     * @return roundId Identifier for the price update round
     * @return answer The price value (typically scaled by decimals)
     * @return startedAt Timestamp when the round started
     * @return updatedAt Timestamp of the last update
     * @return answeredInRound Round in which the answer was computed
     * @custom:security Critical for accurate price feeds
     */
    function latestRoundData()
        external
        view
        returns (
            uint80 roundId,
            int256 answer,
            uint256 startedAt,
            uint256 updatedAt,
            uint80 answeredInRound
        );
}
