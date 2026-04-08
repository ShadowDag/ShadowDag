// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// DEX Order Book — On-chain decentralized exchange primitives.
//
// Provides native order book functionality for trustless trading
// without requiring smart contracts or Layer 2 solutions.
//
// Kaspa has NO native DEX — requires external solutions.
// ShadowDAG integrates DEX primitives directly into the protocol.
//
// Features:
//   - Limit orders (buy/sell at specific price)
//   - Market orders (best available price)
//   - Order matching engine (price-time priority)
//   - Partial fills
//   - Order cancellation
//   - Fee distribution to miners
// ═══════════════════════════════════════════════════════════════════════════

use std::collections::BTreeMap;
use serde::{Serialize, Deserialize};
use crate::errors::DexError;

/// Order side
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OrderSide {
    Buy,
    Sell,
}

/// Order type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OrderType {
    Limit,
    Market,
}

/// Order status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OrderStatus {
    Open,
    PartiallyFilled,
    Filled,
    Cancelled,
}

/// A trading pair (e.g., SDAG/USDT, TOKEN_A/SDAG)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TradingPair {
    pub base:  String,  // e.g., "SDAG"
    pub quote: String,  // e.g., "USDT"
}

impl TradingPair {
    pub fn new(base: &str, quote: &str) -> Self {
        Self { base: base.to_string(), quote: quote.to_string() }
    }

    pub fn symbol(&self) -> String {
        format!("{}/{}", self.base, self.quote)
    }
}

/// An order in the order book
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Order {
    pub id:          String,
    pub owner:       String,
    pub pair:        TradingPair,
    pub side:        OrderSide,
    pub order_type:  OrderType,
    pub price:       u64,     // Price in quote currency satoshis
    pub amount:      u64,     // Amount in base currency satoshis
    pub filled:      u64,     // Amount already filled
    pub status:      OrderStatus,
    pub timestamp:   u64,
    pub block_height: u64,
}

impl Order {
    pub fn remaining(&self) -> u64 {
        self.amount.saturating_sub(self.filled)
    }

    pub fn is_fully_filled(&self) -> bool {
        self.filled >= self.amount
    }
}

/// Trade execution result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Trade {
    pub buy_order_id:  String,
    pub sell_order_id: String,
    pub price:         u64,
    pub amount:        u64,
    pub timestamp:     u64,
}

/// Order book for a single trading pair
pub struct OrderBook {
    pub pair:    TradingPair,
    /// Buy orders sorted by price descending (highest first)
    bids:        BTreeMap<u64, Vec<Order>>,
    /// Sell orders sorted by price ascending (lowest first)
    asks:        BTreeMap<u64, Vec<Order>>,
    /// Total trades executed
    trade_count: u64,
}

impl OrderBook {
    pub fn new(pair: TradingPair) -> Self {
        Self {
            pair,
            bids: BTreeMap::new(),
            asks: BTreeMap::new(),
            trade_count: 0,
        }
    }

    /// Place an order (limit or market) into the book.
    ///
    /// Market orders match immediately and any unfilled remainder is
    /// cancelled rather than posted to the book.
    pub fn place_order(&mut self, order: Order) -> Result<Vec<Trade>, DexError> {
        // Validate that the order's trading pair matches this book
        if order.pair.base != self.pair.base || order.pair.quote != self.pair.quote {
            return Err(DexError::PairNotFound(format!(
                "order pair {}/{} != book pair {}/{}",
                order.pair.base, order.pair.quote, self.pair.base, self.pair.quote
            )));
        }

        let mut trades = Vec::new();
        let mut remaining = order.clone();

        match order.side {
            OrderSide::Buy => {
                // Match against asks (lowest first)
                let mut matched_prices = Vec::new();
                for (&ask_price, ask_orders) in self.asks.iter_mut() {
                    if order.order_type != OrderType::Market && ask_price > order.price {
                        break; // Limit orders respect price ceiling
                    }
                    for ask in ask_orders.iter_mut() {
                        if remaining.remaining() == 0 { break; }
                        let fill = remaining.remaining().min(ask.remaining());
                        remaining.filled += fill;
                        ask.filled += fill;
                        if ask.is_fully_filled() { ask.status = OrderStatus::Filled; }
                        else { ask.status = OrderStatus::PartiallyFilled; }

                        self.trade_count += 1;
                        trades.push(Trade {
                            buy_order_id: order.id.clone(),
                            sell_order_id: ask.id.clone(),
                            price: ask_price,
                            amount: fill,
                            timestamp: order.timestamp,
                        });
                    }
                    ask_orders.retain(|o| !o.is_fully_filled());
                    if ask_orders.is_empty() { matched_prices.push(ask_price); }
                }
                for p in matched_prices { self.asks.remove(&p); }

                // Market orders: remaining unfilled quantity is cancelled, not posted
                if remaining.order_type == OrderType::Market {
                    if remaining.remaining() > 0 {
                        remaining.status = OrderStatus::Cancelled;
                    }
                    return Ok(trades);
                }

                // Place remaining as limit order
                if remaining.remaining() > 0 {
                    remaining.status = if remaining.filled > 0 { OrderStatus::PartiallyFilled } else { OrderStatus::Open };
                    self.bids.entry(order.price).or_default().push(remaining);
                }
            }
            OrderSide::Sell => {
                // Match against bids (highest first)
                let mut matched_prices = Vec::new();
                for (&bid_price, bid_orders) in self.bids.iter_mut().rev() {
                    if order.order_type != OrderType::Market && bid_price < order.price {
                        break; // Limit orders respect price floor
                    }
                    for bid in bid_orders.iter_mut() {
                        if remaining.remaining() == 0 { break; }
                        let fill = remaining.remaining().min(bid.remaining());
                        remaining.filled += fill;
                        bid.filled += fill;
                        if bid.is_fully_filled() { bid.status = OrderStatus::Filled; }
                        else { bid.status = OrderStatus::PartiallyFilled; }

                        self.trade_count += 1;
                        trades.push(Trade {
                            buy_order_id: bid.id.clone(),
                            sell_order_id: order.id.clone(),
                            price: bid_price,
                            amount: fill,
                            timestamp: order.timestamp,
                        });
                    }
                    bid_orders.retain(|o| !o.is_fully_filled());
                    if bid_orders.is_empty() { matched_prices.push(bid_price); }
                }
                for p in matched_prices { self.bids.remove(&p); }

                // Market orders: remaining unfilled quantity is cancelled, not posted
                if remaining.order_type == OrderType::Market {
                    if remaining.remaining() > 0 {
                        remaining.status = OrderStatus::Cancelled;
                    }
                    return Ok(trades);
                }

                if remaining.remaining() > 0 {
                    remaining.status = if remaining.filled > 0 { OrderStatus::PartiallyFilled } else { OrderStatus::Open };
                    self.asks.entry(order.price).or_default().push(remaining);
                }
            }
        }
        Ok(trades)
    }

    /// Cancel an order by ID
    pub fn cancel_order(&mut self, order_id: &str) -> bool {
        let mut found = false;
        self.bids.retain(|_, orders| {
            if let Some(pos) = orders.iter().position(|o| o.id == order_id) {
                orders.remove(pos);
                found = true;
            }
            !orders.is_empty()
        });
        if found { return true; }
        self.asks.retain(|_, orders| {
            if let Some(pos) = orders.iter().position(|o| o.id == order_id) {
                orders.remove(pos);
                found = true;
            }
            !orders.is_empty()
        });
        found
    }

    /// Get best bid price
    pub fn best_bid(&self) -> Option<u64> {
        self.bids.keys().next_back().copied()
    }

    /// Get best ask price
    pub fn best_ask(&self) -> Option<u64> {
        self.asks.keys().next().copied()
    }

    /// Get spread
    pub fn spread(&self) -> Option<u64> {
        match (self.best_bid(), self.best_ask()) {
            (Some(bid), Some(ask)) if ask > bid => Some(ask - bid),
            _ => None,
        }
    }

    /// Get order book depth
    pub fn depth(&self) -> (usize, usize) {
        let bid_depth: usize = self.bids.values().map(|v| v.len()).sum();
        let ask_depth: usize = self.asks.values().map(|v| v.len()).sum();
        (bid_depth, ask_depth)
    }

    pub fn trade_count(&self) -> u64 { self.trade_count }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_order(id: &str, side: OrderSide, price: u64, amount: u64) -> Order {
        Order {
            id: id.to_string(), owner: "SD1test".to_string(),
            pair: TradingPair::new("SDAG", "USDT"),
            side, order_type: OrderType::Limit,
            price, amount, filled: 0,
            status: OrderStatus::Open, timestamp: 0, block_height: 0,
        }
    }

    #[test]
    fn place_and_match_orders() {
        let mut book = OrderBook::new(TradingPair::new("SDAG", "USDT"));

        // Place sell at 100
        book.place_order(make_order("s1", OrderSide::Sell, 100, 500)).unwrap();
        assert_eq!(book.best_ask(), Some(100));

        // Place buy at 100 → should match
        let trades = book.place_order(make_order("b1", OrderSide::Buy, 100, 300)).unwrap();
        assert_eq!(trades.len(), 1);
        assert_eq!(trades[0].amount, 300);
        assert_eq!(trades[0].price, 100);
    }

    #[test]
    fn partial_fill() {
        let mut book = OrderBook::new(TradingPair::new("SDAG", "USDT"));
        book.place_order(make_order("s1", OrderSide::Sell, 50, 1000)).unwrap();
        let trades = book.place_order(make_order("b1", OrderSide::Buy, 50, 400)).unwrap();
        assert_eq!(trades.len(), 1);
        assert_eq!(trades[0].amount, 400);
        // 600 remaining on sell side
        let (_, ask_depth) = book.depth();
        assert_eq!(ask_depth, 1);
    }

    #[test]
    fn cancel_order() {
        let mut book = OrderBook::new(TradingPair::new("SDAG", "USDT"));
        book.place_order(make_order("s1", OrderSide::Sell, 100, 500)).unwrap();
        assert!(book.cancel_order("s1"));
        assert_eq!(book.best_ask(), None);
    }

    #[test]
    fn spread_calculation() {
        let mut book = OrderBook::new(TradingPair::new("SDAG", "USDT"));
        book.place_order(make_order("b1", OrderSide::Buy, 95, 100)).unwrap();
        book.place_order(make_order("s1", OrderSide::Sell, 105, 100)).unwrap();
        assert_eq!(book.spread(), Some(10));
    }

    #[test]
    fn no_match_when_prices_dont_cross() {
        let mut book = OrderBook::new(TradingPair::new("SDAG", "USDT"));
        book.place_order(make_order("s1", OrderSide::Sell, 100, 500)).unwrap();
        let trades = book.place_order(make_order("b1", OrderSide::Buy, 90, 300)).unwrap();
        assert!(trades.is_empty()); // buy at 90, sell at 100 → no match
    }
}
