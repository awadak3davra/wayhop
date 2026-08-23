package server

// pbrKernelTable is the content-addressed execution artifact's dedicated nft table. It is kept
// outside the retired legacy reconciler because host observation and capability reporting still
// need the canonical table name.
const pbrKernelTable = "wayhop_pbr"
