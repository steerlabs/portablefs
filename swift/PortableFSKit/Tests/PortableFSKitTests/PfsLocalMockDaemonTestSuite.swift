import Testing

/// Socket-backed integration tests share one process-local scheduling budget.
/// Keeping them in one serialized suite prevents Swift Testing from multiplying
/// blocking accept/read loops across otherwise independent test cases, while
/// pure value and protocol tests remain parallel.
@Suite(.serialized)
struct PfsLocalMockDaemonTests {}
