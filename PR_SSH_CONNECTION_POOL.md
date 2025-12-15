# SSH Connection Pooling for Validator Services

## Summary

This PR introduces an SSH connection pool to reduce the overhead of creating new SSH connections for each operation. The pool maintains reusable connections to executor machines, significantly improving performance for repeated operations.

## Problem

Currently, the validator creates a new SSH connection for every operation (container create, stop, start, delete, SSH key management, Jupyter installation). With 100+ executors being validated per cycle, this creates significant overhead:

- **Connection establishment latency**: Each `asyncssh.connect()` call involves TCP handshake, SSH handshake, and key exchange
- **Resource consumption**: Each connection consumes file descriptors and memory
- **Redundant work**: The same executor may be connected to multiple times within seconds

### Before (13 separate connection points):
```python
# Each method creates its own connection
async with asyncssh.connect(
    host=executor_info.address,
    port=executor_info.ssh_port,
    username=executor_info.ssh_username,
    client_keys=[pkey],
    known_hosts=None,
) as ssh_client:
    ...
```

## Solution

Implement an `SSHConnectionPool` that:

1. **Reuses connections** - Returns existing healthy connections instead of creating new ones
2. **TTL-based expiration** - Automatically expires connections after 5 minutes (configurable)
3. **Health checking** - Verifies connections are alive before returning them
4. **LRU eviction** - Evicts least-recently-used connections when pool is full
5. **Thread-safe** - Uses async locks for concurrent access
6. **Statistics tracking** - Provides hit rate, eviction count, and pool size metrics

### After:
```python
# Connections are reused from the pool
async with self.ssh_pool.get_connection(
    host=executor_info.address,
    port=executor_info.ssh_port,
    username=executor_info.ssh_username,
    private_key=private_key,
) as ssh_client:
    ...
```

## Changes

### New Files
- `neurons/validators/src/services/ssh_connection_pool.py` - Connection pool implementation
- `neurons/validators/tests/test_ssh_connection_pool.py` - Comprehensive unit tests

### Modified Files
- `neurons/validators/src/services/docker_service.py` - Updated 6 methods to use connection pool:
  - `create_container()`
  - `stop_container()`
  - `start_container()`
  - `delete_container()`
  - `install_jupyter_server()`
  - `remove_ssh_keys()`
  - `add_ssh_key()`

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     DockerService                            │
├─────────────────────────────────────────────────────────────┤
│  create_container()  │  stop_container()  │  start_container()│
│  delete_container()  │  add_ssh_key()     │  remove_ssh_keys()│
│  install_jupyter()   │                    │                   │
└──────────────┬───────────────────────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────────────────────┐
│                   SSHConnectionPool                          │
├─────────────────────────────────────────────────────────────┤
│  • max_connections: 50 (configurable)                        │
│  • connection_ttl: 300s (5 minutes)                          │
│  • idle_timeout: 60s                                         │
│  • health_check_interval: 30s                                │
├─────────────────────────────────────────────────────────────┤
│  Pool Storage: Dict[key, PooledConnection]                   │
│  Key format: "username@host:port"                            │
├─────────────────────────────────────────────────────────────┤
│  Methods:                                                    │
│  • get_connection() → async context manager                  │
│  • close_all() → cleanup                                     │
│  • get_stats() → metrics                                     │
└─────────────────────────────────────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────────────────────┐
│              PooledConnection (dataclass)                    │
├─────────────────────────────────────────────────────────────┤
│  • connection: asyncssh.SSHClientConnection                  │
│  • host, port, username                                      │
│  • created_at, last_used_at                                  │
│  • use_count                                                 │
│  • is_expired(), is_idle(), is_healthy()                     │
└─────────────────────────────────────────────────────────────┘
```

## Expected Impact

| Metric | Before | After (estimated) |
|--------|--------|-------------------|
| SSH connections per validation cycle | 13+ per executor | 1-2 per executor |
| Connection establishment overhead | ~100-200ms each | Amortized ~10-20ms |
| Memory per executor | New connection each time | Reused connection |

## Configuration

Default pool settings (can be customized via `init_ssh_pool()`):

```python
DEFAULT_MAX_CONNECTIONS = 50      # Maximum pooled connections
DEFAULT_CONNECTION_TTL = 300      # 5 minutes before expiration
DEFAULT_IDLE_TIMEOUT = 60         # 1 minute idle before eligible for eviction
DEFAULT_HEALTH_CHECK_INTERVAL = 30 # Background health check frequency
```

## Testing

Added comprehensive unit tests covering:
- ✅ Connection creation on cache miss
- ✅ Connection reuse on cache hit
- ✅ Separate connections for different hosts
- ✅ Unhealthy connection eviction
- ✅ Max connections enforcement (LRU eviction)
- ✅ Pool cleanup (close_all)
- ✅ Statistics tracking (hit rate, evictions)
- ✅ PooledConnection lifecycle (age, expiration, idle)
- ✅ Global pool singleton pattern

## Backward Compatibility

- **No breaking changes** - The pool is an internal optimization
- **Same behavior** - All existing functionality works identically
- **Graceful fallback** - If pool fails, connections are created normally

## Future Improvements

1. **Application lifecycle integration** - Call `init_ssh_pool()` on startup and `close_ssh_pool()` on shutdown
2. **Metrics export** - Expose pool stats to Prometheus/Grafana
3. **Per-executor limits** - Limit connections per executor to prevent resource exhaustion
4. **Connection warming** - Pre-create connections for known executors

## How to Test

```bash
# Run the new tests
cd neurons/validators
pytest tests/test_ssh_connection_pool.py -v

# Run all validator tests
pytest tests/ -v
```

## Checklist

- [x] Code follows project style guidelines (ruff check passes)
- [x] Unit tests added for new functionality
- [x] No breaking changes to existing APIs
- [x] Documentation included in code
- [x] PR description explains the change
