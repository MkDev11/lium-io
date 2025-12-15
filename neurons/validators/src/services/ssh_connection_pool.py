"""SSH Connection Pool Service.

This module provides a connection pool for SSH connections to executors,
reducing the overhead of creating new connections for each operation.

Key features:
- Connection reuse with TTL-based expiration
- Automatic cleanup of stale connections
- Thread-safe async operations
- Health checking before returning connections
- Graceful connection eviction when pool is full
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field

import asyncssh

logger = logging.getLogger(__name__)


def _format_log_extra(extra: dict) -> str:
    """Format extra info for logging without depending on core.utils."""
    return " ".join(f"{k}={v}" for k, v in extra.items())

# Default pool configuration
DEFAULT_MAX_CONNECTIONS = 50
DEFAULT_CONNECTION_TTL = 300  # 5 minutes
DEFAULT_IDLE_TIMEOUT = 60  # 1 minute of idle before eligible for eviction
DEFAULT_HEALTH_CHECK_INTERVAL = 30  # seconds


@dataclass
class PooledConnection:
    """Represents a pooled SSH connection with metadata."""
    
    connection: asyncssh.SSHClientConnection
    host: str
    port: int
    username: str
    created_at: float = field(default_factory=time.time)
    last_used_at: float = field(default_factory=time.time)
    use_count: int = 0
    
    @property
    def age(self) -> float:
        """Return the age of the connection in seconds."""
        return time.time() - self.created_at
    
    @property
    def idle_time(self) -> float:
        """Return how long the connection has been idle in seconds."""
        return time.time() - self.last_used_at
    
    def mark_used(self) -> None:
        """Mark the connection as recently used."""
        self.last_used_at = time.time()
        self.use_count += 1
    
    def is_expired(self, ttl: float) -> bool:
        """Check if the connection has exceeded its TTL."""
        return self.age > ttl
    
    def is_idle(self, idle_timeout: float) -> bool:
        """Check if the connection has been idle too long."""
        return self.idle_time > idle_timeout
    
    async def is_healthy(self) -> bool:
        """Check if the connection is still usable."""
        try:
            # Try a simple command to verify connection is alive
            result = await asyncio.wait_for(
                self.connection.run("echo 1", check=False),
                timeout=5.0
            )
            return result.exit_status == 0
        except Exception:
            return False


class SSHConnectionPool:
    """Async SSH connection pool with automatic lifecycle management.
    
    This pool maintains reusable SSH connections to executor machines,
    significantly reducing connection overhead for repeated operations.
    
    Usage:
        pool = SSHConnectionPool()
        
        # Get a connection (creates new or reuses existing)
        async with pool.get_connection(host, port, username, private_key) as conn:
            result = await conn.run("some_command")
        
        # Connection is automatically returned to pool after use
        
        # Cleanup when done
        await pool.close_all()
    """
    
    def __init__(
        self,
        max_connections: int = DEFAULT_MAX_CONNECTIONS,
        connection_ttl: float = DEFAULT_CONNECTION_TTL,
        idle_timeout: float = DEFAULT_IDLE_TIMEOUT,
        health_check_interval: float = DEFAULT_HEALTH_CHECK_INTERVAL,
    ):
        """Initialize the connection pool.
        
        Args:
            max_connections: Maximum number of connections to maintain
            connection_ttl: Time-to-live for connections in seconds
            idle_timeout: Time after which idle connections can be evicted
            health_check_interval: Interval for background health checks
        """
        self.max_connections = max_connections
        self.connection_ttl = connection_ttl
        self.idle_timeout = idle_timeout
        self.health_check_interval = health_check_interval
        
        # Pool storage: key -> PooledConnection
        self._pool: dict[str, PooledConnection] = {}
        self._lock = asyncio.Lock()
        
        # Track connections currently in use
        self._in_use: set[str] = set()
        
        # Background cleanup task
        self._cleanup_task: asyncio.Task | None = None
        self._closed = False
        
        # Statistics
        self._stats = {
            "hits": 0,
            "misses": 0,
            "evictions": 0,
            "health_check_failures": 0,
        }
    
    def _make_key(self, host: str, port: int, username: str) -> str:
        """Generate a unique key for the connection."""
        return f"{username}@{host}:{port}"
    
    async def start(self) -> None:
        """Start the background cleanup task."""
        if self._cleanup_task is None:
            self._cleanup_task = asyncio.create_task(self._cleanup_loop())
            logger.info(f"SSH connection pool started: {_format_log_extra({'max_connections': self.max_connections, 'connection_ttl': self.connection_ttl, 'idle_timeout': self.idle_timeout})}")
    
    async def stop(self) -> None:
        """Stop the background cleanup task and close all connections."""
        self._closed = True
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
            self._cleanup_task = None
        await self.close_all()
    
    async def _cleanup_loop(self) -> None:
        """Background task to clean up expired and unhealthy connections."""
        while not self._closed:
            try:
                await asyncio.sleep(self.health_check_interval)
                await self._cleanup_expired()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in SSH pool cleanup loop: {_format_log_extra({'error': str(e)})}")
    
    async def _cleanup_expired(self) -> None:
        """Remove expired and unhealthy connections from the pool."""
        async with self._lock:
            keys_to_remove = []
            
            for key, pooled in self._pool.items():
                # Skip connections currently in use
                if key in self._in_use:
                    continue
                
                # Check if expired
                if pooled.is_expired(self.connection_ttl):
                    keys_to_remove.append(key)
                    logger.debug(f"Evicting expired connection: {_format_log_extra({'key': key, 'age': pooled.age})}")
                    continue
                
                # Check health for idle connections
                if pooled.is_idle(self.idle_timeout):
                    if not await pooled.is_healthy():
                        keys_to_remove.append(key)
                        self._stats["health_check_failures"] += 1
                        logger.debug(f"Evicting unhealthy connection: {_format_log_extra({'key': key, 'idle_time': pooled.idle_time})}")
            
            for key in keys_to_remove:
                await self._evict(key)
    
    async def _evict(self, key: str) -> None:
        """Remove a connection from the pool and close it."""
        if key in self._pool:
            pooled = self._pool.pop(key)
            self._stats["evictions"] += 1
            try:
                pooled.connection.close()
                await pooled.connection.wait_closed()
            except Exception:
                pass
    
    async def _create_connection(
        self,
        host: str,
        port: int,
        username: str,
        private_key: str,
    ) -> asyncssh.SSHClientConnection:
        """Create a new SSH connection."""
        pkey = asyncssh.import_private_key(private_key)
        connection = await asyncssh.connect(
            host=host,
            port=port,
            username=username,
            client_keys=[pkey],
            known_hosts=None,
        )
        return connection
    
    async def _enforce_max_connections(self) -> None:
        """Evict connections if pool exceeds max size."""
        while len(self._pool) >= self.max_connections:
            # Find the oldest idle connection to evict
            oldest_key = None
            oldest_time = float('inf')
            
            for key, pooled in self._pool.items():
                if key not in self._in_use and pooled.last_used_at < oldest_time:
                    oldest_key = key
                    oldest_time = pooled.last_used_at
            
            if oldest_key:
                logger.debug(f"Evicting LRU connection to make room: {_format_log_extra({'key': oldest_key, 'pool_size': len(self._pool)})}")
                await self._evict(oldest_key)
            else:
                # All connections are in use, can't evict
                break
    
    def get_connection(
        self,
        host: str,
        port: int,
        username: str,
        private_key: str,
    ) -> "PooledConnectionContext":
        """Get a connection from the pool or create a new one.
        
        Args:
            host: SSH host address
            port: SSH port
            username: SSH username
            private_key: Decrypted private key string
            
        Returns:
            PooledConnectionContext that can be used as an async context manager
        """
        return PooledConnectionContext(self, host, port, username, private_key)
    
    async def _acquire(
        self,
        host: str,
        port: int,
        username: str,
        private_key: str,
    ) -> asyncssh.SSHClientConnection:
        """Internal method to acquire a connection."""
        key = self._make_key(host, port, username)
        
        async with self._lock:
            # Try to get existing connection
            if key in self._pool and key not in self._in_use:
                pooled = self._pool[key]
                
                # Check if still valid
                if not pooled.is_expired(self.connection_ttl):
                    # Verify health before returning
                    if await pooled.is_healthy():
                        pooled.mark_used()
                        self._in_use.add(key)
                        self._stats["hits"] += 1
                        logger.debug(f"SSH pool hit: {_format_log_extra({'key': key, 'use_count': pooled.use_count})}")
                        return pooled.connection
                    else:
                        # Connection is unhealthy, remove it
                        await self._evict(key)
                else:
                    # Connection expired, remove it
                    await self._evict(key)
            
            # Need to create a new connection
            self._stats["misses"] += 1
            
            # Enforce max connections before creating new one
            await self._enforce_max_connections()
        
        # Create connection outside the lock to avoid blocking
        logger.debug(f"SSH pool miss, creating new connection: {_format_log_extra({'key': key})}")
        
        connection = await self._create_connection(host, port, username, private_key)
        
        async with self._lock:
            pooled = PooledConnection(
                connection=connection,
                host=host,
                port=port,
                username=username,
            )
            pooled.mark_used()
            self._pool[key] = pooled
            self._in_use.add(key)
        
        return connection
    
    async def _release(self, host: str, port: int, username: str) -> None:
        """Release a connection back to the pool."""
        key = self._make_key(host, port, username)
        
        async with self._lock:
            self._in_use.discard(key)
    
    async def close_all(self) -> None:
        """Close all connections in the pool."""
        async with self._lock:
            for key in list(self._pool.keys()):
                await self._evict(key)
            self._in_use.clear()
        
        logger.info(f"SSH connection pool closed: {_format_log_extra({'stats': self._stats})}")
    
    def get_stats(self) -> dict:
        """Get pool statistics."""
        return {
            **self._stats,
            "pool_size": len(self._pool),
            "in_use": len(self._in_use),
            "hit_rate": (
                self._stats["hits"] / (self._stats["hits"] + self._stats["misses"])
                if (self._stats["hits"] + self._stats["misses"]) > 0
                else 0.0
            ),
        }


class PooledConnectionContext:
    """Async context manager for pooled connections."""
    
    def __init__(
        self,
        pool: SSHConnectionPool,
        host: str,
        port: int,
        username: str,
        private_key: str,
    ):
        self.pool = pool
        self.host = host
        self.port = port
        self.username = username
        self.private_key = private_key
        self.connection: asyncssh.SSHClientConnection | None = None
    
    async def __aenter__(self) -> asyncssh.SSHClientConnection:
        self.connection = await self.pool._acquire(
            self.host,
            self.port,
            self.username,
            self.private_key,
        )
        return self.connection
    
    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.pool._release(self.host, self.port, self.username)
        # Don't close the connection - it stays in the pool


# Global pool instance (singleton pattern)
_global_pool: SSHConnectionPool | None = None


def get_ssh_pool() -> SSHConnectionPool:
    """Get the global SSH connection pool instance.
    
    Creates the pool on first access with default settings.
    """
    global _global_pool
    if _global_pool is None:
        _global_pool = SSHConnectionPool()
    return _global_pool


async def init_ssh_pool(
    max_connections: int = DEFAULT_MAX_CONNECTIONS,
    connection_ttl: float = DEFAULT_CONNECTION_TTL,
    idle_timeout: float = DEFAULT_IDLE_TIMEOUT,
) -> SSHConnectionPool:
    """Initialize the global SSH connection pool with custom settings.
    
    Should be called during application startup.
    """
    global _global_pool
    if _global_pool is not None:
        await _global_pool.stop()
    
    _global_pool = SSHConnectionPool(
        max_connections=max_connections,
        connection_ttl=connection_ttl,
        idle_timeout=idle_timeout,
    )
    await _global_pool.start()
    return _global_pool


async def close_ssh_pool() -> None:
    """Close the global SSH connection pool.
    
    Should be called during application shutdown.
    """
    global _global_pool
    if _global_pool is not None:
        await _global_pool.stop()
        _global_pool = None
