"""Tests for SSH Connection Pool Service.

This module tests the SSHConnectionPool class functionality including:
- Connection creation and reuse
- TTL-based expiration
- Health checking
- Pool size limits
- Statistics tracking

Note: This test file is self-contained and does not use the shared conftest.py
to avoid dependency on environment variables.
"""

import time
from unittest.mock import AsyncMock, MagicMock, patch

import asyncssh
import pytest

# Skip conftest imports by setting up our own pytest configuration
pytest_plugins = []


class TestSSHConnectionPool:
    """Tests for SSHConnectionPool class."""

    @pytest.fixture
    def mock_ssh_connection(self):
        """Create a mock SSH connection."""
        conn = AsyncMock(spec=asyncssh.SSHClientConnection)
        conn.close = MagicMock()
        conn.wait_closed = AsyncMock()
        return conn

    @pytest.fixture
    def pool(self):
        """Create a fresh connection pool for each test."""
        from services.ssh_connection_pool import SSHConnectionPool
        return SSHConnectionPool(
            max_connections=5,
            connection_ttl=60,
            idle_timeout=30,
        )

    @pytest.mark.asyncio
    async def test_pool_creates_new_connection_on_miss(self, pool, mock_ssh_connection):
        """Pool should create a new connection when none exists."""
        # Mock health check
        mock_ssh_connection.run = AsyncMock(return_value=MagicMock(exit_status=0))
        
        with patch.object(pool, '_create_connection', AsyncMock(return_value=mock_ssh_connection)):
            async with pool.get_connection(
                host="192.168.1.1",
                port=22,
                username="root",
                private_key="fake_key",
            ) as conn:
                assert conn is mock_ssh_connection
            
            # Verify connection was created
            pool._create_connection.assert_called_once()
            
            # Check stats
            stats = pool.get_stats()
            assert stats["misses"] == 1
            assert stats["hits"] == 0

    @pytest.mark.asyncio
    async def test_pool_reuses_existing_connection(self, pool, mock_ssh_connection):
        """Pool should reuse an existing healthy connection."""
        # Mock health check to return healthy
        mock_ssh_connection.run = AsyncMock(return_value=MagicMock(exit_status=0))
        
        with patch.object(pool, '_create_connection', AsyncMock(return_value=mock_ssh_connection)):
            # First connection - creates new
            async with pool.get_connection(
                host="192.168.1.1",
                port=22,
                username="root",
                private_key="fake_key",
            ):
                pass
            
            # Second connection - should reuse
            async with pool.get_connection(
                host="192.168.1.1",
                port=22,
                username="root",
                private_key="fake_key",
            ):
                pass
            
            # Should only have created one connection
            assert pool._create_connection.call_count == 1
            
            # Check stats
            stats = pool.get_stats()
            assert stats["misses"] == 1
            assert stats["hits"] == 1

    @pytest.mark.asyncio
    async def test_pool_creates_separate_connections_for_different_hosts(self, pool):
        """Pool should create separate connections for different hosts."""
        mock_conn1 = AsyncMock(spec=asyncssh.SSHClientConnection)
        mock_conn1.run = AsyncMock(return_value=MagicMock(exit_status=0))
        mock_conn1.close = MagicMock()
        mock_conn1.wait_closed = AsyncMock()
        
        mock_conn2 = AsyncMock(spec=asyncssh.SSHClientConnection)
        mock_conn2.run = AsyncMock(return_value=MagicMock(exit_status=0))
        mock_conn2.close = MagicMock()
        mock_conn2.wait_closed = AsyncMock()
        
        with patch.object(pool, '_create_connection', AsyncMock(side_effect=[mock_conn1, mock_conn2])):
            async with pool.get_connection(
                host="192.168.1.1",
                port=22,
                username="root",
                private_key="fake_key",
            ):
                pass
            
            async with pool.get_connection(
                host="192.168.1.2",
                port=22,
                username="root",
                private_key="fake_key",
            ):
                pass
            
            # Should have created two connections
            assert pool._create_connection.call_count == 2

    @pytest.mark.asyncio
    async def test_pool_evicts_unhealthy_connection(self, pool, mock_ssh_connection):
        """Pool should evict and recreate unhealthy connections."""
        healthy_conn = AsyncMock(spec=asyncssh.SSHClientConnection)
        healthy_conn.run = AsyncMock(return_value=MagicMock(exit_status=0))
        healthy_conn.close = MagicMock()
        healthy_conn.wait_closed = AsyncMock()
        
        # First connection is healthy
        mock_ssh_connection.run = AsyncMock(return_value=MagicMock(exit_status=0))
        mock_ssh_connection.close = MagicMock()
        mock_ssh_connection.wait_closed = AsyncMock()
        
        create_mock = AsyncMock(side_effect=[mock_ssh_connection, healthy_conn])
        
        with patch.object(pool, '_create_connection', create_mock):
            async with pool.get_connection(
                host="192.168.1.1",
                port=22,
                username="root",
                private_key="fake_key",
            ):
                pass
            
            # Make the connection unhealthy
            mock_ssh_connection.run = AsyncMock(side_effect=Exception("Connection lost"))
            
            # Second connection should detect unhealthy and create new
            async with pool.get_connection(
                host="192.168.1.1",
                port=22,
                username="root",
                private_key="fake_key",
            ):
                pass
            
            # Should have created two connections (original + replacement)
            assert pool._create_connection.call_count == 2

    @pytest.mark.asyncio
    async def test_pool_enforces_max_connections(self, pool):
        """Pool should evict LRU connections when max is reached."""
        connections = []
        for i in range(6):  # Pool max is 5
            conn = AsyncMock(spec=asyncssh.SSHClientConnection)
            conn.run = AsyncMock(return_value=MagicMock(exit_status=0))
            conn.close = MagicMock()
            conn.wait_closed = AsyncMock()
            connections.append(conn)
        
        with patch.object(pool, '_create_connection', AsyncMock(side_effect=connections)):
            # Create 6 connections to different hosts
            for i in range(6):
                async with pool.get_connection(
                    host=f"192.168.1.{i}",
                    port=22,
                    username="root",
                    private_key="fake_key",
                ):
                    pass
            
            # Pool should have evicted at least one
            stats = pool.get_stats()
            assert stats["pool_size"] <= 5
            assert stats["evictions"] >= 1

    @pytest.mark.asyncio
    async def test_pool_close_all(self, pool, mock_ssh_connection):
        """close_all should close all connections in the pool."""
        mock_ssh_connection.run = AsyncMock(return_value=MagicMock(exit_status=0))
        
        with patch.object(pool, '_create_connection', AsyncMock(return_value=mock_ssh_connection)):
            async with pool.get_connection(
                host="192.168.1.1",
                port=22,
                username="root",
                private_key="fake_key",
            ):
                pass
            
            await pool.close_all()
            
            # Connection should have been closed
            mock_ssh_connection.close.assert_called()
            
            # Pool should be empty
            stats = pool.get_stats()
            assert stats["pool_size"] == 0

    @pytest.mark.asyncio
    async def test_pool_key_generation(self, pool):
        """Pool should generate correct keys for connections."""
        key = pool._make_key("192.168.1.1", 22, "root")
        assert key == "root@192.168.1.1:22"
        
        key2 = pool._make_key("10.0.0.1", 2222, "admin")
        assert key2 == "admin@10.0.0.1:2222"

    @pytest.mark.asyncio
    async def test_pool_stats_hit_rate(self, pool, mock_ssh_connection):
        """Pool should correctly calculate hit rate."""
        mock_ssh_connection.run = AsyncMock(return_value=MagicMock(exit_status=0))
        
        with patch.object(pool, '_create_connection', AsyncMock(return_value=mock_ssh_connection)):
            # 1 miss, 3 hits = 75% hit rate
            for _ in range(4):
                async with pool.get_connection(
                    host="192.168.1.1",
                    port=22,
                    username="root",
                    private_key="fake_key",
                ):
                    pass
            
            stats = pool.get_stats()
            assert stats["hits"] == 3
            assert stats["misses"] == 1
            assert stats["hit_rate"] == 0.75


class TestPooledConnection:
    """Tests for PooledConnection dataclass."""

    def test_pooled_connection_age(self):
        """PooledConnection should correctly calculate age."""

        from services.ssh_connection_pool import PooledConnection
        
        mock_conn = MagicMock()
        pooled = PooledConnection(
            connection=mock_conn,
            host="192.168.1.1",
            port=22,
            username="root",
            created_at=time.time() - 100,  # Created 100 seconds ago
        )
        
        assert pooled.age >= 100
        assert pooled.age < 101

    def test_pooled_connection_is_expired(self):
        """PooledConnection should correctly detect expiration."""

        from services.ssh_connection_pool import PooledConnection
        
        mock_conn = MagicMock()
        
        # Not expired
        pooled = PooledConnection(
            connection=mock_conn,
            host="192.168.1.1",
            port=22,
            username="root",
            created_at=time.time(),
        )
        assert not pooled.is_expired(60)
        
        # Expired
        pooled_old = PooledConnection(
            connection=mock_conn,
            host="192.168.1.1",
            port=22,
            username="root",
            created_at=time.time() - 120,
        )
        assert pooled_old.is_expired(60)

    def test_pooled_connection_mark_used(self):
        """mark_used should update last_used_at and increment use_count."""

        from services.ssh_connection_pool import PooledConnection
        
        mock_conn = MagicMock()
        pooled = PooledConnection(
            connection=mock_conn,
            host="192.168.1.1",
            port=22,
            username="root",
        )
        
        initial_use_count = pooled.use_count
        initial_last_used = pooled.last_used_at
        
        time.sleep(0.01)  # Small delay
        pooled.mark_used()
        
        assert pooled.use_count == initial_use_count + 1
        assert pooled.last_used_at > initial_last_used


class TestGlobalPoolFunctions:
    """Tests for global pool helper functions."""

    @pytest.mark.asyncio
    async def test_get_ssh_pool_singleton(self):
        """get_ssh_pool should return the same instance."""
        import services.ssh_connection_pool as pool_module
        from services.ssh_connection_pool import get_ssh_pool
        
        # Reset global pool
        pool_module._global_pool = None
        
        pool1 = get_ssh_pool()
        pool2 = get_ssh_pool()
        
        assert pool1 is pool2

    @pytest.mark.asyncio
    async def test_init_ssh_pool_creates_new_pool(self):
        """init_ssh_pool should create a new pool with custom settings."""
        import services.ssh_connection_pool as pool_module
        from services.ssh_connection_pool import close_ssh_pool, init_ssh_pool
        
        # Reset global pool
        pool_module._global_pool = None
        
        pool = await init_ssh_pool(
            max_connections=10,
            connection_ttl=120,
            idle_timeout=60,
        )
        
        assert pool.max_connections == 10
        assert pool.connection_ttl == 120
        assert pool.idle_timeout == 60
        
        # Cleanup
        await close_ssh_pool()

    @pytest.mark.asyncio
    async def test_close_ssh_pool(self):
        """close_ssh_pool should close and clear the global pool."""
        import services.ssh_connection_pool as pool_module
        from services.ssh_connection_pool import close_ssh_pool, init_ssh_pool
        
        await init_ssh_pool()
        assert pool_module._global_pool is not None
        
        await close_ssh_pool()
        assert pool_module._global_pool is None
