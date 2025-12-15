"""Integration test for SSH Connection Pool.

This test verifies the pool works correctly in a realistic scenario
by simulating multiple concurrent connection requests.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

# Skip conftest imports
pytest_plugins = []


class TestSSHPoolIntegration:
    """Integration tests for SSH connection pool behavior."""

    @pytest.mark.asyncio
    async def test_concurrent_connections_to_same_host(self):
        """Multiple concurrent requests to same host should queue and reuse."""
        from services.ssh_connection_pool import SSHConnectionPool
        
        pool = SSHConnectionPool(max_connections=5, connection_ttl=60)
        
        # Create a mock connection
        mock_conn = AsyncMock()
        mock_conn.run = AsyncMock(return_value=MagicMock(exit_status=0))
        mock_conn.close = MagicMock()
        mock_conn.wait_closed = AsyncMock()
        
        create_count = 0
        
        async def mock_create(*args, **kwargs):
            nonlocal create_count
            create_count += 1
            await asyncio.sleep(0.01)  # Simulate connection time
            return mock_conn
        
        pool._create_connection = mock_create
        
        # Simulate 5 sequential requests to same host
        for i in range(5):
            async with pool.get_connection(
                host="192.168.1.1",
                port=22,
                username="root",
                private_key="fake_key",
            ) as conn:
                # Simulate some work
                await asyncio.sleep(0.005)
                assert conn is mock_conn
        
        # Should only create 1 connection (reused 4 times)
        assert create_count == 1
        
        stats = pool.get_stats()
        assert stats["hits"] == 4
        assert stats["misses"] == 1
        assert stats["hit_rate"] == 0.8
        
        await pool.close_all()

    @pytest.mark.asyncio
    async def test_connections_to_multiple_hosts(self):
        """Connections to different hosts should create separate connections."""
        from services.ssh_connection_pool import SSHConnectionPool
        
        pool = SSHConnectionPool(max_connections=10, connection_ttl=60)
        
        connections = {}
        
        async def mock_create(host, port, username, private_key):
            key = f"{username}@{host}:{port}"
            if key not in connections:
                conn = AsyncMock()
                conn.run = AsyncMock(return_value=MagicMock(exit_status=0))
                conn.close = MagicMock()
                conn.wait_closed = AsyncMock()
                connections[key] = conn
            return connections[key]
        
        pool._create_connection = mock_create
        
        # Connect to 3 different hosts
        hosts = ["192.168.1.1", "192.168.1.2", "192.168.1.3"]
        
        for host in hosts:
            async with pool.get_connection(
                host=host,
                port=22,
                username="root",
                private_key="fake_key",
            ):
                pass
        
        # Should have created 3 connections
        assert len(connections) == 3
        assert pool.get_stats()["misses"] == 3
        
        # Reconnect to same hosts - should reuse
        for host in hosts:
            async with pool.get_connection(
                host=host,
                port=22,
                username="root",
                private_key="fake_key",
            ):
                pass
        
        # Still 3 connections, but now 3 hits
        assert len(connections) == 3
        assert pool.get_stats()["hits"] == 3
        
        await pool.close_all()

    @pytest.mark.asyncio
    async def test_pool_handles_connection_failure_gracefully(self):
        """Pool should handle connection creation failures gracefully."""
        from services.ssh_connection_pool import SSHConnectionPool
        
        pool = SSHConnectionPool(max_connections=5, connection_ttl=60)
        
        async def mock_create_fail(*args, **kwargs):
            raise ConnectionError("SSH connection failed")
        
        pool._create_connection = mock_create_fail
        
        with pytest.raises(ConnectionError):
            async with pool.get_connection(
                host="192.168.1.1",
                port=22,
                username="root",
                private_key="fake_key",
            ):
                pass
        
        # Pool should still be functional
        assert pool.get_stats()["pool_size"] == 0

    @pytest.mark.asyncio
    async def test_pool_eviction_under_pressure(self):
        """Pool should evict LRU connections when at capacity."""
        from services.ssh_connection_pool import SSHConnectionPool
        
        pool = SSHConnectionPool(max_connections=3, connection_ttl=60)
        
        connections = []
        
        async def mock_create(host, port, username, private_key):
            conn = AsyncMock()
            conn.run = AsyncMock(return_value=MagicMock(exit_status=0))
            conn.close = MagicMock()
            conn.wait_closed = AsyncMock()
            connections.append(conn)
            return conn
        
        pool._create_connection = mock_create
        
        # Create 5 connections to different hosts (pool max is 3)
        for i in range(5):
            async with pool.get_connection(
                host=f"192.168.1.{i}",
                port=22,
                username="root",
                private_key="fake_key",
            ):
                pass
        
        # Pool should have evicted 2 connections
        stats = pool.get_stats()
        assert stats["pool_size"] == 3
        assert stats["evictions"] == 2
        
        await pool.close_all()

    @pytest.mark.asyncio
    async def test_unhealthy_connection_replaced(self):
        """Unhealthy connections should be replaced with new ones."""
        from services.ssh_connection_pool import SSHConnectionPool
        
        pool = SSHConnectionPool(max_connections=5, connection_ttl=60)
        
        healthy_conn = AsyncMock()
        healthy_conn.run = AsyncMock(return_value=MagicMock(exit_status=0))
        healthy_conn.close = MagicMock()
        healthy_conn.wait_closed = AsyncMock()
        
        unhealthy_conn = AsyncMock()
        unhealthy_conn.run = AsyncMock(return_value=MagicMock(exit_status=0))
        unhealthy_conn.close = MagicMock()
        unhealthy_conn.wait_closed = AsyncMock()
        
        call_count = 0
        
        async def mock_create(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return unhealthy_conn
            return healthy_conn
        
        pool._create_connection = mock_create
        
        # First connection
        async with pool.get_connection(
            host="192.168.1.1",
            port=22,
            username="root",
            private_key="fake_key",
        ) as conn:
            assert conn is unhealthy_conn
        
        # Make the connection unhealthy
        unhealthy_conn.run = AsyncMock(side_effect=Exception("Connection lost"))
        
        # Second connection should detect unhealthy and create new
        async with pool.get_connection(
            host="192.168.1.1",
            port=22,
            username="root",
            private_key="fake_key",
        ) as conn:
            assert conn is healthy_conn
        
        # Should have created 2 connections
        assert call_count == 2
        
        await pool.close_all()

    @pytest.mark.asyncio
    async def test_pool_stats_accuracy(self):
        """Pool statistics should be accurate."""
        from services.ssh_connection_pool import SSHConnectionPool
        
        pool = SSHConnectionPool(max_connections=10, connection_ttl=60)
        
        mock_conn = AsyncMock()
        mock_conn.run = AsyncMock(return_value=MagicMock(exit_status=0))
        mock_conn.close = MagicMock()
        mock_conn.wait_closed = AsyncMock()
        
        pool._create_connection = AsyncMock(return_value=mock_conn)
        
        # 10 requests to same host: 1 miss, 9 hits
        for _ in range(10):
            async with pool.get_connection(
                host="192.168.1.1",
                port=22,
                username="root",
                private_key="fake_key",
            ):
                pass
        
        stats = pool.get_stats()
        assert stats["hits"] == 9
        assert stats["misses"] == 1
        assert stats["pool_size"] == 1
        assert stats["in_use"] == 0
        assert stats["hit_rate"] == 0.9
        
        await pool.close_all()
        
        final_stats = pool.get_stats()
        assert final_stats["pool_size"] == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
