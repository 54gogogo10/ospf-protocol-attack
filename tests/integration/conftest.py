import pytest
import subprocess
import time


@pytest.fixture(scope="session")
def docker_network():
    subprocess.run(
        ["docker-compose", "-f", "docker/topo1-single-area/docker-compose.yml",
         "up", "-d"],
        check=True,
    )
    time.sleep(15)
    yield
    subprocess.run(
        ["docker-compose", "-f", "docker/topo1-single-area/docker-compose.yml",
         "down", "-v"],
        check=True,
    )
