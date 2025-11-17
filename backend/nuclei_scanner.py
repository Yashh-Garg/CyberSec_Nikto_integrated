"""Nuclei scanner integration via Docker."""

import docker
import os
import time
import logging
from datetime import datetime
from typing import Dict, Optional, List
from pathlib import Path

logger = logging.getLogger(__name__)


class NucleiScanner:
    """Nuclei scanner wrapper using Docker."""

    NUCLEI_IMAGE = os.environ.get("NUCLEI_IMAGE", "projectdiscovery/nuclei:latest")
    DEFAULT_TIMEOUT = 3600  # 1 hour
    SCAN_RESULTS_DIR = Path("scan_results")

    def __init__(self, docker_client: Optional[docker.DockerClient] = None):
        """Initialize Nuclei scanner.

        Args:
            docker_client: Docker client instance. If None, creates new client.
        """
        if docker_client:
            self.client = docker_client
        else:
            socket_path = '/var/run/docker.sock'
            is_in_container = os.path.exists(socket_path)

            try:
                if is_in_container:
                    logger.info("Detected Docker container environment, using Unix socket")
                    original_docker_host = os.environ.pop('DOCKER_HOST', None)
                    try:
                        self.client = docker.DockerClient(base_url='unix:///var/run/docker.sock')
                        self.client.ping()
                        logger.info("Successfully connected to Docker via Unix socket")
                    finally:
                        if original_docker_host:
                            os.environ['DOCKER_HOST'] = original_docker_host
                else:
                    logger.info("Detected host environment, using default Docker client")
                    self.client = docker.from_env()
                    self.client.ping()
                    logger.info("Successfully connected to Docker via default client")
            except Exception as e:
                logger.warning(f"Failed to connect with primary method: {e}")
                try:
                    logger.info("Trying Unix socket connection...")
                    self.client = docker.DockerClient(base_url='unix:///var/run/docker.sock')
                    self.client.ping()
                    logger.info("Successfully connected via Unix socket")
                except Exception as e2:
                    logger.warning(f"Unix socket failed: {e2}")
                    if os.name == 'nt' and not is_in_container:
                        try:
                            logger.info("Trying Windows named pipe...")
                            self.client = docker.DockerClient(base_url='npipe:////./pipe/docker_engine')
                            self.client.ping()
                            logger.info("Successfully connected via Windows named pipe")
                        except Exception as e3:
                            logger.warning(f"Windows named pipe failed: {e3}")
                            raise
                    else:
                        docker_host = os.environ.get('DOCKER_HOST')
                        if docker_host and docker_host.startswith('tcp://'):
                            logger.info(f"Trying TCP connection to {docker_host}...")
                            self.client = docker.DockerClient(base_url=docker_host)
                            self.client.ping()
                            logger.info("Successfully connected via TCP")
                        else:
                            error_msg = (
                                "Cannot connect to Docker. Please ensure Docker is running.\n"
                                "For Windows:\n"
                                "1. Open Docker Desktop → Settings → General\n"
                                "2. Enable 'Expose daemon on tcp://localhost:2375 without TLS'\n"
                                "3. Restart Docker Desktop\n"
                                "4. Use: docker-compose -f docker-compose.windows.yml up -d\n"
                                "Or use WSL2 backend in Docker Desktop settings."
                            )
                            raise Exception(error_msg)

        self.SCAN_RESULTS_DIR.mkdir(exist_ok=True)

    def scan(
        self,
        target: str,
        port: int = 80,
        ssl: bool = False,
        options: Optional[List[str]] = None,
        timeout: int = DEFAULT_TIMEOUT
    ) -> Dict:
        """Execute Nuclei scan via Docker container.

        Runs nuclei with JSON output, suitable for parsing and normalization.
        By default uses CVE templates (`-t cves/`).
        """
        scan_id = f"nuclei_{int(time.time())}"
        logger.info(f"Starting Nuclei scan {scan_id} for {target}:{port}")

        try:
            self._ensure_image()

            clean_target = target.strip()
            if clean_target.startswith("http://"):
                clean_target = clean_target[7:]
            elif clean_target.startswith("https://"):
                clean_target = clean_target[8:]
            clean_target = clean_target.rstrip("/")

            protocol = "https" if ssl else "http"
            target_url = f"{protocol}://{clean_target}:{port}"

            output_file = self.SCAN_RESULTS_DIR / f"{scan_id}.json"

            nuclei_args: List[str] = [
                "-u", target_url,
                "-json",
                "-o", f"/output/{scan_id}.json",
            ]

            # Default to CVE templates folder; allow override via options
            has_template_arg = False
            if options:
                for i, opt in enumerate(options):
                    if opt in ("-t", "-templates") and i + 1 < len(options):
                        has_template_arg = True
                        break

            if not has_template_arg:
                nuclei_args = ["-t", "cves/"] + nuclei_args

            if options:
                nuclei_args.extend(options)

            logger.info(f"Running nuclei with args: {' '.join(nuclei_args)}")

            container = self.client.containers.run(
                self.NUCLEI_IMAGE,
                command=nuclei_args,
                detach=True,
                remove=False,
                network_mode="host",
                volumes={
                    str(self.SCAN_RESULTS_DIR.absolute()): {
                        "bind": "/output",
                        "mode": "rw",
                    }
                },
            )

            logger.info(f"Container {container.id} started for scan {scan_id}")

            time.sleep(2)

            wait_result = container.wait(timeout=timeout)
            if isinstance(wait_result, dict):
                exit_code = wait_result.get("StatusCode", 0)
            else:
                exit_code = int(wait_result) if wait_result else 0

            logger.info(f"Nuclei container exited with code: {exit_code}")

            logs = container.logs(stdout=True, stderr=True).decode("utf-8", errors="replace")
            log_events = self._parse_log_events(logs)

            raw_output = ""
            try:
                if output_file.exists():
                    raw_output = output_file.read_text(encoding="utf-8")
                    logger.info(f"Nuclei output size: {len(raw_output)} chars")
                else:
                    logger.warning(f"Nuclei output file not found: {output_file}")
            except Exception as e:
                logger.warning(f"Failed to read Nuclei output: {e}", exc_info=True)

            container.remove()

            if not raw_output.strip():
                raise Exception(
                    f"Nuclei scan completed but no JSON output was generated. "
                    f"Exit code: {exit_code}. Logs preview: {logs[:500]}"
                )

            return {
                "scan_id": scan_id,
                "target": target,
                "port": port,
                "ssl": ssl,
                "exit_code": exit_code,
                "raw_output": raw_output,
                "logs": logs,
                "log_events": log_events,
                "output_format": "json",
            }

        except docker.errors.ContainerError as e:
            logger.error(f"Nuclei container error: {e}")
            raise Exception(f"Nuclei scan failed: {e}")
        except docker.errors.ImageNotFound:
            logger.error(f"Image {self.NUCLEI_IMAGE} not found")
            raise Exception(f"Docker image {self.NUCLEI_IMAGE} not available")
        except Exception as e:
            logger.error(f"Unexpected error during Nuclei scan: {e}")
            raise

    def _ensure_image(self):
        """Ensure Nuclei Docker image is available."""
        try:
            self.client.images.get(self.NUCLEI_IMAGE)
            logger.debug(f"Image {self.NUCLEI_IMAGE} already present")
        except docker.errors.ImageNotFound:
            logger.info(f"Pulling image {self.NUCLEI_IMAGE}")
            self.client.images.pull(self.NUCLEI_IMAGE)

    def _parse_log_events(self, logs: str) -> List[Dict]:
        """Parse raw logs into structured events."""
        events: List[Dict] = []
        if not logs:
            return events

        lines = logs.split("\n")
        for i, line in enumerate(lines):
            line = line.strip()
            if not line:
                continue

            event: Dict[str, object] = {
                "line_number": i + 1,
                "timestamp": datetime.now().isoformat(),
                "message": line,
                "level": "INFO",
            }

            line_lower = line.lower()
            if "error" in line_lower or "failed" in line_lower:
                event["level"] = "ERROR"
            elif "warning" in line_lower or "warn" in line_lower:
                event["level"] = "WARNING"
            elif "debug" in line_lower:
                event["level"] = "DEBUG"

            events.append(event)

        return events


