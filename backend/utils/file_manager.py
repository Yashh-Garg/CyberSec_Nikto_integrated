"""File management utilities for scan results and logs."""

import json
import logging
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class FileManager:
    """Manage scan result files and logs."""
    
    def __init__(self, base_dir: Path = Path(".")):
        self.base_dir = base_dir
        self.scan_results_dir = base_dir / "scan_results"
        self.logs_dir = base_dir / "logs"
        
        # Ensure directories exist
        self.scan_results_dir.mkdir(exist_ok=True)
        self.logs_dir.mkdir(exist_ok=True)
    
    def save_scan_results(self, scan_id: str, scan_data: Dict) -> Path:
        """Save scan results to JSON file."""
        results_file = self.scan_results_dir / f"scan_{scan_id}.json"
        
        try:
            with open(results_file, 'w', encoding='utf-8') as f:
                json.dump(scan_data, f, indent=2, ensure_ascii=False, default=str)
            logger.info(f"Scan results saved to {results_file}")
            return results_file
        except Exception as e:
            logger.error(f"Failed to save scan results: {e}")
            raise
    
    def load_scan_results(self, scan_id: str) -> Optional[Dict]:
        """Load scan results from file."""
        results_file = self.scan_results_dir / f"scan_{scan_id}.json"
        
        if not results_file.exists():
            return None
        
        try:
            with open(results_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load scan results: {e}")
            return None
    
    def list_scan_files(self) -> List[Dict]:
        """List all scan result files."""
        scan_files = []
        
        for file_path in self.scan_results_dir.glob("scan_*.json"):
            try:
                stat = file_path.stat()
                scan_files.append({
                    "file": file_path.name,
                    "size": stat.st_size,
                    "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                    "scan_id": file_path.stem.replace("scan_", "")
                })
            except Exception as e:
                logger.warning(f"Error reading file {file_path}: {e}")
        
        return sorted(scan_files, key=lambda x: x["modified"], reverse=True)
    
    def cleanup_old_scans(self, days: int = 30) -> int:
        """Remove scan files older than specified days."""
        from datetime import timedelta
        
        cutoff_date = datetime.now() - timedelta(days=days)
        removed_count = 0
        
        for file_path in self.scan_results_dir.glob("scan_*.json"):
            try:
                stat = file_path.stat()
                file_date = datetime.fromtimestamp(stat.st_mtime)
                
                if file_date < cutoff_date:
                    file_path.unlink()
                    removed_count += 1
                    logger.info(f"Removed old scan file: {file_path.name}")
            except Exception as e:
                logger.warning(f"Error cleaning up file {file_path}: {e}")
        
        return removed_count
    
    def get_scan_summary(self) -> Dict:
        """Get summary of all scan files."""
        files = self.list_scan_files()
        total_size = sum(f["size"] for f in files)
        
        return {
            "total_files": len(files),
            "total_size_bytes": total_size,
            "total_size_mb": round(total_size / (1024 * 1024), 2),
            "files": files[:10]  # Latest 10 files
        }

