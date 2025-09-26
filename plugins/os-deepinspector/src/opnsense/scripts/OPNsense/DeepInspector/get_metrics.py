import os
import json
import subprocess
import psutil
from datetime import datetime

def get_metrics():
    """Get DPI engine performance metrics"""
    try:
        metrics = {
            'timestamp': datetime.now().isoformat(),
            'system': {},
            'engine': {},
            'network': {}
        }

        # System metrics
        metrics['system'] = {
            'cpu_usage': psutil.cpu_percent(interval=1),
            'memory_usage': psutil.virtual_memory().percent,
            'disk_usage': psutil.disk_usage('/').percent,
            'load_average': list(os.getloadavg())
        }

        # Engine-specific metrics
        engine_pid = get_engine_pid()
        if engine_pid:
            try:
                process = psutil.Process(engine_pid)
                metrics['engine'] = {
                    'pid': engine_pid,
                    'cpu_percent': process.cpu_percent(),
                    'memory_percent': process.memory_percent(),
                    'memory_rss': process.memory_info().rss,
                    'num_threads': process.num_threads(),
                    'status': process.status(),
                    'create_time': process.create_time()
                }
            except psutil.NoSuchProcess:
                metrics['engine'] = {'status': 'not_running'}
        else:
            metrics['engine'] = {'status': 'not_found'}

        # Network interface statistics
        net_stats = psutil.net_io_counters(pernic=True)
        metrics['network'] = {}
        for interface, stats in net_stats.items():
            metrics['network'][interface] = {
                'bytes_sent': stats.bytes_sent,
                'bytes_recv': stats.bytes_recv,
                'packets_sent': stats.packets_sent,
                'packets_recv': stats.packets_recv,
                'errin': stats.errin,
                'errout': stats.errout,
                'dropin': stats.dropin,
                'dropout': stats.dropout
            }

        return metrics

    except Exception as e:
        return {
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }

def get_engine_pid():
    """Get DPI engine process ID"""
    try:
        result = subprocess.run(['pgrep', '-f', 'deepinspector_engine'],
                              capture_output=True, text=True)
        if result.returncode == 0:
            return int(result.stdout.strip().split('\n')[0])
    except:
        pass
    return None

if __name__ == "__main__":
    metrics = get_metrics()
    print(json.dumps(metrics, indent=2))
