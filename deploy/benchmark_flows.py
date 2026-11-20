#!/usr/bin/env python3
"""Measure five read-only collector processes; emit aggregate metrics, no addresses."""
import json
from pathlib import Path
import resource
import statistics
import subprocess
import sys
import time


def benchmark():
    script = Path(__file__).with_name('flow_snapshot.py')
    wall = []
    counts = []
    truncated = 0
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    for _ in range(5):
        start = time.monotonic()
        result = subprocess.run([sys.executable, str(script)], capture_output=True,
                                text=True, timeout=4, check=True)
        wall.append((time.monotonic() - start) * 1000)
        data = json.loads(result.stdout)
        counts.append(data['seen'])
        truncated += int(data['truncated'])
        time.sleep(0.2)
    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    cpu = ((after.ru_utime + after.ru_stime) - (before.ru_utime + before.ru_stime)) / 5
    return {'samples': 5, 'entriesMin': min(counts), 'entriesMax': max(counts),
            'wallMedianMs': round(statistics.median(wall), 3),
            'wallMaxMs': round(max(wall), 3), 'cpuMeanMs': round(cpu * 1000, 3),
            'estimatedOneCorePercentAt15s': round(cpu / 15 * 100, 4),
            'peakChildRssKiB': after.ru_maxrss, 'truncatedSamples': truncated,
            'scope': 'current IPv4 table; not a saturation or forwarding benchmark'}


if __name__ == '__main__':
    print(json.dumps(benchmark()))
