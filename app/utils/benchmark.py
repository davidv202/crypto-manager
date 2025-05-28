import time
import tracemalloc
import os
from app.db.db_manager import Session, Benchmark

def benchmark_operation(func, file_path, algorithm_name, framework_name, operation="encrypt"):
    file_size = os.path.getsize(file_path)

    tracemalloc.start()
    start_time = time.perf_counter()

    try:
        func()  # Execută funcția pasată
    except Exception as e:
        raise e
    finally:
        end_time = time.perf_counter()
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        time_ms = (end_time - start_time) * 1000
        memory_kb = peak / 1024

        session = Session()
        benchmark = Benchmark(
            algorithm=algorithm_name,
            framework=framework_name,
            operation=operation,
            time_ms=time_ms,
            memory_kb=memory_kb,
            file_size_bytes=file_size
        )
        session.add(benchmark)
        session.commit()
        session.close()
