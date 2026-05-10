#!/usr/bin/env python3
import argparse
import hashlib
import os
import queue
import struct
import time
import uuid
from multiprocessing import Event, Process, Queue


def trailing_zero_bits(digest: bytes) -> int:
    count = 0
    for byte in reversed(digest):
        if byte == 0:
            count += 8
        else:
            count += (byte & -byte).bit_length() - 1
            break
    return count


def mine_worker(prefix: bytes, difficulty: int, start: int, step: int, stop_event: Event, result_queue: Queue) -> None:
    buf = bytearray(prefix + b"\x00" * 8)
    prefix_len = len(prefix)
    nonce = start

    while not stop_event.is_set():
        struct.pack_into("<Q", buf, prefix_len, nonce)
        digest = hashlib.sha256(buf).digest()
        if trailing_zero_bits(digest) >= difficulty:
            if not stop_event.is_set():
                stop_event.set()
                result_queue.put(nonce)
            return
        nonce = (nonce + step) & 0xFFFFFFFFFFFFFFFF


def account_loop(label: str, workers: int, difficulty: int, deadline: float | None) -> None:
    minted = 0
    print(f"[*] [{label}] Starting local simulator with {workers} workers", flush=True)

    while True:
        if deadline is not None and time.time() >= deadline:
            print(f"[*] [{label}] Duration reached, stopping", flush=True)
            return

        challenge_id = uuid.uuid4().hex[:12]
        prefix = os.urandom(16)
        print(f"[*] [{label}] Challenge: {challenge_id} | Difficulty: {difficulty} bits", flush=True)

        stop_event = Event()
        result_queue: Queue = Queue()
        processes: list[Process] = []

        start = time.perf_counter()
        for i in range(workers):
            process = Process(
                target=mine_worker,
                args=(prefix, difficulty, i, workers, stop_event, result_queue),
            )
            process.start()
            processes.append(process)

        nonce = None
        try:
            while True:
                if deadline is not None and time.time() >= deadline:
                    stop_event.set()
                    for process in processes:
                        if process.is_alive():
                            process.terminate()
                    for process in processes:
                        process.join()
                    print(f"[*] [{label}] Duration reached during search, stopping", flush=True)
                    return

                try:
                    nonce = result_queue.get(timeout=0.2)
                    break
                except queue.Empty:
                    continue
        finally:
            stop_event.set()

        elapsed = time.perf_counter() - start
        for process in processes:
            process.join(timeout=0.2)
        for process in processes:
            if process.is_alive():
                process.terminate()
                process.join()

        minted += 1
        print(f"[+] [{label}] Found nonce: {nonce} in {elapsed:.2f}s", flush=True)
        if minted % 5 == 0:
            print(f"[+] [{label}] Minted! Session: {minted} | balance: {minted}", flush=True)
        else:
            print(f"[+] [{label}] Minted! Session: {minted}", flush=True)


def parse_threads(value: str) -> int:
    if value == "auto":
        return os.cpu_count() or 1
    try:
        return max(1, int(value))
    except ValueError as exc:
        raise argparse.ArgumentTypeError("threads must be an integer or auto") from exc


def split_workers(total_threads: int, accounts: int) -> list[int]:
    base, remainder = divmod(max(1, total_threads), accounts)
    workers = [base + (1 if i < remainder else 0) for i in range(accounts)]
    return [max(1, count) for count in workers]


def main() -> None:
    parser = argparse.ArgumentParser(description="Local-only rpow-style mining simulator")
    parser.add_argument("--accounts", type=int, default=1, help="Number of virtual accounts")
    parser.add_argument("--threads", default="auto", help="Total worker count or auto")
    parser.add_argument("--difficulty", type=int, default=20, help="Difficulty in trailing zero bits")
    parser.add_argument("--duration", type=float, default=0.0, help="Stop after N seconds")
    parser.add_argument("--labels", default="", help="Comma-separated custom labels")
    args = parser.parse_args()

    if args.accounts < 1:
        raise SystemExit("--accounts must be at least 1")
    if args.difficulty < 1:
        raise SystemExit("--difficulty must be at least 1")
    if args.duration < 0:
        raise SystemExit("--duration cannot be negative")

    total_threads = parse_threads(args.threads)
    worker_counts = split_workers(total_threads, args.accounts)
    labels = [label.strip() for label in args.labels.split(",") if label.strip()]
    if not labels:
        labels = [f"account-{i + 1}" for i in range(args.accounts)]
    elif len(labels) < args.accounts:
        labels.extend(f"account-{i + 1}" for i in range(len(labels), args.accounts))

    deadline = time.time() + args.duration if args.duration > 0 else None

    print("[*] Local simulator only. No network calls, no cookies.", flush=True)
    print(f"[*] Accounts: {args.accounts}", flush=True)
    print(f"[*] Total threads: {total_threads}", flush=True)
    print(f"[*] Difficulty: {args.difficulty} bits", flush=True)

    controllers: list[Process] = []
    for i in range(args.accounts):
        process = Process(
            target=account_loop,
            args=(labels[i], worker_counts[i], args.difficulty, deadline),
        )
        process.start()
        controllers.append(process)

    for process in controllers:
        process.join()


if __name__ == "__main__":
    main()
