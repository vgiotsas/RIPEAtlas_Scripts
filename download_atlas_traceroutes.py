#!/usr/bin/env python3
import os
import gzip
import time
import argparse
import requests  # used only for listing measurement IDs, not for downloading chunks
import subprocess
from datetime import datetime, timezone, timedelta
from typing import Iterator, List


API_BASE = "https://atlas.ripe.net/api/v2"
RETRY_LIMIT = 5
CHUNK_DURATION = 6
FAILED_FILENAME = "failed_measurements.txt"


def get_unix_ts(dt: datetime) -> int:
    """
    Convert a datetime object to a UNIX timestamp (seconds since epoch UTC).

    :param dt: A datetime object representing a UTC time.
    :type dt: datetime
    :return: UNIX timestamp corresponding to dt in UTC.
    :rtype: int
    """
    return int(dt.replace(tzinfo=timezone.utc).timestamp())


def list_public_traceroutes(start_ts: int, stop_ts: int, builtin: bool=False) -> Iterator[int]:
    """
    Yield all public traceroute measurement IDs via pagination using requests (HTTP/1.1).

    Depending on the `builtin` flag, either fetches only measurements created by users
    within a given time window or (if builtin=True) limits to IDs less than or equal to a fixed threshold.

    :param start_ts: Start of the time window as a UNIX timestamp (UTC).
    :type start_ts: int
    :param stop_ts: End of the time window as a UNIX timestamp (UTC).
    :type stop_ts: int
    :param builtin: If True, yield only built-in measurements (ID <= 7000); otherwise, yield those in the time window.
    :type builtin: bool
    :yield: Measurement ID (integer) for each public traceroute.
    :rtype: Iterator[int]
    """
    url = f"{API_BASE}/measurements/"
    params = {"type": "traceroute", "is_public": "true", "page_size": 100}
    if builtin:
        params["id__lte"] = 7000
    else:
        params["start_time__gte"] = start_ts
        params["stop_time__lte"] = stop_ts

    while url:
        resp = requests.get(url, params=params, timeout=90)
        resp.raise_for_status()
        data = resp.json()
        for m in data.get("results", []):
            yield m["id"]
        url = data.get("next")
        params.clear()
        time.sleep(0.2)


def fetch_and_save_results_curl(
    measurement_id: int, start_ts: int, stop_ts: int, out_dir: str
) -> None:
    """
    Use `curl --http1.0` to download RIPE Atlas chunked results in JSONL format.

    Each chunk is saved to a temporary file in a `._temp_chunks` sub-directory.
    Non-empty chunks are appended (gzip-compressed) to
    `<out_dir>/<measurement_id>.jsonl.gz`.  Completely empty measurements
    (chunks that are only “[]”) are detected and *not* preserved: any
    zero-content file is deleted before returning.

    :param measurement_id: The RIPE Atlas measurement ID to fetch.
    :type  measurement_id: int
    :param start_ts:  Start of the time window (Unix UTC).
    :param stop_ts:   End   of the time window (Unix UTC).
    :param out_dir:   Directory where result files and temporary chunks live.
    :return:          None.  On success, a `<id>.jsonl.gz` containing ≥1
                      traceroute appears in *out_dir*; otherwise no file remains.
    :raises RuntimeError: If all curl attempts fail for any chunk.
    """

    final_fn = os.path.join(out_dir, f"{measurement_id}.jsonl.gz")
    temp_dir = os.path.join(out_dir, "._temp_chunks")
    os.makedirs(temp_dir, exist_ok=True)

    # Skip if a non-empty file already exists
    if os.path.exists(final_fn) and os.path.getsize(final_fn) > 0:
        print(f"⏭️  Skipping {measurement_id}, {final_fn} already exists.")
        return

    # Clear any stale temporary chunks
    for f in os.listdir(temp_dir):
        if f.startswith(f"chunk_{measurement_id}_"):
            os.remove(os.path.join(temp_dir, f))

    interval     = CHUNK_DURATION * 3600          # six-hour slices
    current_ts   = start_ts
    chunk_index  = 0
    wrote_data   = False                          # gets flipped to True on first non-empty chunk

    while current_ts <= stop_ts:
        chunk_end_ts  = min(current_ts + interval - 1, stop_ts)
        api_path      = (
            f"/api/v2/measurements/{measurement_id}/results/"
            f"?start={current_ts}&stop={chunk_end_ts}"
        )
        full_url      = f"https://atlas.ripe.net{api_path}"
        chunk_fn      = os.path.join(
            temp_dir, f"chunk_{measurement_id}_{chunk_index:03d}.jsonl"
        )
        print(f"⏳  Downloading (chunk #{chunk_index}): {full_url}")

        # ── retry with exponential back-off ───────────────────────────────
        success = False
        for attempt in range(1, RETRY_LIMIT + 1):
            cmd = [
                "curl", full_url,
                "--http1.0", "--silent", "--show-error", "--fail",  # --fail ⇒ exit≠0 on 4xx/5xx
                "-o", chunk_fn,
            ]
            try:
                subprocess.run(cmd, check=True, stderr=subprocess.PIPE)
                success = True
                break
            except subprocess.CalledProcessError as cpe:
                err = cpe.stderr.decode(errors="ignore").strip()
                print(f"⚠️  Attempt {attempt}/{RETRY_LIMIT} failed: {err}")
                time.sleep(2 ** attempt)
            except Exception as e:
                print(f"⚠️  Unexpected error: {e}")
                time.sleep(2 ** attempt)

        if not success:
            raise RuntimeError(
                f"All {RETRY_LIMIT} curl attempts failed "
                f"for measurement {measurement_id} ({current_ts}-{chunk_end_ts})"
            )

        # ── check whether this chunk is empty (i.e., exactly "[]\n") ─────
        with open(chunk_fn, "rb") as cf:
            chunk_bytes = cf.read()
        if chunk_bytes.strip() in (b"[]", b""):
            # Nothing inside → just drop it
            os.remove(chunk_fn)
        else:
            # First time we see real data ⇒ start/continue gzip file
            with gzip.open(final_fn, "ab") as gz_out:
                gz_out.write(chunk_bytes)
            wrote_data = True
            os.remove(chunk_fn)

        # next slice
        current_ts  = chunk_end_ts + 1
        chunk_index += 1

    # ── tidy up ──────────────────────────────────────────────────────────
    if not wrote_data:
        # Either no file was created, or it is also empty: ensure deletion
        if os.path.exists(final_fn):
            os.remove(final_fn)
        print(f"🚮  {measurement_id}: all chunks empty – file removed.")
    else:
        print(f"✅  Completed {measurement_id}.jsonl.gz")

    # Remove temp dir if it is empty
    if not os.listdir(temp_dir):
        os.rmdir(temp_dir)


def main(date_str: str, out_dir: str, builtin: bool) -> None:
    """
    Main entry point: download public traceroutes for a given UTC date via curl.

    Computes the UTC start/end timestamps for the given date, lists all public traceroute
    measurement IDs in that window (or built-in IDs if `builtin=True`), and for each ID,
    calls `fetch_and_save_results_curl`. Records any failures in a log file.

    :param date_str: Date in "YYYY-MM-DD" format (UTC) for which to fetch results.
    :type date_str: str
    :param out_dir: Directory path where result files and failure log will be saved.
    :type out_dir: str
    :param builtin: If True, download only built-in (ID ≤ 7000) measurements; otherwise, download within date window.
    :type builtin: bool
    :return: None. Writes `.jsonl` files and possibly a "failed_measurements.txt" log.
    :rtype: None
    """
    # Compute UTC start/end for the given date
    day = datetime.fromisoformat(date_str)
    start = datetime(day.year, day.month, day.day, tzinfo=timezone.utc)
    stop = start + timedelta(days=1) - timedelta(seconds=1)

    start_ts = get_unix_ts(start)
    stop_ts = get_unix_ts(stop)

    os.makedirs(out_dir, exist_ok=True)
    failed_ids: List[int] = []

    print(f"📦 Fetching public traceroutes for {date_str} (UTC) via curl …")

    for meas_id in list_public_traceroutes(start_ts, stop_ts, builtin):
        try:
            fetch_and_save_results_curl(meas_id, start_ts, stop_ts, out_dir)
        except Exception as e:
            print(f"❌ Failed measurement {meas_id}: {e}")
            failed_ids.append(meas_id)

        # Small pause between measurements
        time.sleep(0.1)

    # Write any failures to a log
    if failed_ids:
        failed_path = os.path.join(out_dir, FAILED_FILENAME)
        with open(failed_path, "w") as ff:
            for mid in failed_ids:
                ff.write(f"{mid}\n")
        print(f"📝 Wrote {len(failed_ids)} failed IDs to {failed_path}")
    else:
        print("✅ All measurements downloaded successfully.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Download RIPE Atlas public traceroutes for a given UTC date using curl"
    )
    parser.add_argument(
        "--date", "-d", default="2024-05-30",
        help="Date in YYYY-MM-DD (UTC) to fetch results for"
    )
    parser.add_argument(
        "--out", "-o", default="results",
        help="Directory to save .jsonl result files"
    )
    parser.add_argument(
        "--builtin",
        action="store_true",
        default=False,
        help="If set, download the built-in RIPE Measurements, if not set downloads only the user-generated measurements"
    )
    args = parser.parse_args()

    main(args.date, args.out, args.builtin)
