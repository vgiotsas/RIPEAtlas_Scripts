#!/usr/bin/env python3
import os
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

    Each chunk is saved to a temporary file in a `. _temp_chunks` subdirectory, then appended to
    `<out_dir>/<measurement_id>.jsonl`. Retries on failure up to RETRY_LIMIT. Removes temporary files
    when done.

    :param measurement_id: The RIPE Atlas measurement ID to fetch.
    :type measurement_id: int
    :param start_ts: Start of the time window as a UNIX timestamp (UTC).
    :type start_ts: int
    :param stop_ts: End of the time window as a UNIX timestamp (UTC).
    :type stop_ts: int
    :param out_dir: Directory where result files and temporary chunks are saved.
    :type out_dir: str
    :return: None. On success, writes a `<measurement_id>.jsonl` file in out_dir.
    :rtype: None
    :raises RuntimeError: If all curl attempts fail for any chunk.
    """

    final_fn = os.path.join(out_dir, f"{measurement_id}.jsonl")
    temp_dir = os.path.join(out_dir, "._temp_chunks")
    os.makedirs(temp_dir, exist_ok=True)

    # If a final file already exists, skip downloading.
    if os.path.exists(final_fn):
        print(f"⏭️ Skipping {measurement_id}, {final_fn} already exists.")
        return

    # Remove any leftover temp chunks from a previous run
    for f in os.listdir(temp_dir):
        if f.startswith(f"chunk_{measurement_id}_"):
            os.remove(os.path.join(temp_dir, f))

    interval = CHUNK_DURATION * 3600  # 6-hour chunks
    current = start_ts
    chunk_index = 0

    # Ensure the final file is empty (in case this run was aborted halfway)
    if os.path.exists(final_fn):
        os.remove(final_fn)

    while current <= stop_ts:
        chunk_end = min(current + interval - 1, stop_ts)
        path = (
            f"/api/v2/measurements/{measurement_id}/results/"
            f"?start={current}&stop={chunk_end}"
        )
        full_url = f"https://atlas.ripe.net{path}"
        chunk_filename = os.path.join(
            temp_dir, f"chunk_{measurement_id}_{chunk_index:03d}.jsonl"
        )
        print(f"⏳ Downloading (chunk #{chunk_index}): {full_url}")

        success = False
        for attempt in range(1, RETRY_LIMIT + 1):
            # Build the curl command
            cmd = [
                "curl",
                full_url,
                "-o",
                chunk_filename,
                "--http1.0",
                "--silent",
                "--show-error",
            ]
            try:
                proc = subprocess.run(cmd, check=True, stderr=subprocess.PIPE)
                # If HTTP status is 404, curl will return exit code 22: we interpret as “no data”
                if proc.returncode == 0 and os.path.getsize(chunk_filename) == 0:
                    # Empty file means no data in this interval
                    print(f"⚠️ Empty data for chunk #{chunk_index} ({current}-{chunk_end})")
                success = True
                break
            except subprocess.CalledProcessError as cpe:
                stderr = cpe.stderr.decode(errors="ignore").strip()
                print(
                    f"⚠️ Curl attempt {attempt} failed for measurement {measurement_id} "
                    f"(chunk {current}-{chunk_end}): {stderr}"
                )
                time.sleep(2 ** attempt)
            except Exception as e:
                print(
                    f"⚠️ Unexpected error on curl attempt {attempt} "
                    f"for measurement {measurement_id}: {e}"
                )
                time.sleep(2 ** attempt)

        if not success:
            raise RuntimeError(
                f"All {RETRY_LIMIT} curl attempts failed for "
                f"{measurement_id} chunk {current}-{chunk_end}"
            )

        # Append this chunk to the final file (even if empty)
        with open(chunk_filename, "rb") as src, open(final_fn, "ab") as dest:
            dest.write(src.read())

        # Remove the temporary chunk file to save space
        os.remove(chunk_filename)

        current = chunk_end + 1
        chunk_index += 1

    # Clean up temp directory if empty
    if not os.listdir(temp_dir):
        os.rmdir(temp_dir)

    print(f"✅ Completed {measurement_id}.jsonl")


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
        "--date", "-d", default="2024-11-17",
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
