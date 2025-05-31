#!/usr/bin/env python3
import os
import time
import gzip
import argparse
import requests
from datetime import datetime, timezone, timedelta
from typing import Iterator, List

API_BASE = "https://atlas.ripe.net/api/v2"
RETRY_LIMIT = 5
FAILED_FILENAME = "failed_measurements.txt"


def get_unix_ts(dt: datetime) -> int:
    """
    Convert a datetime object to a UNIX timestamp (seconds since epoch UTC).

    :param dt: A datetime object (naïve or timezone-aware) representing a UTC time.
    :type dt: datetime
    :return: UNIX timestamp corresponding to dt in UTC.
    :rtype: int
    """
    return int(dt.replace(tzinfo=timezone.utc).timestamp())


def list_public_traceroutes() -> Iterator[int]:
    """
    Yield all public traceroute measurement IDs via pagination in the RIPE Atlas API.

    This function queries the RIPE Atlas measurements endpoint for traceroutes
    that are marked as public. It handles pagination automatically and yields
    each measurement ID as it is retrieved.

    :return: An iterator over measurement IDs (integers).
    :rtype: Iterator[int]
    """
    url = f"{API_BASE}/measurements/"
    params = {"type": "traceroute", "is_public": "true", "page_size": 100}
    while url:
        resp = requests.get(url, params=params)
        resp.raise_for_status()
        data = resp.json()
        for m in data.get("results", []):
            yield m["id"]
        url = data.get("next")
        params.clear()
        time.sleep(0.2)


def fetch_and_save_results(measurement_id: int, start_ts: int, stop_ts: int, out_dir: str) -> None:
    """
    Download and compress traceroute results for a single measurement, using a temporary file.

    This function queries the RIPE Atlas API for results of the given measurement
    ID within a specified time range (start_ts to stop_ts, inclusive). Data is streamed
    from the API and written directly to a gzip-compressed temporary file. Once the download
    completes and the gzip file is validated, it is renamed to the final filename.

    :param measurement_id: The RIPE Atlas measurement ID to fetch.
    :type measurement_id: int
    :param start_ts: Start of the time window as UNIX timestamp (UTC).
    :type start_ts: int
    :param stop_ts: End of the time window as UNIX timestamp (UTC).
    :type stop_ts: int
    :param out_dir: Path to an existing directory where the .ndjson.gz file will be saved.
    :type out_dir: str
    :return: None. On success, writes a compressed NDJSON file named "<measurement_id>.ndjson.gz".
    :rtype: None
    """
    url = f"{API_BASE}/measurements/{measurement_id}/results/"
    params = {"start_time__gte": start_ts, "stop_time__lte": stop_ts}
    final_fn = os.path.join(out_dir, f"{measurement_id}.ndjson.gz")
    temp_fn = final_fn + ".part"

    # Remove existing temp if present to start fresh
    if os.path.exists(temp_fn):
        os.remove(temp_fn)

    resp = requests.get(url, params=params, stream=True, timeout=30)
    if resp.status_code == 404:
        # No results for this measurement
        return
    resp.raise_for_status()

    # Stream content into temporary gzip file
    with open(temp_fn, 'wb') as f_raw:
        for chunk in resp.iter_content(1024):
            if chunk:
                f_raw.write(chunk)

    # Validate temporary gzip
    try:
        with gzip.open(temp_fn, 'rb') as test_f:
            # Attempt to read a small portion
            test_f.read(1)
    except (OSError, EOFError) as e:
        # Corrupted/incomplete gzip; remove temp and raise to retry
        os.remove(temp_fn)
        raise RuntimeError(f"Corrupted gzip file for {measurement_id}: {e}")

    # Rename temporary to final
    os.replace(temp_fn, final_fn)
    size_kb = os.path.getsize(final_fn) // 1024
    print(f"Saved and validated {measurement_id}.ndjson.gz ({size_kb} KB)")


def main(date_str: str, out_dir: str) -> None:
    """
    Main entry point: download and compress public traceroutes for a given date, with retry.

    Creates the output directory if it does not exist. Iterates over all public
    traceroute measurement IDs and, for each one not already downloaded, attempts
    up to RETRY_LIMIT times to fetch and compress the results for the specified date.
    Failed measurement IDs are collected and written to a file.

    :param date_str: Date in "YYYY-MM-DD" format (UTC) for which to fetch results.
    :type date_str: str
    :param out_dir: Directory path where compressed result files and failure log will be saved.
    :type out_dir: str
    :return: None. Writes .ndjson.gz files and possibly a "failed_measurements.txt" log.
    :rtype: None
    """
    # Define UTC start/end for the given date
    day = datetime.fromisoformat(date_str)
    start = datetime(day.year, day.month, day.day, tzinfo=timezone.utc)
    stop = start + timedelta(days=1) - timedelta(seconds=1)

    start_ts = get_unix_ts(start)
    stop_ts = get_unix_ts(stop)

    os.makedirs(out_dir, exist_ok=True)
    failed_ids: List[int] = []

    print(f"Fetching public traceroutes for {date_str} (UTC) with retry logic...")
    for meas_id in list_public_traceroutes():
        final_fn = os.path.join(out_dir, f"{meas_id}.ndjson.gz")
        # Skip if final file exists
        if os.path.exists(final_fn):
            print(f"Skipping {meas_id}, already completed.")
            continue

        success = False
        for attempt in range(1, RETRY_LIMIT + 1):
            try:
                fetch_and_save_results(meas_id, start_ts, stop_ts, out_dir)
                success = True
                break
            except Exception as e:
                print(f"⚠️ Attempt {attempt} failed for {meas_id}: {e}")
                time.sleep(1)  # brief pause before retry

        if not success:
            print(f"❌ All {RETRY_LIMIT} attempts failed for measurement {meas_id}.")
            failed_ids.append(meas_id)

        time.sleep(0.1)

    # Write failed measurement IDs to file
    if failed_ids:
        failed_path = os.path.join(out_dir, FAILED_FILENAME)
        with open(failed_path, "w") as ff:
            for mid in failed_ids:
                ff.write(f"{mid}\n")
        print(f"Wrote {len(failed_ids)} failed IDs to {failed_path}")
    else:
        print("All measurements downloaded successfully.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Download & compress RIPE Atlas public traceroutes for a given UTC date with retries"
    )
    parser.add_argument(
        "--date", "-d", default="2024-11-17",
        help="Date in YYYY-MM-DD (UTC) to fetch results for"
    )
    parser.add_argument(
        "--out", "-o", default="results",
        help="Directory to save .ndjson.gz result files"
    )
    args = parser.parse_args()
    main(args.date, args.out)
