#!/usr/bin/env python3
"""
RIPE Atlas CGNAT Detection Tool

This tool analyzes RIPE Atlas traceroute data to detect probes behind
Carrier-Grade NAT (CGNAT) infrastructure using multiple detection methods.
"""

import json
import ipaddress
import re
import bz2
import argparse
import sys
import csv
import os
import glob
from collections import defaultdict, Counter
from typing import List, Dict, Set, Tuple, Optional
from dataclasses import dataclass, asdict
import statistics


@dataclass
class TracerouteHop:
    """Represents a single hop in a traceroute"""
    hop_num: int
    ip_address: Optional[str]
    rtt: Optional[float]
    hostname: Optional[str] = None


@dataclass
class TracerouteResult:
    """Represents a complete traceroute measurement"""
    probe_id: int
    target: str
    hops: List[TracerouteHop]
    timestamp: Optional[int] = None
    source_ip: Optional[str] = None


@dataclass
class CGNATIndicator:
    """Represents a CGNAT detection result"""
    probe_id: int
    indicator_type: str
    confidence: float  # 0.0 to 1.0
    evidence: str
    hop_details: Optional[List[TracerouteHop]] = None


class IPClassifier:
    """Utility class for classifying IP addresses"""
    
    # RFC 6598 - Shared Address Space for CGN
    CGNAT_RANGE = ipaddress.IPv4Network('100.64.0.0/10')
    
    # RFC 1918 - Private Address Ranges
    PRIVATE_RANGES = [
        ipaddress.IPv4Network('10.0.0.0/8'),
        ipaddress.IPv4Network('172.16.0.0/12'),
        ipaddress.IPv4Network('192.168.0.0/16')
    ]
    
    # RFC 3927 - Link-Local
    LINK_LOCAL = ipaddress.IPv4Network('169.254.0.0/16')
    
    @classmethod
    def is_cgnat_address(cls, ip_str: str) -> bool:
        """Check if IP is in RFC 6598 CGNAT range"""
        try:
            ip = ipaddress.IPv4Address(ip_str)
            return ip in cls.CGNAT_RANGE
        except (ipaddress.AddressValueError, ValueError):
            return False
    
    @classmethod
    def is_private_address(cls, ip_str: str) -> bool:
        """Check if IP is in RFC 1918 private ranges"""
        try:
            ip = ipaddress.IPv4Address(ip_str)
            return any(ip in network for network in cls.PRIVATE_RANGES)
        except (ipaddress.AddressValueError, ValueError):
            return False
    
    @classmethod
    def is_link_local(cls, ip_str: str) -> bool:
        """Check if IP is link-local"""
        try:
            ip = ipaddress.IPv4Address(ip_str)
            return ip in cls.LINK_LOCAL
        except (ipaddress.AddressValueError, ValueError):
            return False
    
    @classmethod
    def classify_ip(cls, ip_str: str) -> str:
        """Classify IP address type"""
        if not ip_str or ip_str == '*':
            return 'unknown'
        
        try:
            ip = ipaddress.IPv4Address(ip_str)
            if cls.is_cgnat_address(ip_str):
                return 'cgnat'
            elif cls.is_private_address(ip_str):
                return 'private'
            elif cls.is_link_local(ip_str):
                return 'link_local'
            elif ip.is_global:
                return 'public'
            else:
                return 'special'
        except (ipaddress.AddressValueError, ValueError):
            return 'invalid'


class TracerouteParser:
    """Parser for RIPE Atlas traceroute data"""
    
    @staticmethod
    def parse_atlas_json(data: Dict) -> TracerouteResult:
        """Parse RIPE Atlas JSON traceroute format"""
        probe_id = data.get('prb_id', 0)
        target = data.get('dst_addr', '')
        timestamp = data.get('timestamp')
        source_ip = data.get('src_addr')
        
        hops = []
        for hop_data in data.get('result', []):
            hop_num = hop_data.get('hop', 0)
            
            # Handle multiple results per hop
            for result in hop_data.get('result', [{}]):
                ip_address = result.get('from')
                rtt = result.get('rtt')
                
                hop = TracerouteHop(
                    hop_num=hop_num,
                    ip_address=ip_address,
                    rtt=rtt
                )
                hops.append(hop)
        
        return TracerouteResult(
            probe_id=probe_id,
            target=target,
            hops=hops,
            timestamp=timestamp,
            source_ip=source_ip
        )


class CGNATDetector:
    """Main CGNAT detection engine"""
    
    def __init__(self):
        self.probe_clusters = defaultdict(set)  # public_ip -> set of probe_ids
        self.probe_paths = {}  # probe_id -> TracerouteResult
        
    def analyze_traceroute(self, traceroute: TracerouteResult) -> List[CGNATIndicator]:
        """Analyze a single traceroute for CGNAT indicators"""
        indicators = []
        
        # Store for clustering analysis
        self.probe_paths[traceroute.probe_id] = traceroute
        
        # Method 1: RFC 6598 Address Detection
        cgnat_indicators = self._detect_rfc6598_addresses(traceroute)
        indicators.extend(cgnat_indicators)
        
        # Method 2: Private Address Leakage
        private_indicators = self._detect_private_leakage(traceroute)
        indicators.extend(private_indicators)
        
        # Method 3: Hop Pattern Analysis
        pattern_indicators = self._analyze_hop_patterns(traceroute)
        indicators.extend(pattern_indicators)
        
        # Method 4: TTL Analysis
        ttl_indicators = self._analyze_ttl_patterns(traceroute)
        indicators.extend(ttl_indicators)
        
        return indicators
    
    def _detect_rfc6598_addresses(self, traceroute: TracerouteResult) -> List[CGNATIndicator]:
        """Detect RFC 6598 CGNAT addresses in traceroute"""
        indicators = []
        cgnat_hops = []
        
        for hop in traceroute.hops:
            if hop.ip_address and IPClassifier.is_cgnat_address(hop.ip_address):
                cgnat_hops.append(hop)
        
        if cgnat_hops:
            indicator = CGNATIndicator(
                probe_id=traceroute.probe_id,
                indicator_type='rfc6598_address',
                confidence=0.95,  # High confidence
                evidence=f"Found RFC 6598 CGNAT addresses: {[h.ip_address for h in cgnat_hops]}",
                hop_details=cgnat_hops
            )
            indicators.append(indicator)
        
        return indicators
    
    def _detect_private_leakage(self, traceroute: TracerouteResult) -> List[CGNATIndicator]:
        """Detect private address leakage in public paths"""
        indicators = []
        private_hops = []
        public_hops = []
        
        for hop in traceroute.hops:
            if hop.ip_address:
                if IPClassifier.is_private_address(hop.ip_address):
                    private_hops.append(hop)
                elif IPClassifier.classify_ip(hop.ip_address) == 'public':
                    public_hops.append(hop)
        
        # Look for private addresses in paths that also contain public addresses
        if private_hops and public_hops:
            # Check if private addresses appear before public ones (typical NAT pattern)
            private_hop_nums = {h.hop_num for h in private_hops}
            public_hop_nums = {h.hop_num for h in public_hops}
            
            if min(private_hop_nums) < max(public_hop_nums):
                indicator = CGNATIndicator(
                    probe_id=traceroute.probe_id,
                    indicator_type='private_leakage',
                    confidence=0.7,  # Medium-high confidence
                    evidence=f"Private addresses in public path: {[h.ip_address for h in private_hops]}",
                    hop_details=private_hops
                )
                indicators.append(indicator)
        
        return indicators
    
    def _analyze_hop_patterns(self, traceroute: TracerouteResult) -> List[CGNATIndicator]:
        """Analyze hop patterns for CGNAT signatures"""
        indicators = []
        
        # Look for sudden RTT jumps that might indicate NAT boundaries
        rtts = [hop.rtt for hop in traceroute.hops if hop.rtt is not None]
        if len(rtts) < 3:
            return indicators
        
        # Calculate RTT increases between consecutive hops
        rtt_increases = []
        for i in range(1, len(rtts)):
            increase = rtts[i] - rtts[i-1]
            rtt_increases.append(increase)
        
        if rtt_increases:
            # Look for unusually large RTT jumps (potential NAT processing delay)
            avg_increase = statistics.mean(rtt_increases)
            max_increase = max(rtt_increases)
            
            if max_increase > avg_increase * 3 and max_increase > 50:  # >50ms jump
                indicator = CGNATIndicator(
                    probe_id=traceroute.probe_id,
                    indicator_type='rtt_jump',
                    confidence=0.4,  # Lower confidence
                    evidence=f"Large RTT jump detected: {max_increase:.2f}ms"
                )
                indicators.append(indicator)
        
        return indicators
    
    def _analyze_ttl_patterns(self, traceroute: TracerouteResult) -> List[CGNATIndicator]:
        """Analyze TTL patterns for irregularities"""
        indicators = []
        
        # Look for missing hops that might be filtered by NAT equipment
        hop_numbers = [hop.hop_num for hop in traceroute.hops if hop.ip_address]
        if not hop_numbers:
            return indicators
        
        # Check for gaps in hop sequence
        expected_hops = set(range(1, max(hop_numbers) + 1))
        actual_hops = set(hop_numbers)
        missing_hops = expected_hops - actual_hops
        
        # If more than 20% of hops are missing, might indicate NAT filtering
        if len(missing_hops) > len(expected_hops) * 0.2:
            indicator = CGNATIndicator(
                probe_id=traceroute.probe_id,
                indicator_type='missing_hops',
                confidence=0.3,  # Low confidence
                evidence=f"Significant hop gaps detected: {sorted(missing_hops)}"
            )
            indicators.append(indicator)
        
        return indicators
    
    def analyze_probe_clustering(self) -> List[CGNATIndicator]:
        """Analyze probe clustering patterns to detect shared NAT exit points"""
        indicators = []
        
        # Group probes by their apparent exit IP (last public IP in traceroute)
        exit_ip_clusters = defaultdict(set)
        
        for probe_id, traceroute in self.probe_paths.items():
            # Find the last public IP in the traceroute
            last_public_ip = None
            for hop in reversed(traceroute.hops):
                if hop.ip_address and IPClassifier.classify_ip(hop.ip_address) == 'public':
                    last_public_ip = hop.ip_address
                    break
            
            if last_public_ip:
                exit_ip_clusters[last_public_ip].add(probe_id)
        
        # Look for clusters with multiple probes (potential CGNAT)
        for exit_ip, probe_set in exit_ip_clusters.items():
            if len(probe_set) > 1:  # Multiple probes sharing same exit IP
                for probe_id in probe_set:
                    indicator = CGNATIndicator(
                        probe_id=probe_id,
                        indicator_type='probe_clustering',
                        confidence=0.6,  # Medium confidence
                        evidence=f"Shares exit IP {exit_ip} with {len(probe_set)-1} other probes"
                    )
                    indicators.append(indicator)
        
        return indicators
    
    def get_summary_statistics(self) -> Dict:
        """Generate summary statistics of CGNAT detection"""
        total_probes = len(self.probe_paths)
        
        # Count indicators by type
        indicator_counts = defaultdict(int)
        high_confidence_probes = set()
        
        for traceroute in self.probe_paths.values():
            indicators = self.analyze_traceroute(traceroute)
            for indicator in indicators:
                indicator_counts[indicator.indicator_type] += 1
                if indicator.confidence >= 0.8:
                    high_confidence_probes.add(indicator.probe_id)
        
        # Add clustering analysis
        clustering_indicators = self.analyze_probe_clustering()
        for indicator in clustering_indicators:
            indicator_counts[indicator.indicator_type] += 1
        
        return {
            'total_probes_analyzed': total_probes,
            'high_confidence_cgnat_probes': len(high_confidence_probes),
            'indicator_counts': dict(indicator_counts),
            'cgnat_detection_rate': len(high_confidence_probes) / total_probes if total_probes > 0 else 0
        }


def load_traceroutes_from_bz2(filename: str) -> List[Dict]:
    """Load traceroute data from a bz2 compressed file"""
    traceroutes = []
    
    try:
        with bz2.open(filename, 'rt', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                
                try:
                    data = json.loads(line)
                    # Only process traceroute measurements
                    if data.get('type') == 'traceroute':
                        traceroutes.append(data)
                except json.JSONDecodeError as e:
                    print(f"Warning: Failed to parse JSON on line {line_num}: {e}", file=sys.stderr)
                    continue
                except Exception as e:
                    print(f"Warning: Error processing line {line_num}: {e}", file=sys.stderr)
                    continue
    
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error reading file '{filename}': {e}", file=sys.stderr)
        sys.exit(1)
    
    return traceroutes


def find_bz2_files(folder_path: str) -> List[str]:
    """Find all .bz2 files in a folder"""
    if not os.path.isdir(folder_path):
        print(f"Error: '{folder_path}' is not a valid directory", file=sys.stderr)
        sys.exit(1)
    
    # Find all .bz2 files in the folder
    pattern = os.path.join(folder_path, "*.bz2")
    bz2_files = glob.glob(pattern)
    
    if not bz2_files:
        print(f"Error: No .bz2 files found in '{folder_path}'", file=sys.stderr)
        sys.exit(1)
    
    # Sort files for consistent processing order
    bz2_files.sort()
    return bz2_files


def process_multiple_bz2_files(folder_path: str, verbose: bool = False, output_format: str = 'text', 
                              output_file: Optional[str] = None, min_confidence: float = 0.0) -> None:
    """Process all bz2 files in a folder containing RIPE Atlas traceroute data"""
    
    print(f"Finding .bz2 files in {folder_path}...")
    bz2_files = find_bz2_files(folder_path)
    
    print(f"Found {len(bz2_files)} .bz2 files to process")
    if verbose:
        for i, filename in enumerate(bz2_files, 1):
            print(f"  {i}. {os.path.basename(filename)}")
    
    # Initialize detector (will accumulate data across all files)
    detector = CGNATDetector()
    all_indicators = []
    total_measurements = 0
    total_processed = 0
    
    # Process each file
    for file_idx, filename in enumerate(bz2_files, 1):
        print(f"\nProcessing file {file_idx}/{len(bz2_files)}: {os.path.basename(filename)}")
        
        try:
            # Load traceroute data from current file
            traceroute_data = load_traceroutes_from_bz2(filename)
            
            if not traceroute_data:
                print(f"  No valid traceroute data found in {os.path.basename(filename)}")
                continue
            
            file_measurements = len(traceroute_data)
            total_measurements += file_measurements
            print(f"  Loaded {file_measurements} traceroute measurements")
            
            # Process traceroutes from current file
            file_processed = 0
            for data in traceroute_data:
                try:
                    traceroute = TracerouteParser.parse_atlas_json(data)
                    indicators = detector.analyze_traceroute(traceroute)
                    all_indicators.extend(indicators)
                    file_processed += 1
                    total_processed += 1
                    
                    if verbose and total_processed % 5000 == 0:
                        print(f"  Processed {total_processed} total traceroutes...")
                        
                except Exception as e:
                    if verbose:
                        print(f"  Warning: Failed to process traceroute from probe {data.get('prb_id', 'unknown')}: {e}", file=sys.stderr)
                    continue
            
            print(f"  Successfully processed {file_processed} traceroutes from this file")
            
        except Exception as e:
            print(f"  Error processing file {os.path.basename(filename)}: {e}", file=sys.stderr)
            continue
    
    print(f"\nCompleted processing {len(bz2_files)} files")
    print(f"Total measurements loaded: {total_measurements}")
    print(f"Total measurements processed: {total_processed}")
    
    # Analyze clustering across all files
    print("Analyzing probe clustering patterns across all files...")
    clustering_indicators = detector.analyze_probe_clustering()
    all_indicators.extend(clustering_indicators)
    
    # Filter by confidence threshold
    filtered_indicators = filter_indicators_by_confidence(all_indicators, min_confidence)
    
    if min_confidence > 0.0:
        print(f"Filtered to {len(filtered_indicators)} indicators with confidence >= {min_confidence:.2f}")
    
    # Get summary statistics
    stats = detector.get_summary_statistics()
    stats['indicators_above_threshold'] = len(filtered_indicators)
    stats['confidence_threshold'] = min_confidence
    stats['total_files_processed'] = len(bz2_files)
    stats['total_measurements_loaded'] = total_measurements
    stats['total_measurements_processed'] = total_processed
    
    # Output results in specified format
    if output_format == 'json':
        output_json_format(filtered_indicators, stats, output_file)
    elif output_format == 'csv':
        output_csv_format(filtered_indicators, stats, output_file)
    else:  # text format
        output_text_format(filtered_indicators, stats, output_file)
    """Filter indicators by minimum confidence threshold"""
    return [indicator for indicator in indicators if indicator.confidence >= min_confidence]


def output_text_format(indicators: List[CGNATIndicator], stats: Dict, output_file: Optional[str] = None):
    """Output results in human-readable text format"""
    output_lines = []
    
    output_lines.append("CGNAT Detection Results")
    output_lines.append("=" * 80)
    
    if not indicators:
        output_lines.append("No CGNAT indicators found above the confidence threshold.")
    else:
        # Group indicators by probe
        probe_indicators = defaultdict(list)
        for indicator in indicators:
            probe_indicators[indicator.probe_id].append(indicator)
        
        # Sort probes by highest confidence indicator
        sorted_probes = sorted(probe_indicators.items(), 
                              key=lambda x: max(ind.confidence for ind in x[1]), 
                              reverse=True)
        
        for probe_id, probe_inds in sorted_probes:
            output_lines.append(f"\nProbe {probe_id}:")
            for indicator in sorted(probe_inds, key=lambda x: x.confidence, reverse=True):
                output_lines.append(f"  • {indicator.indicator_type.replace('_', ' ').title()}")
                output_lines.append(f"    Confidence: {indicator.confidence:.2f}")
                output_lines.append(f"    Evidence: {indicator.evidence}")
    
    # Add summary statistics
    output_lines.append(f"\nSummary Statistics")
    output_lines.append("=" * 80)
    for key, value in stats.items():
        if isinstance(value, float):
            output_lines.append(f"{key.replace('_', ' ').title()}: {value:.3f}")
        else:
            output_lines.append(f"{key.replace('_', ' ').title()}: {value}")
    
    # Output to file or stdout
    output_text = '\n'.join(output_lines)
    if output_file:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(output_text)
        print(f"Results saved to {output_file}")
    else:
        print(output_text)


def output_json_format(indicators: List[CGNATIndicator], stats: Dict, output_file: Optional[str] = None):
    """Output results in JSON format"""
    # Convert indicators to dictionaries, handling hop_details
    indicators_dict = []
    for indicator in indicators:
        indicator_dict = asdict(indicator)
        # Convert hop_details to simple format if present
        if indicator_dict['hop_details']:
            indicator_dict['hop_details'] = [
                {
                    'hop_num': hop.hop_num,
                    'ip_address': hop.ip_address,
                    'rtt': hop.rtt,
                    'hostname': hop.hostname
                }
                for hop in indicator.hop_details
            ]
        indicators_dict.append(indicator_dict)
    
    output_data = {
        'cgnat_indicators': indicators_dict,
        'summary_statistics': stats,
        'metadata': {
            'total_indicators': len(indicators),
            'unique_probes_with_indicators': len(set(ind.probe_id for ind in indicators))
        }
    }
    
    # Output to file or stdout
    json_output = json.dumps(output_data, indent=2, ensure_ascii=False)
    if output_file:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(json_output)
        print(f"Results saved to {output_file}")
    else:
        print(json_output)


def output_csv_format(indicators: List[CGNATIndicator], stats: Dict, output_file: Optional[str] = None):
    """Output results in CSV format"""
    import io
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow(['probe_id', 'indicator_type', 'confidence', 'evidence'])
    
    # Write indicators
    for indicator in indicators:
        writer.writerow([
            indicator.probe_id,
            indicator.indicator_type,
            f"{indicator.confidence:.3f}",
            indicator.evidence
        ])
    
    # Add summary statistics as comments
    output.write('\n# Summary Statistics\n')
    for key, value in stats.items():
        if isinstance(value, float):
            output.write(f'# {key}: {value:.3f}\n')
        else:
            output.write(f'# {key}: {value}\n')
    
    # Output to file or stdout
    csv_content = output.getvalue()
    if output_file:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(csv_content)
        print(f"Results saved to {output_file}")
    else:
        print(csv_content)


def process_bz2_file(filename: str, verbose: bool = False, output_format: str = 'text', 
                    output_file: Optional[str] = None, min_confidence: float = 0.0) -> None:
    """Process a bz2 file containing RIPE Atlas traceroute data"""
    
    print(f"Loading traceroute data from {filename}...")
    traceroute_data = load_traceroutes_from_bz2(filename)
    
    if not traceroute_data:
        print("No valid traceroute data found in file")
        return
    
    print(f"Loaded {len(traceroute_data)} traceroute measurements")
    
    # Initialize detector
    detector = CGNATDetector()
    
    # Process traceroutes
    all_indicators = []
    processed_count = 0
    
    for data in traceroute_data:
        try:
            traceroute = TracerouteParser.parse_atlas_json(data)
            indicators = detector.analyze_traceroute(traceroute)
            all_indicators.extend(indicators)
            processed_count += 1
            
            if verbose and processed_count % 1000 == 0:
                print(f"Processed {processed_count} traceroutes...")
                
        except Exception as e:
            if verbose:
                print(f"Warning: Failed to process traceroute from probe {data.get('prb_id', 'unknown')}: {e}", file=sys.stderr)
            continue
    
    print(f"Successfully processed {processed_count} traceroutes")
    
    # Analyze clustering
    print("Analyzing probe clustering patterns...")
    clustering_indicators = detector.analyze_probe_clustering()
    all_indicators.extend(clustering_indicators)
    
    # Filter by confidence threshold
    filtered_indicators = filter_indicators_by_confidence(all_indicators, min_confidence)
    
    if min_confidence > 0.0:
        print(f"Filtered to {len(filtered_indicators)} indicators with confidence >= {min_confidence:.2f}")
    
    # Get summary statistics
    stats = detector.get_summary_statistics()
    stats['indicators_above_threshold'] = len(filtered_indicators)
    stats['confidence_threshold'] = min_confidence
    
    # Output results in specified format
    if output_format == 'json':
        output_json_format(filtered_indicators, stats, output_file)
    elif output_format == 'csv':
        output_csv_format(filtered_indicators, stats, output_file)
    else:  # text format
        output_text_format(filtered_indicators, stats, output_file)


def main():
    """Main function with command line argument handling"""
    parser = argparse.ArgumentParser(
        description='Detect CGNAT in RIPE Atlas traceroute data',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Single file processing
  python cgnat_detector.py traceroute_data.json.bz2
  python cgnat_detector.py -v large_dataset.bz2
  
  # Folder processing (all .bz2 files)
  python cgnat_detector.py --input-folder /path/to/data/
  python cgnat_detector.py --input-folder ./measurements/ --output json
  
  # Output and filtering options
  python cgnat_detector.py --output json --output-file results.json data.bz2
  python cgnat_detector.py --min-confidence 0.8 --output csv data.bz2
  python cgnat_detector.py --input-folder ./data/ --min-confidence 0.9 --output-file high_conf.txt
        """
    )
    
    # Input options (mutually exclusive)
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('input_file', nargs='?', 
                           help='BZ2 compressed file containing RIPE Atlas traceroute data')
    input_group.add_argument('--input-folder', 
                           help='Folder containing multiple .bz2 files to process')
    
    # Other options
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose output')
    parser.add_argument('--output', choices=['text', 'json', 'csv'], 
                       default='text', help='Output format (default: text)')
    parser.add_argument('--output-file', 
                       help='Save results to file instead of printing to stdout')
    parser.add_argument('--min-confidence', type=float, default=0.0,
                       help='Minimum confidence threshold (0.0-1.0, default: 0.0)')
    
    args = parser.parse_args()
    
    # Validate confidence threshold
    if not 0.0 <= args.min_confidence <= 1.0:
        print("Error: --min-confidence must be between 0.0 and 1.0", file=sys.stderr)
        sys.exit(1)
    
    if args.input_folder:
        # Process multiple files from folder
        process_multiple_bz2_files(args.input_folder, args.verbose, args.output, args.output_file, args.min_confidence)
    elif args.input_file:
        # Process the specified bz2 file
        process_bz2_file(args.input_file, args.verbose, args.output, args.output_file, args.min_confidence)


if __name__ == "__main__":
    main()