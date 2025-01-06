import os
import time
import r2pipe
import pandas as pd
import re
import json

from tqdm import tqdm
from dataclasses import dataclass
from elftools.elf.elffile import ELFFile
from elftools.elf.constants import P_FLAGS
from typing import Optional, List, Dict, Any
from concurrent.futures import ProcessPoolExecutor, as_completed

from .logger import get_logger
from .utils import check_r2_timeout, check_dependencies

@dataclass
class ElfAddresses:
    """Data class for storing ELF address information"""
    sequence_start: int
    entry_point: int
    sequence_end: int

class ExtractFeature:
    """
    A class for extracting function call graphs from executable files using r2pipe.
    This class handles both ELF files with proper sections and compressed/packed executables.
    """

    def __init__(self):
        """Initialize the ExtractFeature class and check dependencies."""
        deps_available, message = check_dependencies()
        if not deps_available:
            raise RuntimeError(f"Missing dependencies:\n{message}")

    def process_features(
        self,
        df_input: pd.DataFrame,
        dir_feature: str,
        dir_dataset: str,
        timeout_seconds: int,
        dir_log: str = "logs"
    ) -> None:
        """
        Extract opcode features for all files in the dataset.

        Args:
            df_input: Preprocessed DataFrame containing file information
            dir_feature: Directory to save extracted features
            dir_dataset: Directory containing samples
            timeout_seconds: Maximum seconds for feature extraction
            dir_log: Directory for logging
        """
        self.logger = get_logger(__name__, dir_log)
        os.makedirs(dir_feature, exist_ok=True)

        list_args = []
        for _, row in df_input.iterrows():
            str_filename = row['file_name']
            dir_out = ''
            dir_out = os.path.join(dir_feature, str_filename[:2])
            dir_out = os.path.join(dir_out, str_filename)
            os.makedirs(dir_out, exist_ok=True)

            # Create output filename
            dot_file = f"{str_filename}.dot"
            dot_output = os.path.join(dir_out, dot_file)
            json_file = f"{str_filename}.json"
            json_output = os.path.join(dir_out, json_file)

            # Skip if output file already exists
            if os.path.exists(dot_file) and os.path.exists(json_file):
                self.logger.info(f"File already exists: {dot_file[:-4]}")
                continue

            # Determine input path based on label
            path_input = os.path.join(
                dir_dataset,
                str_filename[:2],
                str_filename
            )

            list_args.append((path_input, dot_output, json_output, str_filename, timeout_seconds))

        self._parallel_process(list_args)

    def _get_elf_addresses(
        self,
        path_file: str
    ) -> Optional[ElfAddresses]:
        """
        Get the relevant addresses from an ELF file including sequence start, entry point, and sequence end.

        Args:
            path_file: Path to the ELF file

        Returns:
            ElfAddresses object containing the addresses or None if not found
        """
        try:
            with open(path_file, 'rb') as f:
                elf = ELFFile(f)
                entry_point = elf.header.e_entry

                for segment in elf.iter_segments():
                    if (segment['p_type'] == 'PT_LOAD' and
                        segment['p_filesz'] == segment['p_memsz'] and
                        segment['p_flags'] & (P_FLAGS.PF_R | P_FLAGS.PF_X) == (P_FLAGS.PF_R | P_FLAGS.PF_X)):

                        return ElfAddresses(
                            sequence_start=segment['p_vaddr'],
                            entry_point=entry_point,
                            sequence_end=segment['p_vaddr'] + segment['p_filesz']
                        )

                self.logger.warning(f"No suitable PT_LOAD segment found in {path_file}")
                return None

        except Exception as e:
            self.logger.error(f"Error getting ELF addresses for {path_file}: {str(e)}")
            return None

    def _extract_features(
        self,
        path_file: str
    ) -> List[Dict[str, Any]]:
        """
        Extract function call graphs from an executable file.
        Handles both standard ELF files and compressed/packed executables.

        Args:
            path_file: Path to the executable file

        Returns:
            List of extracted opcodes with their metadata
        """
        r2 = r2pipe.open(path_file, flags=["-2"])
        r2.cmd("aaa")  # Enhanced analysis

        functions = r2.cmd(f'agCd')

        if not functions:
            raise ValueError(f"No functions found for file: {path_file}")

        function_call_graph = ['digraph code {']
        functions_info = {}
        
        EDGE_START_IDX = 6
        EDGE_END_IDX = -2
        pattern = r'\"(0x[0-9a-fA-F]+)\" \[label=\"([^\"]+)\"\];'

        for function in functions.split('\n')[EDGE_START_IDX:EDGE_END_IDX]:
            function = re.sub(r' URL="[^"]*"', '', function)
            function = re.sub(r' \[.*color=[^\]]*\]', '', function)
            function_call_graph.append(function)

            match = re.search(pattern, function)
            if not match:
                if 'label' in function:
                    self.logger.warning(f"{path_file}: No match found for function: {function}")
                continue

            address, name = match.groups()
            functions_info[address] = {
                "function_name": name,
                "instructions": []
            }

            try:
                instructions = r2.cmdj(f'pdfj @ {address}')['ops']
                for inst in instructions:
                    disasm = inst.get('disasm', 'invalid')
                    functions_info[address]['instructions'].append(disasm)
            except Exception as e:
                self.logger.error(f"{path_file}: Error extracting instructions at \"{address}\" for function \"{name}\": {e}")
                functions_info[address]['instructions'].append(f"error")

        function_call_graph.append('}')

        r2.quit()
        return function_call_graph, functions_info

    def _parallel_process(
        self,
        list_args: List[tuple]
    ) -> None:
        """
        Process multiple files in parallel using ProcessPoolExecutor.

        Args:
            list_args: List of tuples containing arguments for _extract_single_file
        """
        with ProcessPoolExecutor(max_workers=os.cpu_count()) as executor:
            futures = [executor.submit(self._extract_single_file, *args) for args in list_args]

            with tqdm(total=len(list_args), desc="Processing files", unit="file") as pbar:
                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        self.logger.error(f"Error occurred while processing file: {e}")
                    finally:
                        pbar.update(1)

    def _extract_single_file(
        self,
        path_input: str,
        dot_output: str,
        json_output: str,
        str_filename: str,
        timeout_seconds: int
    ) -> float:
        """
        Process a single file and extract its features.

        Args:
            path_input: Path to input file
            dot_output: Path to save the DOT file
            json_output: Path to save the JSON file
            str_filename: Name of the file being processed
            timeout_seconds: Maximum seconds for feature extraction

        Returns:
            float: Execution time in seconds, 0 if failed
        """

        try:
            # Check for timeout first
            if check_r2_timeout(path_input, timeout_seconds):
                self.logger.warning(f"{str_filename}: Timeout detected, skipping")
                return 0

            time_start = time.time()
            fcg, functions = self._extract_features(path_input)

            with open(dot_output, 'w', encoding='utf-8') as f:
                f.write('\n'.join(fcg))

            with open(json_output, 'w') as f:
                json.dump(functions, f, indent=4)

            time_exec = time.time() - time_start
            self.logger.info(f"{str_filename},{time_exec:.2f} seconds")
            return time_exec

        except FileNotFoundError:
            self.logger.error(f"{str_filename}: File not found")
        except ValueError as ve:
            self.logger.error(str(ve))
        except Exception as e:
            self.logger.exception(f"Unexpected error occurred: {e}")

        return 0