"""Binary analysis, reverse engineering, and PCAP forensic tools."""

from __future__ import annotations

from typing import Any, Literal

from mcp.server.mcpserver import MCPServer

from ..core.executor import CommandRunner
from ..core.paths import resolve_workspace_path, safe_child, workspace_root


def register_binary_tools(mcp: MCPServer, run_command: CommandRunner) -> None:
    """Register non-network binary and forensic analysis tools."""

    @mcp.tool(name="file_inspect")
    def file_inspect(path: str, timeout: int = 30) -> dict[str, Any]:
        """Identify the file type, architecture hints, and ELF/PE properties."""
        source = resolve_workspace_path(path, must_exist=True, kind="file")
        return run_command.run(["file", str(source)], timeout=timeout)

    @mcp.tool(name="strings_extract")
    def strings_extract(
        path: str,
        minimum_length: int = 4,
        include_all_sections: bool = True,
        timeout: int = 60,
    ) -> dict[str, Any]:
        """Extract printable strings from a mounted binary or artifact.

        Increase `minimum_length` to reduce noise. Output is automatically
        sanitized and truncated; the complete oversized output is saved under
        /workspace/reports.
        """
        if not 1 <= minimum_length <= 100:
            raise ValueError("minimum_length must be between 1 and 100")
        source = resolve_workspace_path(path, must_exist=True, kind="file")
        argv = ["strings", "-n", str(minimum_length)]
        if include_all_sections:
            argv.append("-a")
        argv.append(str(source))
        return run_command.run(argv, timeout=timeout)

    @mcp.tool(name="binwalk_scan")
    def binwalk_scan(
        path: str,
        extract: bool = False,
        output_directory: str | None = None,
        timeout: int = 120,
    ) -> dict[str, Any]:
        """Scan an embedded filesystem or firmware image with Binwalk.

        `extract=false` is read-only. When `extract=true`, files are placed in
        the requested directory under /workspace; the default is
        `binwalk/<artifact-stem>`. Extraction is limited to paths inside the
        mounted workspace.
        """
        source = resolve_workspace_path(path, must_exist=True, kind="file")
        argv = ["binwalk"]
        if extract:
            relative = output_directory or f"binwalk/{source.stem}"
            destination = safe_child(workspace_root(), relative)
            destination.mkdir(parents=True, exist_ok=True)
            argv.extend(["--extract", "--directory", str(destination)])
        argv.append(str(source))
        return run_command.run(argv, timeout=timeout)

    @mcp.tool(name="exiftool_metadata")
    def exiftool_metadata(path: str, timeout: int = 60) -> dict[str, Any]:
        """Read document, image, media, and archive metadata with ExifTool."""
        source = resolve_workspace_path(path, must_exist=True, kind="file")
        return run_command.run(["exiftool", str(source)], timeout=timeout)

    @mcp.tool(name="objdump_analyze")
    def objdump_analyze(
        path: str,
        mode: Literal["headers", "program-headers", "sections", "disassemble", "all"] = "headers",
        section: str | None = None,
        timeout: int = 120,
    ) -> dict[str, Any]:
        """Inspect ELF/COFF headers or disassemble sections with objdump.

        Use `mode="disassemble"` and `section=".text"` for focused assembly
        review. `mode="all"` can be very large and will be truncated.
        """
        source = resolve_workspace_path(path, must_exist=True, kind="file")
        option = {
            "headers": "-f",
            "program-headers": "-p",
            "sections": "-h",
            "disassemble": "-d",
            "all": "-x",
        }[mode]
        argv = ["objdump", option]
        if section:
            argv.extend([f"--section={section}"])
        argv.append(str(source))
        return run_command.run(argv, timeout=timeout)

    @mcp.tool(name="gdb_batch_debug")
    def gdb_batch_debug(
        executable_path: str,
        commands: list[str] | None = None,
        program_arguments: list[str] | None = None,
        timeout: int = 120,
    ) -> dict[str, Any]:
        """Run GDB in batch mode against a mounted executable.

        `commands` is an ordered list of GDB commands such as
        `["info registers", "x/16i $pc"]`. If omitted, GDB prints file and
        disassembly metadata. `program_arguments` are passed after `--args`
        without shell parsing.
        """
        source = resolve_workspace_path(executable_path, must_exist=True, kind="file")
        argv = ["gdb", "--quiet", "--batch", "-ex", "set pagination off"]
        for command in commands or ["info files", "disassemble"]:
            if not command or not command.strip():
                raise ValueError("GDB commands must not be empty")
            argv.extend(["-ex", command])
        argv.extend(["--args", str(source), *[str(arg) for arg in program_arguments or []]])
        return run_command.run(argv, timeout=timeout)

    @mcp.tool(name="tshark_analyze_pcap")
    def tshark_analyze_pcap(
        path: str,
        display_filter: str | None = None,
        output: Literal["summary", "fields", "conversations", "protocol-hierarchy"] = "summary",
        fields: list[str] | None = None,
        frame_limit: int | None = None,
        timeout: int = 120,
    ) -> dict[str, Any]:
        """Analyze a mounted packet capture without touching a live interface.

        Use Wireshark display-filter syntax in `display_filter`. For
        `output="fields"`, provide fields such as `frame.number`,
        `ip.src`, `tcp.stream`, or `http.request.full_uri`. Conversation and
        protocol-hierarchy views run in quiet statistics mode.
        """
        source = resolve_workspace_path(path, must_exist=True, kind="file")
        if output == "fields" and not fields:
            raise ValueError("fields output requires at least one field name")
        argv = ["tshark", "-n", "-r", str(source)]
        if frame_limit is not None:
            if not 1 <= frame_limit <= 100000:
                raise ValueError("frame_limit must be between 1 and 100000")
            argv.extend(["-c", str(frame_limit)])
        if display_filter:
            argv.extend(["-Y", display_filter])
        if output == "summary":
            pass
        elif output == "fields":
            argv.extend(["-T", "fields", "-E", "header=y", "-E", "separator=|"])
            for field_name in fields or []:
                argv.extend(["-e", field_name])
        elif output == "conversations":
            argv.extend(["-q", "-z", "conv,tcp", "-z", "conv,udp"])
        else:
            argv.extend(["-q", "-z", "io,phs"])
        return run_command.run(argv, timeout=timeout)
