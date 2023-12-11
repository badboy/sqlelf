import apsw
import apsw.shell
import oelf

from dataclasses import dataclass
from enum import Flag, auto
from typing import Any, Callable, Iterator, Sequence


@dataclass
class Generator:
    """A generator for the virtual table SQLite module.

    This class is needed because apsw wants to assign columns and
    column_access to the generator function itself."""

    columns: Sequence[str]
    column_access: apsw.ext.VTColumnAccess
    callable: Callable[[], Iterator[dict[str, Any]]]

    def __call__(self) -> Iterator[dict[str, Any]]:
        """Call the generator should return an iterator of dictionaries.

        The dictionaries should have keys that match the column names."""
        return self.callable()

    @staticmethod
    def make_generator(
        columns: list[str], generator: Callable[[], Iterator[dict[str, Any]]]
    ):
        """Create a generator from a callable that returns
        an iterator of dictionaries."""
        return Generator(columns, apsw.ext.VTColumnAccess.By_Name, generator)


class CacheFlag(Flag):
    NONE = 0
    DYNAMIC_ENTRIES = auto()
    HEADERS = auto()
    INSTRUCTIONS = auto()
    SECTIONS = auto()
    EXPORTS = auto()
    IMPORTS = auto()
    SYMBOLS = auto()
    RPATHS = auto()
    LIBS = auto()
    STRINGS = auto()
    VERSION_REQUIREMENTS = auto()
    VERSION_DEFINITIONS = auto()
    DWARF_DIE = auto()
    DWARF_DIE_CALL_GRAPH = auto()

    @classmethod
    def from_string(cls, str: str):
        """Convert a string to a CacheFlag.

        This also specially handles 'ALL' which returns all the flags."""
        if str == "ALL":
            return cls.ALL()
        try:
            return cls[str]
        except KeyError:
            raise ValueError(f"{str} is not a valid CacheFlag")

    @classmethod
    def ALL(cls):
        retval = cls.NONE
        for member in cls.__members__.values():
            retval |= member
        return retval


def register_generator(
    connection: apsw.Connection,
    generator: Generator,
    table_name: str,
    generator_flag: CacheFlag,
    cache_flags: CacheFlag,
) -> None:
    """Register a virtual table generator.

    This method does a bit of duplicate work which checks if we need to cache
    the given generator.

    If so we rename the table with a prefix 'raw' and then create a temp table"""
    original_table_name = table_name
    if generator_flag in cache_flags:
        table_name = f"raw_{table_name}"

    apsw.ext.make_virtual_module(connection, table_name, generator)

    if generator_flag in cache_flags:
        connection.execute(
            f"""CREATE TABLE {original_table_name}
            AS SELECT * FROM {table_name};"""
        )


def register_headers(
    machos: list[oelf.Object], connection: apsw.Connection, cache_flags: CacheFlag
) -> None:
    def dynamic_entries_generator() -> Iterator[dict[str, Any]]:
        for obj in machos:
            header = obj.header
            yield {
                "path": obj.path,
                "magic": header.magic,
                "cputype": header.cputype,
                "cpusubtype": header.cpusubtype,
                "filetype": header.filetype,
                "ncmds": header.ncmds,
                "sizeofcmds": header.sizeofcmds,
                "flags": header.flags,
                "reserved": header.reserved,
            }

    generator = Generator.make_generator(
        [
            "path",
            "magic",
            "cputype",
            "cpusubtype",
            "filetype",
            "ncmds",
            "sizeofcmds",
            "flags",
            "reserved",
        ],
        dynamic_entries_generator,
    )

    register_generator(
        connection,
        generator,
        "macho_headers",
        CacheFlag.HEADERS,
        cache_flags,
    )


def register_symbols(
    machos: list[oelf.Object], connection: apsw.Connection, cache_flags: CacheFlag
) -> None:
    def dynamic_entries_generator() -> Iterator[dict[str, Any]]:
        for obj in machos:
            for sym in obj.symbols():
                yield {
                    "path": obj.path,
                    "name": sym.name,
                    "type": sym.typ,
                    "global": sym.is_global,
                    "weak": sym.weak,
                    "undefined": sym.undefined,
                    "stab": sym.stab,
                    "n_strx": sym.meta.n_strx,
                    "n_type": sym.meta.n_type,
                    "n_sect": sym.meta.n_sect,
                    "n_desc": sym.meta.n_desc,
                    "n_value": sym.meta.n_value,
                }

    generator = Generator.make_generator(
        [
            "path",
            "name",
            "type",
            "global",
            "weak",
            "undefined",
            "stab",
            "n_strx",
            "n_type",
            "n_sect",
            "n_desc",
            "n_value",
        ],
        dynamic_entries_generator,
    )

    register_generator(
        connection,
        generator,
        "macho_symbols",
        CacheFlag.SYMBOLS,
        cache_flags,
    )


def register_sections(
    machos: list[oelf.Object], connection: apsw.Connection, cache_flags: CacheFlag
) -> None:
    def dynamic_entries_generator() -> Iterator[dict[str, Any]]:
        for obj in machos:
            for sect in obj.sections():
                yield {
                    "path": obj.path,
                    "name": sect.name,
                    "segment": sect.segment,
                    "addr": sect.addr,
                    "size": sect.size,
                    "offset": sect.offset,
                    "align": sect.align,
                    "reloff": sect.reloff,
                    "nreloc": sect.nreloc,
                    "flags": sect.flags,
                }

    generator = Generator.make_generator(
        [
            "path",
            "name",
            "segment",
            "addr",
            "size",
            "offset",
            "align",
            "reloff",
            "nreloc",
            "flags",
        ],
        dynamic_entries_generator,
    )

    register_generator(
        connection,
        generator,
        "macho_sections",
        CacheFlag.SECTIONS,
        cache_flags,
    )


def register_exports(
    machos: list[oelf.Object], connection: apsw.Connection, cache_flags: CacheFlag
) -> None:
    def dynamic_entries_generator() -> Iterator[dict[str, Any]]:
        for obj in machos:
            for exp in obj.exports():
                yield {
                    "path": obj.path,
                    "name": exp.name,
                    "size": exp.size,
                    "offset": exp.offset,
                    "type": str(exp.info.typ),
                    "address": exp.info.address,
                    "flags": exp.info.flags,
                    "lib": exp.info.lib,
                    "lib_symbol_name": exp.info.lib_symbol_name,
                }

    generator = Generator.make_generator(
        [
            "path",
            "name",
            "size",
            "offset",
            "type",
            "address",
            "flags",
            "lib",
            "lib_symbol_name",
        ],
        dynamic_entries_generator,
    )

    register_generator(
        connection,
        generator,
        "macho_exports",
        CacheFlag.EXPORTS,
        cache_flags,
    )


def register_imports(
    machos: list[oelf.Object], connection: apsw.Connection, cache_flags: CacheFlag
) -> None:
    def dynamic_entries_generator() -> Iterator[dict[str, Any]]:
        for obj in machos:
            for imp in obj.imports():
                yield {
                    "path": obj.path,
                    "name": imp.name,
                    "dylib": imp.dylib,
                    "lazy": imp.is_lazy,
                    "offset": imp.offset,
                    "size": imp.size,
                    "address": imp.address,
                    "addend": imp.addend,
                    "is_weak": imp.is_weak,
                    "start_of_sequence_offset": imp.start_of_sequence_offset,
                }

    generator = Generator.make_generator(
        [
            "path",
            "name",
            "dylib",
            "lazy",
            "offset",
            "size",
            "address",
            "addend",
            "is_weak",
            "start_of_sequence_offset",
        ],
        dynamic_entries_generator,
    )

    register_generator(
        connection,
        generator,
        "macho_imports",
        CacheFlag.IMPORTS,
        cache_flags,
    )


def register_rpaths(
    machos: list[oelf.Object], connection: apsw.Connection, cache_flags: CacheFlag
) -> None:
    def dynamic_entries_generator() -> Iterator[dict[str, Any]]:
        for obj in machos:
            for rpath in obj.rpaths:
                yield {"path": obj.path, "rpath": rpath}

    generator = Generator.make_generator(
        ["path", "rpath"],
        dynamic_entries_generator,
    )

    register_generator(
        connection,
        generator,
        "macho_rpaths",
        CacheFlag.RPATHS,
        cache_flags,
    )


def register_libs(
    machos: list[oelf.Object], connection: apsw.Connection, cache_flags: CacheFlag
) -> None:
    def dynamic_entries_generator() -> Iterator[dict[str, Any]]:
        for obj in machos:
            for lib in obj.libs:
                yield {"path": obj.path, "lib": lib}

    generator = Generator.make_generator(
        ["path", "lib"],
        dynamic_entries_generator,
    )

    register_generator(
        connection,
        generator,
        "macho_libs",
        CacheFlag.RPATHS,
        cache_flags,
    )


def register_virtual_tables(
    connection: apsw.Connection,
    machos: list[oelf.Object],
    cache_flags: CacheFlag = CacheFlag.SECTIONS | CacheFlag.SYMBOLS,
) -> None:
    """Register the virtual table modules.

    You can make the SQL engine more speedy by only specifying the
    Generators (virtual tables) that you care about via the flags argument.

    Args:
        connection: the connection to register the virtual tables on
        binaries: the list of binaries to analyze
        flags: the bitwise flags which controls which virtual table to enable"""
    register_table_functions = [
        register_headers,
        register_symbols,
        register_sections,
        register_exports,
        register_imports,
        register_rpaths,
        register_libs,
    ]
    for register_function in register_table_functions:
        register_function(machos, connection, CacheFlag.ALL())
