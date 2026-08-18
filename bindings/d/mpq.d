/*
 *  mpq.d -- D programming language module for libmpq
 *
 *  Copyright (c) 2008-2026 Georg Lukas <georg@op-co.de>
 *
 *  This file is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation; either version 2.1 of the License, or
 *  (at your option) any later version.
 *
 *  This file is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with this file; if not, see <https://www.gnu.org/licenses/>.
 *
 *  This module is written to support Phobos. Patches to allow binding to
 *  Tango are welcome.
 */

module mpq;

/* the following pragma does not work on DMD/Linux, generates a warning on
 * GDC/Linux and has not been tested on Windows. Commented out for now. */
// pragma(lib, "libmpq");

import std.string; // for format() and toStringz()
import std.traits; // for ParameterTypeTuple!()

/* libmpq exposes 64-bit offsets through its public API. */
alias long off_t;

/* libmpq error return values. Negative values are errors, zero means success. */
const LIBMPQ_ERROR_OPEN			= -1;	/* open error on file. */
const LIBMPQ_ERROR_CLOSE		= -2;	/* close error on file. */
const LIBMPQ_ERROR_SEEK			= -3;	/* lseek error on file. */
const LIBMPQ_ERROR_READ			= -4;	/* read error on file. */
const LIBMPQ_ERROR_WRITE		= -5;	/* write error on file. */
const LIBMPQ_ERROR_MALLOC		= -6;	/* memory allocation error. */
const LIBMPQ_ERROR_FORMAT		= -7;	/* format error. */
const LIBMPQ_ERROR_NOT_INITIALIZED	= -8;	/* init() wasn't called. */
const LIBMPQ_ERROR_SIZE			= -9;	/* buffer size is too small. */
const LIBMPQ_ERROR_EXIST		= -10;	/* archive, file, or block does not exist. */
const LIBMPQ_ERROR_DECRYPT		= -11;	/* we don't know the decryption seed. */
const LIBMPQ_ERROR_UNPACK		= -12;	/* error on unpacking file. */

/** Opaque archive handle owned by libmpq. */
extern struct mpq_archive_s;
extern struct mpq_writer_s;

struct mpq_archive_create_options_s { uint version; uint max_files; uint sector_size; uint flags; }
struct mpq_file_create_options_s { uint flags; uint compression_first; uint compression_next; ushort locale; ushort platform; }

extern(C) {

/* Return the configured libmpq package version string. */
char *libmpq__version();

/* Open an MPQ archive from a file path and optional embedded archive offset. */
int libmpq__archive_open(mpq_archive_s **mpq_archive, char *mpq_filename, off_t archive_offset);
int libmpq__archive_create(mpq_archive_s **mpq_archive, char *mpq_filename, mpq_archive_create_options_s *options);
int libmpq__file_begin(mpq_archive_s *archive, char *filename, off_t unpacked_size, mpq_file_create_options_s *options, mpq_writer_s **writer);
int libmpq__file_write(mpq_writer_s *writer, ubyte *buffer, off_t size);
int libmpq__file_finish(mpq_writer_s *writer);
int libmpq__file_add(mpq_archive_s *archive, char *filename, ubyte *buffer, off_t size, mpq_file_create_options_s *options);
int libmpq__file_add_path(mpq_archive_s *archive, char *filename, char *source_path, mpq_file_create_options_s *options);

/* Clone an archive using an independent stream and private decoded state. */
int libmpq__archive_clone(mpq_archive_s **clone, mpq_archive_s *source);

/* Close an opened archive and release its decoded metadata tables. */
int libmpq__archive_close(mpq_archive_s *mpq_archive);

/* Return the sum of packed sizes for all extractable files. */
int libmpq__archive_size_packed(mpq_archive_s *mpq_archive, off_t *packed_size);

/* Return the sum of unpacked sizes for all extractable files. */
int libmpq__archive_size_unpacked(mpq_archive_s *mpq_archive, off_t *unpacked_size);

/* Return the byte offset where the MPQ archive starts in the backing file. */
int libmpq__archive_offset(mpq_archive_s *mpq_archive, off_t *offset);

/* Return the MPQ archive format version. */
int libmpq__archive_version(mpq_archive_s *mpq_archive, uint *version_);

/* Return the number of valid file entries discovered while opening the archive. */
int libmpq__archive_files(mpq_archive_s *mpq_archive, uint *files);

/* Return the packed size for one file entry. */
int libmpq__file_size_packed(mpq_archive_s *mpq_archive, uint file_number, off_t *packed_size);

/* Return the unpacked size for one file entry. */
int libmpq__file_size_unpacked(mpq_archive_s *mpq_archive, uint file_number, off_t *unpacked_size);

/* Return the file payload offset relative to the archive start. */
int libmpq__file_offset(mpq_archive_s *mpq_archive, uint file_number, off_t *offset);

/* Return the number of blocks used by one file entry. */
int libmpq__file_blocks(mpq_archive_s *mpq_archive, uint file_number, uint *blocks);

/* Report whether one file entry has the MPQ encrypted flag set. */
int libmpq__file_encrypted(mpq_archive_s *mpq_archive, uint file_number, uint *encrypted);

/* Report whether one file entry uses Blizzard multi-compression. */
int libmpq__file_compressed(mpq_archive_s *mpq_archive, uint file_number, uint *compressed);

/* Report whether one file entry uses PKWARE implosion. */
int libmpq__file_imploded(mpq_archive_s *mpq_archive, uint file_number, uint *imploded);

/* Resolve an MPQ file name to a public file number. */
int libmpq__file_number(mpq_archive_s *mpq_archive, char *filename, uint *number);

/* Calculate the three Storm hashes used to identify an MPQ file name. */
void libmpq__file_hash(char *filename, uint *hash1, uint *hash2, uint *hash3);

/* Resolve a precomputed MPQ file-name hash to a public file number. */
int libmpq__file_number_from_hash(mpq_archive_s *mpq_archive, uint hash1, uint hash2, uint hash3, uint *number);

/* Read a complete file into the caller-provided output buffer. */
int libmpq__file_read(mpq_archive_s *mpq_archive, uint file_number, ubyte *out_buf, off_t out_size, off_t *transferred);

/* Open and cache the packed block offset table for one file entry. */
int libmpq__block_open_offset(mpq_archive_s *mpq_archive, uint file_number);

/* Release a cached block offset table for one file entry. */
int libmpq__block_close_offset(mpq_archive_s *mpq_archive, uint file_number);

/* Return the unpacked size for one block of an opened file entry. */
int libmpq__block_size_unpacked(mpq_archive_s *mpq_archive, uint file_number, uint block_number, off_t *unpacked_size);

/* Read, decrypt and decompress one block from an opened file entry. */
int libmpq__block_read(mpq_archive_s *mpq_archive, uint file_number, uint block_number, ubyte *out_buf, off_t out_size, off_t *transferred);

}


/** Exception raised when a checked libmpq call returns an error code. */
class MPQException : Exception {
	const string[] Errors = [
		"unknown error",
		"open error on file",
		"close error on file",
		"lseek error on file",
		"read error on file",
		"write error on file",
		"memory allocation error",
		"format error",
		"init() wasn't called",
		"buffer size is too small",
		"archive, file, or block does not exist",
		"we don't know the decryption seed",
		"error on unpacking file"];

	public int errno;

	/** Build an exception message from a libmpq function name and error code. */
	this(char[] fnname = "unknown_function", int errno = 0) {

		this.errno = errno;
		if (-errno >= Errors.length)
			errno = 0;
		super(std.string.format("Error in %s(): %s (%d)",
					fnname, Errors[-errno], errno));
	}
}


/** Wrap a libmpq function and throw MPQException when it returns a negative code.
 *
 * thanks for the idea to while(nan) blog,
 * http://while-nan.blogspot.com/2007/06/wrapping-functions-for-fun-and-profit.html
 *
 * use: MPQ_CHECKERR(libmpq__archive_open)(&m, "foo.mpq", -1);
 *   returns the retval of archive_open on success;
 *   throws an MPQException on failure.
 *
 * @param Fn libmpq__function reference
 * @param args libmpq__function parameters
 * @return return value of libmpq__function on success
 * @throw MPQException on error
 */
int MPQ_CHECKERR(alias Fn)(ParameterTypeTuple!(Fn) args)
{
	int result = Fn(args);
	if (result < 0) {
		/* D frontends have historically exposed the aliased function name here. */
		throw new MPQException((&Fn).stringof[2..$], result);
	}
        return result;
}


/** Generate an alias that routes one libmpq function through MPQ_CHECKERR.
 *
 * alias mpq.func_name(...) to MPQ_CHECKERR(libmpq__func_name)(...)
 * @param func_name name of the function being wrapped
 */
template MPQ_FUNC(char[] func_name) {
	const char[] MPQ_FUNC = "alias MPQ_CHECKERR!(libmpq__" ~ func_name ~ ") " ~ func_name ~ ";";
}

alias libmpq__version libversion; /* must be direct alias because it returns char*, not error int */
mixin(MPQ_FUNC!("archive_open"));
mixin(MPQ_FUNC!("archive_clone"));
mixin(MPQ_FUNC!("archive_close"));
mixin(MPQ_FUNC!("archive_packed_size"));
mixin(MPQ_FUNC!("archive_unpacked_size"));
mixin(MPQ_FUNC!("archive_offset"));
mixin(MPQ_FUNC!("archive_version"));
mixin(MPQ_FUNC!("archive_files"));
mixin(MPQ_FUNC!("file_packed_size"));
mixin(MPQ_FUNC!("file_unpacked_size"));
mixin(MPQ_FUNC!("file_offset"));
mixin(MPQ_FUNC!("file_blocks"));
mixin(MPQ_FUNC!("file_encrypted"));
mixin(MPQ_FUNC!("file_compressed"));
mixin(MPQ_FUNC!("file_imploded"));
mixin(MPQ_FUNC!("file_number"));
mixin(MPQ_FUNC!("file_number_from_hash"));
mixin(MPQ_FUNC!("file_read"));
mixin(MPQ_FUNC!("block_open_offset"));
mixin(MPQ_FUNC!("block_close_offset"));
mixin(MPQ_FUNC!("block_unpacked_size"));
mixin(MPQ_FUNC!("block_read"));

/** Generate an Archive getter that returns one archive_* metadata value.
 *
 *   <type> Archive.<name>() { return libmpq__archive_<name>() }
 *
 * @param type return type for the original function reference
 * @param name name of the original function
 * @param name2 name for the prototype (defaults to name, used for "version")
 * @return getter function mixin
 */
template MPQ_A_GET(char[] type, char[] name, char[] name2 = name) {
	const char[] MPQ_A_GET = type ~ " " ~ name2 ~ "() { " ~
			type ~ " ret; " ~
			"archive_" ~ name ~ "(m, &ret); return ret;" ~
		"}";
}

/** High-level wrapper around a libmpq archive handle.
 *
 * syntax: auto a = new mpq.Archive("somefile.mpq");
 */
class Archive {
	mpq_archive_s *m;
	File listfile;
	char[][] listfiledata;

	/** Open an MPQ archive at the optional embedded archive offset. */
	this(char[] archivename, off_t offset = -1) {
		archive_open(&m, toStringz(archivename), offset);
	}

	private this() {
	}

	/** Create an independently readable wrapper for this archive. */
	Archive clone() {
		auto result = new Archive();
		archive_clone(&result.m, m);
		return result;
	}

	mixin(MPQ_A_GET!("off_t", "packed_size"));
	mixin(MPQ_A_GET!("off_t", "unpacked_size"));
	mixin(MPQ_A_GET!("off_t", "offset"));
	mixin(MPQ_A_GET!("uint", "version", "version_"));
	mixin(MPQ_A_GET!("uint", "files"));

	/** Close the underlying libmpq archive handle. */
	~this() {
		archive_close(m);
	}

	/** Return the raw libmpq archive handle used by file wrappers. */
	mpq_archive_s* archive() {
		return m;
	}

	/** Return a File wrapper for the named archive entry. */
	File opIndex(char[] fname) {
		return new File(this, fname);
	}

	/** Return a File wrapper for the numeric archive entry. */
	File opIndex(int fno) {
		return new File(this, fno);
	}

	/** Return the cached (listfile) contents, or an empty list when absent. */
	char[][] filelist() {
		try {
			if (!listfile) {
				listfile = this["(listfile)"];
				listfiledata = (cast(char[])listfile.read()).splitlines();
			}
			return listfiledata;
		} catch (MPQException e) {
			return [];
		}
	}

	/+uint filenumber(char[] filename) {
		try {
			if (!listfile) {
				listfile = this["(listfile)"];
				listfiledata = (cast(char[])listfile.read()).splitlines();
			}
			return listfiledata;
		} catch (MPQException e) {
			return [];
		}
	}+/

}


/** Generate a File getter that returns one file_* metadata value.
 *
 *   <type> File.<name>() { return libmpq__file_<name>() }
 *
 * @param type return type for the original function reference
 * @param name name of the original function
 * @param name2 name for the prototype (defaults to name, used for "version")
 * @return getter function mixin
 */
template MPQ_F_GET(char[] type, char[] name, char[] name2 = name) {
	const char[] MPQ_F_GET = type ~ " " ~ name2 ~ "() { " ~
			type ~ " ret; " ~
			"file_" ~ name ~ "(am, fileno, &ret); " ~
			"return ret;" ~
		"}";
}

/** High-level wrapper around one file entry in an MPQ archive.
 *
 * syntax:
 *    auto a = new mpq.Archive("somefile.mpq");
 *    auto f = a["(listfile)"];
 *    auto f2 = a[0];
 *    auto f3 = new File(a, "(listfile)");
 */
class File {
	Archive a;
	mpq_archive_s* am;
	char[] filename;
	uint fileno;

	/** Open a file wrapper by numeric archive entry index. */
	this(Archive a, int fileno) {
		this.a = a;
		this.am = a.archive();
		if (fileno >= a.files) {
			throw new MPQException(format("File(%d)", fileno),
				LIBMPQ_ERROR_EXIST);
		}
		this.filename = format("file%04d.xxx", fileno);
		this.fileno = fileno;
	}

	/** Open a file wrapper by archive file name. */
	this(Archive a, char[] filename) {
		this.a = a;
		this.am = a.archive();
		this.filename = filename;
		/* file_number() raises MPQException when the archive has no matching name. */
		mpq.file_number(am, toStringz(filename), &this.fileno);
	}

	mixin(MPQ_F_GET!("off_t", "packed_size"));
	mixin(MPQ_F_GET!("off_t", "unpacked_size"));
	mixin(MPQ_F_GET!("off_t", "offset"));
	mixin(MPQ_F_GET!("uint", "blocks"));
	mixin(MPQ_F_GET!("uint", "encrypted"));
	mixin(MPQ_F_GET!("uint", "compressed"));
	mixin(MPQ_F_GET!("uint", "imploded"));

	/** Return the numeric file entry index. */
	uint no() {	return fileno; }

	/** Return the original file name passed to the wrapper. */
	char[] name() {	return filename; }

	/** Read and return the complete unpacked file payload. */
	ubyte[] read() {
		ubyte[] content;
		content.length = this.unpacked_size();
		off_t trans;
		mpq.file_read(am, fileno, content.ptr, content.length, &trans);
		content.length = trans;
		return content;
	}
}
