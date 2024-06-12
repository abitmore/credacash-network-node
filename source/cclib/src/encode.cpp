/*
 * CredaCash (TM) cryptocurrency and blockchain
 *
 * Copyright (C) 2015-2024 Creda Foundation, Inc., or its contributors
 *
 * encode.cpp
*/

#include "cclib.h"
#include "encode.h"
#include "jsonutil.h"

#define TRACE	0

#define LENGTH_DIFF_OFFSET		9

void base64_test(const uint8_t* encode_table, bool no_padding)
{
	for (unsigned i = 0; i < 2000; ++i)
	{
		unsigned len = (rand() & 31) + 1;
		string s;

		for (unsigned j = 0; j < len; ++j)
		{
			char c = 0;

			while (c < 32)
				c = rand() & 255;

			s.push_back(c);
		}

		cerr << s << endl;

		string e;
		base64_encode(encode_table, s, e, no_padding);

		cerr << e << endl;
	}
}

void base64_encode(const uint8_t* table, const string& sval, string& outs, bool no_padding)
{
	CCASSERT(cc_table_mod(table) >= 64);

	outs.clear();

	for (unsigned i = 0; i < sval.length(); i += 3)
	{
		unsigned group = 0;
		int nbits = 0;

		for (unsigned j = 0; j < 3; ++j)
		{
			group <<= 8;
			if (i + j < sval.length())
			{
				group |= sval[i + j];
				nbits += 8;
			}
		}

		for (unsigned j = 0; nbits > 0; ++j)
		{
			outs.push_back(cc_stringify_byte(table, (group >> ((3-j) * 6)) & 63));
			nbits -= 6;
		}
	}

	while (!no_padding && (outs.length() & 3))
		outs.push_back('=');
}

unsigned cc_table_mod(const uint8_t* table)
{
	unsigned mod = table[0];

	if (!mod) mod = 256;

	return mod;
}

// computed expected size of string that would be output by cc_alpha_decode
// call this with a *sym table
unsigned cc_table_expected_strlen(const uint8_t* table, unsigned binlength)
{
	unsigned resize = (table[1] << 8) + table[2];
	if (!resize) resize = 1 << 16;

	return binlength * (1 << 16) / resize;
}

// call this with a *sym table
uint8_t cc_stringify_byte(const uint8_t* table, unsigned c)
{
	if (c >= cc_table_mod(table))
	{
		cerr << "cc_stringify_byte out-of-range char " << c << " >= " << cc_table_mod(table) << endl;

		CCASSERT(c < cc_table_mod(table));
	}

	return table[c + 3];
}

// call this with a *bin table
uint8_t cc_destringify_char(const uint8_t* table, unsigned c)
{
	//cerr << "cc_destringify_char " << c << " " << table[1] << " " << table[2] << endl;
	//cerr << "cc_destringify_char " << (int)c << " " << (int)table[1] << " " << (int)table[2] << endl;

	if (c < table[1] || c > table[2])
	{
		if (0+TRACE) cerr << "cc_destringify_char " << c << " out of range " << (int)table[1] << " to " << (int)table[2] << endl;

		return 255;
	}

	unsigned i = table[c - table[1] + 3];

	if (0 && TRACE) cerr << "cc_destringify_char " << c << " " << table[1] << " " << table[2] << endl;
	if (0 && TRACE) cerr << "cc_destringify_char " << (int)c << " " << (int)table[1] << " " << (int)table[2] << endl;
	if (0 && TRACE) cerr << "cc_destringify_char " << i << endl;

	return i;
}

// shifts out all least significant zero bits
// returns shift amount
static unsigned compute_shift(const unsigned mod, bigint_t& maxval, bigint_t& val)
{
	unsigned shift = 0;

	while (true)
	{
		if (val.asUnsignedLong() & 1)
			break;

		bigint_shift_down(val, 1);
		bigint_shift_down(maxval, 1);

		if (++shift == mod - 1)
			break;
	}

	//cerr << "compute_shift " << shift << endl;

	return shift;
}

#if 0 // unused
// destroys val
static bigint_t bitreverse(bigint_t& val, const unsigned nbits)
{
	bigint_t v = 0UL;

	for (unsigned i = 0; i < nbits; ++i)
	{
		bigint_shift_up(val, 1);

		if (val.asUnsignedLong() & 1)
			v = v + bigint_t(1UL);

		bigint_shift_down(val, 1);
	}

	return v;
}
#endif

// call this with a *sym table
void cc_stringify(const uint8_t* table, const bigint_t& maxval, bool normalize, int nchars, const bigint_t& val, string &outs)
{
	// if normalize is true, the encoding is prefixed by a single char that represents the bit shift left needed to decode the value
	// if nchars > 0, the encoding has as fixed width of nchars
	// if nchars == 0, the encoding has the fixed width that would be required to encode maxval
	// if nchars < 0, the encoding is variable length and ends when the remainder is zero

	bigint_t v = val;
	auto mod = cc_table_mod(table);

	//if (nbits)
	//	v = bitreverse(v, nbits);

	bigint_t mval = maxval;
	if (mval == 0UL)
		subBigInt(bigint_t(0UL), bigint_t(1UL), mval, false);

	//cerr << "encode mval " << hex << mval << dec << endl;

	if (normalize)
	{
		auto shift = compute_shift(mod, mval, v);
		outs.push_back(cc_stringify_byte(table, shift));
	}

	int nc = 0;
	while (mval)
	{
		outs.push_back(cc_stringify_byte(table, v % mod));
		v = v / mod;
		mval = mval / mod;
		nc++;

		//cerr << "encode " << hex << val << " " << v << " " << mval << dec << " " << nc << " " << nchars << " " << outs << endl;

		if (nc == nchars || (nchars < 0 && v == 0UL))
			break;
	}
}

// removes first field from instring and places decoded value into val
// either nchars must be set, or the field must be terminated with CC_ENCODE_SEPARATOR or CC_ENCODE_SEPARATOR_ALT
// call this with a *bin table
CCRESULT cc_destringify(const string& fn, const uint8_t* table, bool normalize, unsigned nchars, string &instring, bigint_t &val, char *output, const uint32_t outsize)
{
	val = 0UL;
	unsigned shift = 0;
	auto mod = cc_table_mod(table);

	if (normalize)
	{
		if (instring.length() < 1)
			return error_input_end(fn, output, outsize);

		shift = cc_destringify_char(table, (uint8_t)instring[0]);

		if (shift == 255)
			return error_invalid_char(fn, output, outsize);

		//cerr << "decode shift " << shift << endl;
	}

	if (!nchars)
	{
		nchars = instring.find(CC_ENCODE_SEPARATOR);
		auto nchars2 = instring.find(CC_ENCODE_SEPARATOR_ALT);
		if (nchars2 < nchars)
			nchars = nchars2;
		if (nchars >= instring.length())
			return error_input_end(fn, output, outsize);
	}

	nchars -= normalize;

	//cerr << "decode " << nchars << " " << instring << endl;

	if (instring.length() < nchars + normalize)
		return error_input_end(fn, output, outsize);

	string sval = instring.substr(normalize, nchars);
	instring = instring.substr(nchars + normalize);

	//cerr << "decode " << sval << endl;

	while (sval.size())
	{
		auto c = cc_destringify_char(table, (uint8_t)sval.back());
		sval.pop_back();

		if (c == 255)
			return error_invalid_char(fn, output, outsize);

		mulBigInt(val, bigint_t((unsigned long)(mod)), val, false);
		addBigInt(val, bigint_t((unsigned long)(c)), val, false);
	}

	bigint_shift_up(val, shift);

	return 0;
}

#if 0	// for testing
#define CC_ENC_SHIFT	16
#endif

typedef uint64_t encint_t;

#define CC_ENC_SHIFT	(sizeof(encint_t)*8 - 8 - 7 - 1)
#define CC_ENC_LOWER	(((encint_t)1 << CC_ENC_SHIFT) - 1)
#define CC_ENC_UPPER	((encint_t)(-1) ^ CC_ENC_LOWER)
#define CC_ENC_MAX		((encint_t)1 << CC_ENC_SHIFT << 8)

#define range_check(v)	CCASSERT((v) < (CC_ENC_MAX << 7))
#define DFMT			hex

// Converts symbols to binary data, using range encoding
// This implementation is lossless when going from symbols -> binary -> symbols
// It is not lossless going from binary -> symbols -> binary because the decoder only works correctly with previously encoded data,
//		not with arbitrary binary data (it works 98% of the time, but not all the time)
// Binary -> symbols can be encoded in blocks of 32 bytes (256 bits) at a time using cc_stringify and cc_destringify
// call this with a *bin table

CCRESULT cc_alpha_encode(const uint8_t* table, const void* data, const unsigned nchars, vector<uint8_t> &outv, bool bclear)
{
	CCASSERT(CC_ENC_MAX);

	unsigned nbytes = 0;	// set nbytes to generate that amount of binary data (formerly implemented as a parameter, may still almost work)

	auto mod = cc_table_mod(table);

	if (TRACE) cerr << "cc_alpha_encode mod " << mod << " nchars " << nchars << " string " << string((char*)data, nchars) << endl;

	if (bclear)
		outv.clear();

	if (!nchars)
		return 0;

	auto sym = (const uint8_t *)data;
	unsigned bufpos = 0;
	encint_t hval = CC_ENC_MAX - 1;
	encint_t lval = 0;
	encint_t eofm = 0;
	bool done = false;

	if (mod == 256)
	{
		for (unsigned i = 0; i < nchars; ++i)
			outv.push_back(sym[i]);

		return 0;
	}

	range_check(hval);

	while (!done)
	{
		unsigned c = mod/2; // picking the midpoint for phantom input symbols may result in shorter output

		if (bufpos < nchars)
			c = cc_destringify_char(table, sym[bufpos++]);

		if (c == 255)
			return -1;

		auto denom = hval - lval + 1;

		hval = lval + ((c + 1) * denom + mod - 1) / mod - 1;
		lval = lval + (c * denom + mod - 1) / mod;

		if (TRACE) cerr << "cc_alpha_encode symbol in " << DFMT << (int)c << " lval " << lval << " hval " << hval << " eofm " << eofm << dec << endl;

		range_check(hval);

		bool bready;

		while (((bready = (((hval ^ lval) & CC_ENC_UPPER) == 0)) || hval < lval + mod - 1) && (nbytes == 0 || outv.size() < nbytes))
		{
			if (!bready)	// fix range before next symbol comes in
			{
				// range reset automagically works because it always pushes out the upper bytes of lval and hval until lval = 0 and hval = max, with dval somewhere in the middle

				if (0+TRACE) cerr << "   **** cc_alpha_encode range warning levels reset at lval " << DFMT << lval << " hval " << hval << dec << endl;
			}

			auto b = lval >> CC_ENC_SHIFT;

			outv.push_back(b);

			hval = ((hval & CC_ENC_LOWER) << 8) | 255;
			lval = ((lval & CC_ENC_LOWER) << 8);

			if (TRACE) cerr << "cc_alpha_encode byte out " << DFMT << (int)b << " lval " << lval << " hval " << hval << " eofm " << eofm << dec << endl;

			range_check(hval);

			if (bufpos == nchars)
			{
				eofm = (eofm << 8) | 255;

				if (((eofm >> CC_ENC_SHIFT) & 255) == 255)
				{
					done = true;	// all bits of next output char would be from the eofm, so we're done

					break;
				}
			}
		}
	}

	if (TRACE) cerr << "cc_alpha_encode " << string((char*)data, nchars) << " --> " << buf2hex(outv.data(), outv.size()) << endl;

	return 0;
}

// Converts binary data to symbols
// to reconstruct a previously encoded string, set nchars to the length of the previously encoded string
// when nchars = 0, some extra phantom symbols are likely to be appended to the end of the string
// call this with a *sym table

void cc_alpha_decode(const uint8_t* table, const void* data, const unsigned nbytes, string &outs, const unsigned nchars, bool bclear)
{
	auto mod = cc_table_mod(table);

	if (TRACE) cerr << "cc_alpha_decode mod " << mod << " nchars " << nchars << " nbytes " << nbytes << " data " << buf2hex(data, nbytes) << endl;

	if (bclear)
		outs.clear();

	if (!nbytes)
		return;

	auto buf = (const uint8_t *)data;
	unsigned bufpos = 0;
	auto outs_base = outs.length();
	encint_t dval = 0;
	encint_t hval = 0;
	encint_t lval = 0;
	encint_t eofm = 0;

	if (mod == 256)
	{
		auto n = nbytes;
		if (nchars && nchars < n)
			n = nchars;

		for (unsigned i = 0; i < n; ++i)
			outs.push_back(buf[i]);

		return;
	}

	while (!nchars || outs.length() < outs_base + nchars)
	{
		bool bready, done = false;

		while ((bready = ((hval ^ lval) & CC_ENC_UPPER) == 0) || hval < lval + mod - 1)
		{
			if (!bready)	// fix range before next symbol goes out (note: this is the code path that messes up lossless decode --> encode --> decode)
				if (0+TRACE) cerr << "   **** cc_alpha_decode range warning levels reset at lval " << DFMT << lval << " dval " << dval << " hval " << hval << dec << endl;

			unsigned b = 128; // picking the midpoint for phantom input bytes may result in shorter output strings

			if (bufpos < nbytes)
				b = buf[bufpos];
			else
				eofm = (eofm << 8) | 255;

			++bufpos;

			hval = ((hval & CC_ENC_LOWER) << 8) | 255;
			dval = ((dval & CC_ENC_LOWER) << 8) | b;
			lval = ((lval & CC_ENC_LOWER) << 8);

			if (TRACE) cerr << "cc_alpha_decode byte in " << DFMT << (int)b << " lval " << lval << " dval " << dval << " hval " << hval << " eofm " << eofm << dec << endl;

			range_check(hval);

			if (!nchars && ((eofm >> CC_ENC_SHIFT) & 255) == 255)
			{
				done = true;	// all bits of next output char would be from the eofm, so we're done

				break;
			}
		}

		if (done)
			break;

		if (dval < lval || dval > hval || hval < lval)
			cerr << "   **** cc_alpha_decode range error lval " << DFMT << lval << " dval " << dval << " hval " << hval << " eofm " << eofm << dec << endl;

		// c = int(((dval - lval) * mod) / (hval - lval + 1)) -- which is always < mod

		auto denom = hval - lval + 1;
		auto c = ((dval - lval) * mod) / denom;

		if (c >= mod)
			cerr << "   **** cc_alpha_decode range error char " << DFMT << c << " >= mod " << mod << " lval " << lval << " dval " << dval << " hval " << hval << " eofm " << eofm << dec << endl;

		// new hval = old lval + int(((c + 1) * denom + mod - 1) / mod) - 1
		hval = lval + ((c + 1) * denom + mod - 1) / mod - 1;

		// new lval = old lval + int((c * denom + mod - 1) / mod)
		lval = lval + (c * denom + mod - 1) / mod;

		outs.push_back(cc_stringify_byte(table, c));

		if (TRACE) cerr << "cc_alpha_decode symbol out " << DFMT << (int)c << " lval " << lval << " dval " << dval << " hval " << hval << " eofm " << eofm << dec << endl;

		range_check(hval);
	}

	if (TRACE) cerr << "cc_alpha_decode " << outs << " <-- " << buf2hex(data, nbytes) << endl;
}

// call this with a *bin table
bool cc_string_uses_symbols(const uint8_t* table, const void* data, const unsigned nchars)
{
	if (cc_table_mod(table) == 256)
		return true;

	auto sym = (const uint8_t *)data;

	for (unsigned i = 0; i < nchars; ++i)
	{
		auto c = cc_destringify_char(table, sym[i]);

		//cerr << "symbol " << sym[i] << " = " << (int)sym[i] << " --> binary " << (int)c << endl;

		if (c == 255)
			return false;
	}

	return true;
}

CCRESULT cc_alpha_encode_shortest(const uint8_t* encode_table, const uint8_t* decode_table, const void* data, const unsigned nchars, vector<uint8_t> &outv, bool bclear)
{
	if (TRACE) cerr << "cc_alpha_encode_shortest " << string((char*)data, nchars) << endl;

	auto start_size = outv.size();

	auto rc = cc_alpha_encode(encode_table, data, nchars, outv, bclear);
	if (rc)
		return rc;

	auto test_size = outv.size() - start_size;

	if (!test_size)
		return 0;

	while (test_size)
	{
		int expected_len = cc_table_expected_strlen(decode_table, test_size);
		int len_diff = expected_len - nchars;
		len_diff += LENGTH_DIFF_OFFSET;
		if (len_diff < 0 || len_diff > 15)
			break;

		string decoded;

		cc_alpha_decode(decode_table, outv.data() + start_size, test_size, decoded, nchars);

		if (decoded.length() != nchars)
			break;

		if (memcmp(decoded.data(), data, nchars))
			break;

		--test_size;
	}

	if (test_size == outv.size() - start_size)
		return -1;

	outv.resize(start_size + test_size + 1);	// one more than the failed test

	if (TRACE) cerr << "cc_alpha_encode_shortest binary size " << test_size + 1 << endl;

	return 0;
}

static const uint8_t* best_encode_table[] = {base10bin, base16bin, base32bin, base32zbin, base34bin, base38bin, base58bin, base66bin, base95bin, base256bin};
static const uint8_t* best_decode_table[] = {base10sym, base16sym, base32sym, base32zsym, base34sym, base38sym, base58sym, base66sym, base95sym, base256sym};

// TODO add a best table index to id function with an offset (ie, lowest id's reserved for future use)

CCRESULT cc_alpha_encode_best(const void* data, const unsigned nchars, vector<uint8_t> &outv)
{
	if (TRACE) cerr << "cc_alpha_encode_best " << string((char*)data, nchars) << endl;

	if (!nchars)
	{
		outv.clear();

		return 0;
	}

	auto ntables = sizeof(best_encode_table)/sizeof(uint8_t*);

	for (unsigned i = 0; i < ntables; ++i)
	{
		outv.clear();
		outv.push_back(i << 4);

		auto rc = cc_alpha_encode_shortest(best_encode_table[i], best_decode_table[i], data, nchars, outv, false);
		if (rc)
			continue;

		auto mod = cc_table_mod(best_decode_table[i]);
		int expected_len = cc_table_expected_strlen(best_decode_table[i], outv.size() - 1);
		int len_diff = expected_len - nchars;

		if (TRACE) cerr << "cc_alpha_encode_best table " << i << " mod " << mod << " binary size " << outv.size() << " expected_len " << expected_len << " nchars " << nchars << " len_diff " << len_diff << endl;

		len_diff += LENGTH_DIFF_OFFSET;	// TODO? put this into a function?

		if (len_diff < 0 || len_diff > 15)
		{
			cerr << "cc_alpha_encode_best error table " << i << " len_diff " << len_diff << " out of range" << endl;

			continue;
		}

		outv[0] |= len_diff;

		return 0;
	}

	outv.clear();

	return -1;
}

CCRESULT cc_alpha_decode_best(const void* data, const unsigned nbytes, string &outs)
{
	if (TRACE) cerr << "cc_alpha_decode_best " << buf2hex(data, nbytes) << endl;

	if (!nbytes)
	{
		outs.clear();

		return 0;
	}

	auto *bufp = (const uint8_t *)data;

	auto ntables = sizeof(best_encode_table)/sizeof(uint8_t*);
	unsigned table = bufp[0] >> 4;
	if (table > ntables - 1)
		return -1;

	int len_diff = (bufp[0] & 15) - LENGTH_DIFF_OFFSET;
	int expected_len = cc_table_expected_strlen(best_decode_table[table], nbytes - 1);
	int nchars = expected_len - len_diff;

	if (TRACE) cerr << "cc_alpha_decode_best table " << table << " binary size " << nbytes << " expected_len " << expected_len << " len_diff " << len_diff << " nchars " << nchars << endl;

	if (nchars < 0)
		return 0;

	cc_alpha_decode(best_decode_table[table], bufp + 1, nbytes - 1, outs, nchars);

	return 0;
}

static void test_one_stringify(const char* table, const uint8_t* encode_table, const uint8_t* decode_table)
{
	if (cc_table_mod(encode_table) >= 255)
		return;

	bigint_t val1, val2;
	val1.randomize();

	if (RandTest(2)) BIGWORD(val1, 0) = 0;
	if (RandTest(2)) BIGWORD(val1, 1) = 0;
	if (RandTest(2)) BIGWORD(val1, 2) = 0;
	if (RandTest(2)) BIGWORD(val1, 3) = 0;

	string encoded;
	string fn = "test";
	char output[128] = {0};
	uint32_t outsize = sizeof(output);
	bool normalize = RandTest(2);

	cc_stringify(decode_table, 0UL, normalize, -1, val1, encoded);

	auto decoded = encoded;

	auto rc = cc_destringify(fn, encode_table, normalize, decoded.length(), decoded, val2, output, outsize);
	if (rc)
	{
		cerr << "stringify_test " << table << " normalize " << normalize << " encoded " << encoded << " decode error: " << output << endl;
		exit(-1);
	}
	else if (val1 != val2)
	{
		cerr << "stringify_test " << table << " normalize " << normalize << " encoded " << encoded << " mismatch " << hex << val1 << " != " << val2 << dec << endl;
		exit(-1);
	}
	else
		if (TRACE) cerr << "--stringify_test OK " << table << " normalize " << normalize << " encoded " << encoded << " val " << hex << val1 << dec << endl;
}

static void test_one_alpha(const char* table, const uint8_t* encode_table, const uint8_t* decode_table)
{
	auto mod = cc_table_mod(encode_table);

	static unsigned seed = 0 -1;
	//srand(++seed);
	//if (TRACE) cerr << "seed " << seed << " mod " << mod << endl;

	vector<uint8_t> rbuf(50), encoded;
	string random, decoded;

	bool generate_decoded = RandTest(2);

	auto buf = rbuf.data();
	auto bufsize = rbuf.size();
	//CCRandom(buf, bufsize);

	unsigned nbytes = rand() % (bufsize + 1);
	if (nbytes > 30 && RandTest(2))
		nbytes = (nbytes & 3) + 1;
	//nbytes = rand() & 7;

	for (unsigned i = 0; i < bufsize; ++i)
		buf[i] = rand();

	if (RandTest(2))
	{
		unsigned fill = rand();
		if (RandTest(2)) fill = -(rand() & 1);
		auto n = rand() % (bufsize + 1);
		if (RandTest(2))
			memset(buf, fill, n);
		else
			memset(&buf[n], fill, bufsize - n);
	}

	unsigned len = rand() % 50;
	if (len > 30 && RandTest(2))
		len = (len & 3) + 1;

	for (unsigned i = 0; i < len; ++i)
		random.push_back(cc_stringify_byte(decode_table, rand() % mod));

	if (RandTest(2))
	{
		unsigned fill = rand() % mod;
		if (RandTest(2)) fill = RandTest(2) * (mod - 1);
		fill = cc_stringify_byte(decode_table, fill);
		auto n = rand() % (len + 1);
		if (RandTest(2))
			memset((char*)random.data(), fill, n);
		else
			memset((char*)random.data() + n, fill, len - n);
	}

	if (generate_decoded)
		cc_alpha_decode(decode_table, buf, nbytes, random);

	auto check = cc_string_uses_symbols(encode_table, random.data(), random.length());
	CCASSERT(check);

	auto rc = cc_alpha_encode(encode_table, random.data(), random.length(), encoded);
	if (rc)
	{
		cerr << "alpha_test " << table << " seed " << seed << " decode invalid input error " << random << endl;
		exit(-1);
	}

	cc_alpha_decode(decode_table, encoded.data(), encoded.size(), decoded);	//, random.length());

	if (generate_decoded)
	{
		if (encoded.size() != nbytes)
		{
			if (TRACE) cerr << "alpha_test " << table << " seed " << seed << " random " << random << " warning encoded size mismatch " << buf2hex(encoded.data(), encoded.size()) << " != " << buf2hex(buf, nbytes) << endl;
			//exit(-1);
		}

		if (encoded.size() < nbytes || memcmp(buf, encoded.data(), nbytes))
		{
			if (TRACE) cerr << "alpha_test " << table << " seed " << seed << " random " << random << " warning encoded mismatch " << buf2hex(encoded.data(), encoded.size()) << " != " << buf2hex(buf, nbytes) << endl;
			//exit(-1);
		}
	}

	if (decoded.length() != random.length())
	{
		if (TRACE) cerr << "alpha_test " << table << " seed " << seed << " warning decoded size mismatch " << decoded.length() << " != " << random.length() << endl;
		//exit(-1);
	}

	if (decoded.length() < random.length() || memcmp(random.data(), decoded.data(), random.length()))
	{
		cerr << "alpha_test " << table << " seed " << seed << " decoded " << decoded << " != " << random << endl;
		exit(-1);
	}

	if (0+TRACE)
	{
		cerr << "--alpha_test OK " << table << " random " << random << endl;
		if (generate_decoded)
		cerr << "  generator " << buf2hex(buf, nbytes) << endl;
		cerr << "    encoded " << buf2hex(encoded.data(), encoded.size()) << endl;
	}
}

static int max_best_test_length_diff = INT_MIN;
static int min_best_test_length_diff = INT_MAX;

static void test_best_alpha(const char* table, const uint8_t* encode_table, const uint8_t* decode_table)
{
	auto mod = cc_table_mod(encode_table);

	static unsigned seed = 0 -1;
	//srand(++seed);
	//if (0+TRACE) cerr << "seed " << seed << " mod " << mod << endl;

	string random, decoded;
	vector<uint8_t> encoded;

	unsigned len = rand() % 100;

	for (unsigned i = 0; i < len; ++i)
		random.push_back(cc_stringify_byte(decode_table, rand() % mod));

	auto check = cc_string_uses_symbols(encode_table, random.data(), random.length());
	CCASSERT(check);

	auto rc = cc_alpha_encode_best(random.data(), random.length(), encoded);
	if (rc)
	{
		cerr << "best_alpha_test cc_alpha_encode_best failed seed " << seed << endl;

		exit(-1);
	}

	rc = cc_alpha_decode_best(encoded.data(), encoded.size(), decoded);
	if (rc)
	{
		cerr << "best_alpha_test cc_alpha_decode_best failed seed " << seed << endl;

		exit(-1);
	}

	if (decoded != random)
	{
		cerr << "best_alpha_test seed " << seed << " decoded mismatch " << decoded << " != " << random << endl;

		exit(-1);
	}

	if (encoded.size())
	{
		int len_diff = encoded[0] & 15;
		max_best_test_length_diff = max(max_best_test_length_diff, len_diff);
		min_best_test_length_diff = min(min_best_test_length_diff, len_diff);
	}
}

static void test_one(const char* table, const uint8_t* encode_table, const uint8_t* decode_table)
{
	test_one_stringify(table, encode_table, decode_table);

	test_one_alpha(table, encode_table, decode_table);

	test_best_alpha(table, encode_table, decode_table);
}

void encode_test()
{
	cerr << "encode_test" << endl;

	for (unsigned i = 0; i < 10000+1*2000000; ++i)
	{
		test_one("base256",		base256bin,			base256sym);
		test_one("base224",		base224bin,			base224sym);
		test_one("base95",		base95bin,			base95sym);
		test_one("base87",		base87bin,			base87sym);
		test_one("base85",		base85bin,			base85sym);
		test_one("base66",		base66bin,			base66sym);
		test_one("base64",		base64bin,			base64sym);
		test_one("base64url",	base64urlbin,		base64urlsym);
		test_one("base58",		base58bin,			base58sym);
		test_one("base57",		base57bin,			base57sym);
		test_one("base38",		base38bin,			base38sym);
		test_one("base38",		base38combobin,		base38sym);
		test_one("base38uc",	base38ucbin,		base38ucsym);
		test_one("base38uc",	base38combobin,		base38ucsym);
		test_one("base36",		base36bin,			base36sym);
		test_one("base36",		base36combobin,		base36sym);
		test_one("base36uc",	base36ucbin,		base36ucsym);
		test_one("base36uc",	base36combobin,		base36ucsym);
		test_one("base34",		base34bin,			base34sym);
		test_one("base32",		base32bin,			base32sym);
		test_one("base32z",		base32zbin,			base32zsym);
		test_one("base26",		base26bin,			base26sym);
		test_one("base26",		base26combobin,		base26sym);
		test_one("base26uc",	base26ucbin,		base26ucsym);
		test_one("base26uc",	base26combobin,		base26ucsym);
		test_one("base17",		base17bin,			base17sym);
		test_one("base17",		base17combobin,		base17sym);
		test_one("base17uc",	base17ucbin,		base17ucsym);
		test_one("base17uc",	base17combobin,		base17ucsym);
		test_one("base16",		base16bin,			base16sym);
		test_one("base16",		base16combobin,		base16sym);
		test_one("base16uc",	base16ucbin,		base16ucsym);
		test_one("base16uc",	base16combobin,		base16ucsym);
		test_one("base10",		base10bin,			base10sym);
		test_one("base8",		base8bin,			base8sym);
	}

	cerr << "encode_test max_best_test_length_diff " << max_best_test_length_diff << endl;
	cerr << "encode_test min_best_test_length_diff " << min_best_test_length_diff << endl;

	cerr << "encode_test done" << endl;
}
