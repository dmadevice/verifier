#include "pe.hpp"

#include <algorithm>
#include <stdexcept>

namespace verifier {

namespace {
u32 rd32(std::string_view d, size_t off) { return off + 4 <= d.size() ? le32(d.data() + off) : 0; }
u16 rd16(std::string_view d, size_t off) { return off + 2 <= d.size() ? le16(d.data() + off) : 0; }
u64 rd64(std::string_view d, size_t off) { return off + 8 <= d.size() ? le64(d.data() + off) : 0; }

struct Raw {
  u32 vsize, va, rawsize, rawptr, ch;
};
struct Headers {
  u64 base = 0;
  u32 sect_align = 0, file_align = 0;
  std::vector<Raw> secs;
  size_t dd = 0;          // the data directories
  size_t header_end = 0;  // the end of the section table
};

Headers read_headers(std::string_view data, const std::string& what) {
  Headers h;
  if (data.size() < 0x40 || data.compare(0, 2, "MZ") != 0) throw std::runtime_error(what + ": not a PE image");
  u32 pe = rd32(data, 0x3c);
  if (data.compare(pe, 4, std::string("PE\0\0", 4)) != 0) throw std::runtime_error(what + ": no PE signature");
  size_t fh = pe + 4;
  u16 nsec = rd16(data, fh + 2), opt_size = rd16(data, fh + 16);
  size_t oh = fh + 20;
  if (rd16(data, oh) != 0x20b) throw std::runtime_error(what + ": not PE32+");
  h.base = rd64(data, oh + 24);
  h.sect_align = rd32(data, oh + 32);
  h.file_align = rd32(data, oh + 36);
  h.dd = oh + 112;
  size_t sec_tab = oh + opt_size;

  for (int i = 0; i < nsec; ++i) {
    size_t s = sec_tab + 40 * i;
    h.secs.push_back(
        {rd32(data, s + 8), rd32(data, s + 12), rd32(data, s + 16), rd32(data, s + 20), rd32(data, s + 36)});
  }
  h.header_end = sec_tab + 40 * nsec;
  return h;
}

// what the image's headers and directories say: sections, .pdata, base relocations, imports, the POGO entry
void read_tables(Image& im, std::string_view data, const Headers& h) {
  u64 base = h.base;
  auto dir = [&](int k) { return std::pair<u32, u32>(rd32(data, h.dd + 8 * k), rd32(data, h.dd + 8 * k + 4)); };
  for (auto& s : h.secs) im.sections.push_back({base + s.va, base + s.va + std::max(s.vsize, s.rawsize), s.ch});
  std::string_view img = im.img;
  // .pdata and base relocations read directly
  auto [exc_va, exc_size] = dir(3);
  for (u32 off = exc_va; off + 12 <= u64(exc_va) + exc_size / 12 * 12 && off + 12 <= img.size(); off += 12) {
    u64 b = base + rd32(img, off);
    im.pdata.push_back({b, base + rd32(img, off + 4), rd32(img, off + 8)});
  }
  auto [rel_va, rel_size] = dir(5);
  for (u64 off = rel_va; off + 8 <= u64(rel_va) + rel_size;) {
    u32 page = rd32(img, off), size = rd32(img, off + 4);
    if (size < 8) break;
    for (u64 e = off + 8; e + 2 <= off + size; e += 2) {
      u16 v = rd16(img, e);
      if ((v >> 12) == 10) im.reloc_sorted.push_back(base + page + (v & 0xFFF));
    }
    off += size;
  }
  // imports: IAT slot -> (dll, name or ordinal)
  auto [imp_va, imp_size] = dir(1);
  if (imp_va) {
    for (u64 d = imp_va; d + 20 <= img.size(); d += 20) {
      u32 ilt = rd32(img, d), name_rva = rd32(img, d + 12), iat = rd32(img, d + 16);
      if (!ilt && !name_rva && !iat) break;
      std::string dll;
      for (u64 p = name_rva; p < img.size() && img[p]; ++p) dll += img[p];
      dll = lower(dll);
      u32 thunks = ilt ? ilt : iat;
      for (u32 k = 0;; ++k) {
        u64 t = rd64(img, u64(thunks) + 8ull * k);
        if (!t) break;
        Import in;
        in.dll = dll;
        if (t >> 63)
          in.ordinal = u32(t & 0xFFFF);
        else
          for (u64 p = (t & 0x7fffffff) + 2; p < img.size() && img[p]; ++p) in.name += img[p];
        im.imports[base + iat + 8ull * k] = in;
      }
    }
  }
  // POGO debug entry (type 13): subsection name -> range
  auto [dbg_va, dbg_size] = dir(6);
  for (u64 e = dbg_va; e + 28 <= u64(dbg_va) + dbg_size; e += 28) {
    if (rd32(img, e + 12) != 13) continue;
    u32 size = rd32(img, e + 16), rva = rd32(img, e + 20);
    std::string_view blob = img.substr(std::min<size_t>(rva, img.size()), size);
    size_t off = 4;
    while (off + 8 <= blob.size()) {
      u32 r = rd32(blob, off), sz = rd32(blob, off + 4);
      off += 8;
      size_t end = blob.find('\0', off);
      if (end == std::string_view::npos) break;
      std::string name(blob.substr(off, end - off));
      off = (end + 4) & ~size_t(3);
      im.pogo[name] = {base + r, base + r + sz};
    }
  }
}

// the memory-mapped image: headers, then each section at its virtual address (raw data, zero-padded). Laid out first
// as a list of steps (a section below the end so far cuts the image back to its address), then done in a buffer of
// zero pages: the gaps (.bss) are never written.
struct Step {
  size_t at, from, n;
  bool zero;
};  // copy data[from, from + n) to `at`, or zero n bytes there
struct Plan {
  std::vector<Step> steps;
  size_t size = 0, cap = 0;  // the image's size; the buffer's (steps may write past the image when it is cut back)
};

Plan plan_layout(std::string_view data, const Headers& h) {
  u32 sect_align = h.sect_align, file_align = h.file_align;
  const std::vector<Raw>& secs = h.secs;
  size_t header_end = h.header_end;
  auto adj_ptr = [&](u32 v) -> u32 { return file_align >= 0x200 ? (v / 0x200) * 0x200 : v; };
  auto adj_va = [&](u32 v) -> u32 {
    u32 sa = sect_align < 0x1000 ? file_align : sect_align;
    return (sa && v % sa) ? sa * (v / sa) : v;
  };
  std::optional<u32> lowest;
  for (auto& s : secs)
    if (s.rawptr > 0) {
      u32 a = adj_ptr(s.rawptr);
      if (!lowest || a < *lowest) lowest = a;
    }
  std::vector<Step> steps;
  size_t size = std::min(data.size(), size_t((!lowest || *lowest < header_end) ? header_end : *lowest)), cap = size;
  steps.push_back({0, 0, size, false});
  for (auto& s : secs) {
    if (s.vsize == 0 && s.rawsize == 0) continue;
    u32 srd = s.rawsize, prd = adj_ptr(s.rawptr), vadj = adj_va(s.va);
    if (srd > data.size() || prd > data.size() || u64(srd) + prd > data.size() || vadj >= 0x10000000) continue;
    if (vadj < size) steps.push_back({vadj, 0, size - vadj, true});  // cut back: what was there is gone
    size = vadj;
    // a section's raw data: from the aligned file pointer for SizeOfRawData, clipped at the unaligned end
    u32 ptr_adj = (sect_align < 0x1000 && s.rawptr == s.va) ? s.va : prd;
    u64 end = u64(ptr_adj) + srd;
    end = std::min<u64>(end, u64(s.rawptr) + s.rawsize);
    if (ptr_adj < data.size() && end > ptr_adj) {
      size_t n = size_t(std::min<u64>(end, data.size()) - ptr_adj);
      steps.push_back({size, ptr_adj, n, false});
      size += n;
    }
    cap = std::max(cap, size);
  }
  return Plan{std::move(steps), size, cap};
}

}  // namespace

Image Image::load(const std::string& path) {
  MappedFile file(path);
  std::string_view data = file.view();
  Headers h = read_headers(data, path);
  Plan plan = plan_layout(data, h);
  auto mem = std::make_shared<ZeroBuffer>(plan.cap);
  for (auto& st : plan.steps) {
    if (st.zero)
      std::memset(mem->data() + st.at, 0, st.n);
    else
      std::memcpy(mem->data() + st.at, data.data() + st.from, st.n);
  }
  Image im;
  im.base = h.base;
  im.img = std::string_view(mem->data(), plan.size);
  im.mem_ = std::move(mem);
  im.headers = std::string(data.substr(0, std::min(h.header_end, data.size())));
  read_tables(im, data, h);
  im.finish();
  return im;
}

Image Image::laid_out(std::string_view headers, std::string_view img, std::shared_ptr<const void> owner) {
  Headers h = read_headers(headers, "laid-out image");
  Image im;
  im.base = h.base;
  im.img = img;
  im.mem_ = std::move(owner);
  im.headers = std::string(headers);
  read_tables(im, headers, h);
  im.finish();
  return im;
}

Image Image::from_parts(u64 base, std::string mem, std::vector<Section> sections,
                        std::map<u64, std::pair<u64, u32>> pdata, std::vector<u64> relocs,
                        std::unordered_map<u64, Import> imports) {
  Image im;
  im.base = base;
  auto buf = std::make_shared<ZeroBuffer>(mem.size());
  if (!mem.empty()) std::memcpy(buf->data(), mem.data(), mem.size());
  im.img = std::string_view(buf->data(), mem.size());
  im.mem_ = std::move(buf);
  im.sections = std::move(sections);
  for (auto& [b, e] : pdata) im.pdata.push_back({b, e.first, e.second});
  im.reloc_sorted = std::move(relocs);
  im.imports = std::move(imports);
  im.finish();
  return im;
}

void Image::finish() {
  std::sort(reloc_sorted.begin(), reloc_sorted.end());
  reloc_sorted.erase(std::unique(reloc_sorted.begin(), reloc_sorted.end()), reloc_sorted.end());
  auto by_begin = [](const PData& a, const PData& b) { return a.begin < b.begin; };
  std::stable_sort(pdata.begin(), pdata.end(), by_begin);
  pdata.erase(
      std::unique(pdata.begin(), pdata.end(), [](const PData& a, const PData& b) { return a.begin == b.begin; }),
      pdata.end());
  pdata.shrink_to_fit();
}

const PData* Image::pdata_at(u64 begin) const {
  auto it = std::lower_bound(pdata.begin(), pdata.end(), begin, [](const PData& p, u64 v) { return p.begin < v; });
  return it != pdata.end() && it->begin == begin ? &*it : nullptr;
}

std::vector<u64> Image::pdata_in(u64 lo, u64 hi) const {
  auto below = [](const PData& p, u64 v) { return p.begin < v; };
  std::vector<u64> out;
  for (auto it = std::lower_bound(pdata.begin(), pdata.end(), lo, below); it != pdata.end() && it->begin < hi; ++it)
    out.push_back(it->begin);
  return out;
}

size_t Image::reloc_lower_bound(u64 va) const {
  return size_t(std::lower_bound(reloc_sorted.begin(), reloc_sorted.end(), va) - reloc_sorted.begin());
}

std::string_view Image::bytes(u64 va, i64 n) const {
  if (va < base || n < 0) return {};
  u64 r = va - base;
  if (r >= img.size()) return {};
  return std::string_view(img).substr(size_t(r), size_t(n));
}

namespace {
template <class T>
T read_at(const Image& img, u64 va) {  // little-endian, zero-filled past the end of the image
  T v = 0;
  auto s = img.bytes(va, sizeof(T));
  std::memcpy(&v, s.data(), s.size());
  return v;
}
}  // namespace

u32 Image::u32_at(u64 va) const { return read_at<u32>(*this, va); }
i32 Image::i32_at(u64 va) const { return static_cast<i32>(u32_at(va)); }
u64 Image::u64_at(u64 va) const { return read_at<u64>(*this, va); }

std::optional<u32> Image::flags(u64 va) const {
  for (auto& s : sections)
    if (s.lo <= va && va < s.hi) return s.ch;
  return std::nullopt;
}
bool Image::executable(u64 va) const {
  auto f = flags(va);
  return f && (*f & SCN_EXEC);
}
bool Image::writable(u64 va) const {
  auto f = flags(va);
  return f && (*f & SCN_WRITE);
}

Bytes Image::cstring(u64 va, bool wide) const {
  size_t step = wide ? 2 : 1;
  Bytes out;
  while (out.size() < MAX_DATA_COMPARE) {
    auto ch = bytes(va + out.size(), i64(step));
    out.append(ch);
    if (ch.size() < step || ch == std::string_view(std::string(step, '\0'))) break;
  }
  return out;
}

std::optional<u64> Image::extent(u64 va) const {
  const PData* p = pdata_at(va);
  if (!p) return std::nullopt;
  u64 end = p->end;
  for (;;) {
    // the entry starting at `end`: the table is sorted by start, so when this entry starts before `end` and the next
    // one not before it, that is the next one or none (else searched, as for overlapping entries)
    const PData* nx = p->begin < end && p + 1 < pdata.data() + pdata.size() && p[1].begin >= end
                          ? (p[1].begin == end ? p + 1 : nullptr)
                          : pdata_at(end);
    if (!nx) break;
    unsigned char vf = nx->unwind < img.size() ? static_cast<unsigned char>(img[nx->unwind]) : 0;
    if (!((vf >> 3) & 0x4)) break;  // UNW_FLAG_CHAININFO: continuation of the same function
    if (nx->end <= end) break;      // an empty or backward range: malformed
    end = nx->end;
    p = nx;
  }
  return end;
}

Unwind Image::unwind(u32 u) const {
  Unwind w;
  if (u64(u) + 4 > img.size()) return w;
  unsigned char vf = img[u], ncodes = img[u + 2];
  w.body = img.substr(u, size_t(4) + 2 * ncodes);
  u64 off = u64(u) + 4 + ((ncodes + 1) & ~1) * 2;
  unsigned flags = vf >> 3;
  if (flags & 0x4) {
    w.has_chain = true;
    w.chain_begin = rd32(img, off);
    w.chain_end = rd32(img, off + 4);
    w.chain_unwind = rd32(img, off + 8);
  } else if (flags & 0x3) {
    w.handler = base + rd32(img, off);
    w.hdata = base + off + 4;
  }
  return w;
}

Bytes type_name(const Image& img, u64 td) { return img.cstring(td + 16); }

Bytes gs_data(const Image& img, u64 va) {
  u32 f = img.u32_at(va);
  return Bytes(img.bytes(va, (f & 4) ? 12 : 4));
}

Rtti rtti(const Image& img, u64 col) {
  Rtti r;
  if (!col || !img.flags(col)) return r;
  r.present = true;
  u32 sig = img.u32_at(col);
  if (sig != 1) {
    r.bad_sig = true;
    r.sig = sig;
    return r;
  }
  r.off = img.u32_at(col + 4);
  r.cdoff = img.u32_at(col + 8);
  u32 td = img.u32_at(col + 12), chd = img.u32_at(col + 16);
  r.attrs = img.u32_at(img.base + chd + 4);
  u32 nbase = img.u32_at(img.base + chd + 8), barr = img.u32_at(img.base + chd + 12);
  for (u32 i = 0; i < std::min<u32>(nbase, 256); ++i) {
    u64 bcd = img.base + img.u32_at(img.base + barr + 4 * i);
    BaseDesc b;
    b.name = type_name(img, img.base + img.u32_at(bcd));
    b.ncont = img.u32_at(bcd + 4);
    b.mdisp = img.i32_at(bcd + 8);
    b.pdisp = img.i32_at(bcd + 12);
    b.vdisp = img.i32_at(bcd + 16);
    b.attr = img.u32_at(bcd + 20);
    r.bases.push_back(std::move(b));
  }
  r.name = type_name(img, img.base + td);
  return r;
}

ThrowInfoSig throw_info(const Image& img, u64 ti) {
  ThrowInfoSig t;
  t.attrs = img.u32_at(ti);
  i32 unwind = img.i32_at(ti + 4);
  u32 cta = img.u32_at(ti + 12);
  u32 n = std::min<u32>(img.u32_at(img.base + cta), 64);
  t.funcs.push_back(unwind ? img.base + u64(i64(unwind)) : 0);
  for (u32 i = 0; i < n; ++i) {
    u64 ct = img.base + img.u32_at(img.base + cta + 4 + 4 * i);
    CatchableSig c;
    c.props = img.u32_at(ct);
    i32 td = img.i32_at(ct + 4);
    c.mdisp = img.i32_at(ct + 8);
    c.pdisp = img.i32_at(ct + 12);
    c.vdisp = img.i32_at(ct + 16);
    c.size = img.i32_at(ct + 20);
    u32 copy = img.u32_at(ct + 24);
    c.name = type_name(img, img.base + u64(i64(td)));
    t.types.push_back(std::move(c));
    t.funcs.push_back(copy ? img.base + copy : 0);
  }
  return t;
}

std::string imp_str(const Import* imp) {
  if (!imp) return "(not an import)";
  return imp->name.empty() ? imp->dll + "#" + std::to_string(imp->ordinal) : imp->dll + "!" + imp->name;
}

}  // namespace verifier
