// Comparison of a function's unwind data: .pdata ranges, UNWIND_INFO chains, and the language handler's data
// (C++ EH FuncInfo with its funclets, GS cookie data, SEH scope tables).
#include <algorithm>

#include "compare.hpp"
#include "layouts.hpp"

namespace verifier {

constexpr int MAX_CHAIN = 32;

Problems Comparer::unwinds(u64 ostart, u64 oend, u64 rstart, u64 rend, std::optional<std::pair<u64, u64>> fi) {
  auto ob = O->pdata_in(ostart, oend), rb = R->pdata_in(rstart, rend);
  bool same = ob.size() == rb.size();
  for (size_t i = 0; same && i < ob.size(); ++i)
    if (ob[i] - ostart != rb[i] - rstart || O->pdata_at(ob[i])->end - ostart != R->pdata_at(rb[i])->end - rstart)
      same = false;
  if (!same) return {{Category::Unwind, ".pdata ranges differ"}};
  Problems probs;
  for (size_t i = 0; i < ob.size(); ++i) {
    auto p = unwind_info(O->pdata_at(ob[i])->unwind, R->pdata_at(rb[i])->unwind, ostart, oend, rstart, rend, fi);
    probs.insert(probs.end(), p.begin(), p.end());
  }
  return probs;
}

Problems Comparer::unwind_info(u32 ou, u32 ru, u64 ostart, u64 oend, u64 rstart, u64 rend,
                               std::optional<std::pair<u64, u64>> fi, int chain_depth) {
  Unwind o = O->unwind(ou), r = R->unwind(ru);
  if (o.body != r.body) return {{Category::Unwind, "UNWIND_INFO codes differ"}};
  if (o.has_chain != r.has_chain || o.handler.has_value() != r.handler.has_value())
    return {{Category::Unwind, "chain/handler presence differs"}};
  if (o.has_chain) {
    if (O->base + o.chain_begin - ostart != R->base + r.chain_begin - rstart ||
        O->base + o.chain_end - ostart != R->base + r.chain_end - rstart)
      return {{Category::Unwind, "chained range differs"}};
    if (chain_depth >= MAX_CHAIN) return {{Category::Unwind, "unwind chain too long"}};
    return unwind_info(o.chain_unwind, r.chain_unwind, ostart, oend, rstart, rend, fi, chain_depth + 1);
  }
  if (!o.handler) return {};
  Key got = resolve(*r.handler);
  if (!got.is_va(*o.handler)) return {{Category::Unwind, "handler " + hex(*o.handler) + " vs " + got.text()}};
  return handler_data(names(*o.handler), *o.hdata, *r.hdata, ostart, oend, rstart, rend, fi);
}

// -- EH ----------------------------------------------------------------------------------------------------------

namespace {
std::optional<u64> extent_or_leaf(const Image& img, u64 va) {  // .pdata's extent, else a leaf function's
  auto e = img.extent(va);
  return e ? e : leaf_extent(img, va);
}
}  // namespace

class EHContext {
 public:
  EHContext(Comparer* c, u64 os, u64 oe, u64 rs, u64 re)
      : c(c), O(c->O), R(c->R), ostart(os), oend(oe), rstart(rs), rend(re) {}
  Comparer* c;
  const Image *O, *R;
  u64 ostart, oend, rstart, rend;
  std::optional<std::pair<u64, u64>> fi;  // the FuncInfo pair being compared (its funclets' handler data)
  std::vector<u64> ofun, rfun;
  Problems probs;

  void funclet(u32 orva, u32 rrva) {
    if ((orva == 0) != (rrva == 0)) {
      probs.push_back({Category::Eh, "funclet presence differs"});
      return;
    }
    if (orva == 0) return;
    u64 o = O->base + orva, r = R->base + rrva;
    auto io = std::find(ofun.begin(), ofun.end(), o), ir = std::find(rfun.begin(), rfun.end(), r);
    long ix = io == ofun.end() ? -1 : long(io - ofun.begin()), jx = ir == rfun.end() ? -1 : long(ir - rfun.begin());
    if (ix != jx) {
      probs.push_back({Category::Eh, "funclet sharing differs"});
      return;
    }
    if (ix >= 0) return;
    ofun.push_back(o);
    rfun.push_back(r);
    if ((ostart <= o && o < oend) || (rstart <= r && r < rend)) {
      if (o - ostart != r - rstart) probs.push_back({Category::Eh, "in-function handler offset differs"});
      return;
    }
    auto oe = extent_or_leaf(*O, o), re = extent_or_leaf(*R, r);
    if (!O->pdata_at(o) != !R->pdata_at(r)) {
      probs.push_back({Category::Eh, "funclet " + hex(o) + ": .pdata presence differs"});
      return;
    }
    if (!oe || !re) {
      probs.push_back({Category::Eh, "funclet " + hex(o) + " has no .pdata"});
      return;
    }
    Problems got = fi ? c->funclet({o, *oe, r, *re}, *fi) : c->function(o, *oe, r, *re);
    for (auto& [cat, why] : got)
      probs.push_back({Category::Eh, "funclet " + std::to_string(ofun.size() - 1) + ": " +
                                         std::string(category_name(cat)) + ": " + why});
  }

  // ('p', off) / ('f', k, off) / ('?',)
  struct Where {
    char t;
    i64 k, off;
    bool operator==(const Where& o) const { return t == o.t && k == o.k && off == o.off; }
  };
  Where where(const Image& img, u64 va, u64 start, u64 end, const std::vector<u64>& funs) {
    if (start <= va && va < end) return {'p', 0, i64(va - start)};
    for (size_t k = 0; k < funs.size(); ++k) {
      u64 f = funs[k];
      auto fe = extent_or_leaf(img, f);
      if (fe && *fe && f <= va && va < *fe) return {'f', i64(k), i64(va - f)};
    }
    return {'?', 0, 0};
  }

  // a field holding a code address: the same place on both sides (in the function; for Ip also in the funclets found
  // so far, for End also the function's end)
  bool same_place(Holds holds, u32 ov, u32 rv) {
    u64 o = O->base + ov, r = R->base + rv;
    static const std::vector<u64> none;
    bool ip = holds == Holds::Ip;
    u64 extra = holds == Holds::End ? 1 : 0;
    Where ow = where(*O, o, ostart, oend + extra, ip ? ofun : none);
    Where rw = where(*R, r, rstart, rend + extra, ip ? rfun : none);
    return ow == rw && ow.t != '?';
  }

  // one record of `l` on each side (layouts.hpp says how), `index` its place in its table for the messages; false
  // when its table stops here
  bool record(const Layout& l, u64 o, u64 r, i64 index) {
    auto fail = [&](const char* text) {
      probs.push_back({Category::Eh, message(text ? text : l.differs, index)});
      return !l.stop_at_first;
    };
    for (auto& f : l.fields)
      if ((f.holds == Holds::Value || f.holds == Holds::Count) && O->u32_at(o + f.off) != R->u32_at(r + f.off))
        return fail(l.differs);
    std::vector<std::pair<int, i64>> counts;  // (offset, entries)
    for (auto& f : l.fields) {
      if (f.holds != Holds::Count) continue;
      u32 raw = O->u32_at(o + f.off);
      i64 v = f.sign ? i64(i32(raw)) : i64(raw);
      if (v < f.lo || v > f.hi) {
        if (!f.clamp) return fail(l.out_of_range ? l.out_of_range : l.differs);
        v = std::min(v, f.hi);
      }
      counts.emplace_back(f.off, std::max<i64>(v, 0));
    }
    for (auto& f : l.fields) {
      u32 ov = O->u32_at(o + f.off), rv = R->u32_at(r + f.off);
      switch (f.holds) {
        case Holds::Funclet:
          funclet(ov, rv);
          break;
        case Holds::Filter:
          if (ov >= 0x10 && rv >= 0x10)
            funclet(ov, rv);
          else if (ov != rv)
            return fail(f.differs);
          break;
        case Holds::Type:
          if ((ov == 0) != (rv == 0) ||
              (ov && !c->same_names({{type_name(*O, rva(*O, f, ov)), type_name(*R, rva(*R, f, rv))}})))
            return fail(f.differs);
          break;
        case Holds::Ip:
        case Holds::Begin:
        case Holds::End:
          if (!same_place(f.holds, ov, rv)) return fail(f.differs);
          break;
        case Holds::Target:
          if ((ov == 0) != (rv == 0) || (ov && O->base + ov - ostart != R->base + rv - rstart)) return fail(f.differs);
          break;
        case Holds::Record:
          if ((ov == 0) != (rv == 0))
            probs.push_back({Category::Eh, message(f.differs, index)});
          else if (ov)
            record(*f.layout, rva(*O, f, ov), rva(*R, f, rv), index);
          break;
        case Holds::Table:
        case Holds::Inline: {
          i64 n = 0;
          for (auto& [off, cn] : counts)
            if (off == f.count_at) n = cn;
          bool inl = f.holds == Holds::Inline;
          u64 of = inl ? o + f.off : rva(*O, f, ov), rf = inl ? r + f.off : rva(*R, f, rv);
          for (i64 i = 0; i < n; ++i)
            if (!record(*f.layout, of + u64(f.layout->size) * u64(i), rf + u64(f.layout->size) * u64(i), i)) break;
          break;
        }
        default:  // Value and Count: compared above; Function: not in handler data
          break;
      }
    }
    return true;
  }

  static u64 rva(const Image& img, const Member& f, u32 raw) {
    return img.base + u64(f.sign ? i64(i32(raw)) : i64(raw));
  }

  // a FuncInfo pair is a guess (one partner on each side: Matching)
  Problems funcinfo(u64 ofi, u64 rfi) {
    if (!c->m.assume(Matching::Kind::FuncInfo, ofi, rfi)) return {{Category::Eh, "FuncInfo sharing differs"}};
    fi = std::make_pair(ofi, rfi);
    record(FUNC_INFO, ofi, rfi, -1);
    return probs;
  }
};

Problems Comparer::handler_data(std::string_view handler, u64 od, u64 rd, u64 ostart, u64 oend, u64 rstart, u64 rend,
                                std::optional<std::pair<u64, u64>> fi) {
  EHContext ctx(this, ostart, oend, rstart, rend);
  // a funclet's FuncInfo is its function's, compared there
  auto funcinfo = [&](u64 ofi, u64 rfi) {
    return fi && *fi == std::make_pair(ofi, rfi) ? Problems{} : ctx.funcinfo(ofi, rfi);
  };
  switch (handler_named(handler)) {
    case Handler::CxxFrame3:
      return funcinfo(O->base + O->u32_at(od), R->base + R->u32_at(rd));
    case Handler::GS:
      if (gs_data(*O, od) != gs_data(*R, rd)) return {{Category::Eh, "GS cookie data differs"}};
      return {};
    case Handler::GS_EH: {
      Problems p = funcinfo(O->base + O->u32_at(od), R->base + R->u32_at(rd));
      if (gs_data(*O, od + 4) != gs_data(*R, rd + 4)) p.push_back({Category::Eh, "GS cookie data differs"});
      return p;
    }
    case Handler::CSpecific:
      ctx.record(SCOPE_TABLE, od, rd, -1);
      return ctx.probs;
    case Handler::CxxFrame4:  // FuncInfo4 is not described (layouts.hpp): the seam for its decoder
    case Handler::Unknown:
      break;
  }
  return {{Category::Eh,
           "handler " + (handler.empty() ? std::string("unknown") : std::string(handler)) + " data is not verifiable"}};
}

}  // namespace verifier
