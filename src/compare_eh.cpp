// Comparison of a function's unwind data: .pdata ranges, UNWIND_INFO chains, and the language handler's data
// (C++ EH FuncInfo with its funclets, GS cookie data, SEH scope tables).
#include <algorithm>
#include <cstring>

#include "compare.hpp"

namespace verifier {

constexpr int MAX_FUNCLET_DEPTH = 4;
constexpr int MAX_CHAIN = 32;

Problems Comparer::unwinds(u64 ostart, u64 oend, u64 rstart, u64 rend, int depth) {
  auto ob = O->pdata_in(ostart, oend), rb = R->pdata_in(rstart, rend);
  bool same = ob.size() == rb.size();
  for (size_t i = 0; same && i < ob.size(); ++i)
    if (ob[i] - ostart != rb[i] - rstart || O->pdata_at(ob[i])->end - ostart != R->pdata_at(rb[i])->end - rstart)
      same = false;
  if (!same) return {{Category::Unwind, ".pdata ranges differ"}};
  Problems probs;
  for (size_t i = 0; i < ob.size(); ++i) {
    auto p = unwind_info(O->pdata_at(ob[i])->unwind, R->pdata_at(rb[i])->unwind, ostart, oend, rstart, rend, depth);
    probs.insert(probs.end(), p.begin(), p.end());
  }
  return probs;
}

Problems Comparer::unwind_info(u32 ou, u32 ru, u64 ostart, u64 oend, u64 rstart, u64 rend, int depth, int chain_depth) {
  Unwind o = O->unwind(ou), r = R->unwind(ru);
  if (o.body != r.body) return {{Category::Unwind, "UNWIND_INFO codes differ"}};
  if (o.has_chain != r.has_chain || o.handler.has_value() != r.handler.has_value())
    return {{Category::Unwind, "chain/handler presence differs"}};
  if (o.has_chain) {
    if (O->base + o.chain_begin - ostart != R->base + r.chain_begin - rstart ||
        O->base + o.chain_end - ostart != R->base + r.chain_end - rstart)
      return {{Category::Unwind, "chained range differs"}};
    if (chain_depth >= MAX_CHAIN) return {{Category::Unwind, "unwind chain too long"}};
    return unwind_info(o.chain_unwind, r.chain_unwind, ostart, oend, rstart, rend, depth, chain_depth + 1);
  }
  if (!o.handler) return {};
  Key got = resolve(*r.handler);
  if (!got.is_va(*o.handler)) return {{Category::Unwind, "handler " + hex(*o.handler) + " vs " + got.text()}};
  return handler_data(names(*o.handler), *o.hdata, *r.hdata, ostart, oend, rstart, rend, depth);
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
  EHContext(Comparer* c, u64 os, u64 oe, u64 rs, u64 re, int d)
      : c(c), O(c->O), R(c->R), ostart(os), oend(oe), rstart(rs), rend(re), depth(d) {}
  Comparer* c;
  const Image *O, *R;
  u64 ostart, oend, rstart, rend;
  int depth;
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
    if (depth >= MAX_FUNCLET_DEPTH) {
      probs.push_back({Category::Eh, "funclet nesting too deep"});
      return;
    }
    for (auto& [cat, why] : c->function(o, *oe, r, *re, depth + 1))
      probs.push_back({Category::Eh, "funclet " + std::to_string(ofun.size() - 1) + ": " + std::string(category_name(cat)) + ": " + why});
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

  void handlers(u64 oarr, u64 rarr, i64 n) {
    for (i64 i = 0; i < n; ++i) {
      u64 o = oarr + 20 * u64(i), r = rarr + 20 * u64(i);
      u32 oadj = O->u32_at(o), otd = O->u32_at(o + 4), oaddr = O->u32_at(o + 12);
      i32 odisp = O->i32_at(o + 8), oframe = O->i32_at(o + 16);
      u32 radj = R->u32_at(r), rtd = R->u32_at(r + 4), raddr = R->u32_at(r + 12);
      i32 rdisp = R->i32_at(r + 8), rframe = R->i32_at(r + 16);
      if (oadj != radj || odisp != rdisp || oframe != rframe) {
        probs.push_back({Category::Eh, "catch handler " + std::to_string(i) + " differs"});
        continue;
      }
      if ((otd == 0) != (rtd == 0) ||
          (otd && !c->same_names({{type_name(*O, O->base + otd), type_name(*R, R->base + rtd)}}))) {
        probs.push_back({Category::Eh, "catch type " + std::to_string(i) + " differs"});
        continue;
      }
      funclet(oaddr, raddr);
    }
  }

  Problems funcinfo(u64 ofi, u64 rfi) {
    if (c->memo_fi.contains(ofi) || c->memo_fir.contains(rfi)) {
      auto a = c->memo_fi.find(ofi);
      auto b = c->memo_fir.find(rfi);
      bool ok = a && *a == rfi && b && *b == ofi;
      return ok ? Problems{} : Problems{{Category::Eh, "FuncInfo sharing differs"}};
    }
    c->memo_fi.set(ofi, rfi);
    c->memo_fir.set(rfi, ofi);
    auto rd = [](const Image* im, u64 p, u32(&m)[10]) {
      for (int k = 0; k < 10; ++k) m[k] = im->u32_at(p + 4 * k);
    };
    u32 om[10], rm[10];
    rd(O, ofi, om);
    rd(R, rfi, rm);
    // magic, max_state(i), unwind_map, ntry, try_map, nip, ip_map, disp_help(i), es_list, ehflags(i)
    if (om[0] != rm[0] || om[1] != rm[1] || om[3] != rm[3] || om[5] != rm[5] || om[7] != rm[7] || om[9] != rm[9])
      return {{Category::Eh, "FuncInfo header differs"}};
    i32 max_state = i32(om[1]);
    u32 ntry = om[3], nip = om[5];
    if (max_state > 0x10000 || ntry > 0x10000 || nip > 0x100000) return {{Category::Eh, "FuncInfo out of range"}};
    for (i32 i = 0; i < max_state; ++i) {
      i32 ost = O->i32_at(O->base + om[2] + 8 * u64(i)), rst = R->i32_at(R->base + rm[2] + 8 * u64(i));
      u32 oact = O->u32_at(O->base + om[2] + 8 * u64(i) + 4), ract = R->u32_at(R->base + rm[2] + 8 * u64(i) + 4);
      if (ost != rst) {
        probs.push_back({Category::Eh, "unwind map entry " + std::to_string(i) + " differs"});
        continue;
      }
      funclet(oact, ract);
    }
    for (u32 i = 0; i < ntry; ++i) {
      u64 ob = O->base + om[4] + 20 * u64(i), rb = R->base + rm[4] + 20 * u64(i);
      i32 o4[4], r4[4];
      for (int z = 0; z < 4; ++z) {
        o4[z] = O->i32_at(ob + 4 * z);
        r4[z] = R->i32_at(rb + 4 * z);
      }
      if (std::memcmp(o4, r4, sizeof o4) != 0) {
        probs.push_back({Category::Eh, "try block " + std::to_string(i) + " differs"});
        continue;
      }
      handlers(O->base + O->u32_at(ob + 16), R->base + R->u32_at(rb + 16), o4[3]);
    }
    if ((om[8] == 0) != (rm[8] == 0)) {
      probs.push_back({Category::Eh, "exception specification presence differs"});
    } else if (om[8]) {
      i32 on = O->i32_at(O->base + om[8]), rn = R->i32_at(R->base + rm[8]);
      u32 oarr = O->u32_at(O->base + om[8] + 4), rarr = R->u32_at(R->base + rm[8] + 4);
      if (on != rn || !(0 <= on && on <= 0x100))
        probs.push_back({Category::Eh, "exception specification differs"});
      else
        handlers(O->base + oarr, R->base + rarr, on);
    }
    for (u32 i = 0; i < nip; ++i) {
      u32 oip = O->u32_at(O->base + om[6] + 8 * u64(i)), rip = R->u32_at(R->base + rm[6] + 8 * u64(i));
      i32 ost = O->i32_at(O->base + om[6] + 8 * u64(i) + 4), rst = R->i32_at(R->base + rm[6] + 8 * u64(i) + 4);
      Where ow = where(*O, O->base + oip, ostart, oend, ofun), rw = where(*R, R->base + rip, rstart, rend, rfun);
      if (ost != rst || !(ow == rw) || ow.t == '?') {
        probs.push_back({Category::Eh, "IP-to-state entry " + std::to_string(i) + " differs"});
        break;
      }
    }
    return probs;
  }

  Problems scope_table(u64 od, u64 rd) {
    u32 n = O->u32_at(od);
    if (n != R->u32_at(rd) || n > 0x1000) return {{Category::Eh, "scope table size differs"}};
    for (u32 i = 0; i < n; ++i) {
      u64 oo = od + 4 + 16 * u64(i), ro = rd + 4 + 16 * u64(i);
      u32 ob = O->u32_at(oo), oe = O->u32_at(oo + 4), oh = O->u32_at(oo + 8), ot = O->u32_at(oo + 12);
      u32 rb = R->u32_at(ro), re = R->u32_at(ro + 4), rh = R->u32_at(ro + 8), rt = R->u32_at(ro + 12);
      Where ow1 = where(*O, O->base + ob, ostart, oend, {}), ow2 = where(*O, O->base + oe, ostart, oend + 1, {});
      Where rw1 = where(*R, R->base + rb, rstart, rend, {}), rw2 = where(*R, R->base + re, rstart, rend + 1, {});
      if (!(ow1 == rw1) || !(ow2 == rw2) || ow1.t == '?' || ow2.t == '?') {
        probs.push_back({Category::Eh, "scope " + std::to_string(i) + " range differs"});
        continue;
      }
      if ((ot == 0) != (rt == 0) || (ot && O->base + ot - ostart != R->base + rt - rstart)) {
        probs.push_back({Category::Eh, "scope " + std::to_string(i) + " target differs"});
        continue;
      }
      if (oh < 0x10 || rh < 0x10) {  // EXCEPTION_EXECUTE_HANDLER etc. are constants, not RVAs
        if (oh != rh) probs.push_back({Category::Eh, "scope " + std::to_string(i) + " filter differs"});
        continue;
      }
      funclet(oh, rh);
    }
    return probs;
  }
};

Problems Comparer::handler_data(std::string_view handler, u64 od, u64 rd, u64 ostart, u64 oend, u64 rstart, u64 rend,
                                int depth) {
  EHContext ctx(this, ostart, oend, rstart, rend, depth);
  if (handler == "__CxxFrameHandler3") return ctx.funcinfo(O->base + O->u32_at(od), R->base + R->u32_at(rd));
  if (handler == "__GSHandlerCheck") {
    if (gs_data(*O, od) != gs_data(*R, rd)) return {{Category::Eh, "GS cookie data differs"}};
    return {};
  }
  if (handler == "__GSHandlerCheck_EH") {
    Problems p = ctx.funcinfo(O->base + O->u32_at(od), R->base + R->u32_at(rd));
    if (gs_data(*O, od + 4) != gs_data(*R, rd + 4)) p.push_back({Category::Eh, "GS cookie data differs"});
    return p;
  }
  if (handler == "__C_specific_handler") return ctx.scope_table(od, rd);
  return {{Category::Eh,
           "handler " + (handler.empty() ? std::string("unknown") : std::string(handler)) + " data is not verifiable"}};
}

}  // namespace verifier
