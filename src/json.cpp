#include "json.hpp"

#include <cmath>
#include <cstdio>
#include <stdexcept>

namespace verifier::json {

const Value* Value::get(std::string_view key) const {
  if (type != Object) return nullptr;
  for (auto& kv : obj) if (kv.first == key) return &kv.second;
  return nullptr;
}

const Value& Value::operator[](std::string_view key) const {
  const Value* v = get(key);
  if (!v) throw std::runtime_error("missing JSON key " + std::string(key));
  return *v;
}

Value& Value::set(const std::string& key, Value v) {
  for (auto& kv : obj) if (kv.first == key) { kv.second = std::move(v); return kv.second; }
  obj.emplace_back(key, std::move(v));
  return obj.back().second;
}

std::int64_t Value::as_int() const {
  if (type == Int) return i;
  if (type == Double) return static_cast<std::int64_t>(d);
  if (type == Bool) return b;
  throw std::runtime_error("JSON value is not a number");
}

const std::string& Value::as_str() const {
  if (type != String) throw std::runtime_error("JSON value is not a string");
  return s;
}

bool Value::truthy() const {
  switch (type) {
    case Null: return false;
    case Bool: return b;
    case Int: return i != 0;
    case Double: return d != 0;
    case String: return !s.empty();
    case Array: return !arr.empty();
    case Object: return !obj.empty();
  }
  return false;
}

namespace {

struct Parser {
  std::string_view t;
  size_t p = 0;

  [[noreturn]] void fail(const char* what) {
    throw std::runtime_error(std::string("JSON: ") + what + " at " + std::to_string(p));
  }
  void ws() { while (p < t.size() && (t[p] == ' ' || t[p] == '\t' || t[p] == '\n' || t[p] == '\r')) ++p; }

  static void utf8(std::string& out, unsigned cp) {
    if (cp < 0x80) out += static_cast<char>(cp);
    else if (cp < 0x800) { out += static_cast<char>(0xC0 | (cp >> 6)); out += static_cast<char>(0x80 | (cp & 0x3F)); }
    else if (cp < 0x10000) {
      out += static_cast<char>(0xE0 | (cp >> 12)); out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
      out += static_cast<char>(0x80 | (cp & 0x3F));
    } else {
      out += static_cast<char>(0xF0 | (cp >> 18)); out += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
      out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F)); out += static_cast<char>(0x80 | (cp & 0x3F));
    }
  }
  unsigned hex4() {
    if (p + 4 > t.size()) fail("short \\u escape");
    unsigned v = 0;
    for (int k = 0; k < 4; ++k) {
      char c = t[p++];
      v = v * 16 + ((c >= '0' && c <= '9') ? c - '0' : (c >= 'a' && c <= 'f') ? c - 'a' + 10 : (c >= 'A' && c <= 'F') ? c - 'A' + 10 : (fail("bad hex"), 0));
    }
    return v;
  }
  std::string string() {
    if (t[p] != '"') fail("expected string");
    ++p;
    std::string out;
    for (;;) {
      if (p >= t.size()) fail("unterminated string");
      char c = t[p++];
      if (c == '"') break;
      if (c != '\\') { out += c; continue; }
      if (p >= t.size()) fail("bad escape");
      char e = t[p++];
      switch (e) {
        case '"': out += '"'; break;
        case '\\': out += '\\'; break;
        case '/': out += '/'; break;
        case 'b': out += '\b'; break;
        case 'f': out += '\f'; break;
        case 'n': out += '\n'; break;
        case 'r': out += '\r'; break;
        case 't': out += '\t'; break;
        case 'u': {
          unsigned cp = hex4();
          if (cp >= 0xD800 && cp < 0xDC00 && p + 1 < t.size() && t[p] == '\\' && t[p + 1] == 'u') {
            size_t save = p; p += 2;
            unsigned lo = hex4();
            if (lo >= 0xDC00 && lo < 0xE000) cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
            else p = save;
          }
          utf8(out, cp);
          break;
        }
        default: fail("bad escape");
      }
    }
    return out;
  }
  Value value() {
    ws();
    if (p >= t.size()) fail("unexpected end");
    char c = t[p];
    if (c == '{') {
      ++p;
      Value v = Value::object();
      ws();
      if (t[p] == '}') { ++p; return v; }
      for (;;) {
        ws();
        std::string k = string();
        ws();
        if (t[p] != ':') fail("expected :");
        ++p;
        v.obj.emplace_back(std::move(k), value());
        ws();
        if (t[p] == ',') { ++p; continue; }
        if (t[p] == '}') { ++p; return v; }
        fail("expected , or }");
      }
    }
    if (c == '[') {
      ++p;
      Value v = Value::array();
      ws();
      if (t[p] == ']') { ++p; return v; }
      for (;;) {
        v.arr.push_back(value());
        ws();
        if (t[p] == ',') { ++p; continue; }
        if (t[p] == ']') { ++p; return v; }
        fail("expected , or ]");
      }
    }
    if (c == '"') return Value::str(string());
    if (t.compare(p, 4, "null") == 0) { p += 4; return Value(); }
    if (t.compare(p, 4, "true") == 0) { p += 4; return Value::boolean(true); }
    if (t.compare(p, 5, "false") == 0) { p += 5; return Value::boolean(false); }
    size_t s = p;
    if (t[p] == '-') ++p;
    bool is_float = false;
    while (p < t.size() && ((t[p] >= '0' && t[p] <= '9') || t[p] == '.' || t[p] == 'e' || t[p] == 'E' || t[p] == '+' || t[p] == '-')) {
      if (t[p] == '.' || t[p] == 'e' || t[p] == 'E') is_float = true;
      ++p;
    }
    if (p == s) fail("unexpected character");
    std::string num(t.substr(s, p - s));
    Value v;
    if (is_float) { v.type = Value::Double; v.d = std::stod(num); }
    else { v.type = Value::Int; v.i = std::stoll(num); }
    return v;
  }
};

void put_str(std::string& out, std::string_view s) {
  out += '"';
  size_t i = 0;
  while (i < s.size()) {
    unsigned char c = s[i];
    if (c == '"') { out += "\\\""; ++i; continue; }
    if (c == '\\') { out += "\\\\"; ++i; continue; }
    if (c == '\n') { out += "\\n"; ++i; continue; }
    if (c == '\r') { out += "\\r"; ++i; continue; }
    if (c == '\t') { out += "\\t"; ++i; continue; }
    if (c == '\b') { out += "\\b"; ++i; continue; }
    if (c == '\f') { out += "\\f"; ++i; continue; }
    if (c < 0x20 || c == 0x7f) {
      if (c == 0x7f) { out += static_cast<char>(c); ++i; continue; }
      char b[8]; std::snprintf(b, sizeof b, "\\u%04x", c); out += b; ++i; continue;
    }
    if (c < 0x80) { out += static_cast<char>(c); ++i; continue; }
    // UTF-8 sequence -> \uXXXX (surrogate pairs above the BMP), as ensure_ascii does
    unsigned cp; int len;
    if ((c & 0xE0) == 0xC0) { cp = c & 0x1F; len = 2; }
    else if ((c & 0xF0) == 0xE0) { cp = c & 0x0F; len = 3; }
    else if ((c & 0xF8) == 0xF0) { cp = c & 0x07; len = 4; }
    else { cp = 0xFFFD; len = 1; }
    for (int k = 1; k < len; ++k) cp = (cp << 6) | (static_cast<unsigned char>(i + k < s.size() ? s[i + k] : 0) & 0x3F);
    i += len;
    char b[16];
    if (cp >= 0x10000) {
      cp -= 0x10000;
      std::snprintf(b, sizeof b, "\\u%04x\\u%04x", 0xD800 + (cp >> 10), 0xDC00 + (cp & 0x3FF));
    } else {
      std::snprintf(b, sizeof b, "\\u%04x", cp);
    }
    out += b;
  }
  out += '"';
}

void dump(std::string& out, const Value& v, int level) {
  auto nl = [&](int lv) { out += '\n'; out.append(static_cast<size_t>(lv), ' '); };
  switch (v.type) {
    case Value::Null: out += "null"; break;
    case Value::Bool: out += v.b ? "true" : "false"; break;
    case Value::Int: out += std::to_string(v.i); break;
    case Value::Double: {
      char b[32]; std::snprintf(b, sizeof b, "%.17g", v.d); out += b; break;   // not used by the report
    }
    case Value::String: put_str(out, v.s); break;
    case Value::Array:
      if (v.arr.empty()) { out += "[]"; break; }
      out += '[';
      for (size_t k = 0; k < v.arr.size(); ++k) {
        if (k) out += ',';
        nl(level + 1);
        dump(out, v.arr[k], level + 1);
      }
      nl(level);
      out += ']';
      break;
    case Value::Object:
      if (v.obj.empty()) { out += "{}"; break; }
      out += '{';
      for (size_t k = 0; k < v.obj.size(); ++k) {
        if (k) out += ',';
        nl(level + 1);
        put_str(out, v.obj[k].first);
        out += ": ";
        dump(out, v.obj[k].second, level + 1);
      }
      nl(level);
      out += '}';
      break;
  }
}

}  // namespace

Value parse(std::string_view text) {
  Parser ps{text};
  Value v = ps.value();
  ps.ws();
  if (ps.p != text.size()) ps.fail("trailing data");
  return v;
}

std::string dumps_indent1(const Value& v) {
  std::string out;
  dump(out, v, 0);
  return out;
}

std::string quote(std::string_view s) {
  std::string out;
  put_str(out, s);
  return out;
}

}  // namespace verifier::json
