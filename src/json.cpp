#include "json.hpp"

#include <cstring>

#include <cmath>
#include <cstdio>
#include <stdexcept>

#include "util.hpp"

namespace verifier::json {

const Value* Value::get(std::string_view key) const {
  if (type != Object) return nullptr;
  for (auto& kv : obj)
    if (kv.first == key) return &kv.second;
  return nullptr;
}

const Value& Value::operator[](std::string_view key) const {
  const Value* v = get(key);
  if (!v) throw std::runtime_error("missing JSON key " + std::string(key));
  return *v;
}

Value& Value::set(const std::string& key, Value v) {
  for (auto& kv : obj)
    if (kv.first == key) {
      kv.second = std::move(v);
      return kv.second;
    }
  obj.emplace_back(key, std::move(v));
  return obj.back().second;
}

std::int64_t Value::as_int() const {
  if (type == Int) return i;
  if (type == Double) return static_cast<std::int64_t>(d);
  if (type == Bool) return b;
  throw std::runtime_error("JSON value is not a number");
}

bool Value::as_bool() const {
  if (type == Bool) return b;
  if (type == Int) return i != 0;
  throw std::runtime_error("JSON value is not a boolean");
}

const std::string& Value::as_str() const {
  if (type != String) throw std::runtime_error("JSON value is not a string");
  return s;
}

namespace {

struct Parser {
  std::string_view t;
  size_t p = 0;

  [[noreturn]] void fail(const char* what) {
    throw std::runtime_error(std::string("JSON: ") + what + " at " + std::to_string(p));
  }
  void ws() {
    while (p < t.size() && (t[p] == ' ' || t[p] == '\t' || t[p] == '\n' || t[p] == '\r')) ++p;
  }

  static void utf8(std::string& out, unsigned cp) {
    if (cp < 0x80)
      out += static_cast<char>(cp);
    else if (cp < 0x800) {
      out += static_cast<char>(0xC0 | (cp >> 6));
      out += static_cast<char>(0x80 | (cp & 0x3F));
    } else if (cp < 0x10000) {
      out += static_cast<char>(0xE0 | (cp >> 12));
      out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
      out += static_cast<char>(0x80 | (cp & 0x3F));
    } else {
      out += static_cast<char>(0xF0 | (cp >> 18));
      out += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
      out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
      out += static_cast<char>(0x80 | (cp & 0x3F));
    }
  }
  unsigned hex4() {
    if (p + 4 > t.size()) fail("short \\u escape");
    unsigned v = 0;
    for (int k = 0; k < 4; ++k) {
      int d = hex_digit(t[p++]);
      if (d < 0) fail("bad hex");
      v = v * 16 + unsigned(d);
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
      if (c != '\\') {
        out += c;
        continue;
      }
      if (p >= t.size()) fail("bad escape");
      char e = t[p++];
      switch (e) {
        case '"':
          out += '"';
          break;
        case '\\':
          out += '\\';
          break;
        case '/':
          out += '/';
          break;
        case 'b':
          out += '\b';
          break;
        case 'f':
          out += '\f';
          break;
        case 'n':
          out += '\n';
          break;
        case 'r':
          out += '\r';
          break;
        case 't':
          out += '\t';
          break;
        case 'u': {
          unsigned cp = hex4();
          if (cp >= 0xD800 && cp < 0xDC00 && p + 1 < t.size() && t[p] == '\\' && t[p + 1] == 'u') {
            size_t save = p;
            p += 2;
            unsigned lo = hex4();
            if (lo >= 0xDC00 && lo < 0xE000)
              cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
            else
              p = save;
          }
          utf8(out, cp);
          break;
        }
        default:
          fail("bad escape");
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
      if (t[p] == '}') {
        ++p;
        return v;
      }
      for (;;) {
        ws();
        std::string k = string();
        ws();
        if (t[p] != ':') fail("expected :");
        ++p;
        v.obj.emplace_back(std::move(k), value());
        ws();
        if (t[p] == ',') {
          ++p;
          continue;
        }
        if (t[p] == '}') {
          ++p;
          return v;
        }
        fail("expected , or }");
      }
    }
    if (c == '[') {
      ++p;
      Value v = Value::array();
      ws();
      if (t[p] == ']') {
        ++p;
        return v;
      }
      for (;;) {
        v.arr.push_back(value());
        ws();
        if (t[p] == ',') {
          ++p;
          continue;
        }
        if (t[p] == ']') {
          ++p;
          return v;
        }
        fail("expected , or ]");
      }
    }
    if (c == '"') return Value::str(string());
    if (t.compare(p, 4, "null") == 0) {
      p += 4;
      return Value();
    }
    if (t.compare(p, 4, "true") == 0) {
      p += 4;
      return Value::boolean(true);
    }
    if (t.compare(p, 5, "false") == 0) {
      p += 5;
      return Value::boolean(false);
    }
    size_t s = p;
    if (t[p] == '-') ++p;
    bool is_float = false;
    while (p < t.size() &&
           ((t[p] >= '0' && t[p] <= '9') || t[p] == '.' || t[p] == 'e' || t[p] == 'E' || t[p] == '+' || t[p] == '-')) {
      if (t[p] == '.' || t[p] == 'e' || t[p] == 'E') is_float = true;
      ++p;
    }
    if (p == s) fail("unexpected character");
    std::string num(t.substr(s, p - s));
    Value v;
    if (is_float) {
      v.type = Value::Double;
      v.d = std::stod(num);
    } else {
      v.type = Value::Int;
      v.i = std::stoll(num);
    }
    return v;
  }
};

inline void newline(std::string& out, int level) {  // a line break and `level`'s indent
  out += '\n';
  out.append(2 * static_cast<size_t>(level), ' ');
}

}  // namespace

// a JSON string literal: UTF-8 is written as is, control characters escaped
namespace {

// whether one of the 8 bytes at p is below 0x20, '"' or '\\' (exact for "none"; a word with one is looked at byte by
// byte)
bool needs_escape(const char* p) {
  constexpr u64 ONES = 0x0101010101010101ull, HIGH = 0x8080808080808080ull;
  u64 x;
  std::memcpy(&x, p, 8);
  auto zero_byte = [](u64 v) { return (v - ONES) & ~v & HIGH; };
  u64 below_space = (x - 0x20 * ONES) & ~x & HIGH;  // a byte below 0x20 (bytes from 0x80 are never flagged)
  return below_space | zero_byte(x ^ ('"' * ONES)) | zero_byte(x ^ ('\\' * ONES));
}

}  // namespace

void put_quoted(std::string& out, std::string_view s) {
  out += '"';
  size_t run = 0;  // the start of the characters not yet written that need no escape
  for (size_t i = 0; i < s.size(); ++i) {
    // eight bytes at a time while none is a control character, '"' or '\\' (most strings have none at all)
    while (i + 8 <= s.size() && !needs_escape(s.data() + i)) i += 8;
    if (i == s.size()) break;
    unsigned char c = static_cast<unsigned char>(s[i]);
    if (c >= 0x20 && c != '"' && c != '\\') continue;
    out.append(s.data() + run, i - run);
    run = i + 1;
    switch (c) {
      case '"':
        out += "\\\"";
        break;
      case '\\':
        out += "\\\\";
        break;
      case '\n':
        out += "\\n";
        break;
      case '\r':
        out += "\\r";
        break;
      case '\t':
        out += "\\t";
        break;
      default:
        char b[8];
        std::snprintf(b, sizeof b, "\\u%04x", c);
        out += b;
    }
  }
  out.append(s.data() + run, s.size() - run);
  out += '"';
}

void put_value(std::string& out, const Value& v, int level) {
  switch (v.type) {
    case Value::Null:
      out += "null";
      break;
    case Value::Bool:
      out += v.b ? "true" : "false";
      break;
    case Value::Int:
      out += std::to_string(v.i);
      break;
    case Value::Double: {
      char b[32];
      std::snprintf(b, sizeof b, "%.17g", v.d);
      out += b;
      break;  // not used by the report
    }
    case Value::String:
      put_quoted(out, v.s);
      break;
    case Value::Array:
      if (v.arr.empty()) {
        out += "[]";
        break;
      }
      out += '[';
      for (size_t k = 0; k < v.arr.size(); ++k) {
        if (k) out += ',';
        newline(out, level + 1);
        put_value(out, v.arr[k], level + 1);
      }
      newline(out, level);
      out += ']';
      break;
    case Value::Object:
      if (v.obj.empty()) {
        out += "{}";
        break;
      }
      out += '{';
      for (size_t k = 0; k < v.obj.size(); ++k) {
        if (k) out += ',';
        newline(out, level + 1);
        put_quoted(out, v.obj[k].first);
        out += ": ";
        put_value(out, v.obj[k].second, level + 1);
      }
      newline(out, level);
      out += '}';
      break;
  }
}

Value parse(std::string_view text) {
  Parser ps{text};
  Value v = ps.value();
  ps.ws();
  if (ps.p != text.size()) ps.fail("trailing data");
  return v;
}

std::string dump(const Value& v) {
  std::string out;
  put_value(out, v, 0);
  out += '\n';
  return out;
}

void put_strings(std::string& out, const std::vector<std::string>& v, int level) {
  if (v.empty()) {
    out += "[]";
    return;
  }
  out += '[';
  for (size_t k = 0; k < v.size(); ++k) {
    if (k) out += ',';
    newline(out, level + 1);
    put_quoted(out, v[k]);
  }
  newline(out, level);
  out += ']';
}

void ObjectWriter::key(std::string_view k) {
  out_ += first_ ? '{' : ',';
  first_ = false;
  newline(out_, level_ + 1);
  put_quoted(out_, k);
  out_ += ": ";
}

void ObjectWriter::end() {
  if (first_) {
    out_ += "{}";
    return;
  }
  newline(out_, level_);
  out_ += '}';
}

}  // namespace verifier::json
