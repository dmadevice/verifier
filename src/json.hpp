// JSON: a small reader for the inputs (IDA exports, library matches) and a writer that formats
// in a fixed style: one-space indent, ASCII only (\uXXXX escapes), ", " / ": " separators, objects in insertion order.
#pragma once
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace verifier::json {

struct Value {
  enum Type { Null, Bool, Int, Double, String, Array, Object } type = Null;
  bool b = false;
  std::int64_t i = 0;
  double d = 0;
  std::string s;
  std::vector<Value> arr;
  std::vector<std::pair<std::string, Value>> obj;   // insertion order

  Value() = default;
  static Value null() { return Value(); }
  static Value boolean(bool v) { Value x; x.type = Bool; x.b = v; return x; }
  static Value integer(std::int64_t v) { Value x; x.type = Int; x.i = v; return x; }
  static Value str(std::string v) { Value x; x.type = String; x.s = std::move(v); return x; }
  static Value array() { Value x; x.type = Array; return x; }
  static Value object() { Value x; x.type = Object; return x; }

  bool is_null() const { return type == Null; }
  const Value* get(std::string_view key) const;          // object member or nullptr
  const Value& operator[](std::string_view key) const;   // throws when missing
  Value& set(const std::string& key, Value v);           // replaces in place (keeps position) or appends
  void push(Value v) { arr.push_back(std::move(v)); }
  std::int64_t as_int() const;
  const std::string& as_str() const;
  bool truthy() const;                                    // false for null, false, 0, "", [], {}
};

Value parse(std::string_view text);   // throws std::runtime_error
std::string dumps_indent1(const Value& v);   // json.dumps(v, indent=1)
std::string quote(std::string_view s);        // a JSON string literal, ensure_ascii

}  // namespace verifier::json
