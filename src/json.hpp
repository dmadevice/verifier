// JSON: a small reader for the inputs (IDA exports, library matches) and a writer for the report (2-space
// indent, UTF-8, objects in insertion order).
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
  bool as_bool() const;   // a boolean, or a number (non-zero is true)
};

Value parse(std::string_view text);   // throws std::runtime_error
std::string dump(const Value& v);         // the document, indented, with a final newline
std::string quote(std::string_view s);    // a JSON string literal

// The writer's pieces, for a document written as it is made (the text dump() gives for the same values)
void put_quoted(std::string& out, std::string_view s);                             // a string
void put_value(std::string& out, const Value& v, int level);                        // a value at `level`
void put_strings(std::string& out, const std::vector<std::string>& v, int level);   // an array of strings at `level`
class ObjectWriter {   // an object at `level`: key() before each member's value, end() after the last
 public:
  ObjectWriter(std::string& out, int level) : out_(out), level_(level) {}
  void key(std::string_view k);
  void end();
  int value_level() const { return level_ + 1; }

 private:
  std::string& out_;
  int level_;
  bool first_ = true;
};

}  // namespace verifier::json
