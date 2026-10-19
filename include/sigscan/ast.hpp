#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "sigscan/diagnostics.hpp"

namespace sigscan {

enum class Severity { Low = 0, Medium = 1, High = 2, Critical = 3 };

[[nodiscard]] const char* severity_name(Severity severity);
[[nodiscard]] std::optional<Severity> parse_severity(std::string_view text);

enum class CmpOp { Eq, Ne, Lt, Le, Gt, Ge };

[[nodiscard]] const char* cmp_op_text(CmpOp op);
[[nodiscard]] bool compare(std::uint64_t lhs, CmpOp op, std::uint64_t rhs);

enum class ExprKind {
  Bool,      // true / false
  And,       // n-ary
  Or,        // n-ary
  Not,       // one child
  Present,   // $a
  Count,     // #a OP N
  At,        // $a at N
  In,        // $a in (N..M), inclusive
  Of,        // any|all|N of (set) / them
  Filesize,  // filesize OP N
};

enum class Quantifier { Any, All, Number };

struct Expr {
  ExprKind kind = ExprKind::Bool;
  SourceLocation loc;
  bool bool_value = false;
  std::vector<std::unique_ptr<Expr>> children;
  std::size_t string_index = 0;  // rule-local string index for Present/Count/At/In
  CmpOp op = CmpOp::Eq;
  std::uint64_t value = 0;   // Count/Filesize threshold, At offset, In start
  std::uint64_t value2 = 0;  // In end
  Quantifier quantifier = Quantifier::Any;
  std::uint64_t quantity = 0;    // for Quantifier::Number
  std::vector<std::size_t> set;  // Of: sorted, unique rule-local string indexes
  std::string set_text;          // "them" or "($b, $c)" as written, for explanations
};

struct MetaValue {
  enum class Type { String, Integer, Boolean };
  Type type = Type::String;
  std::string text;
  std::uint64_t integer = 0;
  bool boolean = false;
};

struct MetaEntry {
  std::string key;
  MetaValue value;
};

struct StringDef {
  std::string id;  // including the leading '$'
  bool is_hex = false;
  std::vector<std::uint8_t> bytes;
  std::vector<std::uint8_t> mask;  // same length as bytes; all 0xFF for text strings
  bool nocase = false;
  bool wide = false;
  bool ascii = false;  // effective: true unless only `wide` was given
  SourceLocation loc;
};

struct Rule {
  std::string name;
  std::vector<std::string> tags;
  std::vector<MetaEntry> meta;
  Severity severity = Severity::Medium;
  std::vector<StringDef> strings;
  std::unique_ptr<Expr> condition;
  std::string condition_text;  // whitespace-collapsed source of the condition
  SourceLocation loc;

  [[nodiscard]] const MetaEntry* find_meta(std::string_view key) const;
};

}  // namespace sigscan
