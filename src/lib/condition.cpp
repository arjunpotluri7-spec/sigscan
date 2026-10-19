#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

#include "sigscan/ast.hpp"
#include "sigscan/scanner.hpp"

namespace sigscan {
namespace {

constexpr std::uint64_t kKiB = 1024;
constexpr std::uint64_t kMiB = 1024ULL * 1024;
constexpr std::uint64_t kGiB = 1024ULL * 1024 * 1024;

const StringHits* hits_for(const EvalContext& ctx, std::size_t index) {
  return index < ctx.hits.size() ? &ctx.hits[index] : nullptr;
}

std::uint64_t count_of(const EvalContext& ctx, std::size_t index) {
  const StringHits* h = hits_for(ctx, index);
  return h == nullptr ? 0 : h->count;
}

// First stored match at or after `offset`, or nullptr.
const MatchRecord* first_at_or_after(const StringHits& hits, std::uint64_t offset) {
  const auto it =
      std::lower_bound(hits.matches.begin(), hits.matches.end(), offset,
                       [](const MatchRecord& m, std::uint64_t value) { return m.offset < value; });
  return it == hits.matches.end() ? nullptr : &*it;
}

std::size_t found_in_set(const Expr& expr, const EvalContext& ctx) {
  std::size_t found = 0;
  for (const std::size_t index : expr.set) {
    if (count_of(ctx, index) > 0) {
      ++found;
    }
  }
  return found;
}

std::string hex_offset(std::uint64_t value) {
  std::ostringstream out;
  out << "0x" << std::hex << value;
  return out.str();
}

std::string threshold_text(std::uint64_t value) {
  if (value >= kMiB && value % kMiB == 0) {
    return std::to_string(value / kMiB) + " MB";
  }
  if (value >= kKiB && value % kKiB == 0) {
    return std::to_string(value / kKiB) + " KB";
  }
  return std::to_string(value) + (value == 1 ? " byte" : " bytes");
}

std::string string_name(const Rule& rule, std::size_t index) {
  return index < rule.strings.size() ? rule.strings[index].id : "$?";
}

std::string to_text(const Expr& expr, const Rule& rule) {
  switch (expr.kind) {
    case ExprKind::Bool:
      return expr.bool_value ? "true" : "false";
    case ExprKind::And:
    case ExprKind::Or: {
      std::string out = "(";
      for (std::size_t i = 0; i < expr.children.size(); ++i) {
        if (i > 0) {
          out += expr.kind == ExprKind::And ? " and " : " or ";
        }
        out += to_text(*expr.children[i], rule);
      }
      return out + ")";
    }
    case ExprKind::Not:
      return "not " + to_text(*expr.children.front(), rule);
    case ExprKind::Present:
      return string_name(rule, expr.string_index);
    case ExprKind::Count:
      return "#" + string_name(rule, expr.string_index).substr(1) + " " + cmp_op_text(expr.op) +
             " " + std::to_string(expr.value);
    case ExprKind::At:
      return string_name(rule, expr.string_index) + " at " + std::to_string(expr.value);
    case ExprKind::In:
      return string_name(rule, expr.string_index) + " in (" + std::to_string(expr.value) + ".." +
             std::to_string(expr.value2) + ")";
    case ExprKind::Of: {
      std::string q = expr.quantifier == Quantifier::Any   ? "any"
                      : expr.quantifier == Quantifier::All ? "all"
                                                           : std::to_string(expr.quantity);
      return q + " of " + expr.set_text;
    }
    case ExprKind::Filesize:
      return std::string("filesize ") + cmp_op_text(expr.op) + " " + threshold_text(expr.value);
  }
  return "?";
}

struct Parts {
  std::vector<std::string> main;
  std::vector<std::string> size;
};

std::string join(const std::vector<std::string>& items, const char* sep) {
  std::string out;
  for (std::size_t i = 0; i < items.size(); ++i) {
    if (i > 0) {
      out += sep;
    }
    out += items[i];
  }
  return out;
}

void collect(const Expr& expr, const Rule& rule, const EvalContext& ctx, Parts& parts);

std::string describe(const Expr& expr, const Rule& rule, const EvalContext& ctx) {
  switch (expr.kind) {
    case ExprKind::Bool:
      return "condition is true";
    case ExprKind::And: {
      Parts inner;
      collect(expr, rule, ctx, inner);
      std::vector<std::string> all = inner.main;
      all.insert(all.end(), inner.size.begin(), inner.size.end());
      return join(all, " and ");
    }
    case ExprKind::Or:
      for (const auto& child : expr.children) {
        if (evaluate(*child, ctx)) {
          return describe(*child, rule, ctx);
        }
      }
      return "condition is true";
    case ExprKind::Not: {
      const Expr& child = *expr.children.front();
      if (child.kind == ExprKind::Present) {
        return string_name(rule, child.string_index) + " not found";
      }
      return "'" + to_text(child, rule) + "' is false";
    }
    case ExprKind::Present: {
      const StringHits* h = hits_for(ctx, expr.string_index);
      std::string out = string_name(rule, expr.string_index) + " found";
      if (h != nullptr && !h->matches.empty()) {
        out += " at " + hex_offset(h->matches.front().offset);
      }
      if (h != nullptr && h->count > 1) {
        out += " (" + std::to_string(h->count) + " times)";
      }
      return out;
    }
    case ExprKind::Count:
      return "#" + string_name(rule, expr.string_index).substr(1) + " is " +
             std::to_string(count_of(ctx, expr.string_index)) + " (" + cmp_op_text(expr.op) + " " +
             std::to_string(expr.value) + ")";
    case ExprKind::At:
      return string_name(rule, expr.string_index) + " at " + hex_offset(expr.value);
    case ExprKind::In: {
      std::string out = string_name(rule, expr.string_index) + " found";
      if (const StringHits* h = hits_for(ctx, expr.string_index)) {
        if (const MatchRecord* m = first_at_or_after(*h, expr.value)) {
          out += " at " + hex_offset(m->offset);
        }
      }
      return out + " within (" + std::to_string(expr.value) + ".." + std::to_string(expr.value2) +
             ")";
    }
    case ExprKind::Of: {
      const std::size_t found = found_in_set(expr, ctx);
      std::string out = std::to_string(found) + " of " + expr.set_text + " found";
      if (found < expr.set.size() && found > 0) {
        std::vector<std::string> names;
        for (const std::size_t index : expr.set) {
          if (count_of(ctx, index) > 0) {
            names.push_back(string_name(rule, index));
          }
        }
        out += " (" + join(names, ", ") + ")";
      }
      return out;
    }
    case ExprKind::Filesize:
      return "filesize " + format_size(ctx.filesize) + " " + cmp_op_text(expr.op) + " " +
             threshold_text(expr.value);
  }
  return "condition is true";
}

void collect(const Expr& expr, const Rule& rule, const EvalContext& ctx, Parts& parts) {
  if (expr.kind == ExprKind::And) {
    for (const auto& child : expr.children) {
      collect(*child, rule, ctx, parts);
    }
    return;
  }
  if (expr.kind == ExprKind::Filesize) {
    parts.size.push_back(describe(expr, rule, ctx));
  } else {
    parts.main.push_back(describe(expr, rule, ctx));
  }
}

}  // namespace

bool evaluate(const Expr& expr, const EvalContext& ctx) {
  switch (expr.kind) {
    case ExprKind::Bool:
      return expr.bool_value;
    case ExprKind::And:
      return std::all_of(expr.children.begin(), expr.children.end(),
                         [&](const auto& c) { return evaluate(*c, ctx); });
    case ExprKind::Or:
      return std::any_of(expr.children.begin(), expr.children.end(),
                         [&](const auto& c) { return evaluate(*c, ctx); });
    case ExprKind::Not:
      return !expr.children.empty() && !evaluate(*expr.children.front(), ctx);
    case ExprKind::Present:
      return count_of(ctx, expr.string_index) > 0;
    case ExprKind::Count:
      return compare(count_of(ctx, expr.string_index), expr.op, expr.value);
    case ExprKind::At: {
      const StringHits* h = hits_for(ctx, expr.string_index);
      const MatchRecord* m = h == nullptr ? nullptr : first_at_or_after(*h, expr.value);
      return m != nullptr && m->offset == expr.value;
    }
    case ExprKind::In: {
      const StringHits* h = hits_for(ctx, expr.string_index);
      const MatchRecord* m = h == nullptr ? nullptr : first_at_or_after(*h, expr.value);
      return m != nullptr && m->offset <= expr.value2;
    }
    case ExprKind::Of: {
      const std::size_t found = found_in_set(expr, ctx);
      switch (expr.quantifier) {
        case Quantifier::Any:
          return found >= 1;
        case Quantifier::All:
          return found == expr.set.size();
        case Quantifier::Number:
          return found >= expr.quantity;
      }
      return false;
    }
    case ExprKind::Filesize:
      return compare(ctx.filesize, expr.op, expr.value);
  }
  return false;
}

std::string explain(const Rule& rule, const EvalContext& ctx) {
  if (!rule.condition) {
    return "matched";
  }
  Parts parts;
  collect(*rule.condition, rule, ctx, parts);
  std::string out = "matched because ";
  out += join(parts.main, " and ");
  if (!parts.size.empty()) {
    out += parts.main.empty() ? "" : "; ";
    out += join(parts.size, ", ");
  }
  return out;
}

std::string format_size(std::uint64_t bytes) {
  std::ostringstream out;
  out << std::fixed << std::setprecision(1);
  if (bytes < kKiB) {
    return std::to_string(bytes) + (bytes == 1 ? " byte" : " bytes");
  }
  if (bytes < kMiB) {
    out << static_cast<double>(bytes) / static_cast<double>(kKiB) << " KB";
  } else if (bytes < kGiB) {
    out << static_cast<double>(bytes) / static_cast<double>(kMiB) << " MB";
  } else {
    out << static_cast<double>(bytes) / static_cast<double>(kGiB) << " GB";
  }
  return out.str();
}

}  // namespace sigscan
