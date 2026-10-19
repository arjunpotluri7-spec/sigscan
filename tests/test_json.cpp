#include <gtest/gtest.h>

#include <sstream>
#include <string>

#include "sigscan/json_writer.hpp"
#include "sigscan/report.hpp"
#include "test_util.hpp"

namespace sigscan {
namespace {

TEST(Json, QuoteEscapesControlCharactersAndQuotes) {
  EXPECT_EQ(json_quote("a\"b\\c\n\t\r"), R"("a\"b\\c\n\t\r")");
  EXPECT_EQ(json_quote(std::string("\x01\x1f\x7f", 3)), R"("\u0001\u001f\u007f")");
}

TEST(Json, QuoteKeepsValidUtf8AndReplacesInvalidBytes) {
  EXPECT_EQ(json_quote("caf\xC3\xA9"), "\"caf\xC3\xA9\"");
  EXPECT_EQ(json_quote("bad\xFF"), "\"bad\\ufffd\"");
  EXPECT_EQ(json_quote("\xC3"), "\"\\ufffd\"");                        // truncated sequence
  EXPECT_EQ(json_quote("\xC0\xAF"), "\"\\ufffd\\ufffd\"");             // overlong encoding
  EXPECT_EQ(json_quote("\xED\xA0\x80"), "\"\\ufffd\\ufffd\\ufffd\"");  // surrogate
}

TEST(Json, WriterProducesParseableNestedDocuments) {
  std::ostringstream out;
  JsonWriter w(out);
  w.begin_object();
  w.field("name", "x");
  w.key("list");
  w.begin_array();
  w.number(1);
  w.number_signed(-2);
  w.boolean(true);
  w.null();
  w.begin_object();
  w.end_object();
  w.begin_array();
  w.end_array();
  w.end_array();
  w.field_number("n", 18446744073709551615ULL);
  w.end_object();
  const test::Json doc = test::parse_json(out.str());
  EXPECT_EQ(doc["name"].str(), "x");
  EXPECT_EQ(doc["list"].arr().size(), 6U);
  EXPECT_TRUE(doc["list"][4].is_object());
  EXPECT_NE(out.str().find("18446744073709551615"), std::string::npos);
}

TEST(Report, HexAndPrintableRendering) {
  EXPECT_EQ(hex_bytes({0x00, 0x4d, 0xff}), "00 4d ff");
  EXPECT_EQ(printable_bytes({'A', 0x00, '~', 0x7f, ' '}), "A.~. ");
}

}  // namespace
}  // namespace sigscan
