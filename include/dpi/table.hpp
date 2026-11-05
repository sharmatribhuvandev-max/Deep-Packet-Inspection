#pragma once

#include <ostream>
#include <string>
#include <utility>
#include <vector>

namespace dpi {

enum class Align { Left, Right };

// A console table with box-drawing borders whose column widths adapt to the
// content. Cell text is expected to be ASCII.
class TextTable {
public:
    explicit TextTable(std::string title = "") : title_(std::move(title)) {}

    void addColumn(std::string header, Align align = Align::Left);
    void addRow(std::vector<std::string> cells);
    void addSeparator();
    void print(std::ostream& os) const;

private:
    struct Row {
        bool separator = false;
        std::vector<std::string> cells;
    };
    std::string title_;
    std::vector<std::string> headers_;
    std::vector<Align> aligns_;
    std::vector<Row> rows_;
};

// Switches the Windows console to UTF-8 so the borders render (no-op elsewhere).
void enableUtf8Console();

}  // namespace dpi
