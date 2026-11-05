#include "dpi/table.hpp"

#include <algorithm>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace dpi {
namespace {

std::string repeat(const char* piece, size_t count) {
    std::string out;
    for (size_t i = 0; i < count; ++i) out += piece;
    return out;
}

std::string pad(const std::string& text, size_t width, Align align) {
    if (text.size() >= width) return text;
    std::string spaces(width - text.size(), ' ');
    return align == Align::Left ? text + spaces : spaces + text;
}

}  // namespace

void TextTable::addColumn(std::string header, Align align) {
    headers_.push_back(std::move(header));
    aligns_.push_back(align);
}

void TextTable::addRow(std::vector<std::string> cells) {
    cells.resize(headers_.size());
    rows_.push_back({false, std::move(cells)});
}

void TextTable::addSeparator() { rows_.push_back({true, {}}); }

void TextTable::print(std::ostream& os) const {
    const size_t cols = headers_.size();
    if (cols == 0) return;

    std::vector<size_t> width(cols);
    for (size_t c = 0; c < cols; ++c) width[c] = headers_[c].size();
    for (const auto& row : rows_) {
        if (row.separator) continue;
        for (size_t c = 0; c < cols; ++c) width[c] = std::max(width[c], row.cells[c].size());
    }

    // Inner width = each column plus one space either side, plus the dividers.
    size_t inner = cols - 1;
    for (size_t w : width) inner += w + 2;
    if (!title_.empty() && title_.size() + 2 > inner) {
        width.back() += title_.size() + 2 - inner;
        inner = title_.size() + 2;
    }

    auto rule = [&](const char* left, const char* mid, const char* right) {
        os << left;
        for (size_t c = 0; c < cols; ++c) {
            os << repeat("─", width[c] + 2);
            os << (c + 1 < cols ? mid : right);
        }
        os << '\n';
    };
    auto line = [&](const std::vector<std::string>& cells, bool header) {
        os << "│";
        for (size_t c = 0; c < cols; ++c) {
            os << ' ' << pad(cells[c], width[c], header ? Align::Left : aligns_[c]) << " │";
        }
        os << '\n';
    };

    if (!title_.empty()) {
        os << "┌" << repeat("─", inner) << "┐\n";
        size_t left = (inner - title_.size()) / 2;
        os << "│" << std::string(left, ' ') << title_ << std::string(inner - left - title_.size(), ' ') << "│\n";
        rule("├", "┬", "┤");
    } else {
        rule("┌", "┬", "┐");
    }
    line(headers_, true);
    rule("├", "┼", "┤");
    for (const auto& row : rows_) {
        if (row.separator) rule("├", "┼", "┤");
        else line(row.cells, false);
    }
    rule("└", "┴", "┘");
}

void enableUtf8Console() {
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
}

}  // namespace dpi
